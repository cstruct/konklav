//! Claim mapping: turning an identity provider's claims into grants.
//!
//! Rules are evaluated at every federated login. Grants they create are
//! recorded as managed by the provider, so re-evaluation adds and removes
//! exactly those and never touches grants made any other way.

use std::collections::{BTreeMap, BTreeSet};

use konklav_core::{MembershipId, SubjectId, TenantId};
use konklav_store::roles::{self, AssignmentTarget};
use konklav_store::sessions::{self, SessionFilter};
use konklav_store::{Connection, StoreError, memberships, tenants};
use serde_json::Value;

use crate::config::ClaimGrant;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Condition {
    Equals(String),
    Contains(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Grant {
    GlobalRole(String),
    Tenant {
        tenant: TenantId,
        roles: Vec<String>,
    },
}

/// One claim mapping rule: when `claim` meets `condition`, grant `grant`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rule {
    pub claim: String,
    pub condition: Condition,
    pub grant: Grant,
}

impl Rule {
    pub fn from_config(config: &ClaimGrant) -> Result<Self, String> {
        let condition = match (&config.equals, &config.contains) {
            (Some(value), None) => Condition::Equals(value.clone()),
            (None, Some(value)) => Condition::Contains(value.clone()),
            _ => {
                return Err(format!(
                    "grant for claim `{}` needs exactly one of equals and contains",
                    config.claim
                ));
            }
        };
        let grant = match (&config.global_role, &config.tenant) {
            (Some(role), None) if config.roles.is_empty() => Grant::GlobalRole(role.clone()),
            (None, Some(tenant)) => Grant::Tenant {
                tenant: tenants::parse_reference(tenant)
                    .filter(|tenant| *tenant != tenants::ROOT)
                    .ok_or_else(|| format!("`{tenant}` is not a tenant id"))?,
                roles: config.roles.clone(),
            },
            _ => {
                return Err(format!(
                    "grant for claim `{}` needs either global_role, or tenant with optional roles",
                    config.claim
                ));
            }
        };
        Ok(Self {
            claim: config.claim.clone(),
            condition,
            grant,
        })
    }

    #[must_use]
    pub fn matches(&self, claims: &Value) -> bool {
        let value = &claims[&self.claim];
        match &self.condition {
            Condition::Equals(expected) => value.as_str() == Some(expected),
            Condition::Contains(expected) => value
                .as_array()
                .is_some_and(|items| items.iter().any(|item| item.as_str() == Some(expected))),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Target {
    Global,
    Membership(uuid::Uuid),
}

impl Target {
    fn of(target: AssignmentTarget) -> Self {
        match target {
            AssignmentTarget::Subject(_) => Self::Global,
            AssignmentTarget::Membership(id) => Self::Membership(id.into()),
        }
    }
}

/// What the rules grant for a set of claims.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Desired {
    pub global_roles: BTreeSet<String>,
    pub tenants: BTreeMap<TenantId, BTreeSet<String>>,
}

#[must_use]
pub fn evaluate(rules: &[Rule], claims: &Value) -> Desired {
    let mut desired = Desired::default();
    for rule in rules.iter().filter(|rule| rule.matches(claims)) {
        match &rule.grant {
            Grant::GlobalRole(role) => {
                desired.global_roles.insert(role.clone());
            }
            Grant::Tenant { tenant, roles } => {
                desired
                    .tenants
                    .entry(*tenant)
                    .or_default()
                    .extend(roles.iter().cloned());
            }
        }
    }
    desired
}

/// Brings the grants `provider` manages for `subject` in line with
/// `desired`. Roles or tenants that don't exist are skipped with a warning,
/// so a stale rule doesn't block logins.
// r[impl federation.mapping.rules]
// r[impl federation.mapping.managed]
pub async fn apply(
    conn: &mut Connection,
    provider: &str,
    subject: SubjectId,
    desired: &Desired,
) -> Result<(), StoreError> {
    // (role, global target or membership)
    let mut wanted: BTreeSet<(uuid::Uuid, Target)> = BTreeSet::new();
    for key in &desired.global_roles {
        match roles::get(conn, tenants::ROOT, key).await {
            Ok(role) => {
                wanted.insert((role.id, Target::Global));
            }
            Err(StoreError::NotFound) => {
                tracing::warn!(provider, role = %key, "claim mapping names a missing global role");
            }
            Err(error) => return Err(error),
        }
    }
    let mut kept_memberships: BTreeSet<MembershipId> = BTreeSet::new();
    for (tenant, keys) in &desired.tenants {
        if matches!(tenants::get(conn, *tenant).await, Err(StoreError::NotFound)) {
            tracing::warn!(provider, %tenant, "claim mapping names a missing tenant");
            continue;
        }
        let membership = match memberships::find_active(conn, subject, *tenant).await? {
            Some(membership) => membership,
            None => {
                memberships::create_managed(
                    conn,
                    MembershipId::new_v7(),
                    subject,
                    *tenant,
                    &serde_json::json!({}),
                    Some(provider),
                )
                .await?
                .0
            }
        };
        kept_memberships.insert(membership.id);
        for key in keys {
            match roles::get(conn, *tenant, key).await {
                Ok(role) => {
                    wanted.insert((role.id, Target::Membership(membership.id.into())));
                }
                Err(StoreError::NotFound) => {
                    tracing::warn!(provider, %tenant, role = %key, "claim mapping names a missing role");
                }
                Err(error) => return Err(error),
            }
        }
    }

    let current = roles::managed_assignments_of(conn, subject, provider).await?;
    let mut present = BTreeSet::new();
    for assignment in current {
        let key = (assignment.role_id, Target::of(assignment.target));
        if assignment.scope.is_none() && wanted.contains(&key) {
            present.insert(key);
        } else {
            roles::unassign(conn, assignment.id).await?;
        }
    }
    for (role, target) in wanted.difference(&present) {
        let target = match target {
            Target::Global => AssignmentTarget::Subject(subject),
            Target::Membership(id) => AssignmentTarget::Membership((*id).into()),
        };
        roles::assign_managed(conn, *role, target, None, Some(provider)).await?;
    }
    for membership in memberships::list_managed(conn, subject, provider).await? {
        if !kept_memberships.contains(&membership.id) {
            memberships::end(conn, membership.id).await?;
            let filter = SessionFilter {
                membership: Some(membership.id),
                ..SessionFilter::default()
            };
            sessions::revoke(conn, &filter, None, "membership_ended").await?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn grant(claim: &str, contains: &str, global_role: &str) -> ClaimGrant {
        ClaimGrant {
            claim: claim.into(),
            equals: None,
            contains: Some(contains.into()),
            global_role: Some(global_role.into()),
            tenant: None,
            roles: vec![],
        }
    }

    #[test]
    fn rules_match_strings_and_list_members() {
        let tenant = TenantId::new_v7();
        let rules = [
            Rule::from_config(&grant("groups", "sre", "operator")).unwrap(),
            Rule::from_config(&ClaimGrant {
                claim: "department".into(),
                equals: Some("support".into()),
                contains: None,
                global_role: None,
                tenant: Some(tenant.to_string()),
                roles: vec!["agent".into()],
            })
            .unwrap(),
        ];
        let desired = evaluate(
            &rules,
            &serde_json::json!({"groups": ["dev", "sre"], "department": "support"}),
        );
        assert_eq!(
            desired.global_roles,
            BTreeSet::from(["operator".to_owned()])
        );
        assert_eq!(
            desired.tenants[&tenant],
            BTreeSet::from(["agent".to_owned()])
        );
        assert_eq!(
            evaluate(&rules, &serde_json::json!({"groups": "sre"})),
            Desired::default(),
            "contains needs a list"
        );
    }

    #[test]
    fn malformed_rules_are_refused() {
        let mut both = grant("groups", "sre", "operator");
        both.equals = Some("x".into());
        assert!(Rule::from_config(&both).is_err());
        let mut root = grant("groups", "sre", "operator");
        root.global_role = None;
        root.tenant = Some("root".into());
        assert!(
            Rule::from_config(&root).is_err(),
            "global roles use global_role"
        );
    }
}
