//! Route authority: what an allowed route decision vouches for, and which
//! of a later decision's required actions it covers.

use std::collections::BTreeSet;

use konklav_core::TenantId;
use serde::{Deserialize, Serialize};

use crate::{Entitlements, RegisteredScopes, Registration, Requirements, Scope};

/// Vouched actions at one scope of the token's tenant.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct VouchedScope {
    pub kind: String,
    pub id: String,
    pub actions: BTreeSet<String>,
}

/// What an allowed route decision vouches for: vouched actions per
/// placement, where the vouching actions were required. Later decisions of
/// the same request are made with it
/// (`authz.decision.route-authority`).
// r[impl authz.decision.vouches]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct RouteAuthority {
    /// Vouched for everywhere.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub global: BTreeSet<String>,
    /// Vouched for tenant-wide in the token's tenant and at its scopes.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub tenant: BTreeSet<String>,
    /// Vouched for at one scope each, and at the registered scopes it
    /// contains.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scopes: Vec<VouchedScope>,
}

impl RouteAuthority {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.global.is_empty() && self.tenant.is_empty() && self.scopes.is_empty()
    }

    fn at(&self, scope: &Scope) -> Option<&BTreeSet<String>> {
        self.scopes
            .iter()
            .find(|vouched| vouched.kind == scope.kind && vouched.id == scope.id)
            .map(|vouched| &vouched.actions)
    }

    fn add_at(&mut self, scope: &Scope, actions: impl IntoIterator<Item = String>) {
        let index = match self
            .scopes
            .iter()
            .position(|vouched| vouched.kind == scope.kind && vouched.id == scope.id)
        {
            Some(index) => index,
            None => {
                self.scopes.push(VouchedScope {
                    kind: scope.kind.clone(),
                    id: scope.id.clone(),
                    actions: BTreeSet::new(),
                });
                self.scopes.len() - 1
            }
        };
        self.scopes[index].actions.extend(actions);
        self.scopes
            .sort_by(|a, b| (&a.kind, &a.id).cmp(&(&b.kind, &b.id)));
    }

    /// Whether a required global action is covered.
    pub(crate) fn covers_global(&self, action: &str) -> bool {
        self.global.contains(action)
    }

    /// Whether a required tenant-wide action is covered.
    pub(crate) fn covers_tenant(&self, action: &str) -> bool {
        self.global.contains(action) || self.tenant.contains(action)
    }

    /// Whether a required action at `scope` is covered, given the scope's
    /// active registered record, if it is a registered scope. `owned` says
    /// whether the scope is the token's tenant's: another tenant's scope is
    /// never covered.
    // r[impl authz.decision.route-authority.coverage]
    pub(crate) fn covers_scope(
        &self,
        action: &str,
        scope: &Scope,
        record: Option<&Registration>,
        owned: bool,
    ) -> bool {
        if !owned {
            return false;
        }
        let at = |scope: &Scope| {
            self.at(scope)
                .is_some_and(|actions| actions.contains(action))
        };
        self.covers_tenant(action)
            || at(scope)
            || record.is_some_and(|record| record.containers.iter().any(at))
    }
}

/// What an allow for `requirements` in `tenant` (the token's) vouches for:
/// for each required action the entitlement set's vouches name, its vouched
/// actions where it was required. Never at a scope of another tenant, and
/// nothing at tenant or scope level without a tenant.
/// A registered scope belongs to its recorded tenant.
// r[impl authz.decision.vouches]
pub(crate) fn vouched_by(
    requirements: &Requirements,
    tenant: Option<TenantId>,
    entitlements: &Entitlements,
    registered: &RegisteredScopes,
) -> RouteAuthority {
    let mut authority = RouteAuthority::default();
    if entitlements.vouches.is_empty() {
        return authority;
    }
    let vouched = |required: &BTreeSet<String>| -> BTreeSet<String> {
        required
            .iter()
            .filter_map(|action| entitlements.vouches.get(action))
            .flatten()
            .cloned()
            .collect()
    };
    authority.global = vouched(&requirements.global);
    let Some(tenant) = tenant else {
        return authority;
    };
    authority.tenant = vouched(&requirements.tenant);
    for required in &requirements.scopes {
        let scope = Scope {
            kind: required.kind.clone(),
            id: required.id.clone(),
        };
        let owner = registered
            .lookup(&scope)
            .flatten()
            .map_or(required.tenant.unwrap_or(tenant), |record| record.tenant);
        if owner != tenant {
            continue;
        }
        let actions = vouched(&required.actions);
        if !actions.is_empty() {
            authority.add_at(&scope, actions);
        }
    }
    authority
}
