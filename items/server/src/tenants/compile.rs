use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt;

use conclave_managed_config::{ManagedConfig, PortableFactConfig};
use serde_json::Value;

use crate::authz::CompiledAuthzModel;
use crate::types::{DynError, PolicyRevision, RoleKey, TenantId};

use super::model::{
    CompiledAssumptionGrant, CompiledEffectiveGrant, CompiledMembership, CompiledScopeGrant,
    CompiledSubject, CompiledTenant, CompiledTenantModel,
};

pub(crate) const DEFAULT_ASSUMPTION_TTL_SECONDS: u64 = 900;
pub(crate) const ROOT_TENANT_ID: &str = "root";

#[derive(Debug)]
pub(crate) struct TenantError {
    message: String,
}

impl TenantError {
    pub(crate) fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for TenantError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.message.fmt(f)
    }
}

impl std::error::Error for TenantError {}

#[derive(Clone, Debug)]
struct RawTenant {
    id: TenantId,
    display_name: Option<String>,
    parent: Option<TenantId>,
    state: String,
}

#[derive(Clone, Debug)]
pub(crate) struct Bitset {
    words: Vec<u64>,
}

impl Bitset {
    pub(crate) fn new(bit_count: usize) -> Self {
        let word_count = bit_count.div_ceil(64).max(1);
        Self {
            words: vec![0; word_count],
        }
    }

    pub(crate) fn insert(&mut self, bit: usize) {
        let word = bit / 64;
        let offset = bit % 64;
        self.words[word] |= 1_u64 << offset;
    }

    pub(crate) fn to_hex(&self) -> String {
        let mut chunks: Vec<String> = self
            .words
            .iter()
            .rev()
            .map(|word| format!("{word:016x}"))
            .collect();

        while chunks.len() > 1
            && chunks
                .first()
                .is_some_and(|chunk| chunk == "0000000000000000")
        {
            chunks.remove(0);
        }

        let hex = chunks.join("");
        let trimmed = hex.trim_start_matches('0');

        if trimmed.is_empty() {
            "0".to_owned()
        } else {
            trimmed.to_owned()
        }
    }
}

pub fn compile_managed_tenants(
    config: &ManagedConfig,
    authz: &CompiledAuthzModel,
) -> Result<CompiledTenantModel, DynError> {
    let tenants = compile_tenants(config)?;
    let subjects = compile_subjects(config)?;
    let memberships = compile_memberships(config, &tenants, &subjects, authz)?;
    let assumption_grants = compile_assumption_grants(config, &tenants, &memberships, authz)?;
    let effective_grants =
        compile_effective_grants(&tenants, &memberships, &assumption_grants, authz)?;
    let policy_revision =
        compute_policy_revision(authz, &tenants, &memberships, &assumption_grants);

    Ok(CompiledTenantModel {
        root_tenant: ROOT_TENANT_ID.to_owned(),
        policy_revision,
        tenants,
        subjects,
        memberships,
        assumption_grants,
        effective_grants,
    })
}

// r[impl tenant.root.bootstrap]
// r[impl tenant.root.managed-entry]
// r[impl tenant.tree.parent-reference]
// r[impl tenant.tree.root-default-parent]
// r[impl tenant.lifecycle.state-machine]
fn compile_tenants(config: &ManagedConfig) -> Result<Vec<CompiledTenant>, DynError> {
    let mut raw_tenants = HashMap::new();
    raw_tenants.insert(
        ROOT_TENANT_ID.to_owned(),
        RawTenant {
            id: ROOT_TENANT_ID.to_owned(),
            display_name: None,
            parent: None,
            state: "active".to_owned(),
        },
    );
    let mut root_configured = false;

    for tenant in &config.tenants {
        if tenant.id.trim().is_empty() {
            return Err(Box::new(TenantError::new("tenant id cannot be empty")));
        }

        validate_tenant_state(&tenant.state)?;

        if tenant.id == ROOT_TENANT_ID {
            if root_configured {
                return Err(Box::new(TenantError::new(format!(
                    "duplicate tenant id {ROOT_TENANT_ID}"
                ))));
            }

            if tenant.parent.is_some() {
                return Err(Box::new(TenantError::new(
                    "root tenant cannot declare a parent",
                )));
            }

            root_configured = true;
            raw_tenants.insert(
                ROOT_TENANT_ID.to_owned(),
                RawTenant {
                    id: ROOT_TENANT_ID.to_owned(),
                    display_name: tenant.display_name.clone(),
                    parent: None,
                    state: tenant.state.clone(),
                },
            );
            continue;
        }

        let parent = tenant
            .parent
            .clone()
            .unwrap_or_else(|| ROOT_TENANT_ID.to_owned());
        let raw = RawTenant {
            id: tenant.id.clone(),
            display_name: tenant.display_name.clone(),
            parent: Some(parent),
            state: tenant.state.clone(),
        };

        if raw_tenants.insert(raw.id.clone(), raw).is_some() {
            return Err(Box::new(TenantError::new(format!(
                "duplicate tenant id {}",
                tenant.id
            ))));
        }
    }

    let mut resolved = HashMap::<TenantId, CompiledTenant>::new();
    let mut visiting = BTreeSet::new();

    for tenant_id in raw_tenants.keys() {
        resolve_tenant(tenant_id, &raw_tenants, &mut visiting, &mut resolved)?;
    }

    let mut tenants: Vec<CompiledTenant> = resolved.into_values().collect();
    tenants.sort_by(|left, right| left.id.cmp(&right.id));
    Ok(tenants)
}

fn resolve_tenant(
    tenant_id: &str,
    tenants: &HashMap<TenantId, RawTenant>,
    visiting: &mut BTreeSet<TenantId>,
    resolved: &mut HashMap<TenantId, CompiledTenant>,
) -> Result<CompiledTenant, DynError> {
    if let Some(existing) = resolved.get(tenant_id) {
        return Ok(existing.clone());
    }

    if !visiting.insert(tenant_id.to_owned()) {
        return Err(Box::new(TenantError::new(format!(
            "cycle detected in tenant tree at {tenant_id}"
        ))));
    }

    let raw = tenants.get(tenant_id).ok_or_else(|| {
        Box::new(TenantError::new(format!("unknown tenant {tenant_id}"))) as DynError
    })?;

    let lineage = if let Some(parent_id) = raw.parent.as_deref() {
        if parent_id == tenant_id {
            return Err(Box::new(TenantError::new(format!(
                "tenant {tenant_id} cannot be its own parent"
            ))));
        }

        let parent = resolve_tenant(parent_id, tenants, visiting, resolved)?;
        let mut lineage = parent.lineage;
        lineage.push(tenant_id.to_owned());
        lineage
    } else {
        vec![tenant_id.to_owned()]
    };

    visiting.remove(tenant_id);

    let compiled = CompiledTenant {
        id: raw.id.clone(),
        display_name: raw.display_name.clone(),
        parent: raw.parent.clone(),
        state: raw.state.clone(),
        lineage,
    };

    resolved.insert(tenant_id.to_owned(), compiled.clone());
    Ok(compiled)
}

fn compile_subjects(config: &ManagedConfig) -> Result<Vec<CompiledSubject>, DynError> {
    let mut seen = BTreeSet::new();
    let mut subjects = Vec::with_capacity(config.subjects.len());

    for subject in &config.subjects {
        if !seen.insert(subject.id.clone()) {
            return Err(Box::new(TenantError::new(format!(
                "duplicate subject id {}",
                subject.id
            ))));
        }

        subjects.push(CompiledSubject {
            id: subject.id.clone(),
            display_name: subject.display_name.clone(),
        });
    }

    Ok(subjects)
}

// r[impl tenant.namespace.isolation]
// r[impl user.membership.tenant-binding]
// r[impl authz.role.tenant-scoped]
// r[impl authz.role.runtime.tenant-local]
// r[impl authz.compile.effective-grants]
// r[impl authz.query.no-recursive-expansion]
fn compile_memberships(
    config: &ManagedConfig,
    tenants: &[CompiledTenant],
    subjects: &[CompiledSubject],
    authz: &CompiledAuthzModel,
) -> Result<Vec<CompiledMembership>, DynError> {
    let tenant_ids: BTreeSet<&str> = tenants.iter().map(|tenant| tenant.id.as_str()).collect();
    let subject_ids: BTreeSet<&str> = subjects.iter().map(|subject| subject.id.as_str()).collect();
    let mut seen = BTreeSet::new();
    let mut memberships = Vec::with_capacity(config.memberships.len());

    for membership in &config.memberships {
        if !subject_ids.contains(membership.subject.as_str()) {
            return Err(Box::new(TenantError::new(format!(
                "membership references unknown subject {}",
                membership.subject
            ))));
        }

        if !tenant_ids.contains(membership.tenant.as_str()) {
            return Err(Box::new(TenantError::new(format!(
                "membership references unknown tenant {}",
                membership.tenant
            ))));
        }

        let identity = (membership.subject.clone(), membership.tenant.clone());
        if !seen.insert(identity.clone()) {
            return Err(Box::new(TenantError::new(format!(
                "duplicate membership {}@{}",
                membership.subject, membership.tenant
            ))));
        }

        let facts = compile_facts(&membership.facts)?;
        let (tenant_bits_hex, scoped_entries) =
            compile_entitlements(&membership.tenant, &membership.roles, authz)?;

        memberships.push(CompiledMembership {
            subject: membership.subject.clone(),
            tenant: membership.tenant.clone(),
            role_keys: membership.roles.clone(),
            tenant_bits_hex,
            scoped_entries,
            facts,
        });
    }

    memberships.sort_by(|left, right| {
        left.tenant
            .cmp(&right.tenant)
            .then_with(|| left.subject.cmp(&right.subject))
    });

    Ok(memberships)
}

// r[impl tenant.admin.no-implicit-child-access]
// r[impl authn.assumption.conclave-action]
// r[impl authz.control-plane.capability.assumption-separate]
fn compile_assumption_grants(
    config: &ManagedConfig,
    tenants: &[CompiledTenant],
    memberships: &[CompiledMembership],
    authz: &CompiledAuthzModel,
) -> Result<Vec<CompiledAssumptionGrant>, DynError> {
    let membership_index: HashMap<(&str, &str), &CompiledMembership> = memberships
        .iter()
        .map(|entry| ((entry.subject.as_str(), entry.tenant.as_str()), entry))
        .collect();
    let tenant_index: HashMap<&str, &CompiledTenant> = tenants
        .iter()
        .map(|tenant| (tenant.id.as_str(), tenant))
        .collect();
    let mut grants = Vec::with_capacity(config.assumption_grants.len());

    for grant in &config.assumption_grants {
        membership_index
            .get(&(grant.subject.as_str(), grant.source_tenant.as_str()))
            .ok_or_else(|| {
                Box::new(TenantError::new(format!(
                    "assumption grant references missing source membership {}@{}",
                    grant.subject, grant.source_tenant
                ))) as DynError
            })?;
        let target_tenant = tenant_index
            .get(grant.target_tenant.as_str())
            .ok_or_else(|| {
                Box::new(TenantError::new(format!(
                    "assumption grant references unknown target tenant {}",
                    grant.target_tenant
                ))) as DynError
            })?;

        if !tenant_is_descendant_of(target_tenant, &grant.source_tenant) {
            return Err(Box::new(TenantError::new(format!(
                "assumption grant target {} is not a descendant of {}",
                grant.target_tenant, grant.source_tenant
            ))));
        }

        compile_entitlements(&grant.target_tenant, &grant.target_roles, authz)?;

        grants.push(CompiledAssumptionGrant {
            subject: grant.subject.clone(),
            source_tenant: grant.source_tenant.clone(),
            target_tenant: grant.target_tenant.clone(),
            target_role_keys: grant.target_roles.clone(),
            ttl_seconds: grant
                .ttl_seconds
                .unwrap_or(DEFAULT_ASSUMPTION_TTL_SECONDS)
                .max(1),
        });
    }

    grants.sort_by(|left, right| {
        left.source_tenant
            .cmp(&right.source_tenant)
            .then_with(|| left.target_tenant.cmp(&right.target_tenant))
            .then_with(|| left.subject.cmp(&right.subject))
    });

    Ok(grants)
}

fn compile_facts(facts: &[PortableFactConfig]) -> Result<BTreeMap<String, Value>, DynError> {
    let mut compiled = BTreeMap::new();

    for fact in facts {
        let mut count = 0;

        if fact.string.is_some() {
            count += 1;
        }
        if fact.integer.is_some() {
            count += 1;
        }
        if fact.boolean.is_some() {
            count += 1;
        }

        if count != 1 {
            return Err(Box::new(TenantError::new(format!(
                "portable fact {} must set exactly one value type",
                fact.key
            ))));
        }

        let value = if let Some(value) = &fact.string {
            Value::String(value.clone())
        } else if let Some(value) = fact.integer {
            Value::Number(value.into())
        } else {
            Value::Bool(fact.boolean.expect("boolean fact should be present"))
        };

        if compiled.insert(fact.key.clone(), value).is_some() {
            return Err(Box::new(TenantError::new(format!(
                "duplicate portable fact {}",
                fact.key
            ))));
        }
    }

    Ok(compiled)
}

fn compile_effective_grants(
    tenants: &[CompiledTenant],
    memberships: &[CompiledMembership],
    assumption_grants: &[CompiledAssumptionGrant],
    authz: &CompiledAuthzModel,
) -> Result<Vec<CompiledEffectiveGrant>, DynError> {
    let tenant_index = tenants
        .iter()
        .map(|tenant| (tenant.id.as_str(), tenant))
        .collect::<HashMap<_, _>>();
    let membership_index = memberships
        .iter()
        .map(|membership| {
            (
                (membership.subject.as_str(), membership.tenant.as_str()),
                membership,
            )
        })
        .collect::<HashMap<_, _>>();
    let mut effective_grants = Vec::with_capacity(memberships.len() + assumption_grants.len());

    for membership in memberships {
        let target_tenant = tenant_index
            .get(membership.tenant.as_str())
            .expect("compiled membership tenant should exist");
        effective_grants.push(CompiledEffectiveGrant {
            grant_kind: "direct".to_owned(),
            subject: membership.subject.clone(),
            source_tenant: None,
            source_tenant_state: None,
            target_tenant: membership.tenant.clone(),
            target_tenant_state: target_tenant.state.clone(),
            tenant_bits_hex: membership.tenant_bits_hex.clone(),
            scoped_entries: membership.scoped_entries.clone(),
            facts: membership.facts.clone(),
            ttl_seconds: None,
        });
    }

    for grant in assumption_grants {
        let source_membership = membership_index
            .get(&(grant.subject.as_str(), grant.source_tenant.as_str()))
            .expect("compiled assumption source membership should exist");
        let source_tenant = tenant_index
            .get(grant.source_tenant.as_str())
            .expect("compiled source tenant should exist");
        let target_tenant = tenant_index
            .get(grant.target_tenant.as_str())
            .expect("compiled target tenant should exist");
        let (tenant_bits_hex, scoped_entries) =
            compile_entitlements(&grant.target_tenant, &grant.target_role_keys, authz)?;

        effective_grants.push(CompiledEffectiveGrant {
            grant_kind: "assumed".to_owned(),
            subject: grant.subject.clone(),
            source_tenant: Some(grant.source_tenant.clone()),
            source_tenant_state: Some(source_tenant.state.clone()),
            target_tenant: grant.target_tenant.clone(),
            target_tenant_state: target_tenant.state.clone(),
            tenant_bits_hex,
            scoped_entries,
            facts: source_membership.facts.clone(),
            ttl_seconds: Some(grant.ttl_seconds),
        });
    }

    effective_grants.sort_by(|left, right| {
        left.subject
            .cmp(&right.subject)
            .then_with(|| left.target_tenant.cmp(&right.target_tenant))
            .then_with(|| left.source_tenant.cmp(&right.source_tenant))
            .then_with(|| left.grant_kind.cmp(&right.grant_kind))
    });

    Ok(effective_grants)
}

// r[impl authz.assignment.multiple]
// r[impl authz.assignment.priority]
// r[impl authz.decision.precedence]
// r[impl authz.decision.deny-equal-precedence]
pub(crate) fn compile_entitlements(
    tenant_id: &str,
    role_keys: &[RoleKey],
    authz: &CompiledAuthzModel,
) -> Result<(String, Vec<CompiledScopeGrant>), DynError> {
    let action_bits = authz
        .actions
        .iter()
        .map(|action| (action.name.as_str(), action.bit))
        .collect::<HashMap<_, _>>();
    let mut tenant_effects = BTreeMap::<String, String>::new();
    let mut scoped_effects = BTreeMap::<
        (crate::types::ScopeKind, Option<crate::types::ScopeId>),
        BTreeMap<String, String>,
    >::new();

    for role_key in role_keys {
        let role = authz.find_role(tenant_id, role_key).ok_or_else(|| {
            Box::new(TenantError::new(format!(
                "tenant {} references unknown local role {}",
                tenant_id, role_key
            ))) as DynError
        })?;

        for policy in &role.policies {
            if let Some(scope_kind) = &policy.scope_kind {
                let effects = scoped_effects
                    .entry((scope_kind.clone(), policy.scope_id.clone()))
                    .or_default();
                for action in &policy.expanded_actions {
                    effects.insert(action.clone(), policy.effect.clone());
                }
            } else {
                for action in &policy.expanded_actions {
                    tenant_effects.insert(action.clone(), policy.effect.clone());
                }
            }
        }
    }

    let tenant_bits = effect_map_to_bits(&tenant_effects, &action_bits, authz.action_count);
    let scoped_entries = scoped_effects
        .into_iter()
        .map(|((kind, id), effects)| {
            let allow = effect_map_to_bits(&effects, &action_bits, authz.action_count);
            CompiledScopeGrant {
                kind,
                id,
                bits_hex: allow.to_hex(),
            }
        })
        .collect();

    Ok((tenant_bits.to_hex(), scoped_entries))
}

fn effect_map_to_bits(
    effects: &BTreeMap<String, String>,
    action_bits: &HashMap<&str, usize>,
    action_count: usize,
) -> Bitset {
    let mut bits = Bitset::new(action_count);

    for (action, effect) in effects {
        if effect != "allow" {
            continue;
        }

        let Some(bit) = action_bits.get(action.as_str()) else {
            continue;
        };
        bits.insert(*bit);
    }

    bits
}

fn validate_tenant_state(state: &str) -> Result<(), DynError> {
    match state {
        "active" | "suspended" | "deleted" => Ok(()),
        other => Err(Box::new(TenantError::new(format!(
            "unsupported tenant state {other}"
        )))),
    }
}

pub(crate) fn tenant_is_descendant_of(target: &CompiledTenant, source_tenant: &str) -> bool {
    target.id != source_tenant && target.lineage.iter().any(|tenant| tenant == source_tenant)
}

// r[impl config.managed.authz-revision-bump]
fn compute_policy_revision(
    authz: &CompiledAuthzModel,
    tenants: &[CompiledTenant],
    memberships: &[CompiledMembership],
    assumption_grants: &[CompiledAssumptionGrant],
) -> PolicyRevision {
    let mut data = Vec::new();
    data.extend_from_slice(format!("catalog:{};", authz.catalog_revision).as_bytes());

    for role in &authz.roles {
        data.extend_from_slice(
            format!(
                "role:{}:{}:{}:{}:{}:{};",
                role.tenant,
                role.key,
                role.revision,
                role.template.as_deref().unwrap_or(""),
                role.tenant_allow_bits_hex,
                role.tenant_deny_bits_hex
            )
            .as_bytes(),
        );

        for scope in &role.scoped_entries {
            data.extend_from_slice(
                format!(
                    "scope:{}:{}:{}:{};",
                    scope.scope_kind,
                    scope.scope_id.as_deref().unwrap_or("*"),
                    scope.allow_bits_hex,
                    scope.deny_bits_hex
                )
                .as_bytes(),
            );
        }
    }

    for tenant in tenants {
        data.extend_from_slice(
            format!(
                "tenant:{}:{}:{};",
                tenant.id,
                tenant.parent.as_deref().unwrap_or(ROOT_TENANT_ID),
                tenant.state
            )
            .as_bytes(),
        );
    }

    for membership in memberships {
        data.extend_from_slice(
            format!(
                "membership:{}:{}:{};",
                membership.subject,
                membership.tenant,
                membership.role_keys.join(",")
            )
            .as_bytes(),
        );

        for (key, value) in &membership.facts {
            data.extend_from_slice(format!("fact:{}:{};", key, value).as_bytes());
        }
    }

    for grant in assumption_grants {
        data.extend_from_slice(
            format!(
                "grant:{}:{}:{}:{}:{};",
                grant.subject,
                grant.source_tenant,
                grant.target_tenant,
                grant.target_role_keys.join(","),
                grant.ttl_seconds
            )
            .as_bytes(),
        );
    }

    fnv1a64(&data)
}

fn fnv1a64(bytes: &[u8]) -> u64 {
    const OFFSET: u64 = 0xcbf29ce484222325;
    const PRIME: u64 = 0x100000001b3;

    bytes.iter().fold(OFFSET, |hash, byte| {
        let hash = hash ^ u64::from(*byte);
        hash.wrapping_mul(PRIME)
    })
}
