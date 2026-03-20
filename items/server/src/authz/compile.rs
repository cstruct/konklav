use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;

use conclave_managed_config::{
    ActionCatalogConfig, ManagedConfig, PolicySpec, RoleConfig, TemplateConfig,
    TemplateSourceConfig,
};

use crate::types::{ActionName, DynError, ScopeId, ScopeKind};

use super::model::{
    CompiledAction, CompiledAuthzModel, CompiledPolicy, CompiledRole, CompiledScopeEntry,
    CompiledTemplate,
};

#[derive(Clone, Debug)]
struct ResolvedTemplate {
    revision: u64,
    lineage: Vec<String>,
    inherited_from: Option<TemplateSourceConfig>,
    source_revision: Option<u64>,
    sync_mode: String,
    policies: Vec<PolicySpec>,
}

#[derive(Clone, Debug)]
struct ResolvedRole {
    revision: u64,
    policies: Vec<PolicySpec>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum PinTarget {
    Latest,
    Revision(u64),
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum VisitState {
    Visiting,
    Visited,
}

#[derive(Clone, Debug)]
struct CompiledPolicyBundle {
    tenant_allow_bits_hex: String,
    tenant_deny_bits_hex: String,
    scoped_entries: Vec<CompiledScopeEntry>,
    policies: Vec<CompiledPolicy>,
}

#[derive(Debug)]
struct AuthzError {
    message: String,
}

impl AuthzError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for AuthzError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.message.fmt(f)
    }
}

impl std::error::Error for AuthzError {}

// r[impl config.managed.authz-template-resources]
pub fn compile_managed_authz(config: &ManagedConfig) -> Result<CompiledAuthzModel, DynError> {
    let compiled_actions = compile_actions(&config.catalog)?;
    let catalog_revision = compute_catalog_revision(&config.catalog);
    let (compiled_templates, resolved_templates) =
        compile_templates(&config.templates, &compiled_actions)?;
    let compiled_roles = compile_roles(&config.roles, &resolved_templates, &compiled_actions)?;

    Ok(CompiledAuthzModel {
        catalog_revision,
        action_count: compiled_actions.len(),
        actions: compiled_actions,
        templates: compiled_templates,
        roles: compiled_roles,
    })
}

// r[impl config.managed.authz-intent-not-revisions]
// r[impl config.managed.authz-pinned-template-normalization]
pub fn normalize_managed_authz(config: &ManagedConfig) -> Result<ManagedConfig, DynError> {
    let compiled = compile_managed_authz(config)?;
    let template_sources = compiled
        .templates
        .into_iter()
        .map(|template| ((template.tenant, template.key), template.source))
        .collect::<HashMap<_, _>>();
    let mut normalized = config.clone();

    for template in &mut normalized.templates {
        if let Some(source) = template_sources.get(&(template.tenant.clone(), template.key.clone()))
        {
            template.source = source.clone();
        }
    }

    Ok(normalized)
}

// r[impl authz.action.catalog.versioned]
// r[impl authz.action.namespace.reserved]
// r[impl authz.action.namespace.conclave-internal]
// r[impl config.managed.authz-system-revisions]
fn compile_actions(catalog: &ActionCatalogConfig) -> Result<Vec<CompiledAction>, DynError> {
    let mut seen = HashSet::new();
    let mut compiled = Vec::with_capacity(catalog.actions.len());

    for (bit, action) in catalog.actions.iter().enumerate() {
        validate_action_name(&action.name, false)?;

        if !seen.insert(action.name.clone()) {
            return Err(Box::new(AuthzError::new(format!(
                "duplicate action in catalog: {}",
                action.name
            ))));
        }

        let namespace = action
            .name
            .split(':')
            .next()
            .expect("action namespace should exist")
            .to_owned();

        compiled.push(CompiledAction {
            name: action.name.clone(),
            namespace,
            bit,
            description: action.description.clone(),
        });
    }

    Ok(compiled)
}

// r[impl authz.role.template.recompute-lineage]
// r[impl authz.role.template.managed-config-reconcile]
// r[impl authz.role.template.overlay]
// r[impl config.managed.authz-selector-overrides]
fn compile_templates(
    templates: &[TemplateConfig],
    actions: &[CompiledAction],
) -> Result<(Vec<CompiledTemplate>, HashMap<String, ResolvedTemplate>), DynError> {
    let mut index_by_identity = HashMap::new();

    for (index, template) in templates.iter().enumerate() {
        validate_template_shape(template)?;
        validate_unique_policy_selectors(&template.policies, &template_identity(template))?;

        let identity = template_identity(template);
        if index_by_identity.insert(identity.clone(), index).is_some() {
            return Err(Box::new(AuthzError::new(format!(
                "duplicate role template identity: {identity}"
            ))));
        }
    }

    let mut states = HashMap::new();
    let mut resolved = HashMap::new();
    let mut compiled = Vec::with_capacity(templates.len());

    for index in 0..templates.len() {
        let resolved_template = resolve_template(
            index,
            templates,
            &index_by_identity,
            &mut states,
            &mut resolved,
        )?;
        compiled.push(build_compiled_template(
            &templates[index],
            &resolved_template,
            actions,
        )?);
    }

    compiled.sort_by(|left, right| {
        left.tenant
            .cmp(&right.tenant)
            .then_with(|| left.key.cmp(&right.key))
    });

    Ok((compiled, resolved))
}

fn resolve_template(
    index: usize,
    templates: &[TemplateConfig],
    index_by_identity: &HashMap<String, usize>,
    states: &mut HashMap<usize, VisitState>,
    resolved: &mut HashMap<String, ResolvedTemplate>,
) -> Result<ResolvedTemplate, DynError> {
    let identity = template_identity(&templates[index]);

    if let Some(existing) = resolved.get(&identity) {
        return Ok(existing.clone());
    }

    if matches!(states.get(&index), Some(VisitState::Visiting)) {
        return Err(Box::new(AuthzError::new(format!(
            "cycle detected while resolving template lineage for {identity}"
        ))));
    }

    states.insert(index, VisitState::Visiting);
    let template = &templates[index];

    let mut lineage = vec![identity.clone()];
    let mut policies = Vec::new();
    let mut inherited_from = None;
    let mut source_revision = None;
    let mut sync_mode = "local".to_owned();

    if let Some(source) = &template.source {
        let source_identity = template_source_identity(source);
        let source_index = index_by_identity
            .get(&source_identity)
            .copied()
            .ok_or_else(|| {
                Box::new(AuthzError::new(format!(
                    "template {identity} references unknown source template {source_identity}"
                ))) as DynError
            })?;
        let parent =
            resolve_template(source_index, templates, index_by_identity, states, resolved)?;
        let pin_target = parse_pin_target(source.pin.as_deref())?;
        let mut normalized_source = source.clone();

        if source.mode == "pinned" {
            match pin_target {
                PinTarget::Latest => {
                    source_revision = Some(parent.revision);
                    normalized_source.pin = Some(parent.revision.to_string());
                }
                PinTarget::Revision(revision) if revision == parent.revision => {
                    source_revision = Some(revision);
                    normalized_source.pin = Some(revision.to_string());
                }
                PinTarget::Revision(revision) => {
                    return Err(Box::new(AuthzError::new(format!(
                        "template {identity} pins {} to revision {revision}, but only current revision {} is available in the compile-time snapshot",
                        source_identity, parent.revision
                    ))));
                }
            }
        } else {
            source_revision = Some(parent.revision);
            normalized_source.pin = None;
        }

        lineage = parent.lineage.clone();
        lineage.push(identity.clone());
        policies = parent.policies.clone();
        sync_mode = normalized_source.mode.clone();
        inherited_from = Some(normalized_source);
    }

    apply_policy_overrides(&mut policies, &template.policies);

    let resolved_template = ResolvedTemplate {
        revision: compute_template_revision(
            template,
            inherited_from.as_ref(),
            source_revision,
            &lineage,
            &policies,
        ),
        lineage,
        inherited_from,
        source_revision,
        sync_mode,
        policies,
    };

    states.insert(index, VisitState::Visited);
    resolved.insert(identity, resolved_template.clone());

    Ok(resolved_template)
}

// r[impl authz.role.assignable.local]
// r[impl authz.role.template.non-assignable]
// r[impl authz.role.template.derive-local]
fn compile_roles(
    roles: &[RoleConfig],
    resolved_templates: &HashMap<String, ResolvedTemplate>,
    actions: &[CompiledAction],
) -> Result<Vec<CompiledRole>, DynError> {
    let mut seen = HashSet::new();

    for role in roles {
        validate_role_shape(role)?;
        validate_unique_policy_selectors(&role.policies, &role_identity(role))?;

        let identity = role_identity(role);
        if !seen.insert(identity.clone()) {
            return Err(Box::new(AuthzError::new(format!(
                "duplicate role identity: {identity}"
            ))));
        }
    }

    let index_by_identity = roles
        .iter()
        .enumerate()
        .map(|(index, role)| (role_identity(role), index))
        .collect::<HashMap<_, _>>();
    let mut states = HashMap::new();
    let mut resolved = HashMap::new();
    let mut compiled = Vec::with_capacity(roles.len());

    for index in 0..roles.len() {
        let role = &roles[index];
        let resolved_role = resolve_role(
            index,
            roles,
            resolved_templates,
            &index_by_identity,
            &mut states,
            &mut resolved,
        )?;
        let bundle = compile_policy_bundle(&resolved_role.policies, actions)?;

        compiled.push(CompiledRole {
            tenant: role.tenant.clone(),
            key: role.key.clone(),
            revision: resolved_role.revision,
            template: role.template.clone(),
            inherits: role.inherits.clone(),
            tenant_allow_bits_hex: bundle.tenant_allow_bits_hex,
            tenant_deny_bits_hex: bundle.tenant_deny_bits_hex,
            scoped_entries: bundle.scoped_entries,
            policies: bundle.policies,
        });
    }

    compiled.sort_by(|left, right| {
        left.tenant
            .cmp(&right.tenant)
            .then_with(|| left.key.cmp(&right.key))
    });

    Ok(compiled)
}

// r[impl authz.role.inheritance.dag]
// r[impl authz.role.inheritance.priority]
// r[impl authz.role.inheritance.tenant-boundary]
fn resolve_role(
    index: usize,
    roles: &[RoleConfig],
    resolved_templates: &HashMap<String, ResolvedTemplate>,
    index_by_identity: &HashMap<String, usize>,
    states: &mut HashMap<usize, VisitState>,
    resolved: &mut HashMap<String, ResolvedRole>,
) -> Result<ResolvedRole, DynError> {
    let identity = role_identity(&roles[index]);

    if let Some(existing) = resolved.get(&identity) {
        return Ok(existing.clone());
    }

    if matches!(states.get(&index), Some(VisitState::Visiting)) {
        return Err(Box::new(AuthzError::new(format!(
            "cycle detected while resolving role inheritance for {identity}"
        ))));
    }

    states.insert(index, VisitState::Visiting);
    let role = &roles[index];
    let mut policies = Vec::new();

    for parent_key in &role.inherits {
        let parent_identity = format!("{}:{parent_key}", role.tenant);
        let parent_index = index_by_identity
            .get(&parent_identity)
            .copied()
            .ok_or_else(|| {
                Box::new(AuthzError::new(format!(
                    "role {identity} references unknown inherited role {parent_identity}"
                ))) as DynError
            })?;
        let parent = resolve_role(
            parent_index,
            roles,
            resolved_templates,
            index_by_identity,
            states,
            resolved,
        )?;
        apply_policy_overrides(&mut policies, &parent.policies);
    }

    if let Some(template_key) = role.template.as_ref() {
        let template = resolved_templates
            .get(&format!("{}:{template_key}", role.tenant))
            .ok_or_else(|| {
                Box::new(AuthzError::new(format!(
                    "role {identity} references unknown local template {}:{}",
                    role.tenant, template_key
                ))) as DynError
            })?;
        apply_policy_overrides(&mut policies, &template.policies);
    }

    apply_policy_overrides(&mut policies, &role.policies);

    let resolved_role = ResolvedRole {
        revision: compute_role_revision(role, &policies),
        policies,
    };

    states.insert(index, VisitState::Visited);
    resolved.insert(identity, resolved_role.clone());

    Ok(resolved_role)
}

fn build_compiled_template(
    template: &TemplateConfig,
    resolved: &ResolvedTemplate,
    actions: &[CompiledAction],
) -> Result<CompiledTemplate, DynError> {
    let local_bundle = compile_policy_bundle(&template.policies, actions)?;
    let bundle = compile_policy_bundle(&resolved.policies, actions)?;

    Ok(CompiledTemplate {
        tenant: template.tenant.clone(),
        key: template.key.clone(),
        revision: resolved.revision,
        sync_mode: resolved.sync_mode.clone(),
        source: resolved.inherited_from.clone(),
        source_revision: resolved.source_revision,
        lineage: resolved.lineage.clone(),
        local_policies: local_bundle.policies,
        tenant_allow_bits_hex: bundle.tenant_allow_bits_hex,
        tenant_deny_bits_hex: bundle.tenant_deny_bits_hex,
        scoped_entries: bundle.scoped_entries,
        policies: bundle.policies,
    })
}

fn compile_policy_bundle(
    policies: &[PolicySpec],
    actions: &[CompiledAction],
) -> Result<CompiledPolicyBundle, DynError> {
    let action_bits = actions
        .iter()
        .map(|action| (action.name.as_str(), action.bit))
        .collect::<HashMap<_, _>>();
    let mut tenant_effects = BTreeMap::<String, String>::new();
    let mut scoped_effects =
        BTreeMap::<(ScopeKind, Option<ScopeId>), BTreeMap<String, String>>::new();
    let mut compiled_policies = Vec::with_capacity(policies.len());

    for policy in policies {
        let compiled_policy = compile_policy(policy, actions)?;

        if let Some(scope_kind) = &policy.scope_kind {
            let entry = scoped_effects
                .entry((scope_kind.clone(), policy.scope_id.clone()))
                .or_default();
            for action in &compiled_policy.expanded_actions {
                entry.insert(action.clone(), policy.effect.clone());
            }
        } else {
            for action in &compiled_policy.expanded_actions {
                tenant_effects.insert(action.clone(), policy.effect.clone());
            }
        }

        compiled_policies.push(CompiledPolicy {
            effect: policy.effect.clone(),
            selector: policy.action.clone(),
            expanded_actions: compiled_policy.expanded_actions,
            bits_hex: compiled_policy.bits.to_hex(),
            scope_kind: policy.scope_kind.clone(),
            scope_id: policy.scope_id.clone(),
        });
    }

    let (tenant_allow, tenant_deny) =
        effect_maps_to_bitsets(&tenant_effects, &action_bits, actions.len());
    let scoped_entries = scoped_effects
        .into_iter()
        .map(|((scope_kind, scope_id), effects)| {
            let (allow, deny) = effect_maps_to_bitsets(&effects, &action_bits, actions.len());
            CompiledScopeEntry {
                scope_kind,
                scope_id,
                allow_bits_hex: allow.to_hex(),
                deny_bits_hex: deny.to_hex(),
            }
        })
        .collect();

    Ok(CompiledPolicyBundle {
        tenant_allow_bits_hex: tenant_allow.to_hex(),
        tenant_deny_bits_hex: tenant_deny.to_hex(),
        scoped_entries,
        policies: compiled_policies,
    })
}

fn effect_maps_to_bitsets(
    effects: &BTreeMap<String, String>,
    action_bits: &HashMap<&str, usize>,
    action_count: usize,
) -> (Bitset, Bitset) {
    let mut allow = Bitset::new(action_count);
    let mut deny = Bitset::new(action_count);

    for (action, effect) in effects {
        let Some(bit) = action_bits.get(action.as_str()) else {
            continue;
        };
        if effect == "allow" {
            allow.insert(*bit);
        } else {
            deny.insert(*bit);
        }
    }

    (allow, deny)
}

fn compile_policy(
    policy: &PolicySpec,
    actions: &[CompiledAction],
) -> Result<CompiledSelector, DynError> {
    validate_policy(policy)?;
    let expanded_actions = expand_selector(&policy.action, actions)?;
    let mut bits = Bitset::new(actions.len());

    for action in &expanded_actions {
        bits.insert(action.bit);
    }

    Ok(CompiledSelector {
        bits,
        expanded_actions: expanded_actions
            .into_iter()
            .map(|action| action.name)
            .collect(),
    })
}

// r[impl authz.role.template.sync-modes]
fn validate_template_shape(template: &TemplateConfig) -> Result<(), DynError> {
    if template.source.is_none() && template.policies.is_empty() {
        return Err(Box::new(AuthzError::new(format!(
            "template {} must declare policies or a source template",
            template_identity(template)
        ))));
    }

    if let Some(source) = &template.source {
        match source.mode.as_str() {
            "tracking" => {
                if source.pin.is_some() {
                    return Err(Box::new(AuthzError::new(format!(
                        "template {} cannot set pin while using tracking mode",
                        template_identity(template)
                    ))));
                }
            }
            "pinned" => match parse_pin_target(source.pin.as_deref())? {
                PinTarget::Latest | PinTarget::Revision(_) => {}
            },
            other => {
                return Err(Box::new(AuthzError::new(format!(
                    "template {} has unsupported sync mode {other}",
                    template_identity(template)
                ))));
            }
        }

        if source.tenant == template.tenant {
            return Err(Box::new(AuthzError::new(format!(
                "template {} cannot use a same-tenant source template; use a local role instead",
                template_identity(template)
            ))));
        }
    }

    Ok(())
}

fn validate_role_shape(role: &RoleConfig) -> Result<(), DynError> {
    if role.template.is_none() && role.inherits.is_empty() && role.policies.is_empty() {
        return Err(Box::new(AuthzError::new(format!(
            "role {} must declare policies, inherit roles, or reference a local template",
            role_identity(role)
        ))));
    }

    Ok(())
}

fn parse_pin_target(pin: Option<&str>) -> Result<PinTarget, DynError> {
    match pin.unwrap_or("latest") {
        "latest" => Ok(PinTarget::Latest),
        value => value.parse::<u64>().map(PinTarget::Revision).map_err(|_| {
            Box::new(AuthzError::new(format!(
                "unsupported pinned template revision {value}; use `latest` or an unsigned integer revision"
            ))) as DynError
        }),
    }
}

fn validate_unique_policy_selectors(policies: &[PolicySpec], owner: &str) -> Result<(), DynError> {
    let mut seen = HashSet::new();

    for policy in policies {
        let selector = policy_selector_key(policy);

        if !seen.insert(selector.clone()) {
            return Err(Box::new(AuthzError::new(format!(
                "{owner} declares the same policy selector more than once: {selector}"
            ))));
        }
    }

    Ok(())
}

fn validate_policy(policy: &PolicySpec) -> Result<(), DynError> {
    match policy.effect.as_str() {
        "allow" | "deny" => {}
        other => {
            return Err(Box::new(AuthzError::new(format!(
                "unsupported policy effect {other}"
            ))));
        }
    }

    validate_action_name(&policy.action, true)?;

    if policy.scope_id.is_some() && policy.scope_kind.is_none() {
        return Err(Box::new(AuthzError::new(format!(
            "policy {} requires scope_kind when scope_id is set",
            policy.action
        ))));
    }

    Ok(())
}

// r[impl authz.action.namespace.conclave-internal]
// r[impl config.managed.exclude-conclave-capabilities]
fn validate_action_name(action: &str, allow_wildcard: bool) -> Result<(), DynError> {
    let parts: Vec<&str> = action.split(':').collect();

    if parts.len() < 2 {
        return Err(Box::new(AuthzError::new(format!(
            "action must contain at least one namespace separator: {action}"
        ))));
    }

    match parts[0] {
        "tenant" | "sys" => {}
        "conclave" => {
            return Err(Box::new(AuthzError::new(format!(
                "the conclave namespace is reserved for built-in control-plane capabilities and cannot be authored in managed authz config: {action}"
            ))));
        }
        other => {
            return Err(Box::new(AuthzError::new(format!(
                "unsupported action namespace {other} in {action}"
            ))));
        }
    }

    let wildcard_positions: Vec<usize> = parts
        .iter()
        .enumerate()
        .filter_map(|(index, part)| (*part == "*").then_some(index))
        .collect();

    if !wildcard_positions.is_empty() {
        if !allow_wildcard {
            return Err(Box::new(AuthzError::new(format!(
                "wildcards are not allowed in catalog actions: {action}"
            ))));
        }

        if wildcard_positions.len() != 1 || wildcard_positions[0] != parts.len() - 1 {
            return Err(Box::new(AuthzError::new(format!(
                "wildcards must appear only as the final action segment: {action}"
            ))));
        }
    }

    for part in parts {
        if part.is_empty() {
            return Err(Box::new(AuthzError::new(format!(
                "action contains an empty segment: {action}"
            ))));
        }
    }

    Ok(())
}

fn expand_selector(
    selector: &str,
    actions: &[CompiledAction],
) -> Result<Vec<CompiledAction>, DynError> {
    let segments: Vec<&str> = selector.split(':').collect();
    let matches: Vec<CompiledAction> = if segments.last() == Some(&"*") {
        let prefix = selector.trim_end_matches('*');
        actions
            .iter()
            .filter(|action| action.name.starts_with(prefix) && action.name.len() > prefix.len())
            .cloned()
            .collect()
    } else {
        actions
            .iter()
            .find(|action| action.name == selector)
            .cloned()
            .into_iter()
            .collect()
    };

    if matches.is_empty() {
        return Err(Box::new(AuthzError::new(format!(
            "policy selector matches no known catalog action: {selector}"
        ))));
    }

    Ok(matches)
}

fn apply_policy_overrides(policies: &mut Vec<PolicySpec>, overrides: &[PolicySpec]) {
    for override_policy in overrides {
        let selector = policy_selector_key(override_policy);

        if let Some(position) = policies
            .iter()
            .position(|policy| policy_selector_key(policy) == selector)
        {
            policies[position] = override_policy.clone();
        } else {
            policies.push(override_policy.clone());
        }
    }
}

fn policy_selector_key(policy: &PolicySpec) -> String {
    format!(
        "{}|{}|{}",
        policy.action,
        policy.scope_kind.as_deref().unwrap_or(""),
        policy.scope_id.as_deref().unwrap_or("")
    )
}

fn template_identity(template: &TemplateConfig) -> String {
    format!("{}:{}", template.tenant, template.key)
}

fn template_source_identity(template: &TemplateSourceConfig) -> String {
    format!("{}:{}", template.tenant, template.key)
}

fn role_identity(role: &RoleConfig) -> String {
    format!("{}:{}", role.tenant, role.key)
}

fn compute_catalog_revision(catalog: &ActionCatalogConfig) -> u32 {
    let mut data = Vec::new();

    for action in &catalog.actions {
        data.extend_from_slice(action.name.as_bytes());
        data.push(0);

        if let Some(description) = action.description.as_deref() {
            data.extend_from_slice(description.as_bytes());
        }

        data.push(0xff);
    }

    let revision = fnv1a64(&data) & 0xffff_ffff;
    revision as u32
}

// r[impl authz.role.template.versioned]
// r[impl config.managed.authz-revision-bump]
fn compute_template_revision(
    template: &TemplateConfig,
    resolved_source: Option<&TemplateSourceConfig>,
    source_revision: Option<u64>,
    lineage: &[String],
    policies: &[PolicySpec],
) -> u64 {
    let mut data = Vec::new();
    data.extend_from_slice(template_identity(template).as_bytes());
    data.push(0xff);

    for entry in lineage {
        data.extend_from_slice(entry.as_bytes());
        data.push(0xfe);
    }

    if let Some(source) = resolved_source.or(template.source.as_ref()) {
        data.extend_from_slice(template_source_identity(source).as_bytes());
        data.push(0xfd);
        data.extend_from_slice(source.mode.as_bytes());
        data.push(0xfc);
        data.extend_from_slice(source.pin.as_deref().unwrap_or("").as_bytes());
        data.push(0xfb);
    }

    data.extend_from_slice(source_revision.unwrap_or_default().to_string().as_bytes());
    data.push(0xfa);

    append_policies_to_hash(&mut data, policies);
    fnv1a64(&data)
}

// r[impl config.managed.authz-revision-bump]
fn compute_role_revision(role: &RoleConfig, policies: &[PolicySpec]) -> u64 {
    let mut data = Vec::new();
    data.extend_from_slice(role_identity(role).as_bytes());
    data.push(0xff);

    if let Some(template) = role.template.as_deref() {
        data.extend_from_slice(template.as_bytes());
        data.push(0xfe);
    }

    for inherited in &role.inherits {
        data.extend_from_slice(inherited.as_bytes());
        data.push(0xfd);
    }

    append_policies_to_hash(&mut data, policies);
    fnv1a64(&data)
}

fn append_policies_to_hash(data: &mut Vec<u8>, policies: &[PolicySpec]) {
    for policy in policies {
        data.extend_from_slice(policy.effect.as_bytes());
        data.push(0xf0);
        data.extend_from_slice(policy.action.as_bytes());
        data.push(0xef);
        data.extend_from_slice(policy.scope_kind.as_deref().unwrap_or("").as_bytes());
        data.push(0xee);
        data.extend_from_slice(policy.scope_id.as_deref().unwrap_or("").as_bytes());
        data.push(0xed);
    }
}

fn fnv1a64(bytes: &[u8]) -> u64 {
    const OFFSET: u64 = 0xcbf29ce484222325;
    const PRIME: u64 = 0x100000001b3;

    bytes.iter().fold(OFFSET, |hash, byte| {
        let hash = hash ^ u64::from(*byte);
        hash.wrapping_mul(PRIME)
    })
}

#[derive(Clone, Debug)]
struct CompiledSelector {
    bits: Bitset,
    expanded_actions: Vec<ActionName>,
}

#[derive(Clone, Debug)]
struct Bitset {
    words: Vec<u64>,
}

impl Bitset {
    fn new(bit_count: usize) -> Self {
        let word_count = bit_count.div_ceil(64);
        Self {
            words: vec![0; word_count.max(1)],
        }
    }

    fn insert(&mut self, bit: usize) {
        let word = bit / 64;
        let offset = bit % 64;
        self.words[word] |= 1_u64 << offset;
    }

    fn to_hex(&self) -> String {
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
