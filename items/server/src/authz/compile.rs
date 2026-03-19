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
    sync_mode: String,
    policies: Vec<PolicySpec>,
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

        lineage = parent.lineage.clone();
        lineage.push(identity.clone());
        policies = parent.policies.clone();
        inherited_from = Some(source.clone());
        sync_mode = source.mode.clone();
    }

    apply_policy_overrides(&mut policies, &template.policies);

    let resolved_template = ResolvedTemplate {
        revision: compute_template_revision(template, &lineage, &policies),
        lineage,
        inherited_from,
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
    let mut compiled = Vec::with_capacity(roles.len());

    for role in roles {
        validate_role_shape(role)?;
        validate_unique_policy_selectors(&role.policies, &role_identity(role))?;

        let identity = role_identity(role);
        if !seen.insert(identity.clone()) {
            return Err(Box::new(AuthzError::new(format!(
                "duplicate role identity: {identity}"
            ))));
        }

        let mut effective_policies = role
            .template
            .as_ref()
            .map(|template_key| {
                resolved_templates
                    .get(&format!("{}:{template_key}", role.tenant))
                    .map(|template| template.policies.clone())
                    .ok_or_else(|| {
                        Box::new(AuthzError::new(format!(
                            "role {identity} references unknown local template {}:{}",
                            role.tenant, template_key
                        ))) as DynError
                    })
            })
            .transpose()?
            .unwrap_or_default();

        apply_policy_overrides(&mut effective_policies, &role.policies);
        let bundle = compile_policy_bundle(&effective_policies, actions)?;

        compiled.push(CompiledRole {
            tenant: role.tenant.clone(),
            key: role.key.clone(),
            revision: compute_role_revision(role, &effective_policies),
            template: role.template.clone(),
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

fn build_compiled_template(
    template: &TemplateConfig,
    resolved: &ResolvedTemplate,
    actions: &[CompiledAction],
) -> Result<CompiledTemplate, DynError> {
    let bundle = compile_policy_bundle(&resolved.policies, actions)?;

    Ok(CompiledTemplate {
        tenant: template.tenant.clone(),
        key: template.key.clone(),
        revision: resolved.revision,
        sync_mode: resolved.sync_mode.clone(),
        source: resolved.inherited_from.clone(),
        lineage: resolved.lineage.clone(),
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
    let mut tenant_allow = Bitset::new(actions.len());
    let mut tenant_deny = Bitset::new(actions.len());
    let mut scoped = BTreeMap::<(ScopeKind, Option<ScopeId>), (Bitset, Bitset)>::new();
    let mut compiled_policies = Vec::with_capacity(policies.len());

    for policy in policies {
        let compiled_policy = compile_policy(policy, actions)?;

        if let Some(scope_kind) = &policy.scope_kind {
            let entry = scoped
                .entry((scope_kind.clone(), policy.scope_id.clone()))
                .or_insert_with(|| (Bitset::new(actions.len()), Bitset::new(actions.len())));

            if policy.effect == "allow" {
                entry.0.union_with(&compiled_policy.bits);
            } else {
                entry.1.union_with(&compiled_policy.bits);
            }
        } else if policy.effect == "allow" {
            tenant_allow.union_with(&compiled_policy.bits);
        } else {
            tenant_deny.union_with(&compiled_policy.bits);
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

    let scoped_entries = scoped
        .into_iter()
        .map(
            |((scope_kind, scope_id), (allow, deny))| CompiledScopeEntry {
                scope_kind,
                scope_id,
                allow_bits_hex: allow.to_hex(),
                deny_bits_hex: deny.to_hex(),
            },
        )
        .collect();

    Ok(CompiledPolicyBundle {
        tenant_allow_bits_hex: tenant_allow.to_hex(),
        tenant_deny_bits_hex: tenant_deny.to_hex(),
        scoped_entries,
        policies: compiled_policies,
    })
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

fn validate_template_shape(template: &TemplateConfig) -> Result<(), DynError> {
    if template.source.is_none() && template.policies.is_empty() {
        return Err(Box::new(AuthzError::new(format!(
            "template {} must declare policies or a source template",
            template_identity(template)
        ))));
    }

    if let Some(source) = &template.source {
        match source.mode.as_str() {
            "tracking" => {}
            "pinned" => {
                return Err(Box::new(AuthzError::new(format!(
                    "template {} uses pinned mode, which requires managed apply state and is not available in the compile-only playground",
                    template_identity(template)
                ))));
            }
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
    if role.template.is_none() && role.policies.is_empty() {
        return Err(Box::new(AuthzError::new(format!(
            "role {} must declare policies or reference a local template",
            role_identity(role)
        ))));
    }

    Ok(())
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

fn compute_template_revision(
    template: &TemplateConfig,
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

    if let Some(source) = &template.source {
        data.extend_from_slice(template_source_identity(source).as_bytes());
        data.push(0xfd);
        data.extend_from_slice(source.mode.as_bytes());
        data.push(0xfc);
    }

    append_policies_to_hash(&mut data, policies);
    fnv1a64(&data)
}

fn compute_role_revision(role: &RoleConfig, policies: &[PolicySpec]) -> u64 {
    let mut data = Vec::new();
    data.extend_from_slice(role_identity(role).as_bytes());
    data.push(0xff);

    if let Some(template) = role.template.as_deref() {
        data.extend_from_slice(template.as_bytes());
        data.push(0xfe);
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

    fn union_with(&mut self, other: &Self) {
        for (word, other_word) in self.words.iter_mut().zip(&other.words) {
            *word |= other_word;
        }
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
