//! The Konklav endpoints the console calls.

use serde_json::{Value, json};

use super::request::{Method, Request, encode};

// --- Signing in (subject-facing) ---------------------------------------------

/// A browser login, so the refresh token comes back as a cookie.
#[must_use]
pub fn login_password(identifier: &str, password: &str) -> Request {
    Request::subject(Method::Post, "/login/password")
        .json(json!({"identifier": identifier, "password": password, "client": "browser"}))
        .anonymous()
}

#[must_use]
pub fn mfa_factors() -> Request {
    Request::subject(Method::Get, "/mfa")
}

#[must_use]
pub fn send_mfa_code(factor: &str) -> Request {
    Request::subject(Method::Post, format!("/mfa/{}/send", encode(factor)))
}

#[must_use]
pub fn complete_mfa(factor: &str, code: &str) -> Request {
    Request::subject(Method::Post, "/login/mfa")
        .json(json!({"factor_id": factor, "code": code.trim()}))
}

/// Starts a passkey login; no identifier is needed.
#[must_use]
pub fn passkey_login_options() -> Request {
    Request::subject(Method::Post, "/login/passkey/options")
        .json(json!({}))
        .anonymous()
}

/// A browser login with the passkey the browser returned.
#[must_use]
pub fn login_passkey(ceremony: &str, credential: &Value) -> Request {
    Request::subject(Method::Post, "/login/passkey")
        .json(json!({"ceremony": ceremony, "credential": credential, "client": "browser"}))
        .anonymous()
}

/// The signed-in operator's own passkeys.
#[must_use]
pub fn own_passkeys() -> Request {
    Request::subject(Method::Get, "/passkeys")
}

#[must_use]
pub fn passkey_registration_options(label: &str) -> Request {
    Request::subject(Method::Post, "/passkeys/registration/options")
        .json(json!({"label": label.trim()}))
}

#[must_use]
pub fn register_passkey(ceremony: &str, credential: &Value) -> Request {
    Request::subject(Method::Post, "/passkeys/registration")
        .json(json!({"ceremony": ceremony, "credential": credential}))
}

#[must_use]
pub fn remove_passkey(id: &str) -> Request {
    Request::subject(Method::Delete, format!("/passkeys/{}", encode(id)))
}

#[must_use]
pub fn step_up_passkey_options() -> Request {
    Request::subject(Method::Post, "/step-up/passkey/options").json(json!({}))
}

#[must_use]
pub fn step_up_password(password: &str) -> Request {
    Request::subject(Method::Post, "/step-up").json(json!({"password": password}))
}

#[must_use]
pub fn step_up_passkey(ceremony: &str, credential: &Value) -> Request {
    Request::subject(Method::Post, "/step-up")
        .json(json!({"ceremony": ceremony, "passkey": credential}))
}

/// Exchanges the refresh cookie for a new access token.
#[must_use]
pub fn refresh() -> Request {
    Request::subject(Method::Post, "/refresh").anonymous()
}

#[must_use]
pub fn sign_out() -> Request {
    Request::subject(Method::Post, "/sign-out")
}

#[must_use]
pub fn own_capabilities() -> Request {
    Request::subject(Method::Get, "/capabilities")
}

// --- Subjects and credentials ------------------------------------------------

#[must_use]
pub fn subjects(kind: &str, identifier: &str, before: Option<&str>) -> Request {
    Request::control(Method::Get, "/subjects")
        .query("kind", Some(kind))
        .query("identifier", Some(identifier))
        .query("before", before)
}

#[must_use]
pub fn subject(id: &str) -> Request {
    Request::control(Method::Get, format!("/subjects/{}", encode(id)))
}

#[must_use]
pub fn create_subject(id: &str, kind: &str) -> Request {
    Request::control(Method::Put, format!("/subjects/{}", encode(id))).json(json!({"kind": kind}))
}

#[must_use]
pub fn set_subject_enabled(id: &str, enabled: bool) -> Request {
    let action = if enabled { "enable" } else { "disable" };
    Request::control(Method::Post, format!("/subjects/{}/{action}", encode(id)))
}

/// `body` is a credential definition tagged by `kind`, as the control plane
/// takes it.
#[must_use]
pub fn create_credential(subject: &str, body: Value) -> Request {
    Request::control(
        Method::Post,
        format!("/subjects/{}/credentials", encode(subject)),
    )
    .json(body)
}

#[must_use]
pub fn revoke_credential(id: &str, reason: &str) -> Request {
    let request = Request::control(Method::Post, format!("/credentials/{}/revoke", encode(id)));
    if reason.trim().is_empty() {
        request
    } else {
        request.json(json!({"reason": reason.trim()}))
    }
}

#[must_use]
pub fn replace_password(id: &str, password: &str) -> Request {
    Request::control(Method::Post, format!("/credentials/{}/replace", encode(id)))
        .json(json!({"password": password}))
}

#[must_use]
pub fn set_break_glass(id: &str, break_glass: bool) -> Request {
    Request::control(
        Method::Put,
        format!("/credentials/{}/break-glass", encode(id)),
    )
    .json(json!({"break_glass": break_glass}))
}

#[must_use]
pub fn rotate_slot(id: &str, slot: &str) -> Request {
    Request::control(
        Method::Post,
        format!("/credentials/{}/slots/{}/rotate", encode(id), encode(slot)),
    )
}

// --- Sessions ----------------------------------------------------------------

/// Filters for listing or revoking sessions. Blank fields don't filter.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SessionFilter {
    pub session: String,
    pub subject: String,
    pub credential: String,
    pub tenant: String,
    pub membership: String,
}

impl SessionFilter {
    #[must_use]
    pub fn subject(id: &str) -> Self {
        Self {
            subject: id.to_owned(),
            ..Self::default()
        }
    }

    #[must_use]
    pub fn session(id: &str) -> Self {
        Self {
            session: id.to_owned(),
            ..Self::default()
        }
    }

    fn fields(&self) -> [(&'static str, &str); 5] {
        [
            ("session", &self.session),
            ("subject", &self.subject),
            ("credential", &self.credential),
            ("tenant", &self.tenant),
            ("membership", &self.membership),
        ]
    }

    /// Whether nothing would be filtered, which Konklav refuses for
    /// revocation.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.fields()
            .iter()
            .all(|(_, value)| value.trim().is_empty())
    }
}

/// Lists sessions. Only subject and credential filter listings.
#[must_use]
pub fn sessions(filter: &SessionFilter, active: bool, before: Option<&str>) -> Request {
    Request::control(Method::Get, "/sessions")
        .query("subject", Some(&filter.subject))
        .query("credential", Some(&filter.credential))
        .query("active", active.then_some(true))
        .query("before", before)
}

#[must_use]
pub fn revoke_sessions(filter: &SessionFilter, reason: &str) -> Request {
    let mut body = serde_json::Map::new();
    for (key, value) in filter.fields() {
        if !value.trim().is_empty() {
            body.insert(key.to_owned(), Value::from(value.trim()));
        }
    }
    if !reason.trim().is_empty() {
        body.insert("reason".to_owned(), Value::from(reason.trim()));
    }
    Request::control(Method::Post, "/sessions/revoke").json(Value::Object(body))
}

// --- Tenants and memberships -------------------------------------------------

#[must_use]
pub fn tenants(parent: &str, before: Option<&str>) -> Request {
    Request::control(Method::Get, "/tenants")
        .query("parent", Some(parent))
        .query("before", before)
}

#[must_use]
pub fn tenant(id: &str) -> Request {
    Request::control(Method::Get, format!("/tenants/{}", encode(id)))
}

#[must_use]
pub fn create_tenant(id: &str, parent: &str, facts: &Value, templates: &[String]) -> Request {
    let parent = if parent.trim().is_empty() {
        "root"
    } else {
        parent.trim()
    };
    Request::control(Method::Put, format!("/tenants/{}", encode(id)))
        .json(json!({"parent": parent, "facts": facts, "templates": templates}))
}

#[must_use]
pub fn set_tenant_facts(id: &str, facts: Value) -> Request {
    Request::control(Method::Put, format!("/tenants/{}/facts", encode(id))).json(facts)
}

#[must_use]
pub fn set_tenant_state(id: &str, state: &str) -> Request {
    Request::control(Method::Put, format!("/tenants/{}/state", encode(id)))
        .json(json!({"state": state}))
}

#[must_use]
pub fn memberships(tenant: &str, active: bool) -> Request {
    Request::control(
        Method::Get,
        format!("/tenants/{}/memberships", encode(tenant)),
    )
    .query("active", active.then_some(true))
}

#[must_use]
pub fn membership(id: &str) -> Request {
    Request::control(Method::Get, format!("/memberships/{}", encode(id)))
}

#[must_use]
pub fn create_membership(id: &str, subject: &str, tenant: &str, facts: &Value) -> Request {
    Request::control(Method::Put, format!("/memberships/{}", encode(id)))
        .json(json!({"subject": subject.trim(), "tenant": tenant, "facts": facts}))
}

#[must_use]
pub fn set_membership_facts(id: &str, facts: Value) -> Request {
    Request::control(Method::Put, format!("/memberships/{}/facts", encode(id))).json(facts)
}

#[must_use]
pub fn end_membership(id: &str) -> Request {
    Request::control(Method::Post, format!("/memberships/{}/end", encode(id)))
}

// --- Catalog, templates, roles and assignments -------------------------------

#[must_use]
pub fn catalog() -> Request {
    Request::control(Method::Get, "/catalog")
}

#[must_use]
pub fn put_catalog(document: Value) -> Request {
    Request::control(Method::Put, "/catalog").json(document)
}

#[must_use]
pub fn templates() -> Request {
    Request::control(Method::Get, "/templates")
}

#[must_use]
pub fn put_template(key: &str, body: Value) -> Request {
    Request::control(Method::Put, format!("/templates/{}", encode(key))).json(body)
}

#[must_use]
pub fn roles(tenant: &str) -> Request {
    Request::control(Method::Get, format!("/tenants/{}/roles", encode(tenant)))
}

#[must_use]
pub fn put_role(tenant: &str, key: &str, body: Value) -> Request {
    Request::control(
        Method::Put,
        format!("/tenants/{}/roles/{}", encode(tenant), encode(key)),
    )
    .json(body)
}

#[must_use]
pub fn delete_role(tenant: &str, key: &str) -> Request {
    Request::control(
        Method::Delete,
        format!("/tenants/{}/roles/{}", encode(tenant), encode(key)),
    )
}

#[must_use]
pub fn global_assignments(subject: &str) -> Request {
    Request::control(
        Method::Get,
        format!("/subjects/{}/global-assignments", encode(subject)),
    )
}

#[must_use]
pub fn assign_global_role(subject: &str, role: &str) -> Request {
    Request::control(
        Method::Post,
        format!("/subjects/{}/global-assignments", encode(subject)),
    )
    .json(json!({"role": role.trim()}))
}

/// Assigns a tenant role to a membership, tenant-wide unless a scope kind
/// and id are both given.
#[must_use]
pub fn assign_membership_role(
    membership: &str,
    role: &str,
    scope_kind: &str,
    scope_id: &str,
) -> Request {
    let scope = (!scope_kind.trim().is_empty() && !scope_id.trim().is_empty())
        .then(|| json!({"kind": scope_kind.trim(), "id": scope_id.trim()}));
    Request::control(
        Method::Post,
        format!("/memberships/{}/assignments", encode(membership)),
    )
    .json(json!({"role": role.trim(), "scope": scope}))
}

#[must_use]
pub fn unassign(assignment: &str) -> Request {
    Request::control(
        Method::Delete,
        format!("/assignments/{}", encode(assignment)),
    )
}

#[must_use]
pub fn entitlements(subject: &str, tenant: &str) -> Request {
    Request::control(
        Method::Get,
        format!("/subjects/{}/entitlements", encode(subject)),
    )
    .query("tenant", Some(tenant))
}

#[must_use]
pub fn explain(subject: &str, tenant: &str, action: &str) -> Request {
    Request::control(
        Method::Get,
        format!("/subjects/{}/explain", encode(subject)),
    )
    .query("tenant", Some(tenant))
    .query("action", Some(action))
}

/// Explains the decision for `requirements`, optionally for one of the
/// subject's sessions.
#[must_use]
pub fn explain_decision(
    subject: &str,
    tenant: &str,
    session: &str,
    requirements: &Value,
) -> Request {
    let mut body = json!({"requirements": requirements});
    if !tenant.trim().is_empty() {
        body["tenant"] = json!(tenant.trim());
    }
    if !session.trim().is_empty() {
        body["session"] = json!(session.trim());
    }
    Request::control(
        Method::Post,
        format!("/subjects/{}/explain-decision", encode(subject)),
    )
    .json(body)
}

// --- Invites -----------------------------------------------------------------

#[must_use]
pub fn create_invite(email: &str, tenant: &str, roles: &[String], hours: i64) -> Request {
    let tenant = (!tenant.trim().is_empty()).then(|| tenant.trim().to_owned());
    Request::control(Method::Post, "/invites").json(json!({
        "email": email.trim(),
        "tenant": tenant,
        "roles": roles,
        "expires_in_hours": hours,
    }))
}

// --- OIDC clients ------------------------------------------------------------

#[must_use]
pub fn oidc_clients() -> Request {
    Request::control(Method::Get, "/oidc/clients")
}

#[must_use]
pub fn put_oidc_client(id: &str, definition: Value) -> Request {
    Request::control(Method::Put, format!("/oidc/clients/{}", encode(id))).json(definition)
}

#[must_use]
pub fn new_client_secret(id: &str) -> Request {
    Request::control(Method::Post, format!("/oidc/clients/{}/secret", encode(id)))
}

#[must_use]
pub fn disable_oidc_client(id: &str) -> Request {
    Request::control(Method::Delete, format!("/oidc/clients/{}", encode(id)))
}

// --- Signing keys ------------------------------------------------------------

#[must_use]
pub fn signing_keys() -> Request {
    Request::control(Method::Get, "/signing-keys")
}

#[must_use]
pub fn revoke_signing_key(kid: &str) -> Request {
    Request::control(
        Method::Post,
        format!("/signing-keys/{}/revoke", encode(kid)),
    )
}

/// Splits a comma- or whitespace-separated list, dropping blanks.
///
/// ```
/// assert_eq!(
///     konklav_console::api::endpoints::list("admin, viewer  billing,"),
///     vec!["admin", "viewer", "billing"],
/// );
/// ```
#[must_use]
pub fn list(value: &str) -> Vec<String> {
    value
        .split(|c: char| c == ',' || c.is_whitespace())
        .filter(|item| !item.is_empty())
        .map(str::to_owned)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::Surface;

    #[test]
    fn logins_ask_for_a_browser_session_without_a_token() {
        let request = login_password("ada@example.com", "pw");
        assert_eq!(request.surface, Surface::Subject);
        assert!(!request.authenticated);
        assert_eq!(request.body.unwrap()["client"], "browser");
        assert!(!refresh().authenticated, "the cookie authenticates refresh");
    }

    #[test]
    fn revocation_names_only_the_given_filters() {
        let filter = SessionFilter {
            subject: " s1 ".into(),
            tenant: "t1".into(),
            ..SessionFilter::default()
        };
        assert!(!filter.is_empty());
        assert!(SessionFilter::default().is_empty());
        let request = revoke_sessions(&filter, "");
        assert_eq!(request.url(), "/control/v1/sessions/revoke");
        assert_eq!(
            request.body.unwrap(),
            json!({"subject": "s1", "tenant": "t1"})
        );
    }

    #[test]
    fn session_listings_filter_by_subject_and_credential_only() {
        let filter = SessionFilter {
            subject: "s1".into(),
            tenant: "ignored".into(),
            ..SessionFilter::default()
        };
        assert_eq!(
            sessions(&filter, true, Some("x")).url(),
            "/control/v1/sessions?subject=s1&active=true&before=x"
        );
    }

    #[test]
    fn membership_assignments_are_scoped_only_with_kind_and_id() {
        let tenant_wide = assign_membership_role("m1", "editor", "project", "");
        assert_eq!(tenant_wide.body.unwrap()["scope"], Value::Null);
        let scoped = assign_membership_role("m1", "editor", "project", "p1");
        assert_eq!(
            scoped.body.unwrap()["scope"],
            json!({"kind": "project", "id": "p1"})
        );
    }

    #[test]
    fn tenants_default_to_the_root_parent() {
        let request = create_tenant("t1", " ", &json!({}), &[]);
        assert_eq!(request.body.unwrap()["parent"], "root");
    }

    #[test]
    fn user_input_cannot_escape_its_path_segment() {
        assert_eq!(
            subject("../signing-keys").url(),
            "/control/v1/subjects/..%2Fsigning-keys"
        );
    }
}
