//! Typed control-plane calls over `konklav-api`, for the CLI's commands.
//!
//! Each call is one request with the session's bound token. Konklav's
//! errors come back as [`Error::Api`].

use konklav_api::{
    AssignRole, Batch, BatchResults, CreateInvite, CreateSubject, CreateTenant, CreatedInvite,
    Deleted, Explanation, Invite, InvitePage, InviteQuery, PutRole, RevokeSessions,
    RevokedSessions, Role, RoleAssignment, Session as KonklavSession, SessionPage, SessionQuery,
    SetTenantState, Subject, SubjectDetail, SubjectPage, SubjectQuery, Tenant, TenantPage,
    TenantQuery, TenantState, Written,
};
use reqwest::Method;
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::error::{Error, Result};
use crate::session::{Session, Surface};

/// A path segment, percent-encoded so that an argument can't reach another
/// endpoint.
fn segment(value: &str) -> String {
    // A URL parser resolves `.` and `..` segments, so their dots are
    // encoded too.
    if value == "." || value == ".." {
        return value.replace('.', "%2E");
    }
    url::form_urlencoded::byte_serialize(value.as_bytes())
        .collect::<String>()
        .replace('+', "%20")
}

/// `path` with `query`'s set fields as its query string.
fn with_query(path: &str, query: &impl Serialize) -> Result<String> {
    let value = serde_json::to_value(query).map_err(|e| Error::local(e.to_string()))?;
    let mut url = url::Url::parse("http://query.invalid").expect("a valid URL");
    {
        let mut pairs = url.query_pairs_mut();
        for (key, value) in value.as_object().into_iter().flatten() {
            match value {
                serde_json::Value::Null | serde_json::Value::Bool(false) => {}
                serde_json::Value::String(text) => {
                    pairs.append_pair(key, text);
                }
                other => {
                    pairs.append_pair(key, &other.to_string());
                }
            }
        }
    }
    Ok(match url.query() {
        Some(query) if !query.is_empty() => format!("{path}?{query}"),
        _ => path.to_owned(),
    })
}

impl Session {
    /// Sends a control-plane request and reads Konklav's answer as `T`.
    ///
    /// # Errors
    ///
    /// [`Error::Api`] when Konklav refuses, and the session's own errors.
    pub async fn call<T: DeserializeOwned>(
        &mut self,
        method: Method,
        path: &str,
        body: Option<&impl Serialize>,
    ) -> Result<T> {
        let body = body
            .map(serde_json::to_value)
            .transpose()
            .map_err(|e| Error::local(e.to_string()))?;
        let response = self
            .send(method, Surface::Control, path, body)
            .await?
            .ok()?;
        serde_json::from_slice(&response.body)
            .map_err(|e| Error::local(format!("unexpected answer from {path}: {e}")))
    }

    async fn get<T: DeserializeOwned>(&mut self, path: &str) -> Result<T> {
        self.call(Method::GET, path, None::<&()>).await
    }

    // --- Tenants ---------------------------------------------------------

    /// # Errors
    ///
    /// See [`Session::call`].
    pub async fn tenants(&mut self, query: &TenantQuery) -> Result<TenantPage> {
        self.get(&with_query("/v1/tenants", query)?).await
    }

    /// # Errors
    ///
    /// See [`Session::call`].
    pub async fn tenant(&mut self, id: &str) -> Result<Tenant> {
        self.get(&format!("/v1/tenants/{}", segment(id))).await
    }

    /// Creates a tenant with a new id.
    ///
    /// # Errors
    ///
    /// See [`Session::call`].
    pub async fn create_tenant(&mut self, tenant: &CreateTenant) -> Result<Tenant> {
        let id = uuid::Uuid::now_v7();
        let written: Written<Tenant> = self
            .call(Method::PUT, &format!("/v1/tenants/{id}"), Some(tenant))
            .await?;
        Ok(written.value)
    }

    /// # Errors
    ///
    /// See [`Session::call`].
    pub async fn set_tenant_state(&mut self, id: &str, state: TenantState) -> Result<Tenant> {
        let written: Written<Tenant> = self
            .call(
                Method::PUT,
                &format!("/v1/tenants/{}/state", segment(id)),
                Some(&SetTenantState { state }),
            )
            .await?;
        Ok(written.value)
    }

    // --- Subjects --------------------------------------------------------

    /// # Errors
    ///
    /// See [`Session::call`].
    pub async fn subjects(&mut self, query: &SubjectQuery) -> Result<SubjectPage> {
        self.get(&with_query("/v1/subjects", query)?).await
    }

    /// # Errors
    ///
    /// See [`Session::call`].
    pub async fn subject(&mut self, id: &str) -> Result<SubjectDetail> {
        self.get(&format!("/v1/subjects/{}", segment(id))).await
    }

    /// Creates a subject with a new id.
    ///
    /// # Errors
    ///
    /// See [`Session::call`].
    pub async fn create_subject(&mut self, subject: &CreateSubject) -> Result<Subject> {
        let id = uuid::Uuid::now_v7();
        self.call(Method::PUT, &format!("/v1/subjects/{id}"), Some(subject))
            .await
    }

    /// Disables (`enable` false) or enables a subject.
    ///
    /// # Errors
    ///
    /// See [`Session::call`].
    pub async fn set_subject_enabled(&mut self, id: &str, enable: bool) -> Result<Subject> {
        let verb = if enable { "enable" } else { "disable" };
        let written: Written<Subject> = self
            .call(
                Method::POST,
                &format!("/v1/subjects/{}/{verb}", segment(id)),
                None::<&()>,
            )
            .await?;
        Ok(written.value)
    }

    // --- Invites ---------------------------------------------------------

    /// # Errors
    ///
    /// See [`Session::call`].
    pub async fn invites(&mut self, query: &InviteQuery) -> Result<InvitePage> {
        self.get(&with_query("/v1/invites", query)?).await
    }

    /// # Errors
    ///
    /// See [`Session::call`].
    pub async fn invite(&mut self, id: &str) -> Result<Invite> {
        self.get(&format!("/v1/invites/{}", segment(id))).await
    }

    /// # Errors
    ///
    /// See [`Session::call`].
    pub async fn create_invite(&mut self, invite: &CreateInvite) -> Result<CreatedInvite> {
        let written: Written<CreatedInvite> =
            self.call(Method::POST, "/v1/invites", Some(invite)).await?;
        Ok(written.value)
    }

    /// # Errors
    ///
    /// See [`Session::call`].
    pub async fn revoke_invite(&mut self, id: &str) -> Result<Invite> {
        self.call(
            Method::POST,
            &format!("/v1/invites/{}/revoke", segment(id)),
            None::<&()>,
        )
        .await
    }

    // --- Roles -----------------------------------------------------------

    /// # Errors
    ///
    /// See [`Session::call`].
    pub async fn roles(&mut self, tenant: &str) -> Result<Vec<Role>> {
        self.get(&format!("/v1/tenants/{}/roles", segment(tenant)))
            .await
    }

    /// # Errors
    ///
    /// See [`Session::call`].
    pub async fn role(&mut self, tenant: &str, key: &str) -> Result<Role> {
        self.get(&format!(
            "/v1/tenants/{}/roles/{}",
            segment(tenant),
            segment(key)
        ))
        .await
    }

    /// Creates or replaces a role.
    ///
    /// # Errors
    ///
    /// See [`Session::call`].
    pub async fn put_role(&mut self, tenant: &str, key: &str, role: &PutRole) -> Result<Role> {
        let written: Written<Role> = self
            .call(
                Method::PUT,
                &format!("/v1/tenants/{}/roles/{}", segment(tenant), segment(key)),
                Some(role),
            )
            .await?;
        Ok(written.value)
    }

    /// # Errors
    ///
    /// See [`Session::call`].
    pub async fn delete_role(&mut self, tenant: &str, key: &str) -> Result<Deleted> {
        let written: Written<Deleted> = self
            .call(
                Method::DELETE,
                &format!("/v1/tenants/{}/roles/{}", segment(tenant), segment(key)),
                None::<&()>,
            )
            .await?;
        Ok(written.value)
    }

    // --- Assignments -----------------------------------------------------

    /// A subject's global role assignments.
    ///
    /// # Errors
    ///
    /// See [`Session::call`].
    pub async fn global_assignments(&mut self, subject: &str) -> Result<Vec<RoleAssignment>> {
        self.get(&format!(
            "/v1/subjects/{}/global-assignments",
            segment(subject)
        ))
        .await
    }

    /// Assigns a role to a subject globally, or within a membership.
    ///
    /// # Errors
    ///
    /// See [`Session::call`].
    pub async fn assign(&mut self, target: &Target, assign: &AssignRole) -> Result<RoleAssignment> {
        let path = match target {
            Target::Subject(id) => format!("/v1/subjects/{}/global-assignments", segment(id)),
            Target::Membership(id) => format!("/v1/memberships/{}/assignments", segment(id)),
        };
        let written: Written<RoleAssignment> = self.call(Method::POST, &path, Some(assign)).await?;
        Ok(written.value)
    }

    /// # Errors
    ///
    /// See [`Session::call`].
    pub async fn unassign(&mut self, id: &str) -> Result<Deleted> {
        let written: Written<Deleted> = self
            .call(
                Method::DELETE,
                &format!("/v1/assignments/{}", segment(id)),
                None::<&()>,
            )
            .await?;
        Ok(written.value)
    }

    // --- Sessions, explain and batches ----------------------------------

    /// # Errors
    ///
    /// See [`Session::call`].
    pub async fn sessions(&mut self, query: &SessionQuery) -> Result<SessionPage> {
        self.get(&with_query("/v1/sessions", query)?).await
    }

    /// # Errors
    ///
    /// See [`Session::call`].
    pub async fn konklav_session(&mut self, id: &str) -> Result<KonklavSession> {
        self.get(&format!("/v1/sessions/{}", segment(id))).await
    }

    /// # Errors
    ///
    /// See [`Session::call`].
    pub async fn revoke_sessions(&mut self, revoke: &RevokeSessions) -> Result<RevokedSessions> {
        self.call(Method::POST, "/v1/sessions/revoke", Some(revoke))
            .await
    }

    /// Why `subject` may or may not do `action`, in `tenant` if given.
    ///
    /// # Errors
    ///
    /// See [`Session::call`].
    pub async fn explain(
        &mut self,
        subject: &str,
        action: &str,
        tenant: Option<&str>,
    ) -> Result<Explanation> {
        let query = konklav_api::ExplainQuery {
            tenant: tenant.map(str::to_owned),
            action: action.to_owned(),
        };
        self.get(&with_query(
            &format!("/v1/subjects/{}/explain", segment(subject)),
            &query,
        )?)
        .await
    }

    /// Applies a batch. Without an idempotency key, one is made, so that a
    /// retry of this call can't apply it twice.
    ///
    /// # Errors
    ///
    /// See [`Session::call`].
    pub async fn apply_batch(&mut self, batch: &Batch) -> Result<BatchResults> {
        let mut batch = batch.clone();
        batch
            .idempotency_key
            .get_or_insert_with(|| uuid::Uuid::new_v4().to_string());
        self.call(Method::POST, "/v1/batch", Some(&batch)).await
    }
}

/// Who a role is assigned to.
#[derive(Debug, Clone)]
pub enum Target {
    /// A subject, globally.
    Subject(String),
    /// A membership, within its tenant.
    Membership(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arguments_stay_in_their_segment() {
        assert_eq!(segment("acme-north"), "acme-north");
        assert_eq!(segment("../sign-out"), "..%2Fsign-out");
        assert_eq!(segment("a b?c#d"), "a%20b%3Fc%23d");
        assert_eq!(segment(".."), "%2E%2E");
    }

    #[test]
    fn queries_carry_only_what_is_set() {
        let query = SessionQuery {
            active: true,
            limit: Some(5),
            ..SessionQuery::default()
        };
        assert_eq!(
            with_query("/v1/sessions", &query).unwrap(),
            "/v1/sessions?active=true&limit=5"
        );
        assert_eq!(
            with_query("/v1/sessions", &SessionQuery::default()).unwrap(),
            "/v1/sessions"
        );
        let query = TenantQuery {
            parent: Some("root".into()),
            ..TenantQuery::default()
        };
        assert_eq!(
            with_query("/v1/tenants", &query).unwrap(),
            "/v1/tenants?parent=root"
        );
    }
}
