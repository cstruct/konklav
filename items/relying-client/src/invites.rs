//! A tenant's link-only invites, made, listed and revoked on the relying
//! surface by the client's service principal, which needs
//! `konklav:tenant:invite` in the tenant.

use serde::{Deserialize, Serialize};

use crate::{Error, RelyingClient, checked, path_segment};

/// A link-only invite to make into a tenant.
#[derive(Clone, Debug, Default, PartialEq, Serialize)]
pub struct NewInvite {
    /// The invite's id, so that repeating the request is safe; Konklav
    /// makes one when absent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<uuid::Uuid>,
    /// Keys of the tenant's roles to assign; none may name a `konklav:`
    /// action.
    pub roles: Vec<String>,
    /// The id of the membership redemption creates.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub membership: Option<uuid::Uuid>,
    /// Membership facts.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub facts: Option<serde_json::Value>,
    /// Clamped to between 1 hour and 30 days; 72 when absent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_in_hours: Option<i64>,
    /// Opaque to Konklav, handed over on redemption.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
    /// Opaque to Konklav, at most 1024 bytes, shown to whoever holds the
    /// token by the invite's preview.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_metadata: Option<serde_json::Value>,
    /// Whether someone without an account may sign up when redeeming it.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub sign_up: bool,
}

/// A made invite, with its token: shown only this once.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct MadeInvite {
    pub invite_id: uuid::Uuid,
    /// When it expires, as RFC 3339.
    pub expires_at: String,
    /// The token, for the link; Konklav keeps only its hash.
    pub token: String,
}

/// Where an invite stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InviteState {
    Pending,
    Redeemed,
    Revoked,
    Expired,
}

/// One of a tenant's link-only invites, without its token.
#[derive(Clone, Debug, PartialEq, Deserialize)]
pub struct TenantInvite {
    pub id: uuid::Uuid,
    pub roles: Vec<String>,
    pub membership: Option<uuid::Uuid>,
    pub state: InviteState,
    /// When it expires, as RFC 3339.
    pub expires_at: String,
    /// When it was redeemed or revoked, as RFC 3339.
    pub consumed_at: Option<String>,
    pub metadata: serde_json::Value,
    pub public_metadata: serde_json::Value,
    #[serde(default)]
    pub sign_up: bool,
}

/// A page of a tenant's invites, newest first; `next` is the `before` of
/// the next page.
#[derive(Clone, Debug, PartialEq, Deserialize)]
pub struct InvitePage {
    pub invites: Vec<TenantInvite>,
    pub next: Option<uuid::Uuid>,
}

fn tenant_path(tenant: &str) -> Result<String, Error> {
    path_segment(tenant)
        .map(|tenant| format!("/v1/tenants/{tenant}/invites"))
        .ok_or_else(|| Error::Status {
            status: 400,
            body: "tenant can't be named in a path".to_owned(),
        })
}

impl RelyingClient {
    /// Makes a link-only invite into `tenant` (a UUID or `root`), and
    /// answers its token, shown only this once.
    // r[impl item.relying-client.invites]
    pub async fn create_invite(
        &self,
        tenant: &str,
        invite: &NewInvite,
    ) -> Result<MadeInvite, Error> {
        let path = tenant_path(tenant)?;
        Ok(checked(self.post(&path, Some(invite)).await?)
            .await?
            .json()
            .await?)
    }

    /// A page of `tenant`'s link-only invites, newest first, before the
    /// invite `before` if given.
    // r[impl item.relying-client.invites]
    pub async fn invites(
        &self,
        tenant: &str,
        before: Option<uuid::Uuid>,
        limit: Option<i64>,
    ) -> Result<InvitePage, Error> {
        let mut path = tenant_path(tenant)?;
        let query: Vec<String> = [
            before.map(|before| format!("before={before}")),
            limit.map(|limit| format!("limit={limit}")),
        ]
        .into_iter()
        .flatten()
        .collect();
        if !query.is_empty() {
            path = format!("{path}?{}", query.join("&"));
        }
        Ok(checked(self.get(&path).await?).await?.json().await?)
    }

    /// Revokes one of `tenant`'s invites; revoking it again changes nothing,
    /// and a redeemed one is refused with 409.
    // r[impl item.relying-client.invites]
    pub async fn revoke_invite(
        &self,
        tenant: &str,
        invite: uuid::Uuid,
    ) -> Result<TenantInvite, Error> {
        let path = format!("{}/{invite}/revoke", tenant_path(tenant)?);
        Ok(checked(self.post::<()>(&path, None).await?)
            .await?
            .json()
            .await?)
    }
}
