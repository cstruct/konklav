//! Passkey ceremonies through `webauthn-rs`. The rest of the server goes
//! through [`Verifier`] and never sees `webauthn-rs` state, which is stored
//! as opaque JSON: ceremony state in challenge `details`, keys in
//! [`PublicKeyData::state`].

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use konklav_core::SubjectId;
use konklav_store::credentials::{PUBLIC_KEY_STATE_VERSION, PublicKeyData};
use serde::Serialize;
use serde::de::DeserializeOwned;
use webauthn_rs::prelude::{
    CreationChallengeResponse, CredentialID, DiscoverableAuthentication, DiscoverableKey, Passkey,
    PasskeyAuthentication, PasskeyRegistration, PublicKeyCredential, RegisterPublicKeyCredential,
    RequestChallengeResponse, Url, Webauthn, WebauthnBuilder,
};
use webauthn_rs_proto::{Mediation, ResidentKeyRequirement};

use crate::config::{Browser, Passkeys};

/// A ceremony or stored key failed to verify. Callers report every failure
/// the same way, so the reason is only logged.
#[derive(Debug, thiserror::Error)]
#[error("passkey verification failed: {0}")]
pub struct Rejected(String);

impl Rejected {
    fn from(error: impl std::fmt::Display) -> Self {
        Self(error.to_string())
    }
}

/// Configured passkey support: the relying party ID and allowed origins.
pub struct Verifier {
    webauthn: Webauthn,
}

/// A newly registered passkey.
pub struct Registered {
    /// The credential ID in unpadded base64url: its login identifier.
    pub credential_id: String,
    pub data: PublicKeyData,
}

/// Who an assertion claims to be, before it is verified.
pub struct Claimed {
    pub subject: SubjectId,
    pub credential_id: String,
}

impl Verifier {
    /// Builds the verifier from configuration. Origins default to the
    /// browser's allowed origins.
    ///
    /// # Errors
    ///
    /// When an origin is not a URL, or is not the relying party ID or a
    /// subdomain of it.
    // r[impl authn.passkey.origin]
    pub fn from_config(passkeys: &Passkeys, browser: Option<&Browser>) -> Result<Self, String> {
        let origins = if passkeys.origins.is_empty() {
            browser
                .map(|b| b.allowed_origins.clone())
                .unwrap_or_default()
        } else {
            passkeys.origins.clone()
        };
        Self::new(&passkeys.rp_id, &passkeys.rp_name, &origins)
    }

    /// # Errors
    ///
    /// As [`Verifier::from_config`].
    pub fn new(rp_id: &str, rp_name: &str, origins: &[String]) -> Result<Self, String> {
        let origins = origins
            .iter()
            .map(|origin| {
                Url::parse(origin).map_err(|error| format!("passkey origin `{origin}`: {error}"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let (first, rest) = origins
            .split_first()
            .ok_or_else(|| "passkeys need at least one origin".to_owned())?;
        for origin in &origins {
            let host = origin.host_str().unwrap_or_default();
            if host != rp_id && !host.ends_with(&format!(".{rp_id}")) {
                return Err(format!(
                    "passkey origin `{origin}` is not within relying party ID `{rp_id}`"
                ));
            }
        }
        let builder = rest.iter().fold(
            WebauthnBuilder::new(rp_id, first)
                .map_err(|error| format!("passkeys: {error}"))?
                .rp_name(rp_name),
            WebauthnBuilder::append_allowed_origin,
        );
        let webauthn = builder
            .build()
            .map_err(|error| format!("passkeys: {error}"))?;
        Ok(Self { webauthn })
    }

    /// Starts registering a passkey for `subject`, excluding the ones it
    /// already has. Returns the options for the browser and the state to
    /// keep until [`Verifier::finish_registration`].
    ///
    /// # Errors
    ///
    /// When stored keys can't be read or the options can't be built.
    // r[impl authn.passkey.registration]
    pub fn start_registration(
        &self,
        subject: SubjectId,
        name: &str,
        existing: &[&PublicKeyData],
    ) -> Result<(CreationChallengeResponse, serde_json::Value), Rejected> {
        let exclude = existing
            .iter()
            .map(|data| stored_key(data).map(|key| key.cred_id().clone()))
            .collect::<Result<Vec<CredentialID>, _>>()?;
        let (mut options, state) = self
            .webauthn
            .start_passkey_registration(*subject.as_uuid(), name, name, Some(exclude))
            .map_err(Rejected::from)?;
        // Login names no account, so the key must be discoverable.
        // r[impl authn.passkey.discoverable]
        if let Some(selection) = options.public_key.authenticator_selection.as_mut() {
            selection.resident_key = Some(ResidentKeyRequirement::Required);
            selection.require_resident_key = true;
        }
        Ok((options, to_json(&state)?))
    }

    /// Verifies the browser's response to [`Verifier::start_registration`].
    ///
    /// # Errors
    ///
    /// When the response doesn't verify against `state`.
    // r[impl authn.passkey.user-verification]
    pub fn finish_registration(
        &self,
        state: serde_json::Value,
        response: &RegisterPublicKeyCredential,
        label: String,
    ) -> Result<Registered, Rejected> {
        let state: PasskeyRegistration = from_json(state)?;
        let key = self
            .webauthn
            .finish_passkey_registration(response, &state)
            .map_err(Rejected::from)?;
        Ok(Registered {
            credential_id: encode_id(key.cred_id()),
            data: PublicKeyData {
                label,
                // Passkey registration asks for no attestation.
                attestation_format: "none".to_owned(),
                last_used_at: None,
                state_version: PUBLIC_KEY_STATE_VERSION,
                state: to_json(&key)?,
            },
        })
    }

    /// Starts a login with any discoverable passkey.
    ///
    /// # Errors
    ///
    /// When the options can't be built.
    pub fn start_login(&self) -> Result<(RequestChallengeResponse, serde_json::Value), Rejected> {
        let (mut options, state) = self
            .webauthn
            .start_discoverable_authentication()
            .map_err(Rejected::from)?;
        // A modal prompt from a button, not autofill.
        options.mediation = None::<Mediation>;
        Ok((options, to_json(&state)?))
    }

    /// Starts a step-up with one of the subject's own passkeys.
    ///
    /// # Errors
    ///
    /// When there are none, or stored keys can't be read.
    pub fn start_step_up(
        &self,
        existing: &[&PublicKeyData],
    ) -> Result<(RequestChallengeResponse, serde_json::Value), Rejected> {
        let keys = existing
            .iter()
            .map(|data| stored_key(data))
            .collect::<Result<Vec<_>, _>>()?;
        let (options, state) = self
            .webauthn
            .start_passkey_authentication(&keys)
            .map_err(Rejected::from)?;
        Ok((options, to_json(&StepUpState(state))?))
    }

    /// The subject and credential an assertion names, unverified.
    ///
    /// # Errors
    ///
    /// When the user handle is missing or not a subject id.
    pub fn claimed(&self, response: &PublicKeyCredential) -> Result<Claimed, Rejected> {
        let (subject, credential_id) = self
            .webauthn
            .identify_discoverable_authentication(response)
            .map_err(Rejected::from)?;
        Ok(Claimed {
            subject: subject.into(),
            credential_id: URL_SAFE_NO_PAD.encode(credential_id),
        })
    }

    /// Verifies a login assertion against the stored key and returns the
    /// key's updated data (counter, backup state, last use).
    ///
    /// # Errors
    ///
    /// When the assertion doesn't verify, including a counter that did not
    /// increase.
    // r[impl authn.passkey.counter]
    pub fn finish_login(
        &self,
        state: serde_json::Value,
        response: &PublicKeyCredential,
        stored: &PublicKeyData,
    ) -> Result<PublicKeyData, Rejected> {
        let state: DiscoverableAuthentication = from_json(state)?;
        let mut key = stored_key(stored)?;
        let result = self
            .webauthn
            .finish_discoverable_authentication(response, state, &[DiscoverableKey::from(&key)])
            .map_err(Rejected::from)?;
        if !result.user_verified() {
            return Err(Rejected("user verification missing".to_owned()));
        }
        key.update_credential(&result);
        updated(stored, &key)
    }

    /// Verifies a step-up assertion. Returns the credential ID used and its
    /// updated data.
    ///
    /// # Errors
    ///
    /// When the assertion doesn't verify against any of `existing`.
    pub fn finish_step_up<'a>(
        &self,
        state: serde_json::Value,
        response: &PublicKeyCredential,
        existing: &'a [(String, PublicKeyData)],
    ) -> Result<(&'a str, PublicKeyData), Rejected> {
        let StepUpState(state) = from_json(state)?;
        let result = self
            .webauthn
            .finish_passkey_authentication(response, &state)
            .map_err(Rejected::from)?;
        if !result.user_verified() {
            return Err(Rejected("user verification missing".to_owned()));
        }
        let used = encode_id(result.cred_id());
        let (id, stored) = existing
            .iter()
            .find(|(id, _)| *id == used)
            .ok_or_else(|| Rejected("unknown credential".to_owned()))?;
        let mut key = stored_key(stored)?;
        key.update_credential(&result);
        Ok((id, updated(stored, &key)?))
    }
}

/// Step-up state, tagged so it can't be confused with login state.
#[derive(serde::Serialize, serde::Deserialize)]
struct StepUpState(PasskeyAuthentication);

fn encode_id(id: &CredentialID) -> String {
    URL_SAFE_NO_PAD.encode(id.as_ref())
}

fn stored_key(data: &PublicKeyData) -> Result<Passkey, Rejected> {
    if data.state_version != PUBLIC_KEY_STATE_VERSION {
        return Err(Rejected(format!(
            "unsupported passkey state version {}",
            data.state_version
        )));
    }
    from_json(data.state.clone())
}

fn updated(stored: &PublicKeyData, key: &Passkey) -> Result<PublicKeyData, Rejected> {
    Ok(PublicKeyData {
        last_used_at: Some(chrono::Utc::now()),
        state: to_json(key)?,
        ..stored.clone()
    })
}

fn to_json(value: &impl Serialize) -> Result<serde_json::Value, Rejected> {
    serde_json::to_value(value).map_err(Rejected::from)
}

fn from_json<T: DeserializeOwned>(value: serde_json::Value) -> Result<T, Rejected> {
    serde_json::from_value(value).map_err(Rejected::from)
}
