//! OIDC client registrations, without their secrets.

use konklav_api as api;
use konklav_store::oidc_clients::{ClientDefinition, ClientKind, IdTokenAlgorithm, OidcClient};

pub(crate) fn oidc_client(client: OidcClient) -> api::OidcClient {
    let definition = client.definition;
    api::OidcClient {
        id: client.id,
        definition: api::OidcClientDefinition {
            kind: match definition.kind {
                ClientKind::Confidential => api::OidcClientKind::Confidential,
                ClientKind::Public => api::OidcClientKind::Public,
            },
            redirect_uris: definition.redirect_uris,
            scopes: definition.scopes,
            audience: definition.audience,
            visible_groups: definition.visible_groups,
            login_url: definition.login_url,
            id_token_alg: match definition.id_token_alg {
                IdTokenAlgorithm::Es256 => api::IdTokenAlgorithm::Es256,
                IdTokenAlgorithm::EdDsa => api::IdTokenAlgorithm::EdDsa,
                IdTokenAlgorithm::Rs256 => api::IdTokenAlgorithm::Rs256,
            },
            refresh: definition.refresh,
            service_subject: definition.service_subject,
            jwks: definition.jwks,
            post_logout_redirect_uris: definition.post_logout_redirect_uris,
            backchannel_logout_uri: definition.backchannel_logout_uri,
            require_pkce: definition.require_pkce,
            require_dpop: definition.require_dpop,
        },
        has_secret: client.has_secret,
        disabled_at: client.disabled_at,
        created_at: client.created_at,
        updated_at: client.updated_at,
    }
}

pub(crate) fn client_definition(definition: api::OidcClientDefinition) -> ClientDefinition {
    ClientDefinition {
        kind: match definition.kind {
            api::OidcClientKind::Confidential => ClientKind::Confidential,
            api::OidcClientKind::Public => ClientKind::Public,
        },
        redirect_uris: definition.redirect_uris,
        scopes: definition.scopes,
        audience: definition.audience,
        visible_groups: definition.visible_groups,
        login_url: definition.login_url,
        id_token_alg: match definition.id_token_alg {
            api::IdTokenAlgorithm::Es256 => IdTokenAlgorithm::Es256,
            api::IdTokenAlgorithm::EdDsa => IdTokenAlgorithm::EdDsa,
            api::IdTokenAlgorithm::Rs256 => IdTokenAlgorithm::Rs256,
        },
        refresh: definition.refresh,
        service_subject: definition.service_subject,
        jwks: definition.jwks,
        post_logout_redirect_uris: definition.post_logout_redirect_uris,
        backchannel_logout_uri: definition.backchannel_logout_uri,
        require_pkce: definition.require_pkce,
        require_dpop: definition.require_dpop,
    }
}

#[cfg(test)]
mod tests {
    use konklav_store::oidc_clients::{ClientDefinition, OidcClient};
    use serde_json::json;

    /// The transport types write and read the storage models' JSON, and
    /// leave the secret's hash out.
    #[test]
    fn clients_keep_the_storage_models_shape() {
        for body in [
            json!({
                "kind": "confidential",
                "redirect_uris": ["https://console.example.com/callback"],
                "scopes": ["openid", "email", "groups"],
                "audience": "console",
                "visible_groups": ["ops-*"],
            }),
            json!({
                "kind": "public",
                "redirect_uris": [],
                "audience": "spa",
                "id_token_alg": "EdDSA",
                "refresh": false,
                "jwks": {"keys": []},
                "login_url": "https://spa.example.com/login",
            }),
        ] {
            let stored: ClientDefinition = serde_json::from_value(body.clone()).unwrap();
            let read: konklav_api::OidcClientDefinition = serde_json::from_value(body).unwrap();
            assert_eq!(super::client_definition(read), stored);
            let client = OidcClient {
                id: "console".into(),
                definition: stored,
                secret_hash: Some(vec![1, 2, 3]),
                has_secret: true,
                disabled_at: None,
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
            };
            assert_eq!(
                serde_json::to_value(super::oidc_client(client.clone())).unwrap(),
                serde_json::to_value(&client).unwrap()
            );
        }
    }
}
