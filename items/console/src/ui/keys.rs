//! Signing keys.

use leptos::prelude::*;
use serde_json::Value;

use super::common::{Gated, Problem, confirm, loaded, timestamp};
use super::console::use_console;
use crate::api::endpoints;
use crate::api::types::SigningKey;
use crate::grants::Capability;

#[component]
pub fn Keys() -> impl IntoView {
    view! {
        <h1>"Signing keys"</h1>
        <Gated capability=Capability::Keys>
            <KeyList/>
        </Gated>
    }
}

#[component]
fn KeyList() -> impl IntoView {
    let console = use_console();
    let error = RwSignal::new(None);
    let keys =
        LocalResource::new(move || console.call::<Vec<SigningKey>>(endpoints::signing_keys()));
    let revoke = move |kid: String, active: bool| {
        let warning = if active {
            "Revoke the active signing key? Tokens it signed stop verifying, and no tokens can be issued until another key is configured."
        } else {
            "Revoke this signing key? Tokens it signed stop verifying."
        };
        if confirm(warning) {
            console.act(
                endpoints::revoke_signing_key(&kid),
                error,
                move |_: Value| keys.refetch(),
            );
        }
    };
    view! {
        <p class="muted">
            "Keys come from configuration and rotate there; the control plane can only revoke them, "
            "as a break-glass measure."
        </p>
        <Problem error/>
        {loaded(keys, move |keys: Vec<SigningKey>| view! {
            <table>
                <thead><tr><th>"Key id"</th><th>"Algorithm"</th><th>"Status"</th><th>"Published"</th><th>"Activated"</th><th>"Retired"</th><th>"Revoked"</th><th></th></tr></thead>
                <tbody>
                    {keys.into_iter().map(|key| {
                        let status = key.status();
                        let kid = key.kid.clone();
                        let at = |value: &Option<String>| value.as_deref().map(timestamp);
                        view! {
                            <tr class:revoked=status == "revoked">
                                <td><code>{key.kid.clone()}</code></td>
                                <td>{key.algorithm.clone()}</td>
                                <td>{status}</td>
                                <td>{timestamp(&key.published_at)}</td>
                                <td>{at(&key.activated_at)}</td>
                                <td>{at(&key.retired_at)}</td>
                                <td>{at(&key.revoked_at)}</td>
                                <td>{(status != "revoked").then(|| view! {
                                    <button class="small danger" on:click=move |_| revoke(kid.clone(), status == "active")>"Revoke"</button>
                                })}</td>
                            </tr>
                        }
                    }).collect_view()}
                </tbody>
            </table>
        })}
    }
}
