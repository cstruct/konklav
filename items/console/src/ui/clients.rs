//! OIDC clients of Conclave's OpenID provider.

use leptos::ev::SubmitEvent;
use leptos::prelude::*;
use serde_json::Value;

use super::common::{
    Field, Gated, JsonField, Problem, Secret, confirm, invalid_input, loaded, parse_json, pretty,
    timestamp,
};
use super::console::use_console;
use crate::api::endpoints;
use crate::api::types::{NewClientSecret, OidcClient};
use crate::grants::Capability;

const CLIENT_EXAMPLE: &str = r#"{
  "kind": "confidential",
  "redirect_uris": ["https://app.example/callback"],
  "scopes": ["openid"],
  "audience": "app"
}"#;

#[component]
pub fn Clients() -> impl IntoView {
    view! {
        <h1>"OIDC clients"</h1>
        <Gated capability=Capability::Clients>
            <ClientList/>
        </Gated>
    }
}

#[component]
fn ClientList() -> impl IntoView {
    let console = use_console();
    let error = RwSignal::new(None);
    let secret = RwSignal::new(None::<(String, String)>);
    let id = RwSignal::new(String::new());
    let definition = RwSignal::new(CLIENT_EXAMPLE.to_owned());
    let clients =
        LocalResource::new(move || console.call::<Vec<OidcClient>>(endpoints::oidc_clients()));
    let save = move |event: SubmitEvent| {
        event.prevent_default();
        let client = id.get_untracked().trim().to_owned();
        if client.is_empty() {
            return error.set(Some(invalid_input("A client needs an id")));
        }
        match parse_json(&definition.get_untracked(), "definition") {
            Ok(value) => console.act(
                endpoints::put_oidc_client(&client, value),
                error,
                move |_: Value| clients.refetch(),
            ),
            Err(failure) => error.set(Some(failure)),
        }
    };
    let rotate = move |client: String| {
        if confirm(&format!(
            "Issue a new secret for {client}? The current one stops working."
        )) {
            let label = format!("The client secret of {client}");
            console.act(
                endpoints::new_client_secret(&client),
                error,
                move |new: NewClientSecret| {
                    secret.set(Some((label, new.client_secret)));
                    clients.refetch();
                },
            );
        }
    };
    let disable = move |client: String| {
        if confirm(&format!(
            "Disable {client}? Its sessions end. Saving its registration again re-enables it."
        )) {
            console.act(
                endpoints::disable_oidc_client(&client),
                error,
                move |_: Value| clients.refetch(),
            );
        }
    };
    view! {
        <Problem error/>
        {move || secret.get().map(|(label, value)| view! { <Secret label value/> })}
        {loaded(clients, move |clients: Vec<OidcClient>| {
            if clients.is_empty() {
                return view! { <p class="muted">"No clients are registered."</p> }.into_any();
            }
            view! {
                <table>
                    <thead><tr><th>"Client"</th><th>"Kind"</th><th>"Audience"</th><th>"Redirect URIs"</th><th>"Secret"</th><th>"State"</th><th></th></tr></thead>
                    <tbody>
                        {clients.into_iter().map(|client| {
                            let edit_id = client.id.clone();
                            let edit_definition = pretty(&client.definition());
                            let rotate_id = client.id.clone();
                            let disable_id = client.id.clone();
                            let confidential = client.kind == "confidential";
                            let disabled = client.disabled_at.clone();
                            view! {
                                <tr class:revoked=disabled.is_some()>
                                    <td><code>{client.id.clone()}</code></td>
                                    <td>{client.kind.clone()}</td>
                                    <td><code>{client.audience.clone()}</code></td>
                                    <td>{client.redirect_uris.join(" ")}</td>
                                    <td>{if client.has_secret { "set" } else if confidential { "none yet" } else { "—" }}</td>
                                    <td>{disabled.as_deref().map_or_else(|| "enabled".to_owned(), |at| format!("disabled {}", timestamp(at)))}</td>
                                    <td class="actions">
                                        <button class="small secondary" on:click=move |_| {
                                            id.set(edit_id.clone());
                                            definition.set(edit_definition.clone());
                                        }>"Edit"</button>
                                        {confidential.then(|| view! {
                                            <button class="small secondary" on:click=move |_| rotate(rotate_id.clone())>"New secret"</button>
                                        })}
                                        {disabled.is_none().then(|| view! {
                                            <button class="small danger" on:click=move |_| disable(disable_id.clone())>"Disable"</button>
                                        })}
                                    </td>
                                </tr>
                            }
                        }).collect_view()}
                    </tbody>
                </table>
            }
            .into_any()
        })}
        <h2>"Register or replace a client"</h2>
        <form class="card" on:submit=save>
            <p class="muted">
                "Saving an existing id replaces its registration and enables it again. "
                "A new confidential client has no secret until you issue one."
            </p>
            <Field label="Client id" value=id placeholder="app"/>
            <JsonField label="Definition" value=definition rows=10/>
            <button type="submit">"Save client"</button>
        </form>
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_example_is_valid_json() {
        assert!(serde_json::from_str::<serde_json::Value>(super::CLIENT_EXAMPLE).is_ok());
    }
}
