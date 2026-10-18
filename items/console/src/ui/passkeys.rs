//! The signed-in operator's own passkeys: adding, listing and removing
//! them. Both changes need a recent authentication, so the page offers to
//! confirm it with the password or a passkey first.

use leptos::ev::SubmitEvent;
use leptos::prelude::*;
use leptos::task::spawn_local;
use serde_json::Value;

use super::common::{Field, Problem, confirm, invalid_input, loaded, timestamp};
use super::console::{Console, use_console};
use crate::api::types::{Ceremony, Passkey, TokenResponse};
use crate::api::{ApiError, endpoints};
use crate::webauthn;

#[component]
pub fn Passkeys() -> impl IntoView {
    let console = use_console();
    view! {
        <h1>"Your passkeys"</h1>
        {move || match console.subject() {
            Some(_) => view! { <PasskeyList/> }.into_any(),
            None => view! {
                <p>"The bootstrap token has no passkeys; sign in as an operator to manage yours."</p>
            }
            .into_any(),
        }}
    }
}

/// Konklav asks for a fresher authentication.
fn needs_step_up(error: &ApiError) -> bool {
    error.code() == Some("FORBIDDEN")
}

/// Adopts the token a step-up returned, which carries the new session
/// version.
fn adopt(console: Console, token: &TokenResponse) {
    console.operator.update(|operator| {
        if let Some(operator) = operator {
            operator.token.clone_from(&token.access_token);
        }
    });
}

#[component]
fn PasskeyList() -> impl IntoView {
    let console = use_console();
    let error = RwSignal::new(None);
    let label = RwSignal::new(String::new());
    let busy = RwSignal::new(false);
    let step_up = RwSignal::new(false);
    let passkeys =
        LocalResource::new(move || console.call::<Vec<Passkey>>(endpoints::own_passkeys()));

    let add = move |event: SubmitEvent| {
        event.prevent_default();
        if label.get_untracked().trim().is_empty() {
            error.set(Some(invalid_input(
                "Give the passkey a name, such as the device it's on.",
            )));
            return;
        }
        error.set(None);
        busy.set(true);
        spawn_local(async move {
            let result = async {
                let started: Ceremony = console
                    .call(endpoints::passkey_registration_options(
                        &label.get_untracked(),
                    ))
                    .await?;
                let credential = webauthn::create(&started.options).await?;
                console
                    .call::<Value>(endpoints::register_passkey(&started.ceremony, &credential))
                    .await
            }
            .await;
            match result {
                Ok(_) => {
                    label.set(String::new());
                    passkeys.refetch();
                }
                Err(failure) => {
                    step_up.set(needs_step_up(&failure));
                    error.set(Some(failure));
                }
            }
            busy.set(false);
        });
    };
    let remove = move |id: String| {
        if !confirm("Remove this passkey? Sessions started with it end.") {
            return;
        }
        error.set(None);
        spawn_local(async move {
            match console.call::<Value>(endpoints::remove_passkey(&id)).await {
                Ok(_) => passkeys.refetch(),
                Err(failure) => {
                    step_up.set(needs_step_up(&failure));
                    error.set(Some(failure));
                }
            }
        });
    };

    view! {
        <p class="muted">
            "A passkey signs you in without a password. Adding or removing one needs a recent sign-in."
        </p>
        <Problem error/>
        {move || step_up.get().then(|| view! { <StepUp done=step_up error/> })}
        {loaded(passkeys, move |listed: Vec<Passkey>| view! {
            <table>
                <thead><tr><th>"Name"</th><th>"Added"</th><th>"Last used"</th><th></th></tr></thead>
                <tbody>
                    {listed.into_iter().map(|passkey| {
                        let id = passkey.id.clone();
                        view! {
                            <tr>
                                <td>{passkey.label.clone()}</td>
                                <td>{timestamp(&passkey.created_at)}</td>
                                <td>{passkey.last_used_at.as_deref().map(timestamp)}</td>
                                <td><button class="small danger" on:click=move |_| remove(id.clone())>"Remove"</button></td>
                            </tr>
                        }
                    }).collect_view()}
                </tbody>
            </table>
        })}
        <form class="card" on:submit=add>
            <Field label="Name" value=label placeholder="Work laptop"/>
            <button type="submit" disabled=move || busy.get()>"Add a passkey"</button>
        </form>
    }
}

/// Confirms the operator again, with the password or a passkey.
#[component]
fn StepUp(done: RwSignal<bool>, error: RwSignal<Option<ApiError>>) -> impl IntoView {
    let console = use_console();
    let password = RwSignal::new(String::new());
    let finish = move |result: Result<TokenResponse, ApiError>| match result {
        Ok(token) => {
            adopt(console, &token);
            error.set(None);
            done.set(false);
        }
        Err(failure) => error.set(Some(failure)),
    };
    let with_password = move |event: SubmitEvent| {
        event.prevent_default();
        spawn_local(async move {
            let request = endpoints::step_up_password(&password.get_untracked());
            password.set(String::new());
            finish(console.call(request).await);
        });
    };
    let with_passkey = move |_| {
        spawn_local(async move {
            let result = async {
                let started: Ceremony = console.call(endpoints::step_up_passkey_options()).await?;
                let credential = webauthn::sign(&started.options).await?;
                console
                    .call(endpoints::step_up_passkey(&started.ceremony, &credential))
                    .await
            }
            .await;
            finish(result);
        });
    };
    view! {
        <form class="card" on:submit=with_password>
            <p>"Confirm it's you, then try again."</p>
            <Field label="Password" value=password kind="password"/>
            <button type="submit">"Confirm"</button>
            " "
            <button type="button" class="secondary" on:click=with_passkey>"Use a passkey"</button>
        </form>
    }
}
