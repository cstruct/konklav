//! Signing in: the operator's own password, MFA if their credential needs
//! it, or the bootstrap token on a first run.

use leptos::ev::SubmitEvent;
use leptos::prelude::*;
use leptos::task::spawn_local;

use super::common::{Field, Problem, invalid_input};
use super::console::{send, use_console};
use crate::api::endpoints;
use crate::api::types::{Factor, TokenResponse};
use crate::operator::{AfterLogin, Operator, after_login};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Password,
    Bootstrap,
}

#[component]
pub fn SignIn() -> impl IntoView {
    let mode = RwSignal::new(Mode::Password);
    view! {
        <main class="sign-in">
            <h1>"Konklav console"</h1>
            <div class="tabs">
                <button class:active=move || mode.get() == Mode::Password on:click=move |_| mode.set(Mode::Password)>
                    "Operator sign-in"
                </button>
                <button class:active=move || mode.get() == Mode::Bootstrap on:click=move |_| mode.set(Mode::Bootstrap)>
                    "Bootstrap token"
                </button>
            </div>
            {move || match mode.get() {
                Mode::Password => view! { <PasswordSignIn/> }.into_any(),
                Mode::Bootstrap => view! { <BootstrapSignIn/> }.into_any(),
            }}
        </main>
    }
}

#[component]
fn PasswordSignIn() -> impl IntoView {
    let console = use_console();
    let identifier = RwSignal::new(String::new());
    let password = RwSignal::new(String::new());
    let error = RwSignal::new(None);
    let busy = RwSignal::new(false);
    // Set while the credential waits for MFA.
    let partial = RwSignal::new(None::<TokenResponse>);
    let factors = RwSignal::new(Vec::<Factor>::new());

    let submit = move |event: SubmitEvent| {
        event.prevent_default();
        error.set(None);
        busy.set(true);
        spawn_local(async move {
            let login =
                endpoints::login_password(&identifier.get_untracked(), &password.get_untracked());
            let result = match send::<TokenResponse>(&login, None).await {
                Ok(token) => match after_login(token) {
                    AfterLogin::Done(token) => console.complete_sign_in(token).await,
                    AfterLogin::Mfa(token) => {
                        match send::<Vec<Factor>>(
                            &endpoints::mfa_factors(),
                            Some(&token.access_token),
                        )
                        .await
                        {
                            Ok(listed) if listed.is_empty() => Err(invalid_input(
                                "Your credential requires MFA, but you have no active factor.",
                            )),
                            Ok(listed) => {
                                factors.set(listed);
                                partial.set(Some(token));
                                Ok(())
                            }
                            Err(failure) => Err(failure),
                        }
                    }
                },
                Err(failure) => Err(failure),
            };
            password.set(String::new());
            if let Err(failure) = result {
                error.set(Some(failure));
            }
            busy.set(false);
        });
    };

    move || match partial.get() {
        Some(token) => view! { <MfaStep token factors=factors.get() back=partial/> }.into_any(),
        None => view! {
            <form class="card" on:submit=submit>
                <Field label="Email address or login identifier" value=identifier/>
                <Field label="Password" value=password kind="password"/>
                <Problem error/>
                <button type="submit" disabled=move || busy.get()>"Sign in"</button>
            </form>
        }
        .into_any(),
    }
}

#[component]
fn MfaStep(
    token: TokenResponse,
    factors: Vec<Factor>,
    back: RwSignal<Option<TokenResponse>>,
) -> impl IntoView {
    let console = use_console();
    let chosen = RwSignal::new(factors.first().map(|f| f.id.clone()).unwrap_or_default());
    let code = RwSignal::new(String::new());
    let error = RwSignal::new(None);
    let sent = RwSignal::new(false);
    let partial = StoredValue::new(token.access_token.clone());
    let kinds = StoredValue::new(factors.clone());
    let chosen_kind = move || {
        kinds.with_value(|factors| {
            factors
                .iter()
                .find(|f| f.id == chosen.get())
                .map(|f| f.kind.clone())
                .unwrap_or_default()
        })
    };

    let send_code = move |_| {
        error.set(None);
        spawn_local(async move {
            let request = endpoints::send_mfa_code(&chosen.get_untracked());
            match send::<serde_json::Value>(&request, Some(&partial.get_value())).await {
                Ok(_) => sent.set(true),
                Err(failure) => error.set(Some(failure)),
            }
        });
    };
    let submit = move |event: SubmitEvent| {
        event.prevent_default();
        error.set(None);
        spawn_local(async move {
            let request = endpoints::complete_mfa(&chosen.get_untracked(), &code.get_untracked());
            let result = match send::<TokenResponse>(&request, Some(&partial.get_value())).await {
                Ok(token) if token.token_kind == "partial" => Err(invalid_input(
                    "That factor is done; your credential requires another one.",
                )),
                Ok(token) => console.complete_sign_in(token).await,
                Err(failure) => Err(failure),
            };
            code.set(String::new());
            if let Err(failure) = result {
                error.set(Some(failure));
            }
        });
    };

    let options = factors
        .into_iter()
        .map(|factor| {
            let label = match factor.kind.as_str() {
                "totp" => "Authenticator app".to_owned(),
                "email_code" => "Code by email".to_owned(),
                other => other.to_owned(),
            };
            view! { <option value=factor.id.clone()>{label}</option> }
        })
        .collect_view();
    view! {
        <form class="card" on:submit=submit>
            <p>"Your credential requires a second factor."</p>
            <label class="field">
                <span>"Factor"</span>
                <select prop:value=move || chosen.get() on:change=move |ev| chosen.set(event_target_value(&ev))>
                    {options}
                </select>
            </label>
            {move || (chosen_kind() == "email_code").then(|| view! {
                <p>
                    <button type="button" class="secondary" on:click=send_code>"Email me a code"</button>
                    {move || sent.get().then_some(" Sent.")}
                </p>
            })}
            <label class="field">
                <span>"Code"</span>
                <input inputmode="numeric" autocomplete="one-time-code" bind:value=code/>
            </label>
            <Problem error/>
            <button type="submit">"Verify"</button>
            " "
            <button type="button" class="link" on:click=move |_| back.set(None)>"Start over"</button>
        </form>
    }
}

#[component]
fn BootstrapSignIn() -> impl IntoView {
    let console = use_console();
    let token = RwSignal::new(String::new());
    let error = RwSignal::new(None);
    let submit = move |event: SubmitEvent| {
        event.prevent_default();
        error.set(None);
        spawn_local(async move {
            let operator = Operator::bootstrap(&token.get_untracked());
            // Any control-plane read tells whether Konklav accepts it.
            match send::<serde_json::Value>(&endpoints::signing_keys(), Some(&operator.token)).await
            {
                Ok(_) => console.operator.set(Some(operator)),
                Err(failure) => error.set(Some(failure)),
            }
        });
    };
    view! {
        <form class="card" on:submit=submit>
            <p>
                "For a first run: the control plane's bootstrap token from the secrets file. "
                "The console keeps it in memory only, so reloading the page forgets it."
            </p>
            <Field label="Bootstrap token" value=token kind="password"/>
            <Problem error/>
            <button type="submit">"Continue"</button>
        </form>
    }
}
