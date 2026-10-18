//! Subjects, their credentials, sessions, global assignments and
//! entitlements.

use leptos::ev::SubmitEvent;
use leptos::prelude::*;
use leptos_router::NavigateOptions;
use leptos_router::components::A;
use leptos_router::hooks::{use_navigate, use_params_map};
use serde_json::{Value, json};

use super::authz::{Explain, GlobalAssignments};
use super::common::{Field, Gated, Id, Problem, Secret, confirm, invalid_input, loaded, timestamp};
use super::console::use_console;
use super::sessions::SessionList;
use crate::api::endpoints::{self, SessionFilter};
use crate::api::types::{
    CreatedCredential, Credential, RotatedSlot, Subject, SubjectDetail, SubjectPage,
};
use crate::grants::Capability;
use crate::ids::new_id;

#[component]
pub fn Subjects() -> impl IntoView {
    view! {
        <h1>"Subjects"</h1>
        <Gated capability=Capability::Subjects>
            <SubjectSearch/>
            <CreateSubject/>
        </Gated>
    }
}

#[component]
fn SubjectSearch() -> impl IntoView {
    let console = use_console();
    let kind = RwSignal::new(String::new());
    let identifier = RwSignal::new(String::new());
    let query = RwSignal::new((String::new(), String::new()));
    let before = RwSignal::new(None::<String>);
    let search = move |event: SubmitEvent| {
        event.prevent_default();
        before.set(None);
        query.set((kind.get_untracked(), identifier.get_untracked()));
    };
    let page = LocalResource::new(move || {
        let (kind, identifier) = query.get();
        console.call::<SubjectPage>(endpoints::subjects(
            &kind,
            &identifier,
            before.get().as_deref(),
        ))
    });
    view! {
        <form class="filters" on:submit=search>
            <label class="field">
                <span>"Kind"</span>
                <select on:change=move |ev| kind.set(event_target_value(&ev))>
                    <option value="">"any"</option>
                    <option value="human">"human"</option>
                    <option value="service">"service"</option>
                </select>
            </label>
            <Field label="Login identifier" value=identifier placeholder="email, phone or key id"/>
            <button type="submit">"Search"</button>
        </form>
        {loaded(page, move |page: SubjectPage| {
            let next = page.next.clone();
            view! {
                <table>
                    <thead><tr><th>"Subject"</th><th>"Kind"</th><th>"State"</th><th>"Created"</th></tr></thead>
                    <tbody>{page.subjects.into_iter().map(|s| view! { <SubjectRow subject=s/> }).collect_view()}</tbody>
                </table>
                {next.map(|next| view! {
                    <button class="secondary" on:click=move |_| before.set(Some(next.clone()))>"Older"</button>
                })}
            }
        })}
    }
}

#[component]
fn SubjectRow(subject: Subject) -> impl IntoView {
    let inactive = subject.state != "active";
    view! {
        <tr class:revoked=inactive>
            <td><A href=format!("/subjects/{}", subject.id)><code>{subject.id.clone()}</code></A></td>
            <td>{subject.kind}</td>
            <td>{subject.state}</td>
            <td>{timestamp(&subject.created_at)}</td>
        </tr>
    }
}

#[component]
fn CreateSubject() -> impl IntoView {
    let console = use_console();
    let kind = RwSignal::new("human".to_owned());
    let error = RwSignal::new(None);
    let navigate = use_navigate();
    let submit = move |event: SubmitEvent| {
        event.prevent_default();
        let id = new_id();
        let navigate = navigate.clone();
        console.act(
            endpoints::create_subject(&id, &kind.get_untracked()),
            error,
            move |subject: Subject| {
                navigate(
                    &format!("/subjects/{}", subject.id),
                    NavigateOptions::default(),
                );
            },
        );
    };
    view! {
        <h2>"New subject"</h2>
        <form class="card row" on:submit=submit>
            <label class="field">
                <span>"Kind"</span>
                <select on:change=move |ev| kind.set(event_target_value(&ev))>
                    <option value="human">"human (a person)"</option>
                    <option value="service">"service (a service principal)"</option>
                </select>
            </label>
            <button type="submit">"Create"</button>
            <Problem error/>
        </form>
    }
}

#[component]
pub fn SubjectPage() -> impl IntoView {
    let params = use_params_map();
    let id = Signal::derive(move || params.read().get("id").unwrap_or_default());
    view! {
        <p><A href="/subjects">"← Subjects"</A></p>
        <h1>"Subject " <code>{id}</code></h1>
        <Gated capability=Capability::Subjects>
            <SubjectDetails id/>
        </Gated>
        <h2>"Sessions"</h2>
        <Gated capability=Capability::Sessions>
            <SessionList filter=Signal::derive(move || SessionFilter::subject(&id.get()))/>
        </Gated>
        <h2>"Global roles"</h2>
        <Gated capability=Capability::Authz>
            <GlobalAssignments subject=id/>
        </Gated>
        <h2>"Entitlements"</h2>
        <Gated capability=Capability::Authz>
            <Explain subject=id/>
        </Gated>
    }
}

/// A secret to show once, with what it is.
type Shown = Option<(String, String)>;

#[component]
fn SubjectDetails(id: Signal<String>) -> impl IntoView {
    let console = use_console();
    let error = RwSignal::new(None);
    let secret = RwSignal::new(None::<Shown>);
    let resource =
        LocalResource::new(move || console.call::<SubjectDetail>(endpoints::subject(&id.get())));
    let set_enabled = move |enabled: bool| {
        if enabled || confirm("Disable this subject? Its sessions end and it can't sign in.") {
            console.act(
                endpoints::set_subject_enabled(&id.get_untracked(), enabled),
                error,
                move |_: Value| resource.refetch(),
            );
        }
    };
    view! {
        <Problem error/>
        {move || secret.get().flatten().map(|(label, value)| view! { <Secret label value/> })}
        {loaded(resource, move |detail: SubjectDetail| {
            let subject = detail.subject.clone();
            let active = subject.state == "active";
            let kind = subject.kind.clone();
            view! {
                <dl class="facts">
                    <dt>"Kind"</dt><dd>{subject.kind.clone()}</dd>
                    <dt>"State"</dt><dd>{subject.state.clone()}</dd>
                    <dt>"Created"</dt><dd>{timestamp(&subject.created_at)}</dd>
                </dl>
                {if active {
                    view! { <button class="danger" on:click=move |_| set_enabled(false)>"Disable"</button> }.into_any()
                } else {
                    view! { <button on:click=move |_| set_enabled(true)>"Enable"</button> }.into_any()
                }}
                <h2>"Credentials"</h2>
                <Credentials credentials=detail.credentials reload=move || resource.refetch() secret/>
                <AddCredential subject=id kind reload=move || resource.refetch() secret/>
            }
        })}
    }
}

#[component]
fn Credentials(
    credentials: Vec<Credential>,
    reload: impl Fn() + Copy + Send + Sync + 'static,
    secret: RwSignal<Option<Shown>>,
) -> impl IntoView {
    let console = use_console();
    let error = RwSignal::new(None);
    let replacing = RwSignal::new(None::<String>);
    let password = RwSignal::new(String::new());
    if credentials.is_empty() {
        return view! { <p class="muted">"No credentials."</p> }.into_any();
    }
    let revoke = move |id: String| {
        let reason = window()
            .prompt_with_message(
                "Revoke this credential? Sessions established with it end. Reason (optional):",
            )
            .ok()
            .flatten();
        if let Some(reason) = reason {
            console.act(
                endpoints::revoke_credential(&id, &reason),
                error,
                move |_: Value| reload(),
            );
        }
    };
    let break_glass = move |id: String, on: bool| {
        console.act(
            endpoints::set_break_glass(&id, on),
            error,
            move |_: Value| reload(),
        );
    };
    let rotate = move |id: String, slot: &'static str| {
        if confirm(&format!(
            "Replace the secret in slot {slot}? Clients using it stop working; the other slot keeps working."
        )) {
            console.act(
                endpoints::rotate_slot(&id, slot),
                error,
                move |rotated: RotatedSlot| {
                    secret.set(Some(Some((
                        format!("Secret key for slot {}", rotated.slot),
                        rotated.secret_key,
                    ))));
                    reload();
                },
            );
        }
    };
    let replace = move |event: SubmitEvent| {
        event.prevent_default();
        let Some(id) = replacing.get_untracked() else {
            return;
        };
        console.act(
            endpoints::replace_password(&id, &password.get_untracked()),
            error,
            move |_: Value| {
                password.set(String::new());
                replacing.set(None);
                reload();
            },
        );
    };
    let rows = credentials
        .into_iter()
        .map(|credential| {
            let id = StoredValue::new(credential.id.clone());
            let active = credential.is_active();
            let status = match (&credential.revoked_at, &credential.revoked_reason) {
                (Some(at), reason) => format!("revoked {} ({})", timestamp(at), reason.as_deref().unwrap_or("revoked")),
                (None, _) => "active".to_owned(),
            };
            let slots = credential.slots.clone().map(|slots| {
                format!(
                    "a: {}{}, b: {}{}",
                    timestamp(&slots.a.created_at),
                    slots.a.expires_at.map(|e| format!(" until {}", timestamp(&e))).unwrap_or_default(),
                    timestamp(&slots.b.created_at),
                    slots.b.expires_at.map(|e| format!(" until {}", timestamp(&e))).unwrap_or_default(),
                )
            });
            let is_password = credential.kind == "password";
            let is_key = credential.kind == "secret_key";
            let can_break_glass = credential.can_be_break_glass();
            let marked = credential.break_glass;
            view! {
                <tr class:revoked=!active>
                    <td><Id id=credential.id.clone()/></td>
                    <td>{credential.kind.clone()}</td>
                    <td><code>{credential.identifier.clone()}</code></td>
                    <td>{(credential.mfa_factors_required > 0).then(|| format!("{} factor(s)", credential.mfa_factors_required))}</td>
                    <td>{slots}</td>
                    <td>{status}{marked.then(|| view! { <span class="chip warning">"break-glass"</span> })}</td>
                    <td class="actions">
                        {active.then(|| view! {
                            <button class="danger small" on:click=move |_| revoke(id.get_value())>"Revoke"</button>
                        })}
                        {(active && is_password).then(|| view! {
                            <button class="small secondary" on:click=move |_| replacing.set(Some(id.get_value()))>"Replace password"</button>
                        })}
                        {(active && is_key).then(|| view! {
                            <button class="small secondary" on:click=move |_| rotate(id.get_value(), "a")>"Rotate a"</button>
                            <button class="small secondary" on:click=move |_| rotate(id.get_value(), "b")>"Rotate b"</button>
                        })}
                        {can_break_glass.then(|| view! {
                            <button class="small secondary" on:click=move |_| break_glass(id.get_value(), !marked)>
                                {if marked { "Unmark break-glass" } else { "Mark break-glass" }}
                            </button>
                        })}
                    </td>
                </tr>
            }
        })
        .collect_view();
    view! {
        <Problem error/>
        <table>
            <thead><tr><th>"Credential"</th><th>"Kind"</th><th>"Identifier"</th><th>"MFA"</th><th>"Slots"</th><th>"State"</th><th></th></tr></thead>
            <tbody>{rows}</tbody>
        </table>
        {move || replacing.get().map(|id| view! {
            <form class="card row" on:submit=replace>
                <span>"New password for " <Id id/></span>
                <Field label="Password" value=password kind="password"/>
                <button type="submit">"Replace"</button>
                <button type="button" class="link" on:click=move |_| replacing.set(None)>"Cancel"</button>
            </form>
        })}
    }
    .into_any()
}

/// The control plane's credential body for `kind`. For `password_hash`,
/// `password` holds an Argon2id hash made elsewhere.
fn credential_body(
    kind: &str,
    identifier: &str,
    password: &str,
    mfa: &str,
) -> Result<Value, crate::api::ApiError> {
    let identifier = identifier.trim();
    match kind {
        "password" | "password_hash" => {
            let mfa: i16 = if mfa.trim().is_empty() {
                0
            } else {
                mfa.trim()
                    .parse()
                    .map_err(|_| invalid_input("MFA factors must be a number"))?
            };
            let mut body =
                json!({"kind": "password", "identifier": identifier, "mfa_factors_required": mfa});
            if kind == "password" {
                body["password"] = json!(password);
            } else {
                body["password_hash"] = json!(password.trim());
            }
            Ok(body)
        }
        "secret_key" => Ok(json!({"kind": "secret_key"})),
        "email_link" | "phone_otp" => Ok(json!({"kind": kind, "identifier": identifier})),
        other => Err(invalid_input(format!("unknown credential kind {other}"))),
    }
}

#[component]
fn AddCredential(
    subject: Signal<String>,
    kind: String,
    reload: impl Fn() + Copy + Send + Sync + 'static,
    secret: RwSignal<Option<Shown>>,
) -> impl IntoView {
    let console = use_console();
    let human = kind == "human";
    let chosen = RwSignal::new(if human { "password" } else { "secret_key" }.to_owned());
    let identifier = RwSignal::new(String::new());
    let password = RwSignal::new(String::new());
    let mfa = RwSignal::new(String::new());
    let error = RwSignal::new(None);
    let submit = move |event: SubmitEvent| {
        event.prevent_default();
        let body = match credential_body(
            &chosen.get_untracked(),
            &identifier.get_untracked(),
            &password.get_untracked(),
            &mfa.get_untracked(),
        ) {
            Ok(body) => body,
            Err(failure) => return error.set(Some(failure)),
        };
        console.act(
            endpoints::create_credential(&subject.get_untracked(), body),
            error,
            move |created: CreatedCredential| {
                if let Some(keys) = created.secret_keys {
                    secret.set(Some(Some((
                        "Both secret keys (slot a, then slot b)".to_owned(),
                        format!("{}\n{}", keys.a, keys.b),
                    ))));
                }
                identifier.set(String::new());
                password.set(String::new());
                reload();
            },
        );
    };
    let options = if human {
        view! {
            <option value="password">"password"</option>
            <option value="password_hash">"password (Argon2id hash)"</option>
            <option value="email_link">"email magic link"</option>
            <option value="phone_otp">"phone code"</option>
        }
        .into_any()
    } else {
        view! { <option value="secret_key">"secret key"</option> }.into_any()
    };
    view! {
        <h3>"Add a credential"</h3>
        <form class="card" on:submit=submit>
            <div class="row">
                <label class="field">
                    <span>"Kind"</span>
                    <select on:change=move |ev| {
                        password.set(String::new());
                        chosen.set(event_target_value(&ev));
                    }>{options}</select>
                </label>
                {move || (chosen.get() != "secret_key").then(|| view! {
                    <Field label="Login identifier" value=identifier placeholder="email address or +E.164 phone"/>
                })}
                {move || match chosen.get().as_str() {
                    "password" => Some(view! {
                        <Field label="Password" value=password kind="password"/>
                        <Field label="MFA factors required" value=mfa placeholder="0"/>
                    }.into_any()),
                    "password_hash" => Some(view! {
                        <Field label="Argon2id hash" value=password placeholder="$argon2id$v=19$m=65536,t=3,p=4$…"/>
                        <Field label="MFA factors required" value=mfa placeholder="0"/>
                    }.into_any()),
                    _ => None,
                }}
            </div>
            {move || (chosen.get() == "password_hash").then(|| view! {
                <p class="muted">"The hash is stored as given, so the password never reaches Konklav. Konklav rehashes it under its own parameters at the first login."</p>
            })}
            <Problem error/>
            <button type="submit">"Add"</button>
        </form>
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_bodies_follow_their_kind() {
        assert_eq!(
            credential_body("password", " ada@example.com ", "pw", "1").unwrap(),
            json!({"kind": "password", "identifier": "ada@example.com", "password": "pw", "mfa_factors_required": 1})
        );
        assert_eq!(
            credential_body("password", "ada", "pw", "").unwrap()["mfa_factors_required"],
            0
        );
        assert!(credential_body("password", "ada", "pw", "two").is_err());
        assert_eq!(
            credential_body("password_hash", "ada", " $argon2id$x ", "").unwrap(),
            json!({"kind": "password", "identifier": "ada", "password_hash": "$argon2id$x", "mfa_factors_required": 0})
        );
        assert_eq!(
            credential_body("secret_key", "ignored", "", "").unwrap(),
            json!({"kind": "secret_key"})
        );
        assert_eq!(
            credential_body("phone_otp", "+46700000000", "", "").unwrap(),
            json!({"kind": "phone_otp", "identifier": "+46700000000"})
        );
    }
}
