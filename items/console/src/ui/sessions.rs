//! Sessions: listing and revocation.

use leptos::ev::SubmitEvent;
use leptos::prelude::*;
use leptos_router::components::A;

use super::common::{Field, Gated, Id, Problem, confirm, loaded, timestamp};
use super::console::use_console;
use crate::api::endpoints::{self, SessionFilter};
use crate::api::types::{RevokedSessions, Session, SessionPage};
use crate::grants::Capability;

#[component]
pub fn Sessions() -> impl IntoView {
    view! {
        <h1>"Sessions"</h1>
        <Gated capability=Capability::Sessions>
            <SessionSearch/>
            <BulkRevoke/>
        </Gated>
    }
}

#[component]
fn SessionSearch() -> impl IntoView {
    let subject = RwSignal::new(String::new());
    let credential = RwSignal::new(String::new());
    let filter = RwSignal::new(SessionFilter::default());
    let search = move |event: SubmitEvent| {
        event.prevent_default();
        filter.set(SessionFilter {
            subject: subject.get_untracked(),
            credential: credential.get_untracked(),
            ..SessionFilter::default()
        });
    };
    view! {
        <form class="filters" on:submit=search>
            <Field label="Subject" value=subject placeholder="any"/>
            <Field label="Credential" value=credential placeholder="any"/>
            <button type="submit">"Search"</button>
        </form>
        <SessionList filter=filter/>
    }
}

/// One page of sessions matching `filter`, newest first, each revocable.
#[component]
pub fn SessionList(#[prop(into)] filter: Signal<SessionFilter>) -> impl IntoView {
    let console = use_console();
    let active = RwSignal::new(true);
    let before = RwSignal::new(None::<String>);
    let error = RwSignal::new(None);
    Effect::new(move |_| {
        filter.track();
        active.track();
        before.set(None);
    });
    let page = LocalResource::new(move || {
        let request = endpoints::sessions(&filter.get(), active.get(), before.get().as_deref());
        console.call::<SessionPage>(request)
    });
    let revoke = move |id: String| {
        if confirm("Revoke this session? Its access and refresh tokens stop working.") {
            let request = endpoints::revoke_sessions(&SessionFilter::session(&id), "");
            console.act(request, error, move |_: RevokedSessions| page.refetch());
        }
    };
    view! {
        <label class="check">
            <input type="checkbox" bind:checked=active/>
            " Only active sessions"
        </label>
        <Problem error/>
        {loaded(page, move |page: SessionPage| {
            let next = page.next.clone();
            if page.sessions.is_empty() {
                return view! { <p class="muted">"No sessions."</p> }.into_any();
            }
            view! {
                <table>
                    <thead>
                        <tr>
                            <th>"Session"</th><th>"Subject"</th><th>"Stage"</th><th>"Client"</th>
                            <th>"Methods"</th><th>"Tenant"</th><th>"Started"</th><th>"Expires"</th>
                            <th>"State"</th><th></th>
                        </tr>
                    </thead>
                    <tbody>
                        {page.sessions.into_iter().map(|session| view! { <SessionRow session revoke/> }).collect_view()}
                    </tbody>
                </table>
                {next.map(|next| view! {
                    <button class="secondary" on:click=move |_| before.set(Some(next.clone()))>"Older"</button>
                })}
            }
            .into_any()
        })}
        {move || before.get().is_some().then(|| view! {
            <button class="link" on:click=move |_| before.set(None)>"Back to newest"</button>
        })}
    }
}

#[component]
fn SessionRow(
    session: Session,
    revoke: impl Fn(String) + Copy + Send + Sync + 'static,
) -> impl IntoView {
    let id = session.id.clone();
    let state = match (&session.revoked_at, &session.revoked_reason) {
        (Some(at), reason) => format!(
            "revoked {} ({})",
            timestamp(at),
            reason.as_deref().unwrap_or("no reason")
        ),
        (None, _) => "active".to_owned(),
    };
    let client = match &session.oidc_client_id {
        Some(client) => format!("{} via {client}", session.client_kind),
        None => session.client_kind.clone(),
    };
    let impersonated = session.impersonator_subject_id.clone();
    let revoked = session.is_revoked();
    view! {
        <tr class:revoked=revoked>
            <td><Id id=session.id.clone()/></td>
            <td><A href=format!("/subjects/{}", session.subject_id)><Id id=session.subject_id.clone()/></A></td>
            <td>{session.stage.clone()}</td>
            <td>{client}</td>
            <td>{session.amr.join(", ")}</td>
            <td>{session.tenant_id.clone().map(|t| view! { <Id id=t/> })}</td>
            <td>{timestamp(&session.created_at)}</td>
            <td>{timestamp(&session.expires_at)}</td>
            <td>
                {state}
                {impersonated.map(|by| view! { <span class="chip">"impersonated by " <Id id=by/></span> })}
            </td>
            <td>
                {(!revoked).then(|| view! {
                    <button class="danger small" on:click=move |_| revoke(id.clone())>"Revoke"</button>
                })}
            </td>
        </tr>
    }
}

#[component]
fn BulkRevoke() -> impl IntoView {
    let console = use_console();
    let subject = RwSignal::new(String::new());
    let credential = RwSignal::new(String::new());
    let tenant = RwSignal::new(String::new());
    let membership = RwSignal::new(String::new());
    let reason = RwSignal::new(String::new());
    let error = RwSignal::new(None);
    let result = RwSignal::new(None::<usize>);
    let submit = move |event: SubmitEvent| {
        event.prevent_default();
        let filter = SessionFilter {
            session: String::new(),
            subject: subject.get_untracked(),
            credential: credential.get_untracked(),
            tenant: tenant.get_untracked(),
            membership: membership.get_untracked(),
        };
        if filter.is_empty() {
            error.set(Some(super::common::invalid_input(
                "Name at least one of subject, credential, tenant or membership.",
            )));
            return;
        }
        if confirm("Revoke every session matching all of these?") {
            let request = endpoints::revoke_sessions(&filter, &reason.get_untracked());
            console.act(request, error, move |revoked: RevokedSessions| {
                result.set(Some(revoked.revoked.len()));
            });
        }
    };
    view! {
        <h2>"Revoke by filter"</h2>
        <form class="card" on:submit=submit>
            <p class="muted">"Sessions must match every field you fill in."</p>
            <div class="row">
                <Field label="Subject" value=subject/>
                <Field label="Credential" value=credential/>
                <Field label="Tenant" value=tenant placeholder="UUID or root"/>
                <Field label="Membership" value=membership/>
            </div>
            <Field label="Reason" value=reason placeholder="revoked_by_operator"/>
            <Problem error/>
            {move || result.get().map(|count| view! { <p class="notice">{format!("Revoked {count} sessions.")}</p> })}
            <button type="submit" class="danger">"Revoke"</button>
        </form>
    }
}
