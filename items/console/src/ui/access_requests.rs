//! Access requests: people who signed in for a client asking for a tenant
//! they aren't a member of, waiting for an operator to let them in.

use leptos::ev::SubmitEvent;
use leptos::prelude::*;
use leptos_router::components::A;

use super::common::{Field, Gated, Id, Problem, confirm, loaded, timestamp};
use super::console::use_console;
use crate::api::endpoints::{self, list};
use crate::api::types::{AccessRequest, AccessRequestPage};
use crate::grants::Capability;

#[component]
pub fn AccessRequests() -> impl IntoView {
    let tenant = RwSignal::new(String::new());
    let state = RwSignal::new("pending".to_owned());
    let filter = RwSignal::new((String::new(), "pending".to_owned()));
    let search = move |event: SubmitEvent| {
        event.prevent_default();
        filter.set((tenant.get_untracked(), state.get_untracked()));
    };
    view! {
        <h1>"Access requests"</h1>
        <Gated capability=Capability::Tenants>
            <p class="muted">
                "People ask for access from the login page when a client asks for a tenant they aren't a member of, "
                "and only for the tenants the server's " <code>"access_requests"</code> " configuration names. "
                "Approving one makes the person a member, with the roles you give; giving a role that names a "
                <code>"konklav:"</code> " action needs " <code>"konklav:control:all"</code> ". Members holding "
                <code>"konklav:tenant:admit"</code> " in a tenant decide its requests too, in your relying system. "
                "Each change is an "
                <code>"access_request.changed"</code> " event on the change feed."
            </p>
            <form class="filters" on:submit=search>
                <Field label="Tenant" value=tenant placeholder="any; a UUID or root"/>
                <label class="field">
                    <span>"State"</span>
                    <select prop:value=move || state.get() on:change=move |ev| state.set(event_target_value(&ev))>
                        <option value="pending">"pending"</option>
                        <option value="approved">"approved"</option>
                        <option value="denied">"denied"</option>
                        <option value="withdrawn">"withdrawn"</option>
                        <option value="">"any"</option>
                    </select>
                </label>
                <button type="submit">"Search"</button>
            </form>
            <RequestList filter/>
        </Gated>
    }
}

/// One page of requests matching `(tenant, state)`, newest first.
#[component]
fn RequestList(filter: RwSignal<(String, String)>) -> impl IntoView {
    let console = use_console();
    let before = RwSignal::new(None::<String>);
    let error = RwSignal::new(None);
    Effect::new(move |_| {
        filter.track();
        before.set(None);
    });
    let page = LocalResource::new(move || {
        let (tenant, state) = filter.get();
        let request = endpoints::access_requests(&tenant, &state, before.get().as_deref());
        console.call::<AccessRequestPage>(request)
    });
    let decided = move || page.refetch();
    view! {
        <Problem error/>
        {loaded(page, move |page: AccessRequestPage| {
            let next = page.next.clone();
            if page.access_requests.is_empty() {
                return view! { <p class="muted">"No access requests."</p> }.into_any();
            }
            view! {
                <table>
                    <thead>
                        <tr>
                            <th>"Request"</th><th>"Subject"</th><th>"Tenant"</th><th>"Asked"</th>
                            <th>"State"</th><th>"Decision"</th>
                        </tr>
                    </thead>
                    <tbody>
                        {page.access_requests.into_iter().map(|request| view! {
                            <RequestRow request error decided/>
                        }).collect_view()}
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
fn RequestRow(
    request: AccessRequest,
    error: RwSignal<Option<crate::api::ApiError>>,
    decided: impl Fn() + Copy + Send + Sync + 'static,
) -> impl IntoView {
    let console = use_console();
    let roles = RwSignal::new(String::new());
    let approve = {
        let id = request.id.clone();
        move |event: SubmitEvent| {
            event.prevent_default();
            let request = endpoints::approve_access_request(&id, &list(&roles.get_untracked()));
            console.act(request, error, move |_: AccessRequest| decided());
        }
    };
    let deny = {
        let id = request.id.clone();
        move |_| {
            if confirm("Deny this request? The person can ask again only after a while.") {
                let request = endpoints::deny_access_request(&id);
                console.act(request, error, move |_: AccessRequest| decided());
            }
        }
    };
    let decision = if request.is_pending() {
        view! {
            <form class="inline" on:submit=approve>
                <input placeholder="roles, comma-separated" bind:value=roles/>
                <button type="submit" class="small">"Approve"</button>
                <button type="button" class="danger small" on:click=deny>"Deny"</button>
            </form>
        }
        .into_any()
    } else {
        view! {
            {request.decided_at.as_deref().map(timestamp)}
            {request.decided_by.clone().map(|by| view! {
                " by " <A href=format!("/subjects/{by}")><Id id=by/></A>
            })}
            {request.membership_id.clone().map(|membership| view! {
                " " <A href=format!("/memberships/{membership}")>"membership"</A>
            })}
        }
        .into_any()
    };
    view! {
        <tr class:revoked=matches!(request.state.as_str(), "denied" | "withdrawn")>
            <td><Id id=request.id.clone()/></td>
            <td><A href=format!("/subjects/{}", request.subject_id)><Id id=request.subject_id.clone()/></A></td>
            <td><A href=format!("/tenants/{}", request.tenant_id)><Id id=request.tenant_id.clone()/></A></td>
            <td>{timestamp(&request.created_at)}</td>
            <td>{request.state.clone()}</td>
            <td class="actions">{decision}</td>
        </tr>
    }
}
