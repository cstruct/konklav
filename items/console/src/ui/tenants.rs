//! Tenants and memberships.

use leptos::ev::SubmitEvent;
use leptos::prelude::*;
use leptos_router::NavigateOptions;
use leptos_router::components::A;
use leptos_router::hooks::{use_navigate, use_params_map};
use serde_json::Value;

use super::authz::MembershipAssignments;
use super::common::{
    Field, Gated, Id, JsonField, Problem, confirm, loaded, parse_json, pretty, timestamp,
};
use super::console::use_console;
use crate::api::endpoints::{self, list};
use crate::api::types::{Membership, MembershipDetail, Tenant, TenantPage};
use crate::grants::Capability;
use crate::ids::new_id;

#[component]
pub fn Tenants() -> impl IntoView {
    view! {
        <h1>"Tenants"</h1>
        <Gated capability=Capability::Tenants>
            <TenantSearch/>
            <CreateTenant parent=Signal::stored("root".to_owned())/>
        </Gated>
    }
}

#[component]
fn TenantSearch() -> impl IntoView {
    let parent = RwSignal::new(String::new());
    let query = RwSignal::new(String::new());
    let search = move |event: SubmitEvent| {
        event.prevent_default();
        query.set(parent.get_untracked());
    };
    view! {
        <p>"The " <A href="/tenants/root">"root tenant"</A> " holds global roles."</p>
        <form class="filters" on:submit=search>
            <Field label="Parent" value=parent placeholder="any; a UUID or root"/>
            <button type="submit">"Search"</button>
        </form>
        <TenantList parent=query/>
    }
}

#[component]
fn TenantList(#[prop(into)] parent: Signal<String>) -> impl IntoView {
    let console = use_console();
    let before = RwSignal::new(None::<String>);
    let page = LocalResource::new(move || {
        console.call::<TenantPage>(endpoints::tenants(&parent.get(), before.get().as_deref()))
    });
    loaded(page, move |page: TenantPage| {
        let next = page.next.clone();
        if page.tenants.is_empty() {
            return view! { <p class="muted">"No tenants."</p> }.into_any();
        }
        view! {
            <table>
                <thead><tr><th>"Tenant"</th><th>"Parent"</th><th>"State"</th><th>"Facts"</th><th>"Created"</th></tr></thead>
                <tbody>
                    {page.tenants.into_iter().map(|tenant| view! {
                        <tr class:revoked=tenant.state != "active">
                            <td><A href=format!("/tenants/{}", tenant.id)><code>{tenant.id.clone()}</code></A></td>
                            <td>{tenant.parent_id.clone().map(|p| view! { <A href=format!("/tenants/{p}")><Id id=p.clone()/></A> })}</td>
                            <td>{tenant.state.clone()}</td>
                            <td><code class="compact">{tenant.facts.to_string()}</code></td>
                            <td>{timestamp(&tenant.created_at)}</td>
                        </tr>
                    }).collect_view()}
                </tbody>
            </table>
            {next.map(|next| view! {
                <button class="secondary" on:click=move |_| before.set(Some(next.clone()))>"Older"</button>
            })}
        }
        .into_any()
    })
}

#[component]
fn CreateTenant(parent: Signal<String>) -> impl IntoView {
    let console = use_console();
    let facts = RwSignal::new("{}".to_owned());
    let templates = RwSignal::new(String::new());
    let error = RwSignal::new(None);
    let navigate = use_navigate();
    let submit = move |event: SubmitEvent| {
        event.prevent_default();
        let facts = match parse_json(&facts.get_untracked(), "facts") {
            Ok(facts) => facts,
            Err(failure) => return error.set(Some(failure)),
        };
        let id = new_id();
        let navigate = navigate.clone();
        console.act(
            endpoints::create_tenant(
                &id,
                &parent.get_untracked(),
                &facts,
                &list(&templates.get_untracked()),
            ),
            error,
            move |_: Value| navigate(&format!("/tenants/{id}"), NavigateOptions::default()),
        );
    };
    view! {
        <h2>"New tenant"</h2>
        <form class="card" on:submit=submit>
            <p class="muted">"Under " <code>{parent}</code> "."</p>
            <JsonField label="Facts" value=facts rows=3/>
            <Field label="Templates to instantiate roles from" value=templates placeholder="comma-separated keys"/>
            <Problem error/>
            <button type="submit">"Create"</button>
        </form>
    }
}

#[component]
pub fn TenantPage() -> impl IntoView {
    let params = use_params_map();
    let id = Signal::derive(move || params.read().get("id").unwrap_or_default());
    view! {
        <p><A href="/tenants">"← Tenants"</A></p>
        <h1>"Tenant " <code>{id}</code></h1>
        <Gated capability=Capability::Tenants>
            <TenantDetails id/>
            <h2>"Memberships"</h2>
            <Memberships tenant=id/>
            <h2>"Child tenants"</h2>
            <TenantList parent=id/>
            <CreateTenant parent=id/>
        </Gated>
        <p><A href=move || format!("/authz?tenant={}", id.get())>"Roles of this tenant →"</A></p>
    }
}

#[component]
fn TenantDetails(id: Signal<String>) -> impl IntoView {
    let console = use_console();
    let error = RwSignal::new(None);
    let resource = LocalResource::new(move || console.call::<Tenant>(endpoints::tenant(&id.get())));
    let set_state = move |state: String| {
        let leaving = state != "active";
        if !leaving
            || confirm(&format!(
                "Make this tenant {state}? Every session targeting it ends."
            ))
        {
            console.act(
                endpoints::set_tenant_state(&id.get_untracked(), &state),
                error,
                move |_: Value| resource.refetch(),
            );
        }
    };
    view! {
        <Problem error/>
        {loaded(resource, move |tenant: Tenant| {
            let facts = RwSignal::new(pretty(&tenant.facts));
            let save = move |event: SubmitEvent| {
                event.prevent_default();
                match parse_json(&facts.get_untracked(), "facts") {
                    Ok(value) => console.act(endpoints::set_tenant_facts(&id.get_untracked(), value), error, move |_: Value| resource.refetch()),
                    Err(failure) => error.set(Some(failure)),
                }
            };
            let states = ["active", "suspended", "deleted"]
                .into_iter()
                .filter(|state| *state != tenant.state)
                .map(|state| view! {
                    <button class=if state == "active" { "small" } else { "small danger" } on:click=move |_| set_state(state.to_owned())>
                        {format!("Make {state}")}
                    </button>
                })
                .collect_view();
            view! {
                <dl class="facts">
                    <dt>"Parent"</dt>
                    <dd>{tenant.parent_id.clone().map(|p| view! { <A href=format!("/tenants/{p}")><code>{p.clone()}</code></A> })}</dd>
                    <dt>"State"</dt><dd>{tenant.state.clone()} " " {states}</dd>
                    <dt>"Created"</dt><dd>{timestamp(&tenant.created_at)}</dd>
                </dl>
                <form class="card" on:submit=save>
                    <JsonField label="Facts" value=facts/>
                    <button type="submit">"Save facts"</button>
                </form>
            }
        })}
    }
}

#[component]
fn Memberships(tenant: Signal<String>) -> impl IntoView {
    let console = use_console();
    let active = RwSignal::new(true);
    let subject = RwSignal::new(String::new());
    let facts = RwSignal::new("{}".to_owned());
    let error = RwSignal::new(None);
    let memberships = LocalResource::new(move || {
        console.call::<Vec<Membership>>(endpoints::memberships(&tenant.get(), active.get()))
    });
    let add = move |event: SubmitEvent| {
        event.prevent_default();
        let facts = match parse_json(&facts.get_untracked(), "facts") {
            Ok(facts) => facts,
            Err(failure) => return error.set(Some(failure)),
        };
        let request = endpoints::create_membership(
            &new_id(),
            &subject.get_untracked(),
            &tenant.get_untracked(),
            &facts,
        );
        console.act(request, error, move |_: Value| {
            subject.set(String::new());
            memberships.refetch();
        });
    };
    view! {
        <label class="check"><input type="checkbox" bind:checked=active/>" Only active memberships"</label>
        {loaded(memberships, |memberships: Vec<Membership>| {
            if memberships.is_empty() {
                return view! { <p class="muted">"No memberships."</p> }.into_any();
            }
            view! {
                <table>
                    <thead><tr><th>"Membership"</th><th>"Subject"</th><th>"State"</th><th>"Facts"</th><th>"Managed by"</th></tr></thead>
                    <tbody>
                        {memberships.into_iter().map(|m| view! {
                            <tr class:revoked=m.state != "active">
                                <td><A href=format!("/memberships/{}", m.id)><Id id=m.id.clone()/></A></td>
                                <td><A href=format!("/subjects/{}", m.subject_id)><Id id=m.subject_id.clone()/></A></td>
                                <td>{m.state.clone()}</td>
                                <td><code class="compact">{m.facts.to_string()}</code></td>
                                <td>{m.managed_by.clone()}</td>
                            </tr>
                        }).collect_view()}
                    </tbody>
                </table>
            }
            .into_any()
        })}
        <h3>"Add a member"</h3>
        <form class="card" on:submit=add>
            <Field label="Subject" value=subject placeholder="subject id"/>
            <JsonField label="Membership facts" value=facts rows=3/>
            <Problem error/>
            <button type="submit">"Add"</button>
        </form>
    }
}

#[component]
pub fn MembershipPage() -> impl IntoView {
    let console = use_console();
    let params = use_params_map();
    let id = Signal::derive(move || params.read().get("id").unwrap_or_default());
    let error = RwSignal::new(None);
    let resource = LocalResource::new(move || {
        console.call::<MembershipDetail>(endpoints::membership(&id.get()))
    });
    let end = move |_| {
        if confirm("End this membership? Sessions targeting it end too.") {
            console.act(
                endpoints::end_membership(&id.get_untracked()),
                error,
                move |_: Value| resource.refetch(),
            );
        }
    };
    view! {
        <h1>"Membership " <code>{id}</code></h1>
        <Gated capability=Capability::Tenants>
            <Problem error/>
            {loaded(resource, move |detail: MembershipDetail| {
                let membership = detail.membership.clone();
                let facts = RwSignal::new(pretty(&membership.facts));
                let save = move |event: SubmitEvent| {
                    event.prevent_default();
                    match parse_json(&facts.get_untracked(), "facts") {
                        Ok(value) => console.act(endpoints::set_membership_facts(&id.get_untracked(), value), error, move |_: Value| resource.refetch()),
                        Err(failure) => error.set(Some(failure)),
                    }
                };
                let tenant = membership.tenant_id.clone();
                let active = membership.state == "active";
                view! {
                    <dl class="facts">
                        <dt>"Subject"</dt><dd><A href=format!("/subjects/{}", membership.subject_id)><code>{membership.subject_id.clone()}</code></A></dd>
                        <dt>"Tenant"</dt><dd><A href=format!("/tenants/{}", membership.tenant_id)><code>{membership.tenant_id.clone()}</code></A></dd>
                        <dt>"State"</dt><dd>{membership.state.clone()}</dd>
                        <dt>"Managed by"</dt><dd>{membership.managed_by.clone().unwrap_or_else(|| "operators".to_owned())}</dd>
                        <dt>"Created"</dt><dd>{timestamp(&membership.created_at)}</dd>
                    </dl>
                    {active.then(|| view! { <button class="danger" on:click=end>"End membership"</button> })}
                    <form class="card" on:submit=save>
                        <JsonField label="Facts" value=facts/>
                        <button type="submit">"Save facts"</button>
                    </form>
                    <h2>"Role assignments"</h2>
                    <Gated capability=Capability::Authz>
                        <MembershipAssignments
                            membership=id
                            tenant=tenant.clone()
                            assignments=detail.assignments.clone()
                            reload=move || resource.refetch()
                        />
                    </Gated>
                }
            })}
        </Gated>
    }
}
