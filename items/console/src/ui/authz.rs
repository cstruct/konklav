//! The catalog, templates, roles, role assignments, and entitlement
//! explanations.

use leptos::ev::SubmitEvent;
use leptos::prelude::*;
use leptos_router::hooks::use_query_map;
use serde_json::{Value, json};

use super::common::{
    Field, Gated, Id, JsonField, Problem, confirm, loaded, parse_json, pretty, timestamp,
};
use super::console::use_console;
use crate::api::endpoints;
use crate::api::types::{Assignment, Entitlements, Explanation, Role, Template};
use crate::grants::Capability;

#[component]
pub fn Authorization() -> impl IntoView {
    let query = use_query_map();
    let tenant = RwSignal::new(
        query
            .read_untracked()
            .get("tenant")
            .unwrap_or_else(|| "root".to_owned()),
    );
    let subject = RwSignal::new(String::new());
    view! {
        <h1>"Authorization"</h1>
        <Gated capability=Capability::Authz>
            <h2>"Roles"</h2>
            <Roles tenant/>
            <h2>"Templates"</h2>
            <Templates/>
            <h2>"Catalog"</h2>
            <Catalog/>
            <h2>"Explain a subject's entitlements"</h2>
            <Field label="Subject" value=subject placeholder="subject id"/>
            {move || (!subject.get().trim().is_empty()).then(|| view! {
                <Explain subject=Signal::derive(move || subject.get().trim().to_owned())/>
            })}
        </Gated>
    }
}

#[component]
fn Catalog() -> impl IntoView {
    let console = use_console();
    let error = RwSignal::new(None);
    let saved = RwSignal::new(false);
    let catalog = LocalResource::new(move || console.call::<Value>(endpoints::catalog()));
    loaded(catalog, move |document: Value| {
        let text = RwSignal::new(pretty(&document));
        let save = move |event: SubmitEvent| {
            event.prevent_default();
            saved.set(false);
            match parse_json(&text.get_untracked(), "catalog") {
                Ok(document)
                    if confirm("Replace the whole catalog? Removed names stop being granted.") =>
                {
                    console.act(endpoints::put_catalog(document), error, move |_: Value| {
                        saved.set(true);
                        catalog.refetch();
                    });
                }
                Ok(_) => {}
                Err(failure) => error.set(Some(failure)),
            }
        };
        view! {
            <form class="card" on:submit=save>
                <p class="muted">
                    "Actions, groups, scope kinds, fact keys and session flags, replaced as one document. "
                    "The " <code>"konklav:"</code> " capabilities are built in and can't be declared."
                </p>
                <JsonField label="Catalog document" value=text rows=16/>
                <Problem error/>
                {move || saved.get().then(|| view! { <p class="notice">"Saved."</p> })}
                <button type="submit">"Save catalog"</button>
            </form>
        }
    })
}

const TEMPLATE_EXAMPLE: &str = r#"{
  "description": "",
  "metadata": {},
  "policies": [{"action": "workspace:read", "effect": "allow", "scope_bound": false}]
}"#;

#[component]
fn Templates() -> impl IntoView {
    let console = use_console();
    let error = RwSignal::new(None);
    let key = RwSignal::new(String::new());
    let body = RwSignal::new(TEMPLATE_EXAMPLE.to_owned());
    let templates =
        LocalResource::new(move || console.call::<Vec<Template>>(endpoints::templates()));
    let save = move |event: SubmitEvent| {
        event.prevent_default();
        match parse_json(&body.get_untracked(), "template") {
            Ok(value) => console.act(
                endpoints::put_template(key.get_untracked().trim(), value),
                error,
                move |_: Value| templates.refetch(),
            ),
            Err(failure) => error.set(Some(failure)),
        }
    };
    view! {
        {loaded(templates, move |templates: Vec<Template>| {
            if templates.is_empty() {
                return view! { <p class="muted">"No templates."</p> }.into_any();
            }
            view! {
                <table>
                    <thead><tr><th>"Template"</th><th>"Description"</th><th>"Policies"</th><th>"Updated"</th><th></th></tr></thead>
                    <tbody>
                        {templates.into_iter().map(|template| {
                            let edit_key = template.key.clone();
                            let edit_body = pretty(&json!({
                                "description": template.description,
                                "metadata": template.metadata,
                                "policies": template.policies,
                            }));
                            view! {
                                <tr>
                                    <td><code>{template.key.clone()}</code></td>
                                    <td>{template.description.clone()}</td>
                                    <td>{policy_summary(&template.policies)}</td>
                                    <td>{timestamp(&template.updated_at)}</td>
                                    <td><button class="small secondary" on:click=move |_| {
                                        key.set(edit_key.clone());
                                        body.set(edit_body.clone());
                                    }>"Edit"</button></td>
                                </tr>
                            }
                        }).collect_view()}
                    </tbody>
                </table>
            }
            .into_any()
        })}
        <form class="card" on:submit=save>
            <p class="muted">"Saving a key that exists replaces that template."</p>
            <Field label="Key" value=key placeholder="clinician"/>
            <JsonField label="Template" value=body rows=8/>
            <Problem error/>
            <button type="submit">"Save template"</button>
        </form>
    }
}

const ROLE_EXAMPLE: &str = r#"{
  "template": null,
  "priority": 0,
  "metadata": {},
  "policies": [{"action": "workspace:read", "effect": "allow", "scope_bound": false}]
}"#;

/// `action (effect)` for each policy.
fn policy_summary(policies: &Value) -> String {
    policies
        .as_array()
        .map(|policies| {
            policies
                .iter()
                .map(|policy| {
                    let action = policy["action"].as_str().unwrap_or("?");
                    match policy["effect"].as_str() {
                        Some("deny") => format!("deny {action}"),
                        _ => action.to_owned(),
                    }
                })
                .collect::<Vec<_>>()
                .join(", ")
        })
        .unwrap_or_default()
}

#[component]
fn Roles(tenant: RwSignal<String>) -> impl IntoView {
    let console = use_console();
    let error = RwSignal::new(None);
    let shown = RwSignal::new(tenant.get_untracked());
    let key = RwSignal::new(String::new());
    let body = RwSignal::new(ROLE_EXAMPLE.to_owned());
    let roles =
        LocalResource::new(move || console.call::<Vec<Role>>(endpoints::roles(&shown.get())));
    let show = move |event: SubmitEvent| {
        event.prevent_default();
        shown.set(tenant.get_untracked().trim().to_owned());
    };
    let save = move |event: SubmitEvent| {
        event.prevent_default();
        match parse_json(&body.get_untracked(), "role") {
            Ok(value) => console.act(
                endpoints::put_role(&shown.get_untracked(), key.get_untracked().trim(), value),
                error,
                move |_: Value| roles.refetch(),
            ),
            Err(failure) => error.set(Some(failure)),
        }
    };
    let delete = move |role: String| {
        if confirm(&format!("Delete role {role}? Its assignments go with it.")) {
            console.act(
                endpoints::delete_role(&shown.get_untracked(), &role),
                error,
                move |_: Value| roles.refetch(),
            );
        }
    };
    view! {
        <form class="filters" on:submit=show>
            <Field label="Tenant" value=tenant placeholder="UUID or root"/>
            <button type="submit">"Show roles"</button>
        </form>
        {move || (shown.get() == "root").then(|| view! {
            <p class="muted">"Roles of the root tenant are global roles; they're assigned to subjects directly, and only they can grant " <code>"konklav:"</code> " capabilities. Roles whose keys start with " <code>"konklav."</code> " are built in: Konklav defines them, and they can be assigned but not changed."</p>
        })}
        {loaded(roles, move |roles: Vec<Role>| {
            if roles.is_empty() {
                return view! { <p class="muted">"No roles in this tenant."</p> }.into_any();
            }
            view! {
                <table>
                    <thead><tr><th>"Role"</th><th>"Template"</th><th>"Priority"</th><th>"Policies"</th><th>"Updated"</th><th></th></tr></thead>
                    <tbody>
                        {roles.into_iter().map(|role| {
                            let edit_key = role.key.clone();
                            let delete_key = role.key.clone();
                            let edit_body = pretty(&json!({
                                "template": role.template,
                                "priority": role.priority,
                                "metadata": role.metadata,
                                "policies": role.policies,
                            }));
                            view! {
                                <tr>
                                    <td><code>{role.key.clone()}</code></td>
                                    <td>{role.template.clone()}</td>
                                    <td>{role.priority}</td>
                                    <td>{policy_summary(&role.policies)}</td>
                                    <td>{timestamp(&role.updated_at)}</td>
                                    <td class="actions">
                                        {if role.builtin {
                                            view! { <span class="muted">"built in"</span> }.into_any()
                                        } else {
                                            view! {
                                                <button class="small secondary" on:click=move |_| {
                                                    key.set(edit_key.clone());
                                                    body.set(edit_body.clone());
                                                }>"Edit"</button>
                                                <button class="small danger" on:click=move |_| delete(delete_key.clone())>"Delete"</button>
                                            }
                                            .into_any()
                                        }}
                                    </td>
                                </tr>
                            }
                        }).collect_view()}
                    </tbody>
                </table>
            }
            .into_any()
        })}
        <form class="card" on:submit=save>
            <p class="muted">"In tenant " <code>{shown}</code> ". Saving a key that exists replaces that role; its own policies override its template's, action by action."</p>
            <Field label="Key" value=key placeholder="editor"/>
            <JsonField label="Role" value=body rows=8/>
            <Problem error/>
            <button type="submit">"Save role"</button>
        </form>
    }
}

/// Where an assignment applies: everywhere for global ones, otherwise
/// tenant-wide or at its scope.
fn scope_label(assignment: &Assignment) -> String {
    match &assignment.scope {
        _ if assignment.target.kind == "subject" => "global".to_owned(),
        Some(scope) => format!("{}/{}", scope.kind, scope.id),
        None => "tenant-wide".to_owned(),
    }
}

/// Role keys by role id, to name assignments.
fn role_key(roles: &[Role], id: &str) -> String {
    roles
        .iter()
        .find(|role| role.id == id)
        .map_or_else(|| id.to_owned(), |role| role.key.clone())
}

/// A subject's global role assignments.
#[component]
pub fn GlobalAssignments(subject: Signal<String>) -> impl IntoView {
    let console = use_console();
    let error = RwSignal::new(None);
    let role = RwSignal::new(String::new());
    let data = LocalResource::new(move || async move {
        let assignments = console
            .call::<Vec<Assignment>>(endpoints::global_assignments(&subject.get()))
            .await?;
        let roles = console.call::<Vec<Role>>(endpoints::roles("root")).await?;
        Ok((assignments, roles))
    });
    let assign = move |event: SubmitEvent| {
        event.prevent_default();
        console.act(
            endpoints::assign_global_role(&subject.get_untracked(), &role.get_untracked()),
            error,
            move |_: Value| {
                role.set(String::new());
                data.refetch();
            },
        );
    };
    let unassign = move |id: String| {
        if confirm(
            "Remove this global role assignment? One managed by an identity provider comes back at the subject's next login through it.",
        ) {
            console.act(endpoints::unassign(&id), error, move |_: Value| {
                data.refetch();
            });
        }
    };
    view! {
        <Problem error/>
        {loaded(data, move |(assignments, roles): (Vec<Assignment>, Vec<Role>)| {
            let options = roles.iter().map(|r| view! { <option value=r.key.clone()>{r.key.clone()}</option> }).collect_view();
            view! {
                <AssignmentTable assignments roles unassign/>
                <form class="card row" on:submit=assign>
                    <label class="field">
                        <span>"Global role"</span>
                        <select prop:value=move || role.get() on:change=move |ev| role.set(event_target_value(&ev))>
                            <option value="">"choose…"</option>
                            {options}
                        </select>
                    </label>
                    <button type="submit">"Assign"</button>
                </form>
            }
        })}
    }
}

/// A membership's role assignments, in its tenant.
#[component]
pub fn MembershipAssignments(
    membership: Signal<String>,
    tenant: String,
    assignments: Vec<Assignment>,
    reload: impl Fn() + Copy + Send + Sync + 'static,
) -> impl IntoView {
    let console = use_console();
    let error = RwSignal::new(None);
    let role = RwSignal::new(String::new());
    let scope_kind = RwSignal::new(String::new());
    let scope_id = RwSignal::new(String::new());
    let tenant = StoredValue::new(tenant);
    let roles = LocalResource::new(move || {
        console.call::<Vec<Role>>(endpoints::roles(&tenant.get_value()))
    });
    let assignments = StoredValue::new(assignments);
    let assign = move |event: SubmitEvent| {
        event.prevent_default();
        let request = endpoints::assign_membership_role(
            &membership.get_untracked(),
            &role.get_untracked(),
            &scope_kind.get_untracked(),
            &scope_id.get_untracked(),
        );
        console.act(request, error, move |_: Value| reload());
    };
    let unassign = move |id: String| {
        if confirm("Remove this role assignment?") {
            console.act(endpoints::unassign(&id), error, move |_: Value| reload());
        }
    };
    view! {
        <Problem error/>
        {loaded(roles, move |roles: Vec<Role>| {
            let options = roles.iter().map(|r| view! { <option value=r.key.clone()>{r.key.clone()}</option> }).collect_view();
            view! {
                <AssignmentTable assignments=assignments.get_value() roles unassign/>
                <form class="card row" on:submit=assign>
                    <label class="field">
                        <span>"Role"</span>
                        <select prop:value=move || role.get() on:change=move |ev| role.set(event_target_value(&ev))>
                            <option value="">"choose…"</option>
                            {options}
                        </select>
                    </label>
                    <Field label="Scope kind" value=scope_kind placeholder="tenant-wide if blank"/>
                    <Field label="Scope id" value=scope_id/>
                    <button type="submit">"Assign"</button>
                </form>
            }
        })}
    }
}

#[component]
fn AssignmentTable(
    assignments: Vec<Assignment>,
    roles: Vec<Role>,
    unassign: impl Fn(String) + Copy + Send + Sync + 'static,
) -> impl IntoView {
    if assignments.is_empty() {
        return view! { <p class="muted">"No assignments."</p> }.into_any();
    }
    view! {
        <table>
            <thead><tr><th>"Role"</th><th>"Scope"</th><th>"Managed by"</th><th>"Assigned"</th><th></th></tr></thead>
            <tbody>
                {assignments.into_iter().map(|assignment| {
                    let id = assignment.id.clone();
                    view! {
                        <tr>
                            <td><code>{role_key(&roles, &assignment.role_id)}</code></td>
                            <td>{scope_label(&assignment)}</td>
                            <td>{assignment.managed_by.clone()}</td>
                            <td>{timestamp(&assignment.created_at)}</td>
                            <td><button class="small danger" on:click=move |_| unassign(id.clone())>"Remove"</button></td>
                        </tr>
                    }
                }).collect_view()}
            </tbody>
        </table>
    }
    .into_any()
}

/// A subject's compiled entitlements in a tenant, and why it has (or
/// lacks) an action.
#[component]
pub fn Explain(subject: Signal<String>) -> impl IntoView {
    let console = use_console();
    let tenant = RwSignal::new(String::new());
    let action = RwSignal::new(String::new());
    let shown = RwSignal::new(None::<String>);
    let asked = RwSignal::new(None::<(String, String)>);
    let entitlements = LocalResource::new(move || {
        let tenant = shown.get().unwrap_or_default();
        console.call::<Entitlements>(endpoints::entitlements(&subject.get(), &tenant))
    });
    let explanation = LocalResource::new(move || async move {
        match asked.get() {
            Some((tenant, action)) => console
                .call::<Explanation>(endpoints::explain(&subject.get(), &tenant, &action))
                .await
                .map(Some),
            None => Ok(None),
        }
    });
    let show = move |event: SubmitEvent| {
        event.prevent_default();
        shown.set(Some(tenant.get_untracked()));
    };
    let explain = move |event: SubmitEvent| {
        event.prevent_default();
        asked.set(Some((
            tenant.get_untracked(),
            action.get_untracked().trim().to_owned(),
        )));
    };
    view! {
        <form class="filters" on:submit=show>
            <Field label="Tenant" value=tenant placeholder="global only if blank"/>
            <button type="submit">"Show entitlements"</button>
        </form>
        {loaded(entitlements, |entitlements: Entitlements| view! { <EntitlementView entitlements/> })}
        <form class="filters" on:submit=explain>
            <Field label="Action" value=action placeholder="workspace:read"/>
            <button type="submit">"Explain"</button>
        </form>
        {loaded(explanation, |explanation: Option<Explanation>| explanation.map(|explanation| view! { <ExplanationView explanation/> }))}
    }
}

#[component]
fn EntitlementView(entitlements: Entitlements) -> impl IntoView {
    let chips = |actions: Vec<String>| {
        if actions.is_empty() {
            view! { <span class="muted">"none"</span> }.into_any()
        } else {
            actions
                .into_iter()
                .map(|a| view! { <code class="chip">{a}</code> })
                .collect_view()
                .into_any()
        }
    };
    view! {
        <dl class="facts">
            <dt>"Global"</dt><dd>{chips(entitlements.global)}</dd>
            <dt>"Tenant-wide"</dt><dd>{chips(entitlements.tenant)}</dd>
            {entitlements.scoped.into_iter().map(|scoped| view! {
                <dt>{format!("{}/", scoped.kind)}<Id id=scoped.id.clone()/></dt>
                <dd>{chips(scoped.actions)}</dd>
            }).collect_view()}
        </dl>
    }
}

#[component]
fn ExplanationView(explanation: Explanation) -> impl IntoView {
    let granted = if explanation.granted_at.is_empty() {
        format!("{} is not granted anywhere.", explanation.action)
    } else {
        format!(
            "{} is granted at: {}.",
            explanation.action,
            explanation.granted_at.join(", ")
        )
    };
    view! {
        <p class="notice">{granted}</p>
        {(!explanation.contributions.is_empty()).then(|| view! {
            <table>
                <thead><tr><th>"Assignment"</th><th>"Level"</th><th>"Policy"</th><th>"Effect"</th><th>"Priority"</th><th>"From template"</th></tr></thead>
                <tbody>
                    {explanation.contributions.into_iter().map(|c| view! {
                        <tr class:revoked=c.effect == "deny">
                            <td><Id id=c.assignment.clone()/></td>
                            <td>{c.level.clone()}</td>
                            <td><code>{c.policy.clone()}</code></td>
                            <td>{c.effect.clone()}</td>
                            <td>{c.priority}</td>
                            <td>{if c.from_template { "yes" } else { "no" }}</td>
                        </tr>
                    }).collect_view()}
                </tbody>
            </table>
        })}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policies_summarise_as_actions_with_denies_marked() {
        let policies = json!([
            {"action": "workspace:read", "effect": "allow"},
            {"action": "workspace:delete", "effect": "deny"},
        ]);
        assert_eq!(
            policy_summary(&policies),
            "workspace:read, deny workspace:delete"
        );
        assert_eq!(policy_summary(&json!(null)), "");
    }

    #[test]
    fn global_assignments_apply_everywhere() {
        let mut assignment: Assignment = serde_json::from_value(json!({
            "id": "a1", "role_id": "r1", "target": {"type": "subject", "id": "s1"},
            "scope": null, "managed_by": null, "created_at": "2026-10-18T00:00:00Z",
        }))
        .unwrap();
        assert_eq!(scope_label(&assignment), "global");
        assignment.target.kind = "membership".into();
        assert_eq!(scope_label(&assignment), "tenant-wide");
        assignment.scope = Some(crate::api::types::Scope {
            kind: "workspace".into(),
            id: "w1".into(),
        });
        assert_eq!(scope_label(&assignment), "workspace/w1");
    }

    #[test]
    fn examples_are_valid_json() {
        for example in [ROLE_EXAMPLE, TEMPLATE_EXAMPLE] {
            assert!(serde_json::from_str::<Value>(example).is_ok());
        }
    }
}
