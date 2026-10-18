//! The console's frame: signing in, navigation and routes.

use leptos::prelude::*;
use leptos_router::components::{A, Route, Router, Routes};
use leptos_router::path;

use super::common::{Id, Loading};
use super::console::{Console, Phase, use_console};
use super::{authz, clients, home, invites, keys, sessions, sign_in, subjects, tenants};
use crate::grants::Capability;

#[component]
pub fn App() -> impl IntoView {
    let console = Console::new();
    provide_context(console);
    console.restore();
    view! {
        <Router>
            {move || match (console.phase.get(), console.signed_in()) {
                (Phase::Restoring, _) => view! { <main class="center"><Loading/></main> }.into_any(),
                (Phase::Ready, false) => view! { <sign_in::SignIn/> }.into_any(),
                (Phase::Ready, true) => view! { <Shell/> }.into_any(),
            }}
        </Router>
    }
}

#[component]
fn Shell() -> impl IntoView {
    let console = use_console();
    let who = move || match console.subject() {
        Some(subject) => view! { "Signed in as " <Id id=subject/> }.into_any(),
        None => view! { <span class="warning">"Bootstrap token"</span> }.into_any(),
    };
    view! {
        <header class="top">
            <A href="/" attr:class="brand">"Conclave" <span>"console"</span></A>
            <span class="who">{who}</span>
            <button class="link" on:click=move |_| console.sign_out()>"Sign out"</button>
        </header>
        <div class="layout">
            <nav class="side">
                <NavLink href="/subjects" label="Subjects" capability=Capability::Subjects/>
                <NavLink href="/tenants" label="Tenants" capability=Capability::Tenants/>
                <NavLink href="/authz" label="Authorization" capability=Capability::Authz/>
                <NavLink href="/sessions" label="Sessions" capability=Capability::Sessions/>
                <NavLink href="/invites" label="Invites" capability=Capability::Invites/>
                <NavLink href="/clients" label="OIDC clients" capability=Capability::Clients/>
                <NavLink href="/keys" label="Signing keys" capability=Capability::Keys/>
            </nav>
            <main class="page">
                <Routes fallback=|| view! { <p>"There's no such page."</p> }>
                    <Route path=path!("/") view=home::Home/>
                    <Route path=path!("/subjects") view=subjects::Subjects/>
                    <Route path=path!("/subjects/:id") view=subjects::SubjectPage/>
                    <Route path=path!("/tenants") view=tenants::Tenants/>
                    <Route path=path!("/tenants/:id") view=tenants::TenantPage/>
                    <Route path=path!("/memberships/:id") view=tenants::MembershipPage/>
                    <Route path=path!("/authz") view=authz::Authorization/>
                    <Route path=path!("/sessions") view=sessions::Sessions/>
                    <Route path=path!("/invites") view=invites::Invites/>
                    <Route path=path!("/clients") view=clients::Clients/>
                    <Route path=path!("/keys") view=keys::Keys/>
                </Routes>
            </main>
        </div>
    }
}

/// A navigation link that marks areas the operator can't use.
#[component]
fn NavLink(href: &'static str, label: &'static str, capability: Capability) -> impl IntoView {
    let console = use_console();
    view! {
        <A href=href>
            {label}
            {move || {
                (!console.allows(capability))
                    .then(|| view! { <span class="lock" title=format!("Needs {}", capability.action())>"no access"</span> })
            }}
        </A>
    }
}
