//! The overview: what the operator may and may not do.

use leptos::prelude::*;

use super::console::use_console;
use crate::grants::{CONTROL_ALL, Capability};

#[component]
pub fn Home() -> impl IntoView {
    let console = use_console();
    let grants = move || console.grants();
    let held = move || {
        let grants = grants();
        let listed: Vec<String> = grants.listed().map(str::to_owned).collect();
        if grants.is_bootstrap() {
            view! {
                <div class="notice warning">
                    "You're using the bootstrap token, which the control plane accepts for everything. "
                    "Create an operator subject with a password, give it a global role granting "
                    <code>{CONTROL_ALL}</code>
                    ", sign in as that operator, and then remove the token from the secrets file."
                </div>
            }
            .into_any()
        } else if listed.is_empty() {
            view! { <p>"You hold no control-plane capabilities."</p> }.into_any()
        } else {
            view! {
                <p>"You hold: " {listed.into_iter().map(|c| view! { <code class="chip">{c}</code> }).collect_view()}</p>
            }
            .into_any()
        }
    };
    let areas = move || {
        let grants = grants();
        Capability::ALL
            .iter()
            .map(|capability| {
                let allowed = grants.allows(*capability);
                view! {
                    <tr class:denied=!allowed>
                        <td>{capability.describes()}</td>
                        <td><code>{capability.action()}</code></td>
                        <td>{if allowed { "yes" } else { "no" }}</td>
                    </tr>
                }
            })
            .collect_view()
    };
    view! {
        <h1>"Overview"</h1>
        {held}
        <table>
            <thead><tr><th>"Area"</th><th>"Capability"</th><th>"Available"</th></tr></thead>
            <tbody>{areas}</tbody>
        </table>
    }
}
