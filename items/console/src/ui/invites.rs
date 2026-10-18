//! Inviting people by email.

use leptos::ev::SubmitEvent;
use leptos::prelude::*;

use super::common::{Field, Gated, Problem, invalid_input, timestamp};
use super::console::use_console;
use crate::api::endpoints::{self, list};
use crate::api::types::CreatedInvite;
use crate::grants::Capability;

#[component]
pub fn Invites() -> impl IntoView {
    let console = use_console();
    let email = RwSignal::new(String::new());
    let tenant = RwSignal::new(String::new());
    let roles = RwSignal::new(String::new());
    let hours = RwSignal::new("72".to_owned());
    let error = RwSignal::new(None);
    let created = RwSignal::new(None::<CreatedInvite>);
    let submit = move |event: SubmitEvent| {
        event.prevent_default();
        let Ok(hours) = hours.get_untracked().trim().parse::<i64>() else {
            return error.set(Some(invalid_input("Hours must be a whole number")));
        };
        let request = endpoints::create_invite(
            &email.get_untracked(),
            &tenant.get_untracked(),
            &list(&roles.get_untracked()),
            hours,
        );
        console.act(request, error, move |invite: CreatedInvite| {
            email.set(String::new());
            created.set(Some(invite));
        });
    };
    view! {
        <h1>"Invites"</h1>
        <Gated capability=Capability::Invites>
            <p class="muted">
                "Konklav doesn't send email: the invite token goes out as a delivery request on the change feed, "
                "for a relying system to deliver."
            </p>
            <form class="card" on:submit=submit>
                <Field label="Email address" value=email kind="email"/>
                <div class="row">
                    <Field label="Tenant to join" value=tenant placeholder="none; a UUID or root"/>
                    <Field label="Roles in that tenant" value=roles placeholder="comma-separated keys"/>
                    <Field label="Valid for (hours)" value=hours/>
                </div>
                <Problem error/>
                {move || created.get().map(|invite| view! {
                    <p class="notice">
                        "Invite " <code>{invite.invite_id}</code> " requested; it expires " {timestamp(&invite.expires_at)} "."
                    </p>
                })}
                <button type="submit">"Invite"</button>
            </form>
        </Gated>
    }
}
