//! The Leptos user interface.

#![allow(
    clippy::must_use_candidate,
    clippy::needless_pass_by_value,
    reason = "Leptos components take their props by value and return views"
)]

mod app;
mod authz;
mod clients;
pub mod common;
mod console;
mod home;
mod invites;
mod keys;
mod passkeys;
mod sessions;
mod sign_in;
mod subjects;
mod tenants;

/// Mounts the console on the page's `<body>`.
pub fn mount() {
    leptos::mount::mount_to_body(app::App);
}
