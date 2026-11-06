//! The runnable examples in `examples/`, against this build's server binary.
//! Each starts real server processes on fresh databases.

use std::path::Path;

fn binary() -> &'static Path {
    Path::new(env!("CARGO_BIN_EXE_konklav-server"))
}

#[tokio::test(flavor = "multi_thread")]
async fn email_links_are_delivered_over_smtp() {
    konklav_examples::scenario::smtp_delivery::run(binary())
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn one_konklav_signs_people_in_to_another() {
    konklav_examples::scenario::federation::run(binary())
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_bootstrap_set_seeds_a_new_deployment() {
    konklav_examples::scenario::bootstrap::run(binary())
        .await
        .unwrap();
}

// r[verify relying.verify.dpop]
// r[verify oidc.provider.dpop.required]
#[tokio::test(flavor = "multi_thread")]
async fn a_browser_apps_tokens_work_only_with_its_dpop_key() {
    konklav_examples::scenario::dpop::run(binary())
        .await
        .unwrap();
}
