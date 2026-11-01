//! Runnable examples of Konklav deployments. Each scenario starts real
//! `konklav-server` processes on fresh databases and drives them over HTTP,
//! the way an app or operator would. They run as binaries for people to
//! read and try, and as tests (`items/server/tests/examples.rs`).

pub mod conformance;
pub mod delivery;
pub mod harness;
pub mod scenario;
pub mod smtp_sink;

/// Errors are reported, not handled: an example stops at the first one.
pub type Error = Box<dyn std::error::Error + Send + Sync>;
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// An error with `message`.
pub fn fail(message: impl Into<String>) -> Error {
    message.into().into()
}

/// Fails with `message` unless `condition` holds.
pub fn check(condition: bool, message: impl FnOnce() -> String) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(fail(message()))
    }
}

/// Prints a step of a scenario.
pub fn step(text: &str) {
    println!("==> {text}");
}
