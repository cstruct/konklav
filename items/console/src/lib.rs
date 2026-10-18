//! The Konklav console: a client-side web app for operating Konklav's
//! control plane, built with Leptos and served as WASM.
//!
//! Everything but [`ui`] is plain Rust, so it's unit-tested natively.

pub mod api;
pub mod grants;
pub mod ids;
pub mod operator;
pub mod ui;
