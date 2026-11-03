//! Rebuilds the crate when a migration changes, since `embed_migrations!`
//! compiles them in and cargo doesn't otherwise notice a new one.

fn main() {
    println!("cargo:rerun-if-changed=migrations");
}
