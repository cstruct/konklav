//! Embeds the login page (`items/login`, built into `items/login/dist`) when
//! the `login-page` feature is on.
//!
//! - `KONKLAV_LOGIN_PAGE_DIST` names another build directory.
//! - Without a build, a placeholder page saying how to make one is embedded
//!   instead, with a warning, so Rust-only work needs no Node.
//! - `KONKLAV_REQUIRE_LOGIN_PAGE=1` turns a missing build into an error, for
//!   release builds and the container image.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::{env, fs};

const PLACEHOLDER: &str = "<!doctype html>
<html lang=\"en\">
<head><meta charset=\"utf-8\"><title>Login page not built</title></head>
<body>
<h1>The login page wasn't built</h1>
<p>This server was compiled without the login page's files. Build them with
<code>mise run login:build</code> and compile the server again.</p>
</body>
</html>
";

fn main() {
    println!("cargo:rerun-if-env-changed=KONKLAV_LOGIN_PAGE_DIST");
    println!("cargo:rerun-if-env-changed=KONKLAV_REQUIRE_LOGIN_PAGE");
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("cargo sets OUT_DIR"));
    let target = out.join("login_page.rs");
    if env::var_os("CARGO_FEATURE_LOGIN_PAGE").is_none() {
        fs::write(
            &target,
            "pub(crate) static FILES: &[Asset] = &[];\npub(crate) const BUILT: bool = false;\n",
        )
        .expect("writing login_page.rs");
        return;
    }
    let manifest =
        PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("cargo sets CARGO_MANIFEST_DIR"));
    let dist = env::var_os("KONKLAV_LOGIN_PAGE_DIST")
        .map_or_else(|| manifest.join("../login/dist"), PathBuf::from);
    println!("cargo:rerun-if-changed={}", dist.display());

    let mut files = Vec::new();
    if dist.join("index.html").is_file() {
        collect(&dist, &dist, &mut files);
        files.sort();
    }
    let built = !files.is_empty();
    if !built {
        let required =
            env::var("KONKLAV_REQUIRE_LOGIN_PAGE").is_ok_and(|v| v == "1" || v == "true");
        assert!(
            !required,
            "KONKLAV_REQUIRE_LOGIN_PAGE is set, but the login page isn't built in {}: run `mise run login:build` first",
            dist.display()
        );
        println!(
            "cargo:warning=the login page isn't built in {}; embedding a placeholder (run `mise run login:build`)",
            dist.display()
        );
        let placeholder = out.join("login-placeholder.html");
        fs::write(&placeholder, PLACEHOLDER).expect("writing the placeholder");
        files.push(("index.html".to_owned(), placeholder));
    }

    let mut code = String::from("pub(crate) static FILES: &[Asset] = &[\n");
    for (path, file) in &files {
        writeln!(
            code,
            "    Asset {{ path: {path:?}, bytes: include_bytes!({:?}) }},",
            file.display().to_string()
        )
        .expect("writing to a String");
    }
    writeln!(code, "];\npub(crate) const BUILT: bool = {built};").expect("writing to a String");
    fs::write(&target, code).expect("writing login_page.rs");
}

/// Every file under `dir`, by its `/`-separated path relative to `root`.
fn collect(root: &Path, dir: &Path, files: &mut Vec<(String, PathBuf)>) {
    for entry in fs::read_dir(dir).expect("reading the login page's build") {
        let path = entry.expect("reading the login page's build").path();
        if path.is_dir() {
            collect(root, &path, files);
        } else {
            let relative = path.strip_prefix(root).expect("under the root");
            let name = relative
                .components()
                .map(|c| c.as_os_str().to_string_lossy().into_owned())
                .collect::<Vec<_>>()
                .join("/");
            files.push((name, path));
        }
    }
}
