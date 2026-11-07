//! The crate's packaging.

/// The value of `key = ...` on the line of `entry` in `manifest`.
fn line<'a>(manifest: &'a str, entry: &str) -> &'a str {
    manifest
        .lines()
        .find(|line| line.starts_with(entry))
        .unwrap_or_else(|| panic!("no `{entry}`"))
}

// r[verify item.axum.published]
#[test]
fn is_published_requiring_the_relying_crates_at_its_own_version() {
    let own = include_str!("../Cargo.toml");
    assert!(own.lines().any(|line| line == "publish = true"));
    assert!(own.lines().any(|line| line == "version.workspace = true"));
    assert!(
        own.lines()
            .any(|line| line == "konklav-relying.workspace = true")
    );
    assert!(
        own.lines()
            .any(|line| line == "konklav-relying-client.workspace = true")
    );

    let workspace = include_str!("../../../Cargo.toml");
    let version = env!("CARGO_PKG_VERSION");
    let exactly = format!(r#"version = "={version}""#);
    for crate_name in ["konklav-axum", "konklav-relying", "konklav-relying-client"] {
        let entry = line(workspace, &format!("{crate_name} = "));
        assert!(entry.contains(&exactly), "{entry} must require ={version}");
    }
}
