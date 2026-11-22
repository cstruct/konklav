//! Checks the page and Trunk configuration the console is built from.

const PAGE: &str = include_str!("../index.html");
const TRUNK: &str = include_str!("../Trunk.toml");

/// The `content` of the page's Content-Security-Policy meta tag.
fn policy() -> &'static str {
    let tag = r#"<meta http-equiv="Content-Security-Policy" content=""#;
    let start = PAGE.find(tag).expect("the page declares a policy") + tag.len();
    let end = PAGE[start..].find('"').expect("the policy is quoted");
    &PAGE[start..start + end]
}

// r[verify item.console.content-security-policy]
#[test]
fn the_page_allows_only_its_own_origin() {
    let directives: Vec<&str> = policy().split(';').map(str::trim).collect();
    assert_eq!(
        directives,
        [
            "default-src 'none'",
            "script-src 'self' 'wasm-unsafe-eval'",
            "style-src 'self'",
            "img-src 'self'",
            "connect-src 'self'",
            "base-uri 'none'",
            "form-action 'none'",
        ]
    );
    // The policy comes before anything the page loads.
    let policy_at = PAGE.find("Content-Security-Policy\" content").unwrap();
    assert!(policy_at < PAGE.find("<link").unwrap());
    assert!(policy_at < PAGE.find("<script").unwrap());
}

// r[verify item.console.content-security-policy]
#[test]
fn nothing_in_the_page_is_inline() {
    // Every script has a `src` and no body, and nothing is styled inline.
    for (at, _) in PAGE.match_indices("<script") {
        let tag_end = at + PAGE[at..].find('>').unwrap();
        assert!(PAGE[at..tag_end].contains(" src="), "inline script");
        assert!(PAGE[tag_end + 1..].starts_with("</script>"), "script body");
    }
    assert!(!PAGE.contains("<style") && !PAGE.contains(" style="));
    // Trunk writes an element naming the bundle, not its inline loader,
    // and `trunk serve` adds no inline reload script.
    let pattern = TRUNK
        .lines()
        .find(|line| line.starts_with("pattern_script"))
        .expect("Trunk.toml replaces the loader");
    assert!(!pattern.contains("<script"));
    assert!(TRUNK.lines().any(|line| line == "no_autoreload = true"));
}
