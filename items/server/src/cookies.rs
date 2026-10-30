//! The cookies Konklav sets, all through [`Cookie`].
//!
//! With secure cookies, every name carries the `__Host-` prefix. Browsers
//! then accept the cookie only from this exact host over HTTPS, with
//! `Path=/` and no `Domain`, so neither a sibling subdomain nor a plain-HTTP
//! response can set or replace one. Without secure cookies (local
//! development over HTTP) browsers refuse prefixed names, so the bare name
//! is used.

use axum::http::{HeaderMap, HeaderValue, header};

use crate::BrowserSettings;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SameSite {
    Strict,
    /// For cookies a cross-site navigation must bring back, such as the
    /// return from an identity provider.
    Lax,
}

/// A cookie Konklav sets: its unprefixed name and `SameSite` policy.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Cookie {
    pub(crate) name: &'static str,
    pub(crate) same_site: SameSite,
}

impl Cookie {
    /// The name browsers see.
    fn full_name(self, secure: bool) -> String {
        if secure {
            format!("__Host-{}", self.name)
        } else {
            self.name.to_owned()
        }
    }

    /// A `Set-Cookie` value; an empty `value` with `max_age` 0 clears it.
    // r[impl session.browser.cookie]
    pub(crate) fn set(self, secure: bool, value: &str, max_age: i64) -> HeaderValue {
        let same_site = match self.same_site {
            SameSite::Strict => "Strict",
            SameSite::Lax => "Lax",
        };
        let secure_attribute = if secure { "; Secure" } else { "" };
        HeaderValue::from_str(&format!(
            "{}={value}; Path=/; Max-Age={max_age}; HttpOnly; SameSite={same_site}{secure_attribute}",
            self.full_name(secure)
        ))
        .expect("cookie header is ASCII")
    }

    /// [`Self::set`] with the browser settings' `secure_cookies`.
    pub(crate) fn set_for(
        self,
        browser: &BrowserSettings,
        value: &str,
        max_age: i64,
    ) -> HeaderValue {
        self.set(browser.secure_cookies, value, max_age)
    }

    /// The cookie's value in a request, under the name `secure` gives it.
    pub(crate) fn read(self, headers: &HeaderMap, secure: bool) -> Option<String> {
        let name = self.full_name(secure);
        headers
            .get_all(header::COOKIE)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .flat_map(|value| value.split(';'))
            .find_map(|pair| {
                let (key, value) = pair.trim().split_once('=')?;
                (key == name).then(|| value.to_owned())
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const COOKIE: Cookie = Cookie {
        name: "konklav_test",
        same_site: SameSite::Strict,
    };

    #[test]
    fn secure_cookies_are_host_only() {
        let set = COOKIE.set(true, "v", 60);
        assert_eq!(
            set.to_str().unwrap(),
            "__Host-konklav_test=v; Path=/; Max-Age=60; HttpOnly; SameSite=Strict; Secure"
        );
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            "a=b; __Host-konklav_test=v".parse().unwrap(),
        );
        assert_eq!(COOKIE.read(&headers, true).as_deref(), Some("v"));
        assert_eq!(
            COOKIE.read(&headers, false),
            None,
            "the bare name is another cookie"
        );
    }

    #[test]
    fn insecure_cookies_keep_the_bare_name() {
        let set = COOKIE.set(false, "v", 60);
        assert!(set.to_str().unwrap().starts_with("konklav_test=v; Path=/;"));
        assert!(!set.to_str().unwrap().contains("Secure"));
    }
}
