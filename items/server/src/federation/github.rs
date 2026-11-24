//! GitHub and GitHub Enterprise as identity providers.
//!
//! GitHub signs people in with plain OAuth 2.0: no discovery document, no
//! ID token. The authorization request and its single-use state are the
//! same as for an OpenID provider; after the code exchange, who signed in
//! comes from GitHub's REST API, called with the person's token, and is
//! turned into the claims an ID token would have carried.

use reqwest::header;
use serde::Deserialize;
use serde::de::DeserializeOwned;

use super::{FederationError, IdClaims, LoginRequest, Settings, answer};

/// Scopes asked for when the provider configures none: the profile and
/// the email addresses.
const DEFAULT_SCOPES: &str = "read:user user:email";
/// The REST API version Konklav is written against.
const API_VERSION: &str = "2022-11-28";
/// Pages of organizations or teams read, of [`PER_PAGE`] each.
const MAX_PAGES: usize = 10;
const PER_PAGE: usize = 100;

/// Where a GitHub's endpoints are.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GitHub {
    authorize: String,
    token: String,
    api: String,
}

impl GitHub {
    /// The endpoints of the GitHub at `issuer`, its web address:
    /// `https://github.com`, a GitHub Enterprise Cloud address under
    /// `ghe.com`, or a GitHub Enterprise Server's.
    ///
    /// # Errors
    ///
    /// When `issuer` isn't an http(s) URL.
    pub fn new(issuer: &str) -> Result<Self, String> {
        let url = reqwest::Url::parse(issuer)
            .map_err(|error| format!("`{issuer}` is not a URL: {error}"))?;
        let host = url
            .host_str()
            .filter(|_| matches!(url.scheme(), "http" | "https"))
            .ok_or_else(|| format!("`{issuer}` is not an http(s) URL"))?
            .to_ascii_lowercase();
        let base = issuer.trim_end_matches('/');
        let api = if host == "github.com" {
            "https://api.github.com".to_owned()
        } else if host.ends_with(".ghe.com") {
            format!("{}://api.{host}", url.scheme())
        } else {
            format!("{base}/api/v3")
        };
        Ok(Self {
            authorize: format!("{base}/login/oauth/authorize"),
            token: format!("{base}/login/oauth/access_token"),
            api,
        })
    }

    /// The REST API's root, without a trailing slash.
    #[must_use]
    pub fn api(&self) -> &str {
        &self.api
    }

    // r[impl federation.github]
    pub(super) fn authorization_url(
        &self,
        settings: &Settings,
        state: &str,
        challenge: &str,
    ) -> Result<String, FederationError> {
        let params = [
            ("response_type", "code"),
            ("client_id", &settings.client_id),
            ("redirect_uri", &settings.redirect_uri),
            ("scope", &scopes(settings)),
            ("state", state),
            ("code_challenge", challenge),
            ("code_challenge_method", "S256"),
        ];
        reqwest::Url::parse_with_params(&self.authorize, &params)
            .map(String::from)
            .map_err(|error| FederationError::Provider(error.to_string()))
    }

    /// Exchanges the code for the person's token and describes them with
    /// it. The token is used for this only, and kept nowhere.
    pub(super) async fn sign_in(
        &self,
        http: &reqwest::Client,
        settings: &Settings,
        code: &str,
        request: &LoginRequest,
    ) -> Result<IdClaims, FederationError> {
        let token = self.exchange(http, settings, code, request).await?;
        let user: User = self.get(http, &token, "/user").await?;
        let scopes = scopes(settings);
        let granted = |scope: &str| scopes.split(' ').any(|s| s == scope);
        let emails = if granted("user:email") || granted("user") {
            Some(self.get::<Vec<Email>>(http, &token, "/user/emails").await?)
        } else {
            None
        };
        let groups = if granted("read:org") || granted("admin:org") {
            let orgs: Vec<Org> = self.pages(http, &token, "/user/orgs").await?;
            let teams: Vec<Team> = self.pages(http, &token, "/user/teams").await?;
            Some(group_names(&orgs, &teams))
        } else {
            None
        };
        Ok(claims(&user, emails.as_deref(), groups))
    }

    async fn exchange(
        &self,
        http: &reqwest::Client,
        settings: &Settings,
        code: &str,
        request: &LoginRequest,
    ) -> Result<String, FederationError> {
        let request = http
            .post(&self.token)
            .header(header::ACCEPT, "application/json")
            .form(&[
                ("client_id", settings.client_id.as_str()),
                ("client_secret", settings.client_secret.as_str()),
                ("code", code),
                ("redirect_uri", settings.redirect_uri.as_str()),
                ("code_verifier", request.code_verifier.as_str()),
            ]);
        let answered: TokenAnswer =
            answer(crate::telemetry::http::send(request, "idp_token").await).await?;
        // GitHub answers a refused exchange with 200 and an `error`.
        match answered {
            TokenAnswer {
                error: Some(error), ..
            } => Err(FederationError::Provider(format!(
                "the token endpoint refused the code: {error}"
            ))),
            TokenAnswer {
                access_token: Some(token),
                ..
            } => Ok(token),
            TokenAnswer { .. } => Err(FederationError::Provider(
                "the token endpoint returned no access token".into(),
            )),
        }
    }

    async fn get<T: DeserializeOwned>(
        &self,
        http: &reqwest::Client,
        token: &str,
        path: &str,
    ) -> Result<T, FederationError> {
        let request = http
            .get(format!("{}{path}", self.api))
            .bearer_auth(token)
            .header(header::ACCEPT, "application/vnd.github+json")
            // GitHub refuses requests without one.
            .header(header::USER_AGENT, "konklav")
            .header("x-github-api-version", API_VERSION);
        answer(crate::telemetry::http::send(request, "idp_github_api").await).await
    }

    /// Every item of a listing, up to [`MAX_PAGES`] pages.
    async fn pages<T: DeserializeOwned>(
        &self,
        http: &reqwest::Client,
        token: &str,
        path: &str,
    ) -> Result<Vec<T>, FederationError> {
        let mut all = Vec::new();
        for page in 1..=MAX_PAGES {
            let items: Vec<T> = self
                .get(
                    http,
                    token,
                    &format!("{path}?per_page={PER_PAGE}&page={page}"),
                )
                .await?;
            let last = items.len() < PER_PAGE;
            all.extend(items);
            if last {
                break;
            }
        }
        Ok(all)
    }
}

fn scopes(settings: &Settings) -> String {
    if settings.scopes.is_empty() {
        DEFAULT_SCOPES.to_owned()
    } else {
        settings.scopes.join(" ")
    }
}

#[derive(Deserialize)]
struct TokenAnswer {
    #[serde(default)]
    access_token: Option<String>,
    #[serde(default)]
    error: Option<String>,
}

#[derive(Deserialize)]
struct User {
    id: u64,
    login: String,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    avatar_url: Option<String>,
    #[serde(default)]
    html_url: Option<String>,
}

#[derive(Deserialize)]
struct Email {
    #[serde(rename = "email")]
    address: String,
    #[serde(default)]
    primary: bool,
    #[serde(default)]
    verified: bool,
}

#[derive(Deserialize)]
struct Org {
    login: String,
}

#[derive(Deserialize)]
struct Team {
    slug: String,
    organization: Org,
}

// r[impl federation.github.groups]
fn group_names(orgs: &[Org], teams: &[Team]) -> Vec<String> {
    let mut groups: Vec<String> = orgs.iter().map(|org| org.login.clone()).collect();
    for team in teams {
        let name = format!("{}/{}", team.organization.login, team.slug);
        if !groups.contains(&name) {
            groups.push(name);
        }
    }
    groups
}

/// The claims of a GitHub login. `emails` is what `/user/emails` listed,
/// when the scopes allowed reading it.
// r[impl federation.github.identity]
fn claims(user: &User, emails: Option<&[Email]>, groups: Option<Vec<String>>) -> IdClaims {
    let primary = emails.and_then(|emails| emails.iter().find(|email| email.primary));
    let (email, email_verified) = match primary {
        Some(primary) => (Some(primary.address.clone()), Some(primary.verified)),
        None => (
            user.email.clone().filter(|email| !email.is_empty()),
            Some(false),
        ),
    };
    let email_verified = email.as_ref().and(email_verified);
    let sub = user.id.to_string();
    let mut raw = serde_json::json!({
        "sub": sub,
        "preferred_username": user.login,
        "name": user.name,
        "picture": user.avatar_url,
        "profile": user.html_url,
        "email": email,
        "email_verified": email_verified,
    });
    if let Some(groups) = groups {
        raw["groups"] = groups.into();
    }
    IdClaims {
        sub,
        email,
        email_verified,
        amr: Vec::new(),
        acr: None,
        auth_time: None,
        nonce: None,
        azp: None,
        aud: serde_json::Value::Null,
        raw,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user() -> User {
        User {
            id: 583_231,
            login: "octocat".into(),
            name: Some("The Octocat".into()),
            email: Some("octocat@public.example".into()),
            avatar_url: None,
            html_url: Some("https://github.com/octocat".into()),
        }
    }

    #[test]
    fn endpoints_follow_the_kind_of_github() {
        let dotcom = GitHub::new("https://github.com").unwrap();
        assert_eq!(dotcom.authorize, "https://github.com/login/oauth/authorize");
        assert_eq!(dotcom.token, "https://github.com/login/oauth/access_token");
        assert_eq!(dotcom.api, "https://api.github.com");
        assert_eq!(
            GitHub::new("https://octo.ghe.com/").unwrap().api,
            "https://api.octo.ghe.com"
        );
        assert_eq!(
            GitHub::new("https://git.example").unwrap().api,
            "https://git.example/api/v3"
        );
        assert!(GitHub::new("ssh://git.example").is_err());
    }

    #[test]
    fn the_account_is_its_numeric_id_and_its_primary_email() {
        let emails = [
            Email {
                address: "other@example.com".into(),
                primary: false,
                verified: true,
            },
            Email {
                address: "octo@example.com".into(),
                primary: true,
                verified: true,
            },
        ];
        let claims = claims(&user(), Some(&emails), None);
        assert_eq!(claims.sub, "583231");
        assert_eq!(claims.email.as_deref(), Some("octo@example.com"));
        assert_eq!(claims.email_verified, Some(true));
        assert_eq!(claims.raw["preferred_username"], "octocat");
        assert!(claims.raw.get("groups").is_none());
    }

    #[test]
    fn a_public_or_unverified_email_is_unverified() {
        let public = claims(&user(), None, None);
        assert_eq!(public.email.as_deref(), Some("octocat@public.example"));
        assert_eq!(public.email_verified, Some(false));
        let unverified = [Email {
            address: "octo@example.com".into(),
            primary: true,
            verified: false,
        }];
        assert_eq!(
            claims(&user(), Some(&unverified), None).email_verified,
            Some(false)
        );
        let mut nobody = user();
        nobody.email = None;
        let none = claims(&nobody, Some(&[]), None);
        assert_eq!((none.email, none.email_verified), (None, None));
    }

    #[test]
    fn groups_are_organizations_and_their_teams() {
        let orgs = [Org {
            login: "acme".into(),
        }];
        let teams = [Team {
            slug: "platform".into(),
            organization: Org {
                login: "acme".into(),
            },
        }];
        assert_eq!(group_names(&orgs, &teams), ["acme", "acme/platform"]);
    }
}
