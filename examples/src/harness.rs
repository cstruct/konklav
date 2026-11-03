//! Starting real `konklav-server` processes, each on its own fresh database
//! on the development Postgres (`mise run db:up`) and its own free ports.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use konklav_test_support::TestDatabase;
use p256::pkcs8::EncodePrivateKey as _;
use reqwest::Method;
use serde_json::Value;
use tokio::process::{Child, Command};

use crate::{Result, fail};

/// The `konklav-server` binary: `KONKLAV_SERVER_BIN`, or `konklav-server`
/// next to this example's binary, as `cargo build` puts them.
#[must_use]
pub fn server_binary() -> PathBuf {
    if let Some(bin) = std::env::var_os("KONKLAV_SERVER_BIN") {
        return bin.into();
    }
    std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(|dir| dir.join("konklav-server")))
        .unwrap_or_else(|| "konklav-server".into())
}

/// The `aud` of every example server's tokens.
pub const AUDIENCE: &str = "konklav-example";

/// What a server is started with, beyond its listeners, database, keys and
/// bootstrap token.
#[derive(Clone, Debug, Default)]
pub struct Setup {
    /// The server binary; [`server_binary`] when absent.
    pub binary: Option<PathBuf>,
    /// The host in the issuer URL, when others reach the server by another
    /// name than `127.0.0.1`, such as `host.docker.internal`.
    pub issuer_host: Option<String>,
    /// The whole issuer URL, when others reach the server through a proxy,
    /// such as one that terminates TLS. Wins over `issuer_host`.
    pub issuer: Option<String>,
    /// Serve as an OpenID provider, sending people to this login page.
    pub login_url: Option<String>,
    /// Origins allowed to use browser sign-in.
    pub browser_origins: Vec<String>,
    /// A claims hook serving the `profile` scope, for an OpenID provider.
    pub claims_hook: Option<String>,
    /// More Styx for the config file.
    pub config: String,
    /// More Styx for the secrets file.
    pub secrets: String,
}

/// A running server, stopped and its database dropped with this value.
pub struct Server {
    /// Base URLs of the three surfaces, as `http://127.0.0.1:port`.
    pub subject: String,
    /// The `iss` of its tokens: [`Self::subject`] unless the setup named an
    /// issuer host.
    pub issuer: String,
    pub relying: String,
    pub control: String,
    /// Accepted for every control-plane call.
    pub bootstrap_token: String,
    /// Where the config, secrets, keys and log live.
    pub dir: PathBuf,
    pub http: reqwest::Client,
    binary: PathBuf,
    child: Option<Child>,
    _db: TestDatabase,
}

/// Ports the OS says are free now, for a server to listen on soon.
fn free_ports() -> Result<[u16; 3]> {
    let listeners = [(); 3].map(|()| std::net::TcpListener::bind("127.0.0.1:0"));
    let mut ports = [0; 3];
    for (port, listener) in ports.iter_mut().zip(listeners) {
        *port = listener?.local_addr()?.port();
    }
    Ok(ports)
}

fn random<const N: usize>() -> [u8; N] {
    let mut bytes = [0; N];
    getrandom::fill(&mut bytes).expect("system randomness");
    bytes
}

/// Styx's quoted string.
fn quoted(text: &str) -> String {
    format!("{text:?}")
}

impl Server {
    /// Writes a config for a fresh database and free ports into a new
    /// directory, without starting anything. [`Self::start`] starts it.
    pub async fn prepare(setup: &Setup) -> Result<Self> {
        let db = TestDatabase::new().await;
        let url = reqwest::Url::parse(db.url())?;
        let [subject, relying, control] = free_ports()?;
        let dir = std::env::temp_dir().join(format!("konklav-example-{}", uuid::Uuid::now_v7()));
        tokio::fs::create_dir_all(&dir).await?;

        let signing = ed25519_dalek::SigningKey::from_bytes(&random());
        tokio::fs::write(
            dir.join("signing-key.pem"),
            ed25519_dalek::pkcs8::EncodePrivateKey::to_pkcs8_pem(
                &signing,
                ed25519_dalek::pkcs8::spki::der::pem::LineEnding::LF,
            )?
            .as_bytes(),
        )
        .await?;
        let issuer = setup.issuer.clone().unwrap_or_else(|| {
            format!(
                "http://{}:{subject}",
                setup.issuer_host.as_deref().unwrap_or("127.0.0.1")
            )
        });
        let oidc = match &setup.login_url {
            Some(login_url) => {
                provider_config(&dir, login_url, setup.claims_hook.as_deref()).await?
            }
            None => String::new(),
        };
        let origins = setup
            .browser_origins
            .iter()
            .map(|o| quoted(o))
            .collect::<Vec<_>>()
            .join(" ");
        let config = format!(
            "listen {{\n    subject \"127.0.0.1:{subject}\"\n    relying \"127.0.0.1:{relying}\"\n    control \"127.0.0.1:{control}\"\n}}\n\
             database {{\n    host {host}\n    port {port}\n    name {name}\n    user {user}\n    max_connections 4\n}}\n\
             telemetry {{logs {{level warn}}}}\n\
             tokens {{\n    issuer {issuer}\n    audience {AUDIENCE}\n    signing_key_file signing-key.pem\n}}\n\
             pacing {{floor_ms 0, jitter_ms 0}}\n\
             browser {{allowed_origins ({origins}), secure_cookies false}}\n\
             {oidc}{extra}\n",
            host = url.host_str().unwrap_or("localhost"),
            port = url.port().unwrap_or(5432),
            name = db.name(),
            user = quoted(url.username()),
            issuer = quoted(&issuer),
            extra = setup.config,
        );
        let bootstrap_token = format!("example-{}", uuid::Uuid::now_v7().simple());
        let secrets = format!(
            "database {{password {}}}\ncontrol {{bootstrap_token {bootstrap_token}}}\n\
             mfa {{totp_keys ({{id example, key {}}})}}\n{}\n",
            quoted(
                &percent_encoding::percent_decode_str(url.password().unwrap_or_default())
                    .decode_utf8_lossy()
            ),
            quoted(&base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                random::<32>()
            )),
            setup.secrets,
        );
        tokio::fs::write(dir.join("config.styx"), config).await?;
        tokio::fs::write(dir.join("secrets.styx"), secrets).await?;

        Ok(Self {
            subject: format!("http://127.0.0.1:{subject}"),
            issuer,
            relying: format!("http://127.0.0.1:{relying}"),
            control: format!("http://127.0.0.1:{control}"),
            bootstrap_token,
            dir,
            http: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()?,
            binary: setup.binary.clone().unwrap_or_else(server_binary),
            child: None,
            _db: db,
        })
    }

    /// Adds to the config and secrets files of a server not yet serving.
    pub async fn extend(&mut self, config: &str, secrets: &str) -> Result<()> {
        for (file, extra) in [("config.styx", config), ("secrets.styx", secrets)] {
            let mut text = tokio::fs::read_to_string(self.dir.join(file)).await?;
            text.push_str(extra);
            tokio::fs::write(self.dir.join(file), text).await?;
        }
        Ok(())
    }

    /// Prepares and starts a server.
    pub async fn start(setup: &Setup) -> Result<Self> {
        let mut server = Self::prepare(setup).await?;
        server.serve().await?;
        Ok(server)
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut command = Command::new(&self.binary);
        command
            .current_dir(&self.dir)
            .arg("--config")
            .arg(self.dir.join("config.styx"))
            .arg("--secrets")
            .arg(self.dir.join("secrets.styx"))
            .args(args)
            .kill_on_drop(true);
        command
    }

    /// Runs a command of the server binary to completion, such as
    /// `bootstrap`, returning its output.
    pub async fn run(&self, args: &[&str]) -> Result<std::process::Output> {
        Ok(self.command(args).output().await?)
    }

    /// Starts `serve` and waits until it's ready.
    pub async fn serve(&mut self) -> Result<()> {
        let log = std::fs::File::create(self.dir.join("server.log"))?;
        let child = self
            .command(&["serve"])
            .stdout(Stdio::null())
            .stderr(log)
            .spawn()
            .map_err(|error| fail(format!("starting {}: {error}", self.binary.display())))?;
        self.child = Some(child);
        let ready = format!("{}/readyz", self.subject);
        for _ in 0..300 {
            if let Some(child) = self.child.as_mut()
                && let Some(status) = child.try_wait()?
            {
                return Err(fail(format!(
                    "the server exited ({status}): {}",
                    self.log()
                )));
            }
            if let Ok(reply) = self.http.get(&ready).send().await
                && reply.status().is_success()
            {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        Err(fail(format!(
            "the server never became ready: {}",
            self.log()
        )))
    }

    /// What the server has logged.
    #[must_use]
    pub fn log(&self) -> String {
        std::fs::read_to_string(self.dir.join("server.log")).unwrap_or_default()
    }

    /// A control-plane call with the bootstrap token, which must succeed.
    pub async fn control(&self, method: Method, path: &str, body: Option<Value>) -> Result<Value> {
        let mut request = self
            .http
            .request(method, format!("{}{path}", self.control))
            .bearer_auth(&self.bootstrap_token);
        if let Some(body) = body {
            request = request.json(&body);
        }
        let reply = request.send().await?;
        let status = reply.status();
        let body = reply.json::<Value>().await.unwrap_or(Value::Null);
        if !status.is_success() {
            return Err(fail(format!("{path}: {status} {body}")));
        }
        Ok(body)
    }

    /// A subject-facing JSON `POST`, returning its status and body.
    pub async fn post(&self, path: &str, body: &Value) -> Result<(reqwest::StatusCode, Value)> {
        let reply = self
            .http
            .post(format!("{}{path}", self.subject))
            .json(body)
            .send()
            .await?;
        let status = reply.status();
        Ok((status, reply.json().await.unwrap_or(Value::Null)))
    }

    /// Creates a service principal with a secret key and returns the key
    /// as `key_id.secret`.
    pub async fn service_principal(&self, global_roles: &[&str]) -> Result<String> {
        let id = uuid::Uuid::now_v7();
        self.control(
            Method::PUT,
            &format!("/v1/subjects/{id}"),
            Some(serde_json::json!({"kind": "service"})),
        )
        .await?;
        let created = self
            .control(
                Method::POST,
                &format!("/v1/subjects/{id}/credentials"),
                Some(serde_json::json!({"kind": "secret_key"})),
            )
            .await?;
        for role in global_roles {
            self.control(
                Method::POST,
                &format!("/v1/subjects/{id}/global-assignments"),
                Some(serde_json::json!({"role": role})),
            )
            .await?;
        }
        created["secret_keys"]["a"]
            .as_str()
            .map(str::to_owned)
            .ok_or_else(|| fail(format!("no secret key in {created}")))
    }

    /// Creates a human subject with a credential, such as
    /// `{"kind": "password", "identifier": ..., "password": ...}`, and
    /// returns its id.
    pub async fn human(&self, credential: Value) -> Result<String> {
        let id = uuid::Uuid::now_v7().to_string();
        self.control(
            Method::PUT,
            &format!("/v1/subjects/{id}"),
            Some(serde_json::json!({"kind": "human"})),
        )
        .await?;
        self.control(
            Method::POST,
            &format!("/v1/subjects/{id}/credentials"),
            Some(credential),
        )
        .await?;
        Ok(id)
    }

    /// Where a file of this server's lives.
    #[must_use]
    pub fn path(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        if let Some(child) = self.child.as_mut() {
            let _ = child.start_kill();
        }
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// The `oidc_provider` section, with an ES256 and an RSA ID-token key
/// written into `dir`.
async fn provider_config(dir: &Path, login_url: &str, hook: Option<&str>) -> Result<String> {
    let key = loop {
        if let Ok(key) = p256::SecretKey::from_slice(&random::<32>()) {
            break key;
        }
    };
    tokio::fs::write(
        dir.join("id-token-key.pem"),
        key.to_pkcs8_pem(p256::pkcs8::LineEnding::LF)?.as_bytes(),
    )
    .await?;
    // An RSA key too, so clients can get RS256 ID tokens.
    let rsa = aws_lc_rs::rsa::KeyPair::generate(aws_lc_rs::rsa::KeySize::Rsa2048)
        .map_err(|error| fail(error.to_string()))?;
    let der: aws_lc_rs::encoding::Pkcs8V1Der<'_> =
        aws_lc_rs::encoding::AsDer::as_der(&rsa).map_err(|error| fail(error.to_string()))?;
    tokio::fs::write(
        dir.join("id-token-rsa-key.pem"),
        pem("PRIVATE KEY", der.as_ref()),
    )
    .await?;
    let hook = hook.map_or_else(String::new, |url| {
        format!(
            "    claims_hook {{\n        url {}\n        scopes {{\n            \
             profile ({})\n        }}\n    }}\n",
            quoted(url),
            PROFILE_CLAIMS.join(" ")
        )
    });
    Ok(format!(
        "oidc_provider {{\n    id_token_key_file id-token-key.pem\n    \
         rsa_key_file id-token-rsa-key.pem\n    login_url {}\n{hook}}}\n",
        quoted(login_url)
    ))
}

/// The claims a [`Setup::claims_hook`] serves for the `profile` scope.
pub const PROFILE_CLAIMS: &[&str] = &[
    "name",
    "given_name",
    "family_name",
    "middle_name",
    "nickname",
    "preferred_username",
    "profile",
    "picture",
    "website",
    "gender",
    "birthdate",
    "zoneinfo",
    "locale",
    "updated_at",
];

/// `der` as a PEM block.
fn pem(label: &str, der: &[u8]) -> String {
    let body = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, der);
    let lines = body
        .as_bytes()
        .chunks(64)
        .map(|line| String::from_utf8_lossy(line).into_owned())
        .collect::<Vec<_>>()
        .join("\n");
    format!("-----BEGIN {label}-----\n{lines}\n-----END {label}-----\n")
}

/// The directory of example data, such as bootstrap sets.
#[must_use]
pub fn data_dir() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}
