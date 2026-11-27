//! `konklav`, the operator CLI.

use std::io::{BufRead as _, IsTerminal as _, Write as _};
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand};
use konklav_cli::profile::{self, Config, CredentialStore, Profile};
use konklav_cli::session::{self, Factor};
use konklav_cli::{BrowserLogin, Context, Error, PasswordLogin, Result, Session, Surface, store};
use reqwest::Method;
use serde_json::{Value, json};

/// Operate a Konklav control plane.
// r[impl item.cli.same-version]
#[derive(Parser)]
#[command(name = "konklav", version)]
struct Cli {
    /// The profile to use, instead of the default one.
    #[arg(long, global = true, env = "KONKLAV_PROFILE")]
    profile: Option<String>,
    /// Print results as JSON, and nothing else, on standard output.
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Sign in, binding the new session to a DPoP key kept on this computer.
    Login(LoginArgs),
    /// Revoke the session and delete its key and tokens from this computer.
    Logout,
    /// Show who the session belongs to and what it may do.
    Whoami,
    /// Send a control-plane request, such as `konklav api GET /v1/tenants`.
    Api(ApiArgs),
}

#[derive(Args)]
struct LoginArgs {
    /// The issuer, Konklav's public base URL. Saves the profile; needed the
    /// first time.
    #[arg(long)]
    url: Option<String>,
    /// The control-plane surface's base URL, when it isn't the issuer.
    #[arg(long)]
    control_url: Option<String>,
    /// Where to keep the key and tokens: keyring (the default) or file, a
    /// file readable only by you.
    #[arg(long)]
    credential_store: Option<CredentialStore>,
    /// Sign in with a password at the terminal instead of the browser.
    #[arg(long, conflicts_with = "secret_key")]
    password: bool,
    /// The login identifier for --password; asked for when left out.
    #[arg(long, requires = "password")]
    identifier: Option<String>,
    /// Read the password from the first line of standard input.
    #[arg(long, requires = "password")]
    password_stdin: bool,
    /// Sign in a service principal with this secret key id. The secret
    /// comes from `KONKLAV_SECRET_KEY` or the first line of standard input.
    #[arg(long, value_name = "KEY_ID")]
    secret_key: Option<String>,
    /// Print the sign-in URL instead of opening a browser, for a browser
    /// elsewhere on this computer.
    #[arg(long, conflicts_with_all = ["password", "secret_key"])]
    no_browser: bool,
}

#[derive(Args)]
struct ApiArgs {
    /// The HTTP method.
    method: String,
    /// The path, starting with /v1.
    path: String,
    /// The JSON body: inline, @file, or @- for standard input.
    #[arg(long, short)]
    data: Option<String>,
    /// Send the request to the subject-facing surface instead.
    #[arg(long)]
    subject: bool,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli).await {
        Ok(code) => code,
        Err(error) => {
            eprintln!("konklav: {error}");
            error.exit_code()
        }
    }
}

async fn run(cli: Cli) -> Result<ExitCode> {
    let dir = profile::config_dir()?;
    if let Some(name) = &cli.profile {
        profile::check_name(name)?;
    }
    match cli.command {
        Command::Login(args) => login(&dir, cli.profile.as_deref(), cli.json, args).await,
        Command::Logout => {
            let session = Session::load(context(&dir, cli.profile.as_deref())?)?;
            let name = session.context().name.clone();
            if let Some(error) = session.logout().await? {
                eprintln!(
                    "konklav: Konklav didn't confirm the sign-out ({error}); the local key and \
                     tokens are deleted anyway"
                );
            }
            print(
                cli.json,
                &json!({"profile": name, "signed_out": true}),
                || format!("Signed out of {name}."),
            );
            Ok(ExitCode::SUCCESS)
        }
        Command::Whoami => {
            let mut session = Session::load(context(&dir, cli.profile.as_deref())?)?;
            let who = whoami(&mut session).await?;
            print(cli.json, &who, || describe(&who));
            Ok(ExitCode::SUCCESS)
        }
        Command::Api(args) => {
            let mut session = Session::load(context(&dir, cli.profile.as_deref())?)?;
            api(&mut session, args).await
        }
    }
}

fn context(dir: &std::path::Path, name: Option<&str>) -> Result<Context> {
    let (name, profile) = Config::load(dir)?.profile(name)?;
    let store = store::open(profile.credential_store, dir);
    Context::new(name, profile, store, Some(dir.to_owned()))
}

/// Prints `value` as JSON, or the human text.
// r[impl item.cli.json]
fn print(json: bool, value: &Value, human: impl FnOnce() -> String) {
    if json {
        println!("{value:#}");
    } else {
        println!("{}", human());
    }
}

async fn login(
    dir: &std::path::Path,
    name: Option<&str>,
    json: bool,
    args: LoginArgs,
) -> Result<ExitCode> {
    let mut config = Config::load(dir)?;
    let name = name
        .map(str::to_owned)
        .or_else(|| config.default.clone())
        .unwrap_or_else(|| "default".into());
    let mut profile = match (&args.url, config.profiles.get(&name)) {
        (Some(url), _) => Profile::new(url, args.control_url.as_deref())?,
        (None, Some(existing)) => {
            let mut existing = existing.clone();
            if let Some(control) = &args.control_url {
                existing.control_url = Some(Profile::new(control, None)?.url);
            }
            existing
        }
        (None, None) => {
            return Err(Error::Usage(format!(
                "profile {name:?} is new; give its issuer with --url"
            )));
        }
    };
    if let Some(kind) = args.credential_store {
        profile.credential_store = kind;
    } else if let Some(existing) = config.profiles.get(&name) {
        profile.credential_store = existing.credential_store;
    }
    if profile.credential_store == CredentialStore::File {
        eprintln!(
            "konklav: keeping the DPoP key and tokens in a file readable only by you, in {}",
            dir.join("credentials").display()
        );
    }
    let store = store::open(profile.credential_store, dir);
    // A new sign-in replaces the profile's old session, which is ended
    // first so that it doesn't linger.
    if let Ok(old) = Session::load(Context::new(
        &name,
        profile.clone(),
        store.clone(),
        Some(dir.to_owned()),
    )?) {
        old.logout().await.ok();
    }
    let context = Context::new(&name, profile.clone(), store, Some(dir.to_owned()))?;
    let mut session = if let Some(key_id) = &args.secret_key {
        let secret = match std::env::var("KONKLAV_SECRET_KEY") {
            Ok(secret) => secret,
            Err(_) => read_line("Secret: ", true)?,
        };
        session::login_secret_key(context, key_id, &secret).await?
    } else if args.password {
        let identifier = match args.identifier {
            Some(identifier) => identifier,
            None => read_line("Login identifier: ", false)?,
        };
        let password = if args.password_stdin {
            first_line(&mut std::io::stdin().lock())?
        } else {
            read_line("Password: ", true)?
        };
        let mut login = session::login_password(context, &identifier, &password).await?;
        loop {
            match login {
                PasswordLogin::Done(session) => break session,
                PasswordLogin::Mfa(pending) => {
                    let factors = pending.factors().await?;
                    let factor = choose_factor(&factors)?;
                    if factor.kind == "email_code" {
                        pending.send_code(factor.id).await?;
                        eprintln!("A code is on its way by email.");
                    }
                    let code = read_line("Code: ", false)?;
                    login = pending.complete(factor.id, &code).await?;
                }
            }
        }
    } else {
        browser_login(context, args.no_browser).await?
    };
    config.profiles.insert(name.clone(), profile);
    if config.default.is_none() {
        config.default = Some(name.clone());
    }
    config.save(dir)?;
    let who = whoami(&mut session).await?;
    print(json, &who, || format!("Signed in.\n{}", describe(&who)));
    Ok(ExitCode::SUCCESS)
}

/// Signs in through the browser: opens the sign-in page, unless told not
/// to, and waits for it to come back to the loopback listener.
async fn browser_login(context: Context, no_browser: bool) -> Result<Session> {
    let login = BrowserLogin::start(context).await?;
    if no_browser {
        eprintln!(
            "Open this URL in a browser on this computer to sign in:\n\n  {}\n",
            login.url()
        );
    } else {
        eprintln!(
            "Opening the sign-in page in your browser. If it doesn't open, visit:\n\n  {}\n",
            login.url()
        );
        if let Err(error) = webbrowser::open(login.url()) {
            eprintln!("konklav: couldn't open a browser ({error}); open the URL yourself");
        }
    }
    eprintln!("Waiting for the sign-in to finish…");
    login.finish(konklav_cli::browser::TIMEOUT).await
}

fn choose_factor(factors: &[Factor]) -> Result<Factor> {
    match factors {
        [] => Err(Error::local(
            "the credential needs MFA, but no factor is active",
        )),
        [only] => Ok(only.clone()),
        many => {
            for (i, factor) in many.iter().enumerate() {
                eprintln!("  {}. {}", i + 1, factor.kind);
            }
            let choice = read_line("Factor: ", false)?;
            choice
                .trim()
                .parse::<usize>()
                .ok()
                .and_then(|n| many.get(n.checked_sub(1)?))
                .cloned()
                .ok_or_else(|| Error::usage(format!("no factor {choice:?}")))
        }
    }
}

/// Asks for one line on the terminal, without echo for secrets.
fn read_line(prompt: &str, secret: bool) -> Result<String> {
    let stdin = std::io::stdin();
    if !stdin.is_terminal() {
        return first_line(&mut stdin.lock());
    }
    if secret {
        return rpassword::prompt_password(prompt).map_err(|e| Error::local(e.to_string()));
    }
    eprint!("{prompt}");
    std::io::stderr().flush().ok();
    first_line(&mut stdin.lock())
}

fn first_line(input: &mut impl std::io::BufRead) -> Result<String> {
    let mut line = String::new();
    input
        .read_line(&mut line)
        .map_err(|e| Error::local(e.to_string()))?;
    let line = line.trim_end_matches(['\r', '\n']).to_owned();
    if line.is_empty() {
        return Err(Error::usage("nothing was entered"));
    }
    Ok(line)
}

async fn whoami(session: &mut Session) -> Result<Value> {
    let answer = session
        .send(Method::GET, Surface::Subject, "/v1/capabilities", None)
        .await?
        .ok()?
        .json()?;
    let context = session.context();
    Ok(json!({
        "profile": context.name,
        "url": context.profile.url,
        "control_url": context.profile.control_base(),
        "session_id": session.id(),
        "subject": answer["subject"],
        "capabilities": answer["capabilities"],
    }))
}

fn describe(who: &Value) -> String {
    let capabilities = who["capabilities"]
        .as_array()
        .map(|all| {
            all.iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join(", ")
        })
        .filter(|joined| !joined.is_empty())
        .unwrap_or_else(|| "none".into());
    format!(
        "Profile:      {}\nKonklav:      {}\nSubject:      {}\nSession:      {}\nCapabilities: {}",
        who["profile"].as_str().unwrap_or_default(),
        who["url"].as_str().unwrap_or_default(),
        who["subject"].as_str().unwrap_or_default(),
        who["session_id"].as_str().unwrap_or_default(),
        capabilities,
    )
}

// r[impl item.cli.no-token-output]
async fn api(session: &mut Session, args: ApiArgs) -> Result<ExitCode> {
    let method = Method::from_bytes(args.method.to_ascii_uppercase().as_bytes())
        .map_err(|_| Error::usage(format!("not an HTTP method: {:?}", args.method)))?;
    let body = args.data.as_deref().map(read_body).transpose()?;
    let surface = if args.subject {
        Surface::Subject
    } else {
        Surface::Control
    };
    let response = session.send(method, surface, &args.path, body).await?;
    let text = match serde_json::from_slice::<Value>(&response.body) {
        Ok(value) => format!("{value:#}"),
        Err(_) => String::from_utf8_lossy(&response.body).into_owned(),
    };
    if response.status.is_success() {
        if !text.is_empty() {
            println!("{text}");
        }
        Ok(ExitCode::SUCCESS)
    } else {
        eprintln!("konklav: {}", response.status);
        if !text.is_empty() {
            eprintln!("{text}");
        }
        Ok(ExitCode::from(if response.status.as_u16() == 401 {
            3
        } else {
            1
        }))
    }
}

fn read_body(data: &str) -> Result<Value> {
    let text = match data.strip_prefix('@') {
        Some("-") => {
            let mut text = String::new();
            for line in std::io::stdin().lock().lines() {
                text.push_str(&line.map_err(|e| Error::local(e.to_string()))?);
                text.push('\n');
            }
            text
        }
        Some(path) => {
            std::fs::read_to_string(path).map_err(|e| Error::usage(format!("{path}: {e}")))?
        }
        None => data.to_owned(),
    };
    serde_json::from_str(&text).map_err(|e| Error::usage(format!("the body isn't JSON: {e}")))
}
