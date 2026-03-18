use clap::{Parser, Subcommand};
use conclave_controlplane_api::{
    InviteCreateRequest, ManagedApplyRequest, ManagedPlanRequest, ManagedValidateRequest,
};
use conclave_managed_config::ManagedConfig;

#[derive(Parser)]
#[command(name = "conclave")]
struct Cli {
    #[arg(
        long,
        env = "CONCLAVE_CONTROL_PLANE_URL",
        default_value = "http://127.0.0.1:8080"
    )]
    control_plane_url: String,
    #[arg(
        long,
        env = "CONCLAVE_BOOTSTRAP_TOKEN",
        default_value = "conclave-bootstrap-token"
    )]
    bootstrap_token: String,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Validate,
    Plan,
    Apply,
    InviteCreate {
        #[arg(long)]
        subject: String,
        #[arg(long, default_value_t = 900)]
        expires_in_seconds: u64,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let cli = Cli::parse();
    let client = reqwest::Client::new();

    match cli.command {
        Commands::Validate => {
            let managed = ManagedConfig::load_from_dir(".")?.managed;
            let response = client
                .post(format!("{}/v1/managed/validate", cli.control_plane_url))
                .bearer_auth(&cli.bootstrap_token)
                .json(&ManagedValidateRequest { managed })
                .send()
                .await?;
            println!("{}", response.text().await?);
        }
        Commands::Plan => {
            let managed = ManagedConfig::load_from_dir(".")?.managed;
            let response = client
                .post(format!("{}/v1/managed/plan", cli.control_plane_url))
                .bearer_auth(&cli.bootstrap_token)
                .json(&ManagedPlanRequest { managed })
                .send()
                .await?;
            println!("{}", response.text().await?);
        }
        Commands::Apply => {
            let managed = ManagedConfig::load_from_dir(".")?.managed;
            let response = client
                .post(format!("{}/v1/managed/apply", cli.control_plane_url))
                .bearer_auth(&cli.bootstrap_token)
                .json(&ManagedApplyRequest { managed })
                .send()
                .await?;
            println!("{}", response.text().await?);
        }
        Commands::InviteCreate {
            subject,
            expires_in_seconds,
        } => {
            let response = client
                .post(format!("{}/v1/invites", cli.control_plane_url))
                .bearer_auth(&cli.bootstrap_token)
                .json(&InviteCreateRequest {
                    subject,
                    expires_in_seconds: Some(expires_in_seconds),
                })
                .send()
                .await?;
            println!("{}", response.text().await?);
        }
    }

    Ok(())
}
