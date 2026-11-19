//! `chain-payments`: one binary for every role.
//!
//! - `serve`: the public session API (`PUBLIC_LISTEN_ADDR`, default 0.0.0.0:8080) and the merchant API and metrics
//!   (`INTERNAL_LISTEN_ADDR`, default 0.0.0.0:8081) in one process;
//! - `worker`: settles pending payments, expires sessions, delivers webhooks (single writer);
//! - `migrate`: applies the schema (the owner role);
//! - `merchant add`: creates a merchant and writes its API key to a file (never printed);
//! - `merchant set-webhook`: changes or removes a merchant's webhook address (`merchant rotate-key` replaces its key);
//! - `keygen`: writes a new ed25519 seed to a file and prints only the public key.

use std::io::Write;
use std::net::SocketAddr;
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use chain_payments_core::quote::Signer;
use chain_payments_core::session::random_id;
use chain_payments_service::app::App;
use chain_payments_service::config::Config;
use chain_payments_service::{api, worker};
use chain_payments_store::Store;
use chain_payments_store::config::{Access, DatabaseSettings};
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "chain-payments", version, about = "Chain Payments: exact, quoted crypto payments for merchants")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Serve the public session API and the merchant API.
    Serve {
        #[arg(long, env = "PUBLIC_LISTEN_ADDR", default_value = "0.0.0.0:8080")]
        public: SocketAddr,
        #[arg(long, env = "INTERNAL_LISTEN_ADDR", default_value = "0.0.0.0:8081")]
        internal: SocketAddr,
        #[arg(long, env = "DB_POOL_SIZE", default_value_t = 8)]
        pool: u32,
    },
    /// Settle payments, expire sessions and deliver webhooks; serves /metrics and /healthz.
    Worker {
        #[arg(long, env = "WORKER_LISTEN_ADDR", default_value = "0.0.0.0:8081")]
        listen: SocketAddr,
    },
    /// Apply the database schema.
    Migrate,
    /// Merchant administration.
    Merchant {
        #[command(subcommand)]
        action: MerchantAction,
    },
    /// Write a new ed25519 seed (32 bytes, mode 0600) and print its public key.
    Keygen {
        #[arg(long)]
        out: PathBuf,
    },
}

#[derive(Subcommand)]
enum MerchantAction {
    /// Create a merchant. Its API key is either new, written to --key-out (mode 0600) and never printed, or read from
    /// --key-file (a key generated elsewhere, e.g. a Secret both namespaces mount; then the command is idempotent: a
    /// merchant that already has that key is left as it is).
    Add {
        #[arg(long)]
        name: String,
        #[arg(long)]
        webhook_url: Option<String>,
        /// Enabled payment method ids (comma-separated).
        #[arg(long, value_delimiter = ',')]
        methods: Vec<String>,
        #[arg(long, conflicts_with = "key_file", required_unless_present = "key_file")]
        key_out: Option<PathBuf>,
        #[arg(long)]
        key_file: Option<PathBuf>,
    },
    /// Give a merchant a new API key (written to --key-out).
    RotateKey {
        #[arg(long)]
        id: uuid::Uuid,
        #[arg(long)]
        key_out: PathBuf,
    },
    /// Change a merchant's webhook address (--webhook-url), or remove it (--clear). Deliveries still pending go to
    /// the new address: the worker reads it when it sends.
    SetWebhook {
        #[arg(long)]
        id: uuid::Uuid,
        #[arg(long, conflicts_with = "clear", required_unless_present = "clear")]
        webhook_url: Option<String>,
        #[arg(long)]
        clear: bool,
    },
}

/// What `merchant add --key-file` says when the merchant already exists: nothing is changed, but a webhook address
/// that differs from the one given is named, so a stale address is noticed instead of silently kept (FU-0156).
fn webhook_difference(stored: Option<&str>, given: Option<&str>) -> Option<String> {
    if given.is_none() || stored == given {
        return None;
    }
    Some(format!(
        "its webhook address is {} but {} was given; change it with `merchant set-webhook`",
        stored.unwrap_or("(none)"),
        given.unwrap_or("(none)")
    ))
}

fn write_secret(path: &PathBuf, bytes: &[u8]) -> anyhow::Result<()> {
    let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(path)?;
    f.write_all(bytes)?;
    Ok(())
}

fn store(pool: u32) -> anyhow::Result<Store> {
    let get = |k: &str| std::env::var(k).ok();
    let settings = DatabaseSettings::from_env(get)?;
    Ok(Store::new(settings.lazy_pool(pool, Access::ReadWrite)?))
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    let term = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut s) => {
                s.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    tokio::select! { _ = ctrl_c => {}, _ = term => {} }
}

async fn run(cli: Cli) -> anyhow::Result<()> {
    match cli.command {
        Command::Serve { public, internal, pool } => {
            let config = Config::from_env(|k| std::env::var(k).ok())?;
            anyhow::ensure!(config.quote_signer.is_some(), "serve signs quotes: set QUOTE_KEY_FILE");
            let app = Arc::new(App::new(store(pool)?, config)?);
            let pl = tokio::net::TcpListener::bind(public).await?;
            let il = tokio::net::TcpListener::bind(internal).await?;
            tracing::info!(%public, %internal, "listening");
            let a = axum::serve(pl, api::public_router(app.clone())).with_graceful_shutdown(shutdown_signal());
            let b = axum::serve(il, api::merchant_router(app)).with_graceful_shutdown(shutdown_signal());
            let (ra, rb) = tokio::join!(a, b);
            ra?;
            rb?;
            Ok(())
        }
        Command::Worker { listen } => {
            let config = Config::from_env(|k| std::env::var(k).ok())?;
            anyhow::ensure!(config.webhook_signer.is_some(), "the worker signs webhooks: set WEBHOOK_KEY_FILE");
            let app = Arc::new(App::new(store(4)?, config)?);
            let l = tokio::net::TcpListener::bind(listen).await?;
            tracing::info!(%listen, "worker metrics listening");
            let server = axum::serve(l, api::worker_router(app.clone())).with_graceful_shutdown(shutdown_signal());
            let (rw, rs) = tokio::join!(worker::run(app, shutdown_signal()), server);
            rw?;
            rs?;
            Ok(())
        }
        Command::Migrate => {
            store(1)?.migrate().await?;
            println!("schema up to date");
            Ok(())
        }
        Command::Merchant { action: MerchantAction::Add { name, webhook_url, methods, key_out, key_file } } => {
            if let Some(u) = &webhook_url
                && !worker::webhook_url_allowed(u)
            {
                anyhow::bail!("the webhook URL must be https (or http to an in-cluster .svc host)");
            }
            let store = store(1)?;
            let key = match (&key_out, &key_file) {
                (Some(out), None) => {
                    let key = format!("cpk_{}", random_id(24));
                    write_secret(out, key.as_bytes())?;
                    key
                }
                (None, Some(file)) => {
                    let key = std::fs::read_to_string(file)?.trim().to_string();
                    if !(32..=128).contains(&key.len()) || !key.starts_with("cpk_") {
                        anyhow::bail!(
                            "{} does not hold a merchant API key (cpk_…, 32 to 128 characters)",
                            file.display()
                        );
                    }
                    if let Some(m) = store.merchant_by_key(&key).await? {
                        println!("merchant {} already has this key; nothing changed", m.id);
                        if let Some(note) = webhook_difference(m.webhook_url.as_deref(), webhook_url.as_deref()) {
                            println!("note: {note}");
                        }
                        return Ok(());
                    }
                    key
                }
                _ => anyhow::bail!("give --key-out or --key-file"),
            };
            let id = store.create_merchant(&name, &key, webhook_url.as_deref(), &methods).await?;
            match key_out {
                Some(out) => println!("merchant {id}; API key written to {}", out.display()),
                None => println!("merchant {id} created with the key from the key file"),
            }
            Ok(())
        }
        Command::Merchant { action: MerchantAction::RotateKey { id, key_out } } => {
            let key = format!("cpk_{}", random_id(24));
            write_secret(&key_out, key.as_bytes())?;
            if !store(1)?.rotate_merchant_key(id, &key).await? {
                anyhow::bail!("no merchant {id}");
            }
            println!("new API key for {id} written to {}", key_out.display());
            Ok(())
        }
        Command::Merchant { action: MerchantAction::SetWebhook { id, webhook_url, clear: _ } } => {
            if let Some(u) = &webhook_url
                && !worker::webhook_url_allowed(u)
            {
                anyhow::bail!("the webhook URL must be https (or http to an in-cluster .svc host)");
            }
            if !store(1)?.set_merchant_webhook(id, webhook_url.as_deref()).await? {
                anyhow::bail!("no merchant {id}");
            }
            match webhook_url {
                Some(u) => println!("merchant {id}: webhook address set to {u}"),
                None => println!("merchant {id}: webhook address removed (no webhooks are sent)"),
            }
            Ok(())
        }
        Command::Keygen { out } => {
            let seed = hex_seed();
            let signer = Signer::from_seed(&seed).map_err(|e| anyhow::anyhow!("{e}"))?;
            write_secret(&out, &seed)?;
            println!("{}", signer.public_hex());
            Ok(())
        }
    }
}

fn hex_seed() -> Vec<u8> {
    let s = random_id(32);
    (0..32).map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap_or(0)).collect()
}

fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .with_writer(std::io::stderr)
        .json()
        .init();
    let rt = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };
    match rt.block_on(run(Cli::parse())) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn the_command_line_is_consistent() {
        Cli::command().debug_assert();
    }

    #[test]
    fn set_webhook_takes_an_address_or_clear_but_not_both() {
        let id = "00000000-0000-4000-8000-000000000001";
        let parse = |args: &[&str]| {
            Cli::try_parse_from([&["chain-payments", "merchant", "set-webhook", "--id", id], args].concat())
        };
        assert!(parse(&["--webhook-url", "https://example.org/hook"]).is_ok());
        assert!(parse(&["--clear"]).is_ok());
        assert!(parse(&[]).is_err());
        assert!(parse(&["--clear", "--webhook-url", "https://example.org/hook"]).is_err());
    }

    #[test]
    fn add_names_a_stale_webhook_address_and_is_quiet_otherwise() {
        let old = "http://link-in-bio-api.link-in-bio.svc:8081/internal/v1/payments";
        let new = "http://link-in-bio-api.hosting.svc:8081/internal/v1/payments";
        let note = webhook_difference(Some(old), Some(new)).unwrap();
        assert!(note.contains(old) && note.contains(new) && note.contains("set-webhook"));
        assert!(webhook_difference(None, Some(new)).unwrap().contains("(none)"));
        assert_eq!(webhook_difference(Some(new), Some(new)), None);
        assert_eq!(webhook_difference(Some(old), None), None);
    }
}
