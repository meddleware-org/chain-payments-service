//! Configuration from the environment (instance values from a ConfigMap; keys from files mounted from Secrets). Every
//! value is checked at start; a process refuses to start on anything doubtful.

use std::collections::HashMap;
use std::time::Duration;

use chain_payments_core::quote::Signer;
use chain_payments_core::registry::Registry;

use crate::prices::Source;

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("{0} is not set")]
    Missing(&'static str),
    #[error("{0}: {1}")]
    Invalid(&'static str, String),
}

pub struct Config {
    pub registry: Registry,
    pub quote_signer: Signer,
    pub webhook_signer: Signer,
    /// Full node gRPC base URL per network (`SUI_GRPC_TESTNET`, `SUI_GRPC_MAINNET`, …).
    pub grpc: HashMap<String, String>,
    pub sources: Vec<Source>,
    pub gecko_ids: HashMap<String, String>,
    pub min_sources: usize,
    pub max_spread_bps: u128,
    pub quote_ttl: Duration,
    pub price_cache: Duration,
    /// Browser origins allowed to call the public session API (the merchants' checkout pages).
    pub allowed_origins: Vec<String>,
    /// Quotes one session may ask for.
    pub max_quotes_per_session: i64,
}

fn read_seed(var: &'static str, get: &impl Fn(&str) -> Option<String>) -> Result<Signer, ConfigError> {
    let path = get(var).ok_or(ConfigError::Missing(var))?;
    let raw = std::fs::read(&path).map_err(|e| ConfigError::Invalid(var, format!("cannot read the key file: {e}")))?;
    let seed = if raw.len() == 32 {
        raw
    } else {
        let text = String::from_utf8_lossy(&raw).trim().to_string();
        hex::decode(&text)
            .map_err(|_| ConfigError::Invalid(var, "the key file is neither 32 bytes nor 64 hex characters".into()))?
    };
    if seed.len() != 32 {
        return Err(ConfigError::Invalid(var, "the key must be 32 bytes".into()));
    }
    Signer::from_seed(&seed).map_err(|e| ConfigError::Invalid(var, e.to_string()))
}

fn bounded<T: std::str::FromStr + PartialOrd + Copy>(
    get: &impl Fn(&str) -> Option<String>,
    var: &'static str,
    default: T,
    min: T,
    max: T,
) -> Result<T, ConfigError> {
    match get(var) {
        None => Ok(default),
        Some(v) => match v.trim().parse::<T>() {
            Ok(n) if n >= min && n <= max => Ok(n),
            _ => Err(ConfigError::Invalid(var, "out of range".into())),
        },
    }
}

impl Config {
    pub fn from_env(get: impl Fn(&str) -> Option<String>) -> Result<Self, ConfigError> {
        let methods_file = get("METHODS_FILE").ok_or(ConfigError::Missing("METHODS_FILE"))?;
        let bytes = std::fs::read(&methods_file).map_err(|e| ConfigError::Invalid("METHODS_FILE", e.to_string()))?;
        let registry = Registry::from_json(&bytes).map_err(|e| ConfigError::Invalid("METHODS_FILE", e.to_string()))?;
        let quote_signer = read_seed("QUOTE_KEY_FILE", &get)?;
        let webhook_signer = read_seed("WEBHOOK_KEY_FILE", &get)?;
        if quote_signer.public_hex() == webhook_signer.public_hex() {
            return Err(ConfigError::Invalid("WEBHOOK_KEY_FILE", "must differ from the quote key".into()));
        }
        let mut grpc = HashMap::new();
        for m in &registry.methods {
            let var = format!("SUI_GRPC_{}", m.network.to_ascii_uppercase());
            let url =
                get(&var).ok_or_else(|| ConfigError::Invalid("SUI_GRPC_<NETWORK>", format!("{var} is not set")))?;
            let ok = url.starts_with("https://") || (m.network == "localnet" && url.starts_with("http://127.0.0.1:"));
            if !ok {
                return Err(ConfigError::Invalid("SUI_GRPC_<NETWORK>", format!("{var} must be https")));
            }
            grpc.insert(m.network.clone(), url);
        }
        let sources: Vec<Source> = get("PRICE_SOURCES")
            .unwrap_or_else(|| "kraken,coinbase,coingecko".into())
            .split(',')
            .map(|s| {
                Source::parse(s).ok_or_else(|| ConfigError::Invalid("PRICE_SOURCES", format!("unknown source {s}")))
            })
            .collect::<Result<_, _>>()?;
        if sources.is_empty() || sources.len() > 3 {
            return Err(ConfigError::Invalid("PRICE_SOURCES", "one to three sources".into()));
        }
        let gecko_ids = get("COINGECKO_IDS")
            .unwrap_or_else(|| "SUI=sui,USDC=usd-coin".into())
            .split(',')
            .filter_map(|p| p.split_once('=').map(|(k, v)| (k.trim().to_string(), v.trim().to_string())))
            .collect();
        let min_sources = bounded(&get, "PRICE_MIN_SOURCES", 2usize, 1, 3)?;
        if min_sources > sources.len() {
            return Err(ConfigError::Invalid("PRICE_MIN_SOURCES", "more than the configured sources".into()));
        }
        let allowed_origins: Vec<String> = get("ALLOWED_ORIGINS")
            .unwrap_or_default()
            .split(',')
            .map(|s| s.trim().trim_end_matches('/').to_string())
            .filter(|s| !s.is_empty())
            .collect();
        for o in &allowed_origins {
            let ok =
                o.starts_with("https://") || o.starts_with("http://127.0.0.1:") || o.starts_with("http://localhost:");
            if !ok || o.matches('/').count() != 2 {
                return Err(ConfigError::Invalid("ALLOWED_ORIGINS", format!("{o} is not an origin")));
            }
        }
        Ok(Self {
            registry,
            quote_signer,
            webhook_signer,
            grpc,
            sources,
            gecko_ids,
            min_sources,
            max_spread_bps: bounded(&get, "PRICE_MAX_SPREAD_BPS", 200u128, 10, 1000)?,
            quote_ttl: Duration::from_secs(bounded(&get, "QUOTE_TTL_SECS", 120u64, 30, 300)?),
            price_cache: Duration::from_secs(bounded(&get, "PRICE_CACHE_SECS", 30u64, 5, 300)?),
            allowed_origins,
            max_quotes_per_session: bounded(&get, "MAX_QUOTES_PER_SESSION", 30i64, 1, 500)?,
        })
    }
}
