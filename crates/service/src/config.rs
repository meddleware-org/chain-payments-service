//! Configuration from the environment (instance values from a ConfigMap; keys from files mounted from Secrets). Every
//! value is checked at start; a process refuses to start on anything doubtful.

use std::collections::HashMap;
use std::time::Duration;

use chain_payments_core::quote::Signer;
use chain_payments_core::registry::Registry;

use crate::prices::Source;

/// Why the configuration was refused. A message names the variable and what is wrong, never a secret or a URL.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// A required variable is not set.
    #[error("{0} is not set")]
    Missing(&'static str),
    /// A variable is set to something that is not acceptable, with the reason.
    #[error("{0}: {1}")]
    Invalid(&'static str, String),
}

/// The validated configuration of one process: the payment methods, the keys it holds, the nodes and price sources, and the limits.
pub struct Config {
    /// The payment methods this instance offers.
    pub registry: Registry,
    /// The quote signing key: only the API (`serve`) holds it (`QUOTE_KEY_FILE`).
    pub quote_signer: Option<Signer>,
    /// The quote key's public half (hex): from the signer, or `QUOTE_PUBLIC_KEY` where the key is not held (the worker
    /// compares it with each merchant's on-chain key).
    pub quote_public: String,
    /// The webhook signing key: only the worker holds it (`WEBHOOK_KEY_FILE`).
    pub webhook_signer: Option<Signer>,
    /// The webhook key's public half (hex): from the signer, or `WEBHOOK_PUBLIC_KEY` (the API publishes it).
    pub webhook_public: String,
    /// GraphQL endpoint per network (`SUI_GRAPHQL_TESTNET`, …), used only to find `Paid` events no checkout submitted;
    /// every candidate is still verified through the full nodes above.
    pub graphql: HashMap<String, String>,
    /// Full node gRPC base URLs per network (`SUI_GRPC_TESTNET`, `SUI_GRPC_MAINNET`, …; comma-separated). Mainnet needs
    /// two nodes on different hosts, run by different operators: a payment counts only when both report it the same way.
    pub grpc: HashMap<String, Vec<String>>,
    /// The price sources, one to three.
    pub sources: Vec<Source>,
    /// The CoinGecko id for each price symbol.
    pub gecko_ids: HashMap<String, String>,
    /// How many sources must agree on a price (at least two).
    pub min_sources: usize,
    /// The widest disagreement between sources that still gives a price, in basis points.
    pub max_spread_bps: u128,
    /// How long a signed quote is valid.
    pub quote_ttl: Duration,
    /// How long an agreed price is reused.
    pub price_cache: Duration,
    /// Browser origins allowed to call the public session API (the merchants' checkout pages).
    pub allowed_origins: Vec<String>,
    /// Quotes one session may ask for.
    pub max_quotes_per_session: i64,
}

/// Read a 32-byte ed25519 seed from the file the variable names (raw, or as 64 hex characters); the errors name the variable and never the content.
fn read_seed(var: &'static str, get: &impl Fn(&str) -> Option<String>) -> Result<Signer, ConfigError> {
    // The key lives in a file mounted from a Secret, never in an environment variable.
    let path = get(var).ok_or(ConfigError::Missing(var))?;
    // A read failure names the variable and the cause, never the key.
    let raw = std::fs::read(&path).map_err(|e| ConfigError::Invalid(var, format!("cannot read the key file: {e}")))?;
    // Either 32 raw bytes or 64 hex characters.
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
    // The signer rejects a seed that is not valid.
    Signer::from_seed(&seed).map_err(|e| ConfigError::Invalid(var, e.to_string()))
}

/// Read a number from a variable within bounds, or use the default; an out-of-range value names the variable, not the number.
fn bounded<T: std::str::FromStr + PartialOrd + Copy>(
    get: &impl Fn(&str) -> Option<String>,
    var: &'static str,
    default: T,
    min: T,
    max: T,
) -> Result<T, ConfigError> {
    match get(var) {
        // An unset variable takes the default.
        None => Ok(default),
        Some(v) => match v.trim().parse::<T>() {
            // Inside the bounds; outside is an error that names the variable.
            Ok(n) if n >= min && n <= max => Ok(n),
            _ => Err(ConfigError::Invalid(var, "out of range".into())),
        },
    }
}

impl Config {
    /// Read and check every setting, refusing to start on anything doubtful.
    pub fn from_env(get: impl Fn(&str) -> Option<String>) -> Result<Self, ConfigError> {
        // The payment methods come from a file mounted from a ConfigMap, checked by the registry parser.
        let methods_file = get("METHODS_FILE").ok_or(ConfigError::Missing("METHODS_FILE"))?;
        // The registry is read as bytes and parsed by the core crate.
        let bytes = std::fs::read(&methods_file).map_err(|e| ConfigError::Invalid("METHODS_FILE", e.to_string()))?;
        let registry = Registry::from_json(&bytes).map_err(|e| ConfigError::Invalid("METHODS_FILE", e.to_string()))?;
        // Each process holds only the key it signs with, and the other one's public half.
        // Each process holds only the key it signs with, and the public half of the other.
        let quote_signer = get("QUOTE_KEY_FILE").map(|_| read_seed("QUOTE_KEY_FILE", &get)).transpose()?;
        let webhook_signer = get("WEBHOOK_KEY_FILE").map(|_| read_seed("WEBHOOK_KEY_FILE", &get)).transpose()?;
        // The public half of a key: derived from the signer when this process holds it (a configured one must match), else read from the variable.
        let public = |var: &'static str, signer: &Option<Signer>, file: &'static str| -> Result<String, ConfigError> {
            match (signer, get(var)) {
                // A configured public key must match the key file, so the two cannot drift.
                (Some(s), Some(p)) if !p.trim().eq_ignore_ascii_case(&s.public_hex()) => {
                    Err(ConfigError::Invalid(var, format!("does not match {file}")))
                }
                // The public half is derived from the key this process holds.
                (Some(s), _) => Ok(s.public_hex()),
                // A process that does not hold the key takes the public half from its configuration.
                (None, Some(p)) => {
                    let p = p.trim().to_ascii_lowercase();
                    if p.len() == 64 && p.bytes().all(|b| b.is_ascii_hexdigit()) {
                        Ok(p)
                    } else {
                        Err(ConfigError::Invalid(var, "64 hex characters".into()))
                    }
                }
                // A process with neither the key nor its public half cannot compare anything.
                (None, None) => Err(ConfigError::Invalid(var, format!("set {file} or {var}"))),
            }
        };
        let quote_public = public("QUOTE_PUBLIC_KEY", &quote_signer, "QUOTE_KEY_FILE")?;
        let webhook_public = public("WEBHOOK_PUBLIC_KEY", &webhook_signer, "WEBHOOK_KEY_FILE")?;
        // The two keys must differ, so a signature for one use is never valid for the other.
        if quote_public == webhook_public {
            return Err(ConfigError::Invalid("WEBHOOK_KEY_FILE", "must differ from the quote key".into()));
        }
        let mut grpc = HashMap::new();
        let mut graphql = HashMap::new();
        // Every network a method uses needs a full node and, optionally, a GraphQL endpoint.
        for m in &registry.methods {
            // The variable for this network, for example `SUI_GRPC_TESTNET`.
            let var = format!("SUI_GRPC_{}", m.network.to_ascii_uppercase());
            let raw =
                get(&var).ok_or_else(|| ConfigError::Invalid("SUI_GRPC_<NETWORK>", format!("{var} is not set")))?;
            // Several nodes are comma-separated.
            let urls: Vec<String> = raw.split(',').map(|u| u.trim().to_string()).filter(|u| !u.is_empty()).collect();
            for url in &urls {
                let ok =
                    url.starts_with("https://") || (m.network == "localnet" && url.starts_with("http://127.0.0.1:"));
                if !ok {
                    return Err(ConfigError::Invalid("SUI_GRPC_<NETWORK>", format!("{var} must be https")));
                }
            }
            // The host of each URL, so the nodes can be required to differ.
            let host = |u: &str| {
                u.split("://").nth(1).unwrap_or("").split(['/', ':']).next().unwrap_or("").to_ascii_lowercase()
            };
            // Sort and de-duplicate the hosts to compare their count with the URLs.
            let mut hosts: Vec<String> = urls.iter().map(|u| host(u)).collect();
            hosts.sort();
            hosts.dedup();
            // Several nodes must be on different hosts, or they would not be independent.
            if urls.is_empty() || hosts.len() != urls.len() {
                return Err(ConfigError::Invalid(
                    "SUI_GRPC_<NETWORK>",
                    format!("{var}: one or more full nodes, each on its own host"),
                ));
            }
            // Mainnet needs two nodes from different operators: a payment counts only when both agree.
            if m.network == "mainnet" && urls.len() < 2 {
                return Err(ConfigError::Invalid(
                    "SUI_GRPC_<NETWORK>",
                    format!("{var}: mainnet needs two full nodes from different operators (comma-separated)"),
                ));
            }
            // Keep the validated list for the network.
            grpc.insert(m.network.clone(), urls);
            let gvar = format!("SUI_GRAPHQL_{}", m.network.to_ascii_uppercase());
            // The public GraphQL endpoints are the default, used only to find payments nobody submitted.
            let default = match m.network.as_str() {
                "testnet" => Some("https://graphql.testnet.sui.io/graphql"),
                "mainnet" => Some("https://graphql.mainnet.sui.io/graphql"),
                _ => None,
            };
            // A GraphQL endpoint is optional; without one only the unsubmitted-payment search is off.
            if let Some(g) = get(&gvar).or(default.map(String::from)) {
                let ok = g.starts_with("https://") || (m.network == "localnet" && g.starts_with("http://127.0.0.1:"));
                if !ok {
                    return Err(ConfigError::Invalid("SUI_GRAPHQL_<NETWORK>", format!("{gvar} must be https")));
                }
                graphql.insert(m.network.clone(), g);
            }
        }
        // The price sources, comma-separated; the defaults are three independent ones.
        let sources: Vec<Source> = get("PRICE_SOURCES")
            .unwrap_or_else(|| "kraken,coinbase,coingecko".into())
            .split(',')
            .map(|s| {
                Source::parse(s).ok_or_else(|| ConfigError::Invalid("PRICE_SOURCES", format!("unknown source {s}")))
            })
            .collect::<Result<_, _>>()?;
        // Between one and three sources; the price code asks at most three.
        if sources.is_empty() || sources.len() > 3 {
            return Err(ConfigError::Invalid("PRICE_SOURCES", "one to three sources".into()));
        }
        // Symbol to CoinGecko id pairs (`SUI=sui`).
        let gecko_ids = get("COINGECKO_IDS")
            .unwrap_or_else(|| "SUI=sui,USDC=usd-coin".into())
            .split(',')
            .filter_map(|p| p.split_once('=').map(|(k, v)| (k.trim().to_string(), v.trim().to_string())))
            .collect();
        // At least two sources always (ADR-0011 §3): one source alone has nothing to agree with.
        // At least two sources always (ADR-0011): one source alone has nothing to agree with.
        let min_sources = bounded(&get, "PRICE_MIN_SOURCES", 2usize, 2, 3)?;
        if min_sources > sources.len() {
            return Err(ConfigError::Invalid("PRICE_MIN_SOURCES", "more than the configured sources".into()));
        }
        // The checkout origins allowed to call the public API, without a trailing slash.
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
                return Err(ConfigError::Invalid(
                    "ALLOWED_ORIGINS",
                    "an entry is not an origin (https://host[:port], no path)".to_string(),
                ));
            }
        }
        // Every value has been checked above: building the struct cannot fail.
        Ok(Self {
            registry,
            quote_signer,
            quote_public,
            webhook_signer,
            webhook_public,
            graphql,
            grpc,
            sources,
            gecko_ids,
            min_sources,
            // Two percent by default; never below 0.1 % or above 10 %.
            max_spread_bps: bounded(&get, "PRICE_MAX_SPREAD_BPS", 200u128, 10, 1000)?,
            // A quote lasts two minutes by default: long enough to approve in a wallet, short enough that the price is fresh.
            quote_ttl: Duration::from_secs(bounded(&get, "QUOTE_TTL_SECS", 120u64, 30, 300)?),
            price_cache: Duration::from_secs(bounded(&get, "PRICE_CACHE_SECS", 30u64, 5, 300)?),
            allowed_origins,
            max_quotes_per_session: bounded(&get, "MAX_QUOTES_PER_SESSION", 30i64, 1, 500)?,
        })
    }
}

/// Unit tests for this module.
#[cfg(test)]
mod tests {
    use super::*;

    /// The test environment: valid files in `dir`, with `extra` overriding or adding variables.
    fn env(dir: &std::path::Path, extra: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(dir.join("q.key"), [1u8; 32]).unwrap();
        std::fs::write(dir.join("w.key"), [2u8; 32]).unwrap();
        std::fs::write(
            dir.join("methods.json"),
            r#"{"methods":[{"id":"sui-testnet:SUI","chain":"sui","network":"testnet","coinType":"0x2::sui::SUI","symbol":"SUI","decimals":9,"priceSymbol":"SUI","packageId":"0x5f67","merchantObject":"0x29d6"}]}"#,
        )
        .unwrap();
        let mut m: HashMap<String, String> = [
            ("METHODS_FILE", dir.join("methods.json").display().to_string()),
            ("QUOTE_KEY_FILE", dir.join("q.key").display().to_string()),
            ("WEBHOOK_KEY_FILE", dir.join("w.key").display().to_string()),
            ("SUI_GRPC_TESTNET", "https://fullnode.testnet.sui.io:443".to_string()),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect();
        for (k, v) in extra {
            m.insert((*k).to_string(), (*v).to_string());
        }
        move |k: &str| m.get(k).cloned()
    }

    /// A fresh temporary directory for key files.
    fn dir(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("cp-config-{name}-{}", std::process::id()))
    }

    /// Defaults are accepted.
    #[test]
    fn defaults_are_accepted() {
        let c = Config::from_env(env(&dir("ok"), &[])).unwrap();
        assert_eq!((c.min_sources, c.max_spread_bps, c.quote_ttl.as_secs()), (2, 200, 120));
    }

    /// A single price source is never enough.
    #[test]
    fn a_single_price_source_is_never_enough() {
        let e = Config::from_env(env(&dir("one"), &[("PRICE_MIN_SOURCES", "1")])).err().unwrap();
        assert!(e.to_string().contains("PRICE_MIN_SOURCES"), "{e}");
        let e = Config::from_env(env(&dir("few"), &[("PRICE_SOURCES", "kraken")])).err().unwrap();
        assert!(e.to_string().contains("PRICE_MIN_SOURCES"), "{e}");
    }

    /// Doubtful values are refused.
    #[test]
    fn doubtful_values_are_refused() {
        let d = dir("bad");
        let same = d.join("q.key").display().to_string();
        for extra in [
            [("WEBHOOK_KEY_FILE", same.as_str())],
            [("SUI_GRPC_TESTNET", "http://fullnode.testnet.sui.io")],
            [("ALLOWED_ORIGINS", "https://a.example/path")],
            [("QUOTE_TTL_SECS", "3600")],
            [("SUI_GRPC_TESTNET", "https://a.example,https://a.example:443")],
        ] {
            assert!(Config::from_env(env(&d, &extra)).is_err(), "{extra:?}");
        }
    }

    /// Each process holds only its own key.
    #[test]
    fn each_process_holds_only_its_own_key() {
        let d = dir("keys");
        let q = env(&d, &[]);
        let full = Config::from_env(&q).unwrap();
        let (qp, wp) = (full.quote_public.clone(), full.webhook_public.clone());
        // The API: the quote key and the webhook's public half.
        let api = Config::from_env(|k: &str| match k {
            "WEBHOOK_KEY_FILE" => None,
            "WEBHOOK_PUBLIC_KEY" => Some(wp.clone()),
            _ => q(k),
        })
        .unwrap();
        assert!(api.quote_signer.is_some() && api.webhook_signer.is_none());
        assert_eq!(api.webhook_public, wp);
        // The worker: the webhook key and the quote key's public half.
        let worker = Config::from_env(|k: &str| match k {
            "QUOTE_KEY_FILE" => None,
            "QUOTE_PUBLIC_KEY" => Some(qp.clone()),
            _ => q(k),
        })
        .unwrap();
        assert!(worker.quote_signer.is_none() && worker.webhook_signer.is_some());
        // Neither half: refused; a public half that contradicts the key file: refused.
        assert!(Config::from_env(|k: &str| if k == "QUOTE_KEY_FILE" { None } else { q(k) }).is_err());
        assert!(
            Config::from_env(|k: &str| if k == "QUOTE_PUBLIC_KEY" { Some("00".repeat(32)) } else { q(k) }).is_err()
        );
    }

    /// Mainnet needs two full nodes on different hosts.
    #[test]
    fn mainnet_needs_two_full_nodes_on_different_hosts() {
        let d = dir("mainnet");
        std::fs::create_dir_all(&d).unwrap();
        let methods = d.join("mainnet.json");
        std::fs::write(
            &methods,
            r#"{"methods":[{"id":"sui-mainnet:SUI","chain":"sui","network":"mainnet","coinType":"0x2::sui::SUI","symbol":"SUI","decimals":9,"priceSymbol":"SUI","packageId":"0x5f67","merchantObject":"0x29d6"}]}"#,
        )
        .unwrap();
        let m = methods.display().to_string();
        let with =
            |nodes: &str| Config::from_env(env(&d, &[("METHODS_FILE", m.as_str()), ("SUI_GRPC_MAINNET", nodes)]));
        let err = with("https://fullnode.mainnet.sui.io:443").err().unwrap();
        assert!(err.to_string().contains("two full nodes"), "{err}");
        let c = with("https://fullnode.mainnet.sui.io:443, https://sui-mainnet.example.org").unwrap();
        assert_eq!(c.grpc["mainnet"].len(), 2);
    }
}
