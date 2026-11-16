//! Price sources (free, public, no key, no user data sent): Kraken, Coinbase and CoinGecko, each asked for the coin's price
//! in GBP. The answers are combined by `chain_payments_core::price::agree` (median, spread guard). A short cache keeps the
//! sources from being asked more than every `cache_secs` per symbol.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use chain_payments_core::money::parse_price_pico;
use chain_payments_core::price::{Agreed, PriceError, Sample, agree};
use serde_json::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    Kraken,
    Coinbase,
    CoinGecko,
}

impl Source {
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim() {
            "kraken" => Some(Source::Kraken),
            "coinbase" => Some(Source::Coinbase),
            "coingecko" => Some(Source::CoinGecko),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Source::Kraken => "kraken",
            Source::Coinbase => "coinbase",
            Source::CoinGecko => "coingecko",
        }
    }

    fn url(self, symbol: &str, gecko_id: Option<&str>) -> Option<String> {
        match self {
            Source::Kraken => Some(format!("https://api.kraken.com/0/public/Ticker?pair={symbol}GBP")),
            Source::Coinbase => Some(format!("https://api.coinbase.com/v2/prices/{symbol}-GBP/spot")),
            Source::CoinGecko => {
                gecko_id.map(|id| format!("https://api.coingecko.com/api/v3/simple/price?ids={id}&vs_currencies=gbp"))
            }
        }
    }

    /// Reads the GBP price out of a source's reply (pico-pounds per coin).
    pub fn read(self, body: &Value, gecko_id: Option<&str>) -> Option<u128> {
        let text = match self {
            // Kraken: the mid of the best ask and bid of the (only) pair in `result`.
            Source::Kraken => {
                if body["error"].as_array().is_some_and(|e| !e.is_empty()) {
                    return None;
                }
                let pair = body["result"].as_object()?.values().next()?;
                let ask = parse_price_pico(pair["a"][0].as_str()?).ok()?;
                let bid = parse_price_pico(pair["b"][0].as_str()?).ok()?;
                if bid > ask {
                    return None;
                }
                return Some((ask + bid) / 2);
            }
            Source::Coinbase => {
                if body["data"]["currency"].as_str() != Some("GBP") {
                    return None;
                }
                body["data"]["amount"].as_str()?.to_string()
            }
            Source::CoinGecko => {
                let v = &body[gecko_id?]["gbp"];
                // A JSON number: format without exponent.
                let f = v.as_f64()?;
                if !(f.is_finite() && f > 0.0) {
                    return None;
                }
                format!("{f:.12}")
            }
        };
        parse_price_pico(&text).ok()
    }
}

pub struct Prices {
    client: reqwest::Client,
    sources: Vec<Source>,
    gecko_ids: HashMap<String, String>,
    min_sources: usize,
    max_spread_bps: u128,
    cache_for: Duration,
    cache: Mutex<HashMap<String, (Instant, Agreed)>>,
}

impl Prices {
    pub fn new(
        sources: Vec<Source>,
        gecko_ids: HashMap<String, String>,
        min_sources: usize,
        max_spread_bps: u128,
        cache_for: Duration,
    ) -> anyhow::Result<Self> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let client = reqwest::Client::builder()
            .user_agent(concat!("chain-payments/", env!("CARGO_PKG_VERSION")))
            .redirect(reqwest::redirect::Policy::none())
            .https_only(true)
            .no_proxy()
            .connect_timeout(Duration::from_secs(4))
            .timeout(Duration::from_secs(6))
            .build()?;
        Ok(Self {
            client,
            sources,
            gecko_ids,
            min_sources,
            max_spread_bps,
            cache_for,
            cache: Mutex::new(HashMap::new()),
        })
    }

    async fn ask(&self, source: Source, symbol: &str) -> Option<Sample> {
        let gecko = self.gecko_ids.get(symbol).map(String::as_str);
        let url = source.url(symbol, gecko)?;
        let r = self.client.get(url).header("accept", "application/json").send().await.ok()?;
        if !r.status().is_success() {
            return None;
        }
        let bytes = r.bytes().await.ok()?;
        if bytes.len() > 64 * 1024 {
            return None;
        }
        let body: Value = serde_json::from_slice(&bytes).ok()?;
        let price_pico = source.read(&body, gecko)?;
        Some(Sample { source: source.name(), price_pico })
    }

    /// The agreed GBP price of `symbol`, from the cache when fresh.
    pub async fn price(&self, symbol: &str) -> Result<Agreed, PriceError> {
        if let Ok(c) = self.cache.lock()
            && let Some((at, a)) = c.get(symbol)
            && at.elapsed() < self.cache_for
        {
            return Ok(a.clone());
        }
        // At most three sources, asked at the same time.
        let nth = |i: usize| async move {
            match self.sources.get(i) {
                Some(s) => self.ask(*s, symbol).await,
                None => None,
            }
        };
        let (a, b, c) = tokio::join!(nth(0), nth(1), nth(2));
        let agreed = agree([a, b, c].into_iter().flatten().collect(), self.min_sources, self.max_spread_bps)?;
        if let Ok(mut c) = self.cache.lock() {
            c.insert(symbol.to_string(), (Instant::now(), agreed.clone()));
        }
        Ok(agreed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn reads_each_sources_live_format() {
        // Shapes recorded from the live APIs on 2026-11-16.
        let kraken = json!({"error":[],"result":{"SUIGBP":{"a":["0.54180000","4371","4371.000"],"b":["0.54130000","1401","1401.000"]}}});
        assert_eq!(Source::Kraken.read(&kraken, None), Some(541_550_000_000));
        let coinbase = json!({"data":{"amount":"0.541369315156065648","base":"SUI","currency":"GBP"}});
        assert_eq!(Source::Coinbase.read(&coinbase, None), Some(541_369_315_156));
        let gecko = json!({"sui":{"gbp":0.541989}});
        assert_eq!(Source::CoinGecko.read(&gecko, Some("sui")), Some(541_989_000_000));
        assert_eq!(Source::Kraken.read(&json!({"error":["EQuery:Unknown asset pair"]}), None), None);
        assert_eq!(Source::Coinbase.read(&json!({"data":{"amount":"1","currency":"USD"}}), None), None);
        assert_eq!(Source::CoinGecko.read(&json!({"sui":{"gbp":-1}}), Some("sui")), None);
    }
}
