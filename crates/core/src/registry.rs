//! The payment methods an instance offers: chain, network, coin type, decimals and the symbol prices are fetched for.
//! Instance configuration (a JSON file), checked here. Adding a chain is a new `chain` value plus its module.

use serde::{Deserialize, Serialize};

use crate::quote::canonical_coin_type;

/// One payment method: a chain, network and coin an instance accepts, and where the money goes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Method {
    /// Stable id, for example `sui-testnet:SUI`.
    pub id: String,
    /// The chain (only `sui` is supported).
    pub chain: String,
    /// The network (`mainnet`, `testnet`, `devnet` or `localnet`).
    pub network: String,
    /// The coin type in the canonical long form.
    pub coin_type: String,
    /// The symbol shown to the buyer.
    pub symbol: String,
    /// The coin's decimal places.
    pub decimals: u8,
    /// The symbol price sources are asked for (`SUI`, `USDC`).
    pub price_symbol: String,
    /// A stablecoin pegged to GBP needs no price source (1 coin = £1).
    #[serde(default)]
    pub gbp_pegged: bool,
    /// The on-chain package that defines `Paid` for this chain/network.
    pub package_id: String,
    /// The merchant object on-chain that payments with this method go to.
    pub merchant_object: String,
    /// The address the merchant object must pay (its `recipient`). The worker compares it with the chain: a different or
    /// a pending recipient stops quoting for the merchant. Absent: only a pending recipient stops it.
    #[serde(default)]
    pub recipient: Option<String>,
}

/// The list of methods an instance offers.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Registry {
    /// The methods, in the order they are shown.
    pub methods: Vec<Method>,
}

/// A problem with the methods file, naming the method and what is wrong.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("payment methods: {0}")]
pub struct RegistryError(pub String);

/// Whether the text is a `0x`-prefixed hex object id of at most 64 digits.
fn is_object_id(s: &str) -> bool {
    let h = s.trim_start_matches("0x");
    s.starts_with("0x") && !h.is_empty() && h.len() <= 64 && h.bytes().all(|b| b.is_ascii_hexdigit())
}

impl Registry {
    /// Parse and validate the methods file: unique ids, a known chain and network, canonical coin types, sane symbols and decimals, well-formed ids.
    pub fn from_json(bytes: &[u8]) -> Result<Self, RegistryError> {
        // Unknown fields are refused by the type, so a misspelt key is an error, not a silent default.
        let mut r: Registry = serde_json::from_slice(bytes).map_err(|e| RegistryError(e.to_string()))?;
        // Method ids must be unique: a session names its methods by id.
        let mut seen = std::collections::BTreeSet::new();
        for m in &mut r.methods {
            if !seen.insert(m.id.clone()) {
                return Err(RegistryError(format!("duplicate id {}", m.id)));
            }
            // Adding a chain is a new value here and a new chain module, not a configuration change.
            if m.chain != "sui" {
                return Err(RegistryError(format!("{}: unsupported chain {}", m.id, m.chain)));
            }
            // Only the networks Sui has.
            if !["mainnet", "testnet", "devnet", "localnet"].contains(&m.network.as_str()) {
                return Err(RegistryError(format!("{}: unknown network {}", m.id, m.network)));
            }
            // Store the canonical form, so every later comparison is exact.
            m.coin_type = canonical_coin_type(&m.coin_type).map_err(|e| RegistryError(format!("{}: {e}", m.id)))?;
            // A symbol is letters and digits only (it is shown and used in a price lookup); decimals are bounded.
            if m.decimals > 18 || !m.symbol.bytes().all(|b| b.is_ascii_alphanumeric()) || m.symbol.is_empty() {
                return Err(RegistryError(format!("{}: bad symbol or decimals", m.id)));
            }
            // Both ids must be `0x` hex, so a typo is caught at start-up rather than at the first payment.
            if !is_object_id(&m.package_id) || !is_object_id(&m.merchant_object) {
                return Err(RegistryError(format!("{}: bad package or merchant object id", m.id)));
            }
        }
        Ok(r)
    }

    /// The method with this id, if there is one.
    pub fn get(&self, id: &str) -> Option<&Method> {
        self.methods.iter().find(|m| m.id == id)
    }
}

/// Unit tests for this module.
#[cfg(test)]
mod tests {
    use super::*;

    /// Parses and canonicalises.
    #[test]
    fn parses_and_canonicalises() {
        let r = Registry::from_json(
            br#"{"methods":[{"id":"sui-testnet:SUI","chain":"sui","network":"testnet","coinType":"0x2::sui::SUI","symbol":"SUI","decimals":9,"priceSymbol":"SUI","packageId":"0x5f67","merchantObject":"0xabc"}]}"#,
        )
        .unwrap();
        assert!(r.get("sui-testnet:SUI").unwrap().coin_type.starts_with("0000"));
        assert!(Registry::from_json(br#"{"methods":[{"id":"x","chain":"eth","network":"testnet","coinType":"0x2::sui::SUI","symbol":"SUI","decimals":9,"priceSymbol":"SUI","packageId":"0x1","merchantObject":"0x2"}]}"#).is_err());
    }
}
