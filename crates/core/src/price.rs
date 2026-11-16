//! Combining price sources: the quote price is the median of at least `min_sources` samples, and only when every sample
//! is within `max_spread_bps` of every other; otherwise there is no quote (the merchant's list price, if any, applies).

use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Sample {
    pub source: &'static str,
    /// Pico-pounds per whole coin.
    pub price_pico: u128,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PriceError {
    #[error("only {got} price source(s) answered; {need} are needed")]
    TooFewSources { got: usize, need: usize },
    #[error("the price sources disagree by {spread_bps} basis points (at most {max_bps})")]
    Disagree { spread_bps: u128, max_bps: u128 },
}

/// The agreed price and the samples behind it (kept with every quote as its valuation record).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Agreed {
    pub price_pico: u128,
    pub samples: Vec<Sample>,
    pub spread_bps: u128,
}

pub fn agree(mut samples: Vec<Sample>, min_sources: usize, max_spread_bps: u128) -> Result<Agreed, PriceError> {
    samples.retain(|s| s.price_pico > 0);
    if samples.len() < min_sources.max(1) {
        return Err(PriceError::TooFewSources { got: samples.len(), need: min_sources.max(1) });
    }
    samples.sort_by_key(|s| s.price_pico);
    let lo = samples[0].price_pico;
    let hi = samples[samples.len() - 1].price_pico;
    let spread_bps = (hi - lo).saturating_mul(10_000) / lo;
    if spread_bps > max_spread_bps {
        return Err(PriceError::Disagree { spread_bps, max_bps: max_spread_bps });
    }
    let n = samples.len();
    let price_pico = if n % 2 == 1 {
        samples[n / 2].price_pico
    } else {
        (samples[n / 2 - 1].price_pico + samples[n / 2].price_pico) / 2
    };
    Ok(Agreed { price_pico, samples, spread_bps })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(source: &'static str, p: u128) -> Sample {
        Sample { source, price_pico: p }
    }

    #[test]
    fn median_of_agreeing_sources() {
        let a = agree(vec![s("a", 1000), s("b", 1010), s("c", 1005)], 2, 200).unwrap();
        assert_eq!(a.price_pico, 1005);
        let a = agree(vec![s("a", 1000), s("b", 1010)], 2, 200).unwrap();
        assert_eq!(a.price_pico, 1005);
    }

    #[test]
    fn refuses_disagreement_and_too_few() {
        assert!(matches!(agree(vec![s("a", 1000), s("b", 1100)], 2, 200), Err(PriceError::Disagree { .. })));
        assert!(matches!(agree(vec![s("a", 1000)], 2, 200), Err(PriceError::TooFewSources { got: 1, need: 2 })));
        assert!(matches!(agree(vec![s("a", 1000), s("b", 0)], 2, 200), Err(PriceError::TooFewSources { .. })));
    }
}
