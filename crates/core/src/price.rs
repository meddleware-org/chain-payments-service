//! Combining price sources: the quote price is the median of at least `min_sources` samples, and only when every sample
//! is within `max_spread_bps` of every other; otherwise there is no quote (the merchant's list price, if any, applies).

use serde::Serialize;

/// One price from one source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Sample {
    /// The source's name, for the valuation record (never a URL).
    pub source: &'static str,
    /// Pico-pounds per whole coin.
    pub price_pico: u128,
}

/// Why no agreed price exists.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PriceError {
    /// Fewer sources answered than the minimum; there is no quote.
    #[error("only {got} price source(s) answered; {need} are needed")]
    TooFewSources {
        /// How many sources answered with a usable price.
        got: usize,
        /// How many were needed.
        need: usize,
    },
    /// The sources disagree by more than the allowed spread; there is no quote.
    #[error("the price sources disagree by {spread_bps} basis points (at most {max_bps})")]
    Disagree {
        /// The spread between the lowest and highest sample, in basis points.
        spread_bps: u128,
        /// The most the instance allows.
        max_bps: u128,
    },
}

/// The agreed price and the samples behind it (kept with every quote as its valuation record).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Agreed {
    /// The median price in pico-pounds per whole coin.
    pub price_pico: u128,
    /// The samples behind it, kept with the quote as its valuation record.
    pub samples: Vec<Sample>,
    /// The spread between the lowest and highest sample, in basis points.
    pub spread_bps: u128,
}

/// Agree on a price: drop zero prices, require the minimum number of sources and a spread within the limit, and return the median.
pub fn agree(mut samples: Vec<Sample>, min_sources: usize, max_spread_bps: u128) -> Result<Agreed, PriceError> {
    // A source that answered zero is treated as not having answered.
    samples.retain(|s| s.price_pico > 0);
    // At least one source is always required, whatever the configuration says.
    if samples.len() < min_sources.max(1) {
        return Err(PriceError::TooFewSources { got: samples.len(), need: min_sources.max(1) });
    }
    // Sorted, the lowest and highest are the ends and the median is in the middle.
    samples.sort_by_key(|s| s.price_pico);
    // The extremes decide the spread: if they agree, every sample does.
    let lo = samples[0].price_pico;
    let hi = samples[samples.len() - 1].price_pico;
    // Spread as a fraction of the lowest price, in basis points; saturating so a huge price cannot overflow.
    let spread_bps = (hi - lo).saturating_mul(10_000) / lo;
    // Disagreeing sources mean no quote at all, not a guess: the merchant's list price applies.
    if spread_bps > max_spread_bps {
        return Err(PriceError::Disagree { spread_bps, max_bps: max_spread_bps });
    }
    let n = samples.len();
    // The median of an odd count is the middle sample...
    let price_pico = if n % 2 == 1 {
        samples[n / 2].price_pico
    } else {
        // ...and of an even count the mean of the two middle ones.
        (samples[n / 2 - 1].price_pico + samples[n / 2].price_pico) / 2
    };
    Ok(Agreed { price_pico, samples, spread_bps })
}

/// Unit tests for this module.
#[cfg(test)]
mod tests {
    use super::*;

    /// A sample from a named source.
    fn s(source: &'static str, p: u128) -> Sample {
        Sample { source, price_pico: p }
    }

    /// Median of agreeing sources.
    #[test]
    fn median_of_agreeing_sources() {
        let a = agree(vec![s("a", 1000), s("b", 1010), s("c", 1005)], 2, 200).unwrap();
        assert_eq!(a.price_pico, 1005);
        let a = agree(vec![s("a", 1000), s("b", 1010)], 2, 200).unwrap();
        assert_eq!(a.price_pico, 1005);
    }

    /// Refuses disagreement and too few.
    #[test]
    fn refuses_disagreement_and_too_few() {
        assert!(matches!(agree(vec![s("a", 1000), s("b", 1100)], 2, 200), Err(PriceError::Disagree { .. })));
        assert!(matches!(agree(vec![s("a", 1000)], 2, 200), Err(PriceError::TooFewSources { got: 1, need: 2 })));
        assert!(matches!(agree(vec![s("a", 1000), s("b", 0)], 2, 200), Err(PriceError::TooFewSources { .. })));
    }
}
