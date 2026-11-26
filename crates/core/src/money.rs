//! Money and prices without floating point. Prices are fixed-point: pico-pounds (10⁻¹² GBP) per whole coin. Amounts are
//! the coin's smallest unit (MIST for SUI, 10⁻⁶ for USDC). A conversion always rounds the coin amount **up**, so the
//! merchant never receives less than the GBP price.

/// 10¹² pico-pounds in a pound; 10¹⁰ in a penny.
pub const PICO_PER_PENNY: u128 = 10_000_000_000;

/// Why a decimal price or an amount could not be converted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum MoneyError {
    /// The text is not a plain decimal number.
    #[error("not a decimal number")]
    NotANumber,
    /// The number does not fit the fixed-point range.
    #[error("the number is out of range")]
    OutOfRange,
    /// A price of zero would make every conversion divide by nothing.
    #[error("the price must be positive")]
    NotPositive,
}

/// Parses a non-negative decimal string ("0.5413", "1", "1.000000000001") into pico-pounds (rounding to 12 places,
/// half-up). Exponents, signs and spaces are refused.
pub fn parse_price_pico(s: &str) -> Result<u128, MoneyError> {
    let s = s.trim();
    // A price is a short plain number; a long input is refused before it is parsed.
    if s.is_empty() || s.len() > 40 {
        return Err(MoneyError::NotANumber);
    }
    // Split at the decimal point; a number with no point has no fraction.
    let (int, frac) = s.split_once('.').unwrap_or((s, ""));
    // Only ASCII digits on both sides: no sign, no exponent, no leading point (`.5`), no thousands separators.
    if int.is_empty() || !int.bytes().all(|b| b.is_ascii_digit()) || !frac.bytes().all(|b| b.is_ascii_digit()) {
        return Err(MoneyError::NotANumber);
    }
    let int: u128 = int.parse().map_err(|_| MoneyError::OutOfRange)?;
    // The fraction as digit values, so it can be cut or padded to twelve places.
    let mut digits: Vec<u8> = frac.bytes().map(|b| b - b'0').collect();
    // Round half up on the thirteenth digit.
    let round_up = digits.len() > 12 && digits[12] >= 5;
    // Exactly twelve places (pico): shorter fractions are padded with zeros, longer ones cut.
    digits.resize(12, 0);
    let mut frac_val: u128 = 0;
    // Build the fraction as an integer without floating point.
    for d in digits.iter().take(12) {
        frac_val = frac_val * 10 + u128::from(*d);
    }
    let mut v =
        // Whole pounds in pico, plus the fraction; overflow is an error, never a wrap.
        int.checked_mul(1_000_000_000_000).and_then(|v| v.checked_add(frac_val)).ok_or(MoneyError::OutOfRange)?;
    if round_up {
        v = v.checked_add(1).ok_or(MoneyError::OutOfRange)?;
    }
    // A price that rounds to zero is refused: it would divide by zero in every conversion.
    if v == 0 {
        return Err(MoneyError::NotPositive);
    }
    Ok(v)
}

/// The coin amount (smallest units, rounded up) worth `pence` at `price_pico` per whole coin with `decimals`.
pub fn pence_to_units(pence: u64, price_pico: u128, decimals: u8) -> Result<u64, MoneyError> {
    if price_pico == 0 {
        return Err(MoneyError::NotPositive);
    }
    // The coin's smallest units per whole coin; a silly decimals value overflows into an error.
    let scale = 10u128.checked_pow(u32::from(decimals)).ok_or(MoneyError::OutOfRange)?;
    // pence × pico per penny × scale, in 128 bits so no real price can overflow it.
    let num = u128::from(pence)
        .checked_mul(PICO_PER_PENNY)
        .and_then(|v| v.checked_mul(scale))
        .ok_or(MoneyError::OutOfRange)?;
    // Round the coin amount UP: the merchant must never receive less than the GBP price.
    let units = num.div_ceil(price_pico);
    u64::try_from(units).map_err(|_| MoneyError::OutOfRange)
}

/// Pence shown for an amount of coin (rounded down), for receipts.
pub fn units_to_pence(units: u64, price_pico: u128, decimals: u8) -> Result<u64, MoneyError> {
    let scale = 10u128.checked_pow(u32::from(decimals)).ok_or(MoneyError::OutOfRange)?;
    // The reverse conversion rounds DOWN: a receipt never shows more than was paid.
    let v = u128::from(units).checked_mul(price_pico).ok_or(MoneyError::OutOfRange)? / scale / PICO_PER_PENNY;
    u64::try_from(v).map_err(|_| MoneyError::OutOfRange)
}

/// "£3.00" for 300.
pub fn format_gbp(pence: u64) -> String {
    format!("£{}.{:02}", pence / 100, pence % 100)
}

/// "1.234567890" SUI for 1_234_567_890 MIST (decimals 9), trailing zeros kept to two places.
pub fn format_units(units: u64, decimals: u8) -> String {
    if decimals == 0 {
        return units.to_string();
    }
    let scale = 10u64.pow(u32::from(decimals));
    // The fractional part, left-padded to the coin's decimals.
    let frac = format!("{:0width$}", units % scale, width = usize::from(decimals));
    let trimmed = frac.trim_end_matches('0');
    // Trim trailing zeros but keep at least two places.
    let frac = if trimmed.len() < 2 { &frac[..2.min(frac.len())] } else { trimmed };
    format!("{}.{}", units / scale, frac)
}

/// Unit tests for this module.
#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// Parses prices.
    #[test]
    fn parses_prices() {
        assert_eq!(parse_price_pico("0.5413").unwrap(), 541_300_000_000);
        assert_eq!(parse_price_pico("1").unwrap(), 1_000_000_000_000);
        assert_eq!(parse_price_pico("0.0000000000005").unwrap(), 1);
        for bad in ["", "-1", "1e3", " ", "1.2.3", ".5", "0", "0.0000000000001", "abc"] {
            assert!(parse_price_pico(bad).is_err(), "{bad}");
        }
    }

    /// Converts pounds to coin rounding up.
    #[test]
    fn converts_pounds_to_coin_rounding_up() {
        // £3 at £0.5413 per SUI = 5.5422131... SUI = 5_542_213_190 MIST (rounded up).
        let mist = pence_to_units(300, parse_price_pico("0.5413").unwrap(), 9).unwrap();
        assert_eq!(mist, 5_542_213_191);
        // £3 at £0.7583 per USDC = 3.956215... USDC = 3_956_216 (6 decimals, rounded up).
        assert_eq!(pence_to_units(300, parse_price_pico("0.7583").unwrap(), 6).unwrap(), 3_956_218);
        assert_eq!(format_gbp(300), "£3.00");
        assert_eq!(format_units(5_542_213_191, 9), "5.542213191");
        assert_eq!(format_units(3_000_000, 6), "3.00");
    }

    proptest! {
        /// The coin amount is never worth less than the price.
        #[test]
        fn never_short(pence in 1u64..1_000_000, price in 1u128..10_000_000_000_000_000, decimals in 0u8..12) {
            if let Ok(units) = pence_to_units(pence, price, decimals) {
                let scale = 10u128.pow(u32::from(decimals));
                prop_assert!(u128::from(units) * price >= u128::from(pence) * PICO_PER_PENNY * scale);
            }
        }
    }
}
