//! Utility functions for ZKP operations.

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use crate::errors::{Result, ZKPError};

/// Fixed-point scaling factor (3 decimal places).
pub const SCALE_FACTOR: i64 = 1_000;

/// Expected feature count.
pub const EXPECTED_FEATURES: usize = 41;

/// Expected model weight count.
pub const EXPECTED_WEIGHTS: usize = 3 * 4; // 3 trees × 4 levels

// ============================================================
// Float <-> Field Conversion (Fixed-Point Encoding)
// ============================================================

/// Convert a float to a field element using fixed-point encoding.
///
/// Rejects:
/// - NaN
/// - Infinite values
/// - Values exceeding i64 range after scaling
pub fn float_to_field(value: f64) -> Result<Fr> {
    if !value.is_finite() {
        return Err(ZKPError::InvalidInput(
            "Float must be finite".into(),
        ));
    }

    let scaled = (value * SCALE_FACTOR as f64).round();

    if scaled < i64::MIN as f64 || scaled > i64::MAX as f64 {
        return Err(ZKPError::InvalidInput(
            "Scaled float exceeds i64 bounds".into(),
        ));
    }

    let int_val = scaled as i64;

    Ok(if int_val >= 0 {
        Fr::from(int_val as u64)
    } else {
        -Fr::from((-int_val) as u64)
    })
}

/// Convert a field element back to float (for debugging only).
///
/// ⚠️ Not safe for cryptographic canonical decoding.
/// Only valid if originally encoded via `float_to_field`.
pub fn field_to_float(field: Fr) -> f64 {
    let bigint = field.into_bigint();

    // Interpret as signed i64 assuming small magnitude encoding
    let mut bytes = [0u8; 8];
    let le_bytes = bigint.to_bytes_le();

    for (i, b) in le_bytes.iter().take(8).enumerate() {
        bytes[i] = *b;
    }

    let unsigned = u64::from_le_bytes(bytes);
    unsigned as f64 / SCALE_FACTOR as f64
}

// ============================================================
// Vector Conversions
// ============================================================

pub fn floats_to_fields(values: &[f64]) -> Result<Vec<Fr>> {
    values.iter().map(|&v| float_to_field(v)).collect()
}

// ============================================================
// Feature Commitment
// ============================================================

/// Compute a placeholder commitment over features.
///
/// ⚠️ This is NOT collision resistant.
/// Replace with Poseidon hash in production.
pub fn compute_commitment(features: &[Fr]) -> Fr {
    features.iter().fold(Fr::from(0u64), |acc, f| acc + f)
}

// ============================================================
// Validation
// ============================================================

pub fn validate_features(features: &[f64]) -> Result<()> {
    if features.len() != EXPECTED_FEATURES {
        return Err(ZKPError::InvalidInput(format!(
            "Expected {} features, got {}",
            EXPECTED_FEATURES,
            features.len()
        )));
    }
    Ok(())
}

pub fn validate_weights(weights: &[f64]) -> Result<()> {
    if weights.len() != EXPECTED_WEIGHTS {
        return Err(ZKPError::InvalidInput(format!(
            "Expected {} weights, got {}",
            EXPECTED_WEIGHTS,
            weights.len()
        )));
    }
    Ok(())
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_float_conversion() {
        let original = 42.5;
        let field = float_to_field(original).unwrap();
        let converted = field_to_float(field);
        assert!((original - converted).abs() < 0.01);
    }

    #[test]
    fn test_commitment() {
        let features = vec![Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)];
        let commitment = compute_commitment(&features);
        assert_eq!(commitment, Fr::from(6u64));
    }
}