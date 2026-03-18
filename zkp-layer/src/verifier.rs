//! Production-grade ZKP Verifier for Validator Nodes

use ark_bn254::{Bn254, Fr};
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::{Groth16, PreparedVerifyingKey, Proof};
use ark_serialize::CanonicalDeserialize;

use crate::errors::{Result, ZKPError};

#[allow(dead_code)]
/// Verification result returned to validator logic
pub struct VerificationResult {
    pub is_valid: bool,
    pub classification: String,
    pub threat_score: f64,
}

/// Verify Groth16 proof and apply validator-level policy checks
pub fn validator_verify_threat(
    proof_bytes: &[u8],
    public_inputs_bytes: &[Vec<u8>],
    vk: &PreparedVerifyingKey<Bn254>,
) -> Result<bool> {
    // -------------------------
    // Deserialize Proof
    // -------------------------
    let proof = Proof::<Bn254>::deserialize_compressed(proof_bytes)
        .map_err(|e| ZKPError::Serialization(e.to_string()))?;

    // -------------------------
    // Deserialize Public Inputs
    // -------------------------
    let mut public_inputs = Vec::new();

    for input_bytes in public_inputs_bytes {
        let field = Fr::deserialize_compressed(&input_bytes[..])
            .map_err(|e| ZKPError::Serialization(e.to_string()))?;
        public_inputs.push(field);
    }

    if public_inputs.len() != 4 {
        return Err(ZKPError::InvalidInput(
            "Invalid number of public inputs".into(),
        ));
    }

    // -------------------------
    // Verify Proof
    // -------------------------
    let is_valid = Groth16::<Bn254>::verify_proof(vk, &proof, &public_inputs)
        .map_err(|_e| ZKPError::Verification)?;

    if !is_valid {
        tracing::warn!("Invalid proof detected");
        return Ok(false);
    }

    // -------------------------
    // Extract Meaningful Values
    // -------------------------
    let classification_field = public_inputs[2];
    let threat_score_field = public_inputs[3];

    let classification = if classification_field == Fr::from(1u64) {
        "malicious".to_string()
    } else {
        "benign".to_string()
    };

    let threat_score_numeric = threat_score_field
        .into_bigint()
        .to_bytes_le()
        .first()
        .copied()
        .unwrap_or(0) as f64
        / 100.0;

    // -------------------------
    // Policy-Level Validation
    // -------------------------
    if classification == "malicious" && threat_score_numeric < 0.7 {
        tracing::warn!("Malicious classification but score below policy threshold");
        return Ok(false);
    }

    tracing::info!(
        "✅ Proof verified: {} with score {:.2}",
        classification,
        threat_score_numeric
    );

    Ok(true)
}
