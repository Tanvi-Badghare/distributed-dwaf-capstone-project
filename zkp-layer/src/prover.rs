//! Production-grade Proof Generation Module

use ark_bn254::{Bn254, Fr};
use ark_crypto_primitives::snark::SNARK;
use ark_groth16::{Groth16, ProvingKey};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{rand::rngs::StdRng, rand::SeedableRng, Zero};
use std::fs::File;
use std::path::Path;

use crate::circuits::MLInferenceCircuit;
use crate::errors::{Result, ZKPError};
use crate::utils::{compute_commitment, floats_to_fields, validate_features, validate_weights};

/// Proof container for transport
#[derive(Debug, Clone)]
pub struct ProofData {
    pub proof_bytes: Vec<u8>,
    pub public_inputs: Vec<Vec<u8>>, // Canonical serialized field elements
}
#[allow(dead_code)]
/// Setup Groth16 proving key
pub fn setup_prover(
    poseidon_config: ark_crypto_primitives::sponge::poseidon::PoseidonConfig<Fr>,
) -> Result<ProvingKey<Bn254>> {
    tracing::info!("Generating proving key...");

    // Blank circuit with no witnesses
    let circuit = MLInferenceCircuit {
        features: Some(vec![Fr::zero(); 41]),
        model_weights: Some(vec![Fr::zero(); 12]),
        feature_commitment: Some(Fr::zero()),
        model_hash: Some(Fr::zero()),
        classification_result: Some(Fr::zero()),
        threat_score: Some(Fr::zero()),
        poseidon_config: poseidon_config.clone(),
    };

    let mut rng = StdRng::seed_from_u64(0u64);

    let params = Groth16::<Bn254>::generate_random_parameters_with_reduction(circuit, &mut rng)
        .map_err(|e| ZKPError::Setup(e.to_string()))?;

    tracing::info!("Proving key generated");
    Ok(params)
}

#[allow(dead_code)]
/// Save proving key
pub fn save_proving_key(pk: &ProvingKey<Bn254>, path: &Path) -> Result<()> {
    let mut file = File::create(path)?;
    pk.serialize_compressed(&mut file)
        .map_err(|e| ZKPError::Serialization(e.to_string()))?;
    Ok(())
}

#[allow(dead_code)]
/// Load proving key
pub fn load_proving_key(path: &Path) -> Result<ProvingKey<Bn254>> {
    let mut file = File::open(path)?;
    ProvingKey::<Bn254>::deserialize_compressed(&mut file)
        .map_err(|e| ZKPError::Serialization(e.to_string()))
}

#[allow(dead_code)]
/// Generate ZK proof
pub fn generate_proof(
    features: &[f64],
    model_weights: &[f64],
    classification: &str,
    threat_score: f64,
    proving_key: &ProvingKey<Bn254>,
    poseidon_config: ark_crypto_primitives::sponge::poseidon::PoseidonConfig<Fr>,
) -> Result<ProofData> {
    tracing::info!("Starting proof generation...");

    validate_features(features)?;
    validate_weights(model_weights)?;

    if !(0.0..=1.0).contains(&threat_score) {
        return Err(ZKPError::InvalidInput(
            "Threat score must be between 0.0 and 1.0".into(),
        ));
    }

    // Convert inputs
    let feature_fields = floats_to_fields(features)?;
    let weight_fields = floats_to_fields(model_weights)?;

    // -------------------------
    // Feature Commitment
    // -------------------------
    let commitment = compute_commitment(&feature_fields);

    // -------------------------
    // Model Hash
    // -------------------------
    let model_hash = compute_commitment(&weight_fields);

    // -------------------------
    // Classification Mapping
    // -------------------------
    let result_field = match classification {
        "benign" => Fr::from(0u64),
        "malicious" => Fr::from(1u64),
        _ => return Err(ZKPError::InvalidInput("Invalid classification".into())),
    };

    let score_field = Fr::from((threat_score * 100.0).round() as u64);

    // -------------------------
    // Build Circuit
    // -------------------------
    let circuit = MLInferenceCircuit {
        features: Some(feature_fields),
        model_weights: Some(weight_fields),
        feature_commitment: Some(commitment),
        model_hash: Some(model_hash),
        classification_result: Some(result_field),
        threat_score: Some(score_field),
        poseidon_config,
    };

    // -------------------------
    // Generate Proof
    // -------------------------
    let mut rng = StdRng::seed_from_u64(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos() as u64,
    );

    let proof = Groth16::<Bn254>::prove(proving_key, circuit, &mut rng)
        .map_err(|_| ZKPError::ProofGeneration)?;

    let mut proof_bytes = Vec::new();
    proof
        .serialize_compressed(&mut proof_bytes)
        .map_err(|e| ZKPError::Serialization(e.to_string()))?;

    // Public inputs must match circuit order
    let public_fields = vec![commitment, model_hash, result_field, score_field];

    let mut public_inputs = Vec::new();
    for field in public_fields {
        let mut bytes = Vec::new();
        field
            .serialize_compressed(&mut bytes)
            .map_err(|e| ZKPError::Serialization(e.to_string()))?;
        public_inputs.push(bytes);
    }

    tracing::info!("Proof generated ({} bytes)", proof_bytes.len());

    Ok(ProofData {
        proof_bytes,
        public_inputs,
    })
}
