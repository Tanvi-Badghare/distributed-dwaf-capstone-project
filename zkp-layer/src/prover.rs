//! Production-grade Proof Generation Module

use ark_bn254::{Bn254, Fr};
use ark_groth16::{Groth16, ProvingKey, Proof};
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};
use ark_std::rand::{rngs::OsRng, RngCore};
use ark_relations::r1cs::ConstraintSynthesizer;
use ark_sponge::{
    poseidon::{PoseidonConfig, PoseidonSponge},
    CryptographicSponge,
};
use std::fs::File;
use std::path::Path;

use crate::circuits::MLInferenceCircuit;
use crate::utils::{floats_to_fields, validate_features, validate_weights};
use crate::errors::{ZKPError, Result};

/// Proof container for transport
#[derive(Debug, Clone)]
pub struct ProofData {
    pub proof_bytes: Vec<u8>,
    pub public_inputs: Vec<Vec<u8>>, // Canonical serialized field elements
}

/// Setup Groth16 proving key
pub fn setup_prover(
    poseidon_config: PoseidonConfig<Fr>,
) -> Result<ProvingKey<Bn254>> {
    log::info!("Generating proving key...");

    // Blank circuit with no witnesses
    let circuit = MLInferenceCircuit {
        features: Some(vec![Fr::zero(); 41]),
        model_weights: Some(vec![Fr::zero(); 12]),
        feature_commitment: Some(Fr::zero()),
        model_hash: Some(Fr::zero()),
        classification_result: Some(Fr::zero()),
        threat_score: Some(Fr::zero()),
        poseidon_config,
    };

    let mut rng = OsRng;

    let params = Groth16::<Bn254>::generate_random_parameters_with_reduction(
        circuit,
        &mut rng,
    )
    .map_err(|e| ZKPError::SetupError(e.to_string()))?;

    log::info!("✅ Proving key generated");
    Ok(params)
}

/// Save proving key
pub fn save_proving_key(pk: &ProvingKey<Bn254>, path: &Path) -> Result<()> {
    let mut file = File::create(path)?;
    pk.serialize_compressed(&mut file)
        .map_err(|e| ZKPError::SerializationError(e.to_string()))?;
    Ok(())
}

/// Load proving key
pub fn load_proving_key(path: &Path) -> Result<ProvingKey<Bn254>> {
    let mut file = File::open(path)?;
    ProvingKey::<Bn254>::deserialize_compressed(&mut file)
        .map_err(|e| ZKPError::SerializationError(e.to_string()))
}

/// Generate ZK proof
pub fn generate_proof(
    features: &[f64],
    model_weights: &[f64],
    classification: &str,
    threat_score: f64,
    proving_key: &ProvingKey<Bn254>,
    poseidon_config: PoseidonConfig<Fr>,
) -> Result<ProofData> {
    log::info!("Starting proof generation...");

    validate_features(features)?;
    validate_weights(model_weights)?;

    if !(0.0..=1.0).contains(&threat_score) {
        return Err(ZKPError::InvalidInput(
            "Threat score must be between 0.0 and 1.0".into(),
        ));
    }

    // Convert inputs
    let feature_fields = floats_to_fields(features);
    let weight_fields = floats_to_fields(model_weights);

    // -------------------------
    // Poseidon Feature Commitment
    // -------------------------
    let mut sponge = PoseidonSponge::new(&poseidon_config);
    for f in &feature_fields {
        sponge.absorb(f);
    }
    let commitment = sponge.squeeze_field_elements(1)[0];

    // -------------------------
    // Poseidon Model Hash
    // -------------------------
    let mut model_sponge = PoseidonSponge::new(&poseidon_config);
    for w in &weight_fields {
        model_sponge.absorb(w);
    }
    let model_hash = model_sponge.squeeze_field_elements(1)[0];

    // -------------------------
    // Classification Mapping
    // -------------------------
    let result_field = match classification {
        "benign" => Fr::from(0u64),
        "malicious" => Fr::from(1u64),
        _ => {
            return Err(ZKPError::InvalidInput(
                "Invalid classification".into(),
            ))
        }
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
    let mut rng = OsRng;

    let proof = Groth16::<Bn254>::prove(proving_key, circuit, &mut rng)
        .map_err(|e| ZKPError::ProofGenerationError(e.to_string()))?;

    let mut proof_bytes = Vec::new();
    proof.serialize_compressed(&mut proof_bytes)
        .map_err(|e| ZKPError::SerializationError(e.to_string()))?;

    // Public inputs must match circuit order
    let public_fields = vec![
        commitment,
        model_hash,
        result_field,
        score_field,
    ];

    let mut public_inputs = Vec::new();
    for field in public_fields {
        let mut bytes = Vec::new();
        field.serialize_compressed(&mut bytes)
            .map_err(|e| ZKPError::SerializationError(e.to_string()))?;
        public_inputs.push(bytes);
    }

    log::info!("✅ Proof generated ({} bytes)", proof_bytes.len());

    Ok(ProofData {
        proof_bytes,
        public_inputs,
    })
}
