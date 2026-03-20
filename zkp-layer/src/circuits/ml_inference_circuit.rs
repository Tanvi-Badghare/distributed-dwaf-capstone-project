//! Production-grade ML Inference Circuit for ZKP-WAF
//!
//! Security guarantees:
//! - Features are bound via Poseidon commitment
//! - Model weights are bound via public model_hash
//! - All numeric values are range constrained
//! - Integer semantics preserved (no unsafe field division)

use ark_bn254::Fr;
use ark_crypto_primitives::sponge::poseidon::constraints::PoseidonSpongeVar;
use ark_crypto_primitives::sponge::{
    constraints::CryptographicSpongeVar, poseidon::PoseidonConfig,
};
use ark_ff::Zero;
use ark_r1cs_std::{
    alloc::AllocVar, boolean::Boolean, eq::EqGadget, fields::fp::FpVar, select::CondSelectGadget,
    ToBitsGadget,
};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

const NUM_FEATURES: usize = 41;
const NUM_WEIGHTS: usize = 12;

pub struct MLInferenceCircuit {
    // Private
    pub features: Option<Vec<Fr>>,
    pub model_weights: Option<Vec<Fr>>,

    // Public
    pub feature_commitment: Option<Fr>,
    pub model_hash: Option<Fr>,
    pub classification_result: Option<Fr>,
    pub threat_score: Option<Fr>,

    // Poseidon config (must match verifier side)
    pub poseidon_config: PoseidonConfig<Fr>,
}

impl ConstraintSynthesizer<Fr> for MLInferenceCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        // =========================
        // Allocate Private Inputs
        // =========================
        let feature_vars: Vec<FpVar<Fr>> = self
            .features
            .unwrap_or_else(|| vec![Fr::zero(); NUM_FEATURES])
            .into_iter()
            .map(|f| FpVar::new_witness(cs.clone(), || Ok(f)))
            .collect::<Result<_, _>>()?;

        let weight_vars: Vec<FpVar<Fr>> = self
            .model_weights
            .unwrap_or_else(|| vec![Fr::zero(); NUM_WEIGHTS])
            .into_iter()
            .map(|w| FpVar::new_witness(cs.clone(), || Ok(w)))
            .collect::<Result<_, _>>()?;

        // =========================
        // Allocate Public Inputs
        // =========================
        let commitment_var = FpVar::new_input(cs.clone(), || {
            Ok(self.feature_commitment.unwrap_or(Fr::zero()))
        })?;

        let model_hash_var =
            FpVar::new_input(cs.clone(), || Ok(self.model_hash.unwrap_or(Fr::zero())))?;

        let classification_var = FpVar::new_input(cs.clone(), || {
            Ok(self.classification_result.unwrap_or(Fr::zero()))
        })?;

        let threat_score_var =
            FpVar::new_input(cs.clone(), || Ok(self.threat_score.unwrap_or(Fr::zero())))?;

        // =========================
        // Range Constraints
        // =========================
        for feature in &feature_vars {
            let bits = feature.to_bits_le()?;
            for bit in bits.iter().skip(16) {
                bit.enforce_equal(&Boolean::constant(false))?;
            }
        }

        for weight in &weight_vars {
            let bits = weight.to_bits_le()?;
            for bit in bits.iter().skip(16) {
                bit.enforce_equal(&Boolean::constant(false))?;
            }
        }

        // =========================
        // Feature Commitment (Poseidon in-circuit)
        // =========================
        let mut sponge = PoseidonSpongeVar::new(cs.clone(), &self.poseidon_config);

        sponge.absorb(&feature_vars.as_slice())?;

        let computed_commitment = sponge.squeeze_field_elements(1)?[0].clone();
        computed_commitment.enforce_equal(&commitment_var)?;

        // =========================
        // Model Hash Binding (Poseidon in-circuit)
        // =========================
        let mut model_sponge = PoseidonSpongeVar::new(cs.clone(), &self.poseidon_config);

        model_sponge.absorb(&weight_vars.as_slice())?;

        let computed_model_hash = model_sponge.squeeze_field_elements(1)?[0].clone();
        computed_model_hash.enforce_equal(&model_hash_var)?;

        // =========================
        // Tree Evaluation
        // =========================
        let mut votes = Vec::new();

        for tree in 0..3 {
            let f = &feature_vars[tree];
            let threshold = &weight_vars[tree * 4];
            let is_malicious = f.is_cmp(threshold, std::cmp::Ordering::Greater, false)?;
            votes.push(is_malicious);
        }

        // =========================
        // Vote Sum
        // =========================
        let mut vote_sum = FpVar::<Fr>::Constant(Fr::zero());

        for vote in &votes {
            let vote_fp = FpVar::from(vote.clone());
            vote_sum += vote_fp;
        }

        // Enforce vote_sum < 4 (2 bits sufficient)
        let vote_bits = vote_sum.to_bits_le()?;
        for bit in vote_bits.iter().skip(2) {
            bit.enforce_equal(&Boolean::constant(false))?;
        }

        // =========================
        // Majority Classification
        // =========================
        let two = FpVar::Constant(Fr::from(2u64));
        let is_majority = vote_sum.is_cmp(&two, std::cmp::Ordering::Greater, true)?;

        let one_fp = FpVar::Constant(Fr::from(1u64));
        let zero_fp = FpVar::Constant(Fr::zero());

        let computed_classification = FpVar::conditionally_select(&is_majority, &one_fp, &zero_fp)?;
        computed_classification.enforce_equal(&classification_var)?;

        // =========================
        // Threat Score Mapping (Integer Safe)
        // =========================
        let thirty_three = FpVar::Constant(Fr::from(33u64));
        let sixty_six = FpVar::Constant(Fr::from(66u64));
        let hundred = FpVar::Constant(Fr::from(100u64));

        let is_zero = vote_sum.is_eq(&zero_fp)?;
        let is_one = vote_sum.is_eq(&FpVar::Constant(Fr::from(1u64)))?;
        let is_two = vote_sum.is_eq(&FpVar::Constant(Fr::from(2u64)))?;

        let computed_score = FpVar::conditionally_select(
            &is_zero,
            &zero_fp,
            &FpVar::conditionally_select(
                &is_one,
                &thirty_three,
                &FpVar::conditionally_select(&is_two, &sixty_six, &hundred)?,
            )?,
        )?;

        computed_score.enforce_equal(&threat_score_var)?;

        Ok(())
    }
}
