//! ZKP-WAF
//!
//! Zero-Knowledge Proof layer for the Distributed Web Application Firewall (DWAF).
//!
//! This crate provides:
//! - Groth16 (BN254) ML inference circuit
//! - Poseidon-based feature commitments
//! - Proof generation (Prover)
//! - Proof verification with validator policy enforcement
//! - Utility helpers and structured error handling
//!
//! Designed to operate as a cryptographic service layer
//! inside the DWAF federated security architecture.

#![forbid(unsafe_code)]

/// Circuit definitions
pub mod circuits;

/// Proof generation logic
pub mod prover;

/// Proof verification and validator policy enforcement
pub mod verifier;

/// Utility helpers (serialization, hashing, encoding)
pub mod utils;

/// Error types
pub mod errors;

// -----------------------------------------------------
// Public Re-Exports (Stable Integration Surface)
// -----------------------------------------------------

pub use circuits::MLInferenceCircuit;

pub use prover::{
    generate_proof,
    setup_prover,
    load_proving_key,
    save_proving_key,
    ProofData,
};

pub use verifier::validator_verify_threat;

pub use errors::{Result, ZKPError};
