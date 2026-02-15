//! ZKP-WAF
//!
//! Zero-Knowledge Proof layer for a privacy-preserving Web Application Firewall.
//!
//! This crate provides:
//! - ML inference circuit definition (Groth16, BN254)
//! - Proof generation (Prover)
//! - Proof verification (Verifier)
//! - Utility helpers and error handling
//!
//! Designed for integration as a service layer inside DWAF.

#![forbid(unsafe_code)]

use std::sync::Once;

static INIT: Once = Once::new();

// Public modules
pub mod circuits;
pub mod prover;
pub mod verifier;
pub mod utils;
pub mod errors;

// Re-export commonly used types
pub use circuits::ml_inference_circuit::{MLInferenceCircuit, NSLKDDFeatures};
pub use prover::{setup_prover, generate_proof, ProofData};
pub use verifier::{setup_verifier, verify_proof};
pub use errors::ZKPError;

/// Initializes the ZKP system runtime.
///
/// Safe to call multiple times.
/// Sets up structured logging if not already initialized.
pub fn init() {
    INIT.call_once(|| {
        tracing_subscriber::fmt()
            .with_target(false)
            .with_level(true)
            .init();

        tracing::info!("ZKP-WAF system initialized");
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_init_multiple_calls_safe() {
        init();
        init(); // should not panic
    }
}
