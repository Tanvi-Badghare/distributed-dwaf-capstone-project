//! Circuit layer for ZKP-WAF.
//!
//! This module defines all R1CS circuit implementations used for
//! zero-knowledge proof generation and verification.

pub mod ml_inference_circuit;

// Re-export primary circuit for ergonomic access
pub use ml_inference_circuit::MLInferenceCircuit;
