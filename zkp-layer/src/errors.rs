//! Error types for ZKP operations.

use thiserror::Error;

/// Unified error type for the ZKP layer.
///
/// This enum separates:
/// - Cryptographic failures
/// - Input validation errors
/// - System/IO failures
/// - Setup/configuration issues
#[derive(Error, Debug)]
pub enum ZKPError {
    // =============================
    // Circuit & Proof Lifecycle
    // =============================

    #[error("Circuit constraint generation failed")]
    ConstraintGeneration,

    #[error("Proof generation failed")]
    ProofGeneration,

    #[error("Proof verification failed")]
    Verification,

    #[error("Invalid proof")]
    InvalidProof,

    // =============================
    // Input & Serialization
    // =============================

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Invalid input: {0}")]
    InvalidInput(String),

    // =============================
    // Setup / Configuration
    // =============================

    #[error("Trusted setup failed: {0}")]
    Setup(String),

    // =============================
    // External/System Errors
    // =============================

    #[error("IO error")]
    Io(#[from] std::io::Error),

    #[error("Unknown internal error: {0}")]
    Internal(String),
}

/// Convenient Result alias for ZKP operations.
pub type Result<T> = std::result::Result<T, ZKPError>;
