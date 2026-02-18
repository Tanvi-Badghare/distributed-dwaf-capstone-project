//! ZKP-WAF API Server
//! REST API for zero-knowledge ML inference proof generation & verification

use actix_web::{
    middleware,
    web, App, HttpResponse, HttpServer, Result as ActixResult,
};
use ark_bn254::Bn254;
use ark_groth16::{ProvingKey, VerifyingKey};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use log::{error, info, warn};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::{Instant, SystemTime};

mod circuits;
mod errors;
mod prover;
mod utils;
mod verifier;

use crate::errors::ZKPError;
use crate::prover::{generate_proof, load_proving_key, save_proving_key, setup_prover};
use crate::verifier::{
    load_verification_key, save_verification_key, setup_verifier, verify_proof,
};

// ============================================================================
// APPLICATION STATE
// ============================================================================

#[derive(Clone)]
struct AppState {
    proving_key: Arc<RwLock<Option<ProvingKey<Bn254>>>>,
    verification_key: Arc<RwLock<Option<VerifyingKey<Bn254>>>>,
    stats: Arc<RwLock<ServiceStats>>,
    start_time: SystemTime,
}

#[derive(Clone, Debug, Default)]
struct ServiceStats {
    total_proofs_generated: u64,
    total_proofs_verified: u64,
    successful_verifications: u64,
    failed_verifications: u64,
    total_proof_time_ms: u128,
    total_verification_time_ms: u128,
}

// ============================================================================
// REQUEST / RESPONSE TYPES
// ============================================================================

#[derive(Debug, Deserialize)]
struct GenerateProofRequest {
    features: Vec<f64>,
    model_weights: Vec<f64>,
    classification: String,
    threat_score: f64,
}

#[derive(Debug, Serialize)]
struct GenerateProofResponse {
    success: bool,
    proof: Option<String>,
    public_inputs: Option<Vec<String>>,
    generation_time_ms: u128,
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct VerifyProofRequest {
    proof: String,
    public_inputs: Vec<String>,
}

#[derive(Debug, Serialize)]
struct VerifyProofResponse {
    success: bool,
    is_valid: bool,
    classification: Option<String>,
    threat_score: Option<f64>,
    verification_time_ms: u128,
    error: Option<String>,
}

#[derive(Debug, Serialize)]
struct HealthResponse {
    status: String,
    service: String,
    version: String,
    proving_key_loaded: bool,
    verification_key_loaded: bool,
    uptime_seconds: u64,
}

#[derive(Debug, Serialize)]
struct StatsResponse {
    total_proofs_generated: u64,
    total_proofs_verified: u64,
    successful_verifications: u64,
    failed_verifications: u64,
    success_rate: f64,
    avg_proof_time_ms: f64,
    avg_verification_time_ms: f64,
}

#[derive(Debug, Deserialize)]
struct SetupRequest {
    regenerate: Option<bool>,
}

#[derive(Debug, Serialize)]
struct SetupResponse {
    success: bool,
    proving_key_path: String,
    verification_key_path: String,
    setup_time_ms: u128,
    error: Option<String>,
}

// ============================================================================
// ENDPOINTS
// ============================================================================

async fn health_check(data: web::Data<AppState>) -> ActixResult<HttpResponse> {
    let pk_loaded = data.proving_key.read().unwrap().is_some();
    let vk_loaded = data.verification_key.read().unwrap().is_some();

    let uptime = data
        .start_time
        .elapsed()
        .unwrap_or_default()
        .as_secs();

    let response = HealthResponse {
        status: if pk_loaded && vk_loaded {
            "healthy".into()
        } else {
            "degraded".into()
        },
        service: "zkp-waf".into(),
        version: env!("CARGO_PKG_VERSION").into(),
        proving_key_loaded: pk_loaded,
        verification_key_loaded: vk_loaded,
        uptime_seconds: uptime,
    };

    Ok(HttpResponse::Ok().json(response))
}

async fn generate_proof_endpoint(
    req: web::Json<GenerateProofRequest>,
    data: web::Data<AppState>,
) -> ActixResult<HttpResponse> {
    let start = Instant::now();

    let pk_guard = data.proving_key.read().unwrap();
    let pk = match pk_guard.as_ref() {
        Some(k) => k,
        None => {
            return Ok(HttpResponse::ServiceUnavailable().json(
                GenerateProofResponse {
                    success: false,
                    proof: None,
                    public_inputs: None,
                    generation_time_ms: 0,
                    error: Some("Proving key not loaded. Call /setup".into()),
                },
            ))
        }
    };

    match generate_proof(
        &req.features,
        &req.model_weights,
        &req.classification,
        req.threat_score,
        pk,
    ) {
        Ok(proof_data) => {
            let elapsed = start.elapsed().as_millis();

            let proof_base64 = BASE64.encode(&proof_data.proof_bytes);

            {
                let mut stats = data.stats.write().unwrap();
                stats.total_proofs_generated += 1;
                stats.total_proof_time_ms += elapsed;
            }

            Ok(HttpResponse::Ok().json(GenerateProofResponse {
                success: true,
                proof: Some(proof_base64),
                public_inputs: Some(proof_data.public_inputs),
                generation_time_ms: elapsed,
                error: None,
            }))
        }
        Err(e) => {
            error!("Proof generation failed: {}", e);
            Ok(HttpResponse::InternalServerError().json(
                GenerateProofResponse {
                    success: false,
                    proof: None,
                    public_inputs: None,
                    generation_time_ms: start.elapsed().as_millis(),
                    error: Some(e.to_string()),
                },
            ))
        }
    }
}

async fn verify_proof_endpoint(
    req: web::Json<VerifyProofRequest>,
    data: web::Data<AppState>,
) -> ActixResult<HttpResponse> {
    let start = Instant::now();

    let vk_guard = data.verification_key.read().unwrap();
    let vk = match vk_guard.as_ref() {
        Some(v) => v,
        None => {
            return Ok(HttpResponse::ServiceUnavailable().json(
                VerifyProofResponse {
                    success: false,
                    is_valid: false,
                    classification: None,
                    threat_score: None,
                    verification_time_ms: 0,
                    error: Some("Verification key not loaded. Call /setup".into()),
                },
            ))
        }
    };

    let proof_bytes = match BASE64.decode(&req.proof) {
        Ok(b) => b,
        Err(_) => {
            return Ok(HttpResponse::BadRequest().json(
                VerifyProofResponse {
                    success: false,
                    is_valid: false,
                    classification: None,
                    threat_score: None,
                    verification_time_ms: 0,
                    error: Some("Invalid base64 proof".into()),
                },
            ))
        }
    };

    match verify_proof(&proof_bytes, &req.public_inputs, vk) {
        Ok(result) => {
            let elapsed = start.elapsed().as_millis();

            {
                let mut stats = data.stats.write().unwrap();
                stats.total_proofs_verified += 1;
                stats.total_verification_time_ms += elapsed;

                if result.is_valid {
                    stats.successful_verifications += 1;
                } else {
                    stats.failed_verifications += 1;
                }
            }

            Ok(HttpResponse::Ok().json(VerifyProofResponse {
                success: true,
                is_valid: result.is_valid,
                classification: Some(result.classification),
                threat_score: Some(result.threat_score),
                verification_time_ms: elapsed,
                error: None,
            }))
        }
        Err(e) => {
            error!("Verification error: {}", e);

            Ok(HttpResponse::InternalServerError().json(
                VerifyProofResponse {
                    success: false,
                    is_valid: false,
                    classification: None,
                    threat_score: None,
                    verification_time_ms: start.elapsed().as_millis(),
                    error: Some(e.to_string()),
                },
            ))
        }
    }
}

async fn stats_endpoint(data: web::Data<AppState>) -> ActixResult<HttpResponse> {
    let stats = data.stats.read().unwrap();

    let success_rate = if stats.total_proofs_verified > 0 {
        (stats.successful_verifications as f64
            / stats.total_proofs_verified as f64)
            * 100.0
    } else {
        0.0
    };

    let avg_proof = if stats.total_proofs_generated > 0 {
        stats.total_proof_time_ms as f64
            / stats.total_proofs_generated as f64
    } else {
        0.0
    };

    let avg_verify = if stats.total_proofs_verified > 0 {
        stats.total_verification_time_ms as f64
            / stats.total_proofs_verified as f64
    } else {
        0.0
    };

    Ok(HttpResponse::Ok().json(StatsResponse {
        total_proofs_generated: stats.total_proofs_generated,
        total_proofs_verified: stats.total_proofs_verified,
        successful_verifications: stats.successful_verifications,
        failed_verifications: stats.failed_verifications,
        success_rate,
        avg_proof_time_ms: avg_proof,
        avg_verification_time_ms: avg_verify,
    }))
}

// ============================================================================
// MAIN
// ============================================================================

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();

    let app_state = web::Data::new(AppState {
        proving_key: Arc::new(RwLock::new(None)),
        verification_key: Arc::new(RwLock::new(None)),
        stats: Arc::new(RwLock::new(ServiceStats::default())),
        start_time: SystemTime::now(),
    });

    info!("ZKP-WAF v{} starting...", env!("CARGO_PKG_VERSION"));

    HttpServer::new(move || {
        App::new()
            .app_data(app_state.clone())
            .wrap(middleware::Logger::default())
            .wrap(middleware::Compress::default())
            .route("/health", web::get().to(health_check))
            .route("/generate-proof", web::post().to(generate_proof_endpoint))
            .route("/verify-proof", web::post().to(verify_proof_endpoint))
            .route("/stats", web::get().to(stats_endpoint))
    })
    .bind(("0.0.0.0", 8080))?
    .workers(4)
    .run()
    .await
}
