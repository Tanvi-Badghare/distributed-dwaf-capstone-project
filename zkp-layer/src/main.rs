//! ZKP-WAF API Server
//! REST interface for Groth16 proof generation & verification

use actix_web::{
    middleware,
    web, App, HttpResponse, HttpServer, Result as ActixResult,
};
use ark_bn254::{Bn254, Fr};
use ark_groth16::{ProvingKey, VerifyingKey};
use ark_sponge::poseidon::PoseidonConfig;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use log::{error, info};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, RwLock};
use std::time::{Instant, SystemTime};

mod circuits;
mod errors;
mod prover;
mod utils;
mod verifier;

use crate::errors::ZKPError;
use crate::prover::{generate_proof};
use crate::verifier::validator_verify_threat;

// ============================================================================
// APPLICATION STATE
// ============================================================================

#[derive(Clone)]
struct AppState {
    proving_key: Arc<RwLock<Option<ProvingKey<Bn254>>>>,
    verification_key: Arc<RwLock<Option<VerifyingKey<Bn254>>>>,
    poseidon_config: PoseidonConfig<Fr>,
    start_time: SystemTime,
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

    Ok(HttpResponse::Ok().json(HealthResponse {
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
    }))
}

// ----------------------------------------------------------------------------

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
                    error: Some("Proving key not loaded".into()),
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
        data.poseidon_config.clone(),
    ) {
        Ok(proof_data) => {
            let elapsed = start.elapsed().as_millis();

            // Encode proof
            let proof_base64 = BASE64.encode(&proof_data.proof_bytes);

            // Encode public inputs
            let public_inputs_encoded: Vec<String> = proof_data
                .public_inputs
                .iter()
                .map(|bytes| BASE64.encode(bytes))
                .collect();

            Ok(HttpResponse::Ok().json(GenerateProofResponse {
                success: true,
                proof: Some(proof_base64),
                public_inputs: Some(public_inputs_encoded),
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

// ----------------------------------------------------------------------------

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
                    verification_time_ms: 0,
                    error: Some("Verification key not loaded".into()),
                },
            ))
        }
    };

    // Decode proof
    let proof_bytes = match BASE64.decode(&req.proof) {
        Ok(bytes) => bytes,
        Err(_) => {
            return Ok(HttpResponse::BadRequest().json(
                VerifyProofResponse {
                    success: false,
                    is_valid: false,
                    verification_time_ms: 0,
                    error: Some("Invalid base64 proof".into()),
                },
            ))
        }
    };

    // Decode public inputs
    let mut public_inputs_bytes = Vec::new();
    for input in &req.public_inputs {
        match BASE64.decode(input) {
            Ok(bytes) => public_inputs_bytes.push(bytes),
            Err(_) => {
                return Ok(HttpResponse::BadRequest().json(
                    VerifyProofResponse {
                        success: false,
                        is_valid: false,
                        verification_time_ms: 0,
                        error: Some("Invalid base64 public input".into()),
                    },
                ))
            }
        }
    }

    match validator_verify_threat(&proof_bytes, &public_inputs_bytes, vk) {
        Ok(is_valid) => {
            let elapsed = start.elapsed().as_millis();

            Ok(HttpResponse::Ok().json(VerifyProofResponse {
                success: true,
                is_valid,
                verification_time_ms: elapsed,
                error: None,
            }))
        }
        Err(e) => {
            error!("Verification failed: {}", e);
            Ok(HttpResponse::InternalServerError().json(
                VerifyProofResponse {
                    success: false,
                    is_valid: false,
                    verification_time_ms: start.elapsed().as_millis(),
                    error: Some(e.to_string()),
                },
            ))
        }
    }
}

// ============================================================================
// MAIN
// ============================================================================

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();

    info!("Starting ZKP-WAF API...");

    // TODO: Replace with your actual Poseidon parameters
    let poseidon_config = PoseidonConfig::<Fr>::default();

    let app_state = web::Data::new(AppState {
        proving_key: Arc::new(RwLock::new(None)),
        verification_key: Arc::new(RwLock::new(None)),
        poseidon_config,
        start_time: SystemTime::now(),
    });

    HttpServer::new(move || {
        App::new()
            .app_data(app_state.clone())
            .wrap(middleware::Logger::default())
            .route("/health", web::get().to(health_check))
            .route("/generate-proof", web::post().to(generate_proof_endpoint))
            .route("/verify-proof", web::post().to(verify_proof_endpoint))
    })
    .bind(("0.0.0.0", 8080))?
    .workers(4)
    .run()
    .await
}
