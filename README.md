# Distributed Web Application Firewall (DWAF)

> ⚠️ **Research Notice:** This is a research-only defensive system demonstrating distributed anomaly detection, ZKP verification, and consensus-based threat validation. All components are intentionally sandboxed and isolated for academic experimentation. Not intended for production use.

---

## Overview

DWAF is a federated security architecture combining:

- **Machine learning–based anomaly detection** across distributed traffic streams
- **Zero-knowledge cryptographic attestation** (Groth16/BN254) for privacy-preserving threat verification
- **Distributed validator consensus** for multi-node threat agreement
- **STIX 2.1 / TAXII 2.1** threat intelligence sharing

DWAF enables collaborative threat detection across multiple nodes while preserving sensitive traffic data through privacy-preserving proof generation and structured intelligence dissemination.

---

## Architecture

DWAF operates as a multi-stage security pipeline:

![Architectural Diagram](./docs/dwaf-capstone-flowchart.png)

| Stage | Component | Description |
|-------|-----------|-------------|
| 1 | **ML Detection** | Ensemble anomaly detection on distributed traffic streams |
| 2 | **ZKP Attestation** | Groth16 proofs of malicious inference without exposing raw features |
| 3 | **Validator Voting** | Threshold-based majority voting across independent validator nodes |
| 4 | **Threat Intelligence** | STIX 2.1 objects distributed via TAXII 2.1 collections |
| 5 | **Adaptive Mitigation** | Validated threats update enforcement rules and retrain local models |

---

## Core Components

### 🔍 ML Detector (`ml-detector/`)
- Ensemble anomaly detection — Isolation Forest + Random Forest
- Real-time feature extraction and inference
- Adaptive model retraining via feedback loop

### 🔐 ZKP Layer (`zkp-layer/`)
- Groth16 zero-knowledge proof system over BN254 curve
- Poseidon hash commitments for feature vectors
- Proves malicious inference without exposing raw traffic data
- Written in Rust

### 🗳 Validator Network (`validator-network/`)
- Distributed consensus protocol in Go
- Independent ZKP verification across validator nodes
- Threshold-based majority voting

### 🌐 TAXII Server (`taxii-server/`)
- STIX 2.1 threat object encoding
- TAXII 2.1 collection distribution
- Standardised intelligence dissemination

### 🔄 Feedback Service (`feedback-service/`)
- Continuous model retraining loop
- WAF rule adaptation from validated threats

### 🎯 Orchestrator (`orchestrator/`)
- Go-based pipeline coordinator
- Service health management and routing

---

## Tech Stack

| Layer | Technology |
|-------|------------|
| ZKP | Rust — Groth16 (BN254), Poseidon |
| ML | Python — scikit-learn, Flask |
| Orchestration | Go |
| Threat Intelligence | STIX 2.1 / TAXII 2.1 |
| Infrastructure | Docker / Docker Compose |

---

## Quick Start

**Prerequisites:** Docker, Docker Compose, Make

```bash
# 1. Build all services
make build

# 2. Start core services
make up

# 3. Run full integration
make up-all

# 4. Check health
make health

# 5. Run demo
make demo
```

---

## Project Structure

```
dwaf_capstone_project/
├── ml-detector/          # Python ML anomaly detection service
├── zkp-layer/            # Rust ZKP proof generation and verification
├── validator-network/    # Go distributed consensus and voting
├── orchestrator/         # Go pipeline coordinator
├── taxii-server/         # Python STIX/TAXII threat intelligence
├── feedback-service/     # Python adaptive model retraining
├── config/               # Shared configuration and ZKP parameters
├── scripts/              # Build and deployment automation
├── tests/                # Integration and unit tests
└── docs/                 # Architecture documentation
```

---

## Authors and Contributions

| Contributor | Role |
|-------------|------|
| **Tanvi Badghare** | System architecture, ZKP layer (Groth16), distributed verification workflow |
| **Aditi Pandey & Anjali** | ML anomaly detection models (Isolation Forest, Random Forest) |
| **Jivesh Rai and Anshul** | STIX 2.1 / TAXII 2.1 threat intelligence module |
| **Entire Team** | Technical documentation and repository organisation |

---

## Research Context

DWAF is an experimental exploration of combining:
- Privacy-preserving cryptography (ZKP)
- Distributed validation and consensus
- Standardised cyber threat intelligence
- Federated anomaly detection

into a unified distributed WAF architecture.

---

## Roadmap

- [ ] `ml-detector/README.md` — model training and evaluation docs
- [ ] `zkp-layer/README.md` — circuit design and proof system docs
- [ ] `validator-network/README.md` — consensus protocol docs
- [ ] `docs/DEPLOYMENT.md` — production deployment guide
- [ ] Trusted setup ceremony documentation
- [ ] Benchmark suite for proof generation latency

---

## ⚠️ Security & Key Management Notice

- ZKP parameters and cryptographic keys are for **demonstration and testing only**
- Production-grade trusted setup and secure key storage are **not yet implemented**
- `config/zkp-params.json` contains configuration only — no real cryptographic material
- Sensitive key material (`*.bin`) is excluded from version control via `.gitignore`
