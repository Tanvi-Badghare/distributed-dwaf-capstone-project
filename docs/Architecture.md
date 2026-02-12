## System Overview

The Distributed Web Application Firewall (DWAF) is a federated security architecture that combines machine learning–based anomaly detection, zero-knowledge proof verification, distributed validator consensus, and standardized threat intelligence sharing to provide privacy-preserving, real-time protection across multiple web entities.

The system enables collaborative threat detection while ensuring that raw traffic features and detection logic remain confidential.

---

## Key Innovation

Unlike traditional centralized WAF deployments, DWAF provides:

- **No single point of failure**: Distributed validator voting prevents unilateral approval of threat decisions  
- **Privacy preservation**: Zero-knowledge proofs verify malicious inference without exposing raw traffic features  
- **Decentralized validation**: Independent validator nodes collectively verify ZK proofs  
- **Automated mitigation**: Approved threats propagate enforcement updates across federated nodes  
- **Standards compliance**: STIX 2.1 / TAXII 2.1 integration ensures interoperability  

---

## High-Level Architecture

┌───────────────────────────────────────────────┐
│        FEDERATED TESTBED ENVIRONMENT (N = 5) │
│                                               │
│  Web App 1   Web App 2   Web App 3   Web App 4 │
│       \        |         |         /           │
│        ─────── Traffic Ingestion ───────       │
└─────────────────────────┬─────────────────────┘
                          │
                          ▼
┌───────────────────────────────────────────────┐
│ TRAFFIC ORCHESTRATOR / AGGREGATION LAYER     │
│                                               │
│ • Aggregates traffic from federated apps     │
│ • Normalizes request format                  │
│ • Routes traffic to ML detector              │
│ • Coordinates downstream pipeline flow       │
└─────────────────────────┬─────────────────────┘
                          │
                          ▼
┌───────────────────────────────────────────────┐
│ STAGE I: ML-BASED ANOMALY DETECTION          │
│                                               │
│ • Real-time feature extraction               │
│ • Isolation Forest + Random Forest inference │
│ • Suspicious traffic flagged as candidate    │
└─────────────────────────┬─────────────────────┘
                          │
                          ▼
┌───────────────────────────────────────────────┐
│ STAGE II: ZERO-KNOWLEDGE PROOF GENERATION     │
│                                               │
│ • Prover constructs Groth16 proof            │
│ • Public inputs: threat_flag, confidence     │
│ • Private inputs: traffic_features           │
│ • Raw traffic never leaves ML node           │
└─────────────────────────┬─────────────────────┘
                          │
                          ▼
┌───────────────────────────────────────────────┐
│ STAGE III: DISTRIBUTED VALIDATOR CONSENSUS   │
│                                               │
│ • Independent validator nodes                │
│ • ZKP verification                           │
│ • Threshold-based majority approval          │
│ • No single node can approve alone           │
└─────────────────────────┬─────────────────────┘
                          │
                          ▼
┌───────────────────────────────────────────────┐
│ STAGE IV: STANDARDIZED THREAT DISTRIBUTION    │
│                                               │
│ • Validated threats encoded as STIX objects  │
│ • Disseminated via TAXII 2.1 collections     │
│ • Federated threat intelligence propagation  │
└─────────────────────────┬─────────────────────┘
                          │
                          ▼
┌───────────────────────────────────────────────┐
│ STAGE V: ADAPTIVE FEDERATED MITIGATION        │
│                                               │
│ • WAF rule updates across participating nodes│
│ • Blocklist synchronization                  │
│ • Model adaptation trigger                   │
└───────────────────────────────────────────────┘