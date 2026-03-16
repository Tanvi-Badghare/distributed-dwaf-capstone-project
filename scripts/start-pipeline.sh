#!/usr/bin/env bash
# start-pipeline.sh — starts all DWAF services in correct order
# Usage: bash scripts/start-pipeline.sh

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "======================================================"
echo " DWAF — Distributed Web Application Firewall"
echo " Starting full pipeline..."
echo "======================================================"

require_cmd () {
    command -v "$1" >/dev/null 2>&1 || {
        echo "❌ Required command not found: $1"
        exit 1
    }
}

require_cmd curl
require_cmd uvicorn

PIDS=()

start_service () {
    "$@" &
    pid=$!
    PIDS+=("$pid")
    echo "  PID: $pid"
}

cleanup () {
    echo ""
    echo "Stopping all services..."
    for pid in "${PIDS[@]:-}"; do
        kill "$pid" 2>/dev/null || true
    done
    exit 0
}

trap cleanup INT TERM

# ── Stage I: ML Detector ──────────────────────────────────────────────────────
echo ""
echo "[1/6] Starting ML Detector (port 8000)..."
cd "$ROOT_DIR/ml-detector"
start_service uvicorn api_server:app --host 0.0.0.0 --port 8000 --log-level info
sleep 3

# ── Stage II: ZKP Layer ───────────────────────────────────────────────────────
echo ""
echo "[2/6] Starting ZKP Layer (port 8080)..."
cd "$ROOT_DIR/zkp-layer"
start_service ./target/release/zkp-waf
sleep 3

# ── Stage III: Validator Network ──────────────────────────────────────────────
echo ""
echo "[3/6] Starting Validator Network (ports 9000-9002)..."
cd "$ROOT_DIR/validator-network"

VALIDATOR_CONFIG=config/validator-0.yaml start_service ./validator
VALIDATOR_CONFIG=config/validator-1.yaml start_service ./validator
VALIDATOR_CONFIG=config/validator-2.yaml start_service ./validator
sleep 2

# ── Stage IV: TAXII Server ────────────────────────────────────────────────────
echo ""
echo "[4/6] Starting TAXII Server (port 6000)..."
cd "$ROOT_DIR/taxii-server"
start_service uvicorn app:app --host 0.0.0.0 --port 6000 --log-level info
sleep 2

# ── Stage V: Feedback Service ─────────────────────────────────────────────────
echo ""
echo "[5/6] Starting Feedback Service (port 5000)..."
cd "$ROOT_DIR/feedback-service"
start_service uvicorn app:app --host 0.0.0.0 --port 5000 --log-level info
sleep 2

# ── Stage VI: Orchestrator ────────────────────────────────────────────────────
echo ""
echo "[6/6] Starting Orchestrator (port 7000)..."
cd "$ROOT_DIR/orchestrator"
start_service ./orchestrator
sleep 3

# ── Health checks ─────────────────────────────────────────────────────────────
echo ""
echo "======================================================"
echo " Health Checks"
echo "======================================================"

check () {
    local name=$1
    local url=$2

    if curl -sf "$url" > /dev/null 2>&1; then
        echo "  ✅ $name"
    else
        echo "  ❌ $name — not responding at $url"
    fi
}

check "ML Detector"      "http://localhost:8000/health"
check "ZKP Layer"        "http://localhost:8080/health"
check "Validator-0"      "http://localhost:9000/health"
check "Validator-1"      "http://localhost:9001/health"
check "Validator-2"      "http://localhost:9002/health"
check "TAXII Server"     "http://localhost:6000/health"
check "Feedback Service" "http://localhost:5000/health"
check "Orchestrator"     "http://localhost:7000/health"

echo ""
echo "======================================================"
echo " Pipeline running. Press Ctrl+C to stop all."
echo "======================================================"

wait