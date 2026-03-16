#!/usr/bin/env bash
# train-models.sh — trains the ML detector models
# Usage: bash scripts/train-models.sh
# Usage: bash scripts/train-models.sh --csv path/to/custom.csv

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ML_DIR="$ROOT_DIR/ml-detector"
CSV_PATH="$ML_DIR/training/csic2010/csic_2010.csv"

if [[ "${1:-}" == "--csv" && -n "${2:-}" ]]; then
    CSV_PATH="$2"
fi

echo "======================================================"
echo " DWAF — ML Model Training"
echo "======================================================"
echo ""
echo "Dataset : $CSV_PATH"
echo "Models  : $ML_DIR/models/"
echo ""

if [ ! -f "$CSV_PATH" ]; then
    echo "❌ Dataset not found: $CSV_PATH"
    echo ""
    echo "Place dataset at:"
    echo "  $CSV_PATH"
    exit 1
fi

echo "✅ Dataset found"
echo ""

if ! command -v python3 >/dev/null 2>&1; then
    echo "❌ Python3 not installed"
    exit 1
fi

echo "Installing dependencies..."
cd "$ML_DIR"
pip install -r requirements.txt -q
echo "✅ Dependencies installed"
echo ""

echo "Training models..."
echo "------------------------------------------------------"

python3 training/train.py --csv "$CSV_PATH"

echo ""
echo "======================================================"
echo " Training complete"
echo " Models saved to: $ML_DIR/models/"
echo "======================================================"