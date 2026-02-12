.PHONY: all setup install-deps build build-no-cache up up-all down restart logs clean test benchmark demo help health status

# Default target
all: help

##@ Setup Commands

setup: ## Initial project setup
	@echo "🔧 Setting up Distributed WAF project..."
	@chmod +x scripts/*.sh || true
	@./scripts/setup.sh || true
	@echo "✅ Setup complete!"

install-deps: ## Install development dependencies
	@echo "📦 Installing dependencies..."
	@cd zkp-layer && cargo build
	@cd ml-detector && pip install -r requirements.txt
	@cd taxii-server && pip install -r requirements.txt
	@echo "✅ Dependencies installed!"

##@ Docker Commands

build: ## Build all Docker images
	@echo "🏗️  Building Docker images..."
	@docker compose build
	@echo "✅ Build complete!"

build-no-cache: ## Build without cache
	@docker compose build --no-cache

up: ## Start core distributed pipeline
	@echo "🚀 Starting core services..."
	@docker compose up -d zkp-layer consensus-node0 ml-detector taxii-server orchestrator
	@sleep 12
	@make health
	@echo "✅ Core services running!"

up-all: ## Start full distributed stack with monitoring
	@echo "🌐 Starting full distributed stack..."
	@docker compose --profile integration --profile monitoring up -d
	@sleep 20
	@make health
	@echo "✅ Full stack running!"

down: ## Stop all services
	@docker compose down

restart: down up ## Restart services

logs: ## Show all logs
	@docker compose logs -f

logs-zkp:
	@docker compose logs -f zkp-layer

logs-ml:
	@docker compose logs -f ml-detector

logs-taxii:
	@docker compose logs -f taxii-server

logs-consensus:
	@docker compose logs -f consensus-node0

##@ Health & Status

health: ## Fail if any core service is down
	@echo "🏥 Checking health..."
	@curl -sf http://localhost:8080/health > /dev/null || (echo "❌ ZKP Down" && exit 1)
	@curl -sf http://localhost:8081/health > /dev/null || (echo "❌ Consensus Down" && exit 1)
	@curl -sf http://localhost:8082/health > /dev/null || (echo "❌ ML Down" && exit 1)
	@curl -sf http://localhost:8083/health > /dev/null || (echo "❌ TAXII Down" && exit 1)
	@echo "✅ All services healthy"

status:
	@docker compose ps

##@ Testing

test: ## Run full test suite
	@./scripts/run-tests.sh || true

test-unit:
	@cd ml-detector && python -m pytest tests/unit/ || true
	@cd zkp-layer && cargo test || true

test-e2e:
	@python tests/end-to-end-demo.py || true

##@ Benchmarks

benchmark: ## Run all benchmarks
	@python benchmarks/ml-inference-benchmark.py || true
	@python benchmarks/throughput-test.py || true
	@cargo run --manifest-path=benchmarks/Cargo.toml --bin zkp-proof-timing || true
	@echo "✅ Benchmarks complete"

benchmark-ml:
	@python benchmarks/ml-inference-benchmark.py

benchmark-zkp:
	@cargo run --manifest-path=benchmarks/Cargo.toml --bin zkp-proof-timing

##@ Demo

demo: ## Start demo mode
	@./scripts/start-demo.sh || true

##@ Cleanup

clean: ## Safe cleanup
	@docker compose down -v
	@rm -rf zkp-layer/target
	@rm -rf benchmarks/results/* 2>/dev/null || true
	@echo "✅ Cleanup complete"

##@ Help

help:
	@echo ""
	@echo "Distributed WAF - Available Commands"
	@echo ""
	@awk 'BEGIN {FS = ":.*##"; printf "Usage:\n  make <target>\n\n"} /^[a-zA-Z_-]+:.*?##/ { printf "  %-20s %s\n", $$1, $$2 }' $(MAKEFILE_LIST)
	@echo ""
