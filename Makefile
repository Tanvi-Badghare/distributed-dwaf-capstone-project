.PHONY: all setup build up down restart logs clean test benchmark demo help

# Default target
all: help

##@ Setup Commands

setup: ## Initial project setup (download datasets, create directories)
	@echo "🔧 Setting up Distributed WAF project..."
	@chmod +x scripts/*.sh
	@./scripts/setup.sh
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
	@docker-compose build
	@echo "✅ Build complete!"

build-no-cache: ## Build all Docker images without cache
	@echo "🏗️  Building Docker images (no cache)..."
	@docker-compose build --no-cache
	@echo "✅ Build complete!"

up: ## Start all core services (ML, ZKP, Consensus, TAXII)
	@echo "🚀 Starting core services..."
	@docker-compose up -d zkp-layer consensus-node0 consensus-node1 consensus-node2 consensus-node3 ml-detector taxii-server
	@echo "⏳ Waiting for services to be healthy..."
	@sleep 10
	@make health
	@echo "✅ All services are running!"

up-all: ## Start all services including orchestrator
	@echo "🚀 Starting all services including orchestrator..."
	@docker-compose --profile integration up -d
	@echo "⏳ Waiting for services to be healthy..."
	@sleep 15
	@make health
	@echo "✅ All services are running!"

up-sites: ## Start vulnerable test sites
	@echo "🚀 Starting vulnerable test sites..."
	@docker-compose --profile sites up -d
	@echo "✅ Test sites are running!"
	@echo "   - PHP Site: http://localhost:9001"
	@echo "   - Django Site: http://localhost:9002"
	@echo "   - Node.js Site: http://localhost:9003"

up-monitoring: ## Start monitoring stack (Prometheus + Grafana)
	@echo "📊 Starting monitoring stack..."
	@docker-compose --profile monitoring up -d
	@echo "✅ Monitoring is running!"
	@echo "   - Prometheus: http://localhost:9090"
	@echo "   - Grafana: http://localhost:3000 (admin/admin)"

down: ## Stop all services
	@echo "🛑 Stopping all services..."
	@docker-compose down
	@echo "✅ All services stopped!"

down-volumes: ## Stop all services and remove volumes
	@echo "🛑 Stopping all services and removing volumes..."
	@docker-compose down -v
	@echo "✅ All services stopped and volumes removed!"

restart: ## Restart all services
	@echo "🔄 Restarting services..."
	@make down
	@make up
	@echo "✅ Services restarted!"

logs: ## Show logs from all services
	@docker-compose logs -f

logs-zkp: ## Show ZKP layer logs
	@docker-compose logs -f zkp-layer

logs-consensus: ## Show consensus logs
	@docker-compose logs -f consensus-node0 consensus-node1 consensus-node2 consensus-node3

logs-ml: ## Show ML detector logs
	@docker-compose logs -f ml-detector

logs-taxii: ## Show TAXII server logs
	@docker-compose logs -f taxii-server

logs-orchestrator: ## Show orchestrator logs
	@docker-compose logs -f orchestrator

##@ Health & Status Commands

health: ## Check health of all services
	@echo "🏥 Checking service health..."
	@echo ""
	@curl -sf http://localhost:8080/health > /dev/null && echo "✅ ZKP Service (8080): Healthy" || echo "❌ ZKP Service (8080): Down"
	@curl -sf http://localhost:8081/health > /dev/null && echo "✅ Consensus Node 0 (8081): Healthy" || echo "❌ Consensus Node 0 (8081): Down"
	@curl -sf http://localhost:8082/health > /dev/null && echo "✅ ML Detector (8082): Healthy" || echo "❌ ML Detector (8082): Down"
	@curl -sf http://localhost:8083/health > /dev/null && echo "✅ TAXII Server (8083): Healthy" || echo "❌ TAXII Server (8083): Down"
	@echo ""

status: ## Show status of all containers
	@docker-compose ps

##@ Testing Commands

test: ## Run all tests
	@echo "🧪 Running all tests..."
	@./scripts/run-tests.sh
	@echo "✅ Tests complete!"

test-unit: ## Run unit tests only
	@echo "🧪 Running unit tests..."
	@cd ml-detector && python -m pytest tests/unit/
	@cd zkp-layer && cargo test
	@echo "✅ Unit tests complete!"

test-integration: ## Run integration tests
	@echo "🧪 Running integration tests..."
	@python tests/integration/test_ml_to_zkp.py
	@python tests/integration/test_consensus_to_taxii.py
	@echo "✅ Integration tests complete!"

test-e2e: ## Run end-to-end demo test
	@echo "🧪 Running end-to-end test..."
	@python tests/end-to-end-demo.py
	@echo "✅ End-to-end test complete!"

test-sql-injection: ## Test SQL injection detection
	@echo "🧪 Testing SQL injection detection..."
	@./tests/sql-injection-test.sh
	@echo "✅ SQL injection tests complete!"

test-byzantine: ## Test Byzantine fault tolerance
	@echo "🧪 Testing Byzantine fault tolerance..."
	@./tests/byzantine-node-test.sh
	@echo "✅ Byzantine tests complete!"

##@ Benchmark Commands

benchmark: ## Run all benchmarks
	@echo "📊 Running benchmarks..."
	@python benchmarks/ml-inference-benchmark.py
	@python benchmarks/throughput-test.py
	@cargo run --manifest-path=benchmarks/zkp-proof-timing.rs
	@go run benchmarks/consensus-latency.go
	@echo "✅ Benchmarks complete! Results in benchmarks/results/"

benchmark-ml: ## Benchmark ML detector only
	@python benchmarks/ml-inference-benchmark.py

benchmark-zkp: ## Benchmark ZKP proof generation/verification
	@cd benchmarks && cargo run --bin zkp-proof-timing

benchmark-consensus: ## Benchmark consensus latency
	@go run benchmarks/consensus-latency.go

benchmark-e2e: ## Benchmark end-to-end latency
	@go run benchmarks/end-to-end-latency.go

##@ Demo Commands

demo: ## Run full system demonstration
	@echo "🎬 Starting demonstration..."
	@./scripts/start-demo.sh
	@echo "✅ Demonstration complete!"

demo-attack: ## Simulate SQL injection attack
	@echo "⚔️  Simulating SQL injection attack..."
	@curl -X POST http://localhost:8082/detect \
		-H "Content-Type: application/json" \
		-d '{"http_request": "GET /search?q='\'' OR 1=1--", "source_ip": "192.168.1.100"}'
	@echo ""
	@echo "✅ Attack simulation complete!"

##@ Development Commands

train-models: ## Train ML models on NSL-KDD dataset
	@echo "🤖 Training ML models..."
	@cd ml-detector/training && python train.py
	@echo "✅ Models trained and saved to ml-detector/models/"

evaluate-models: ## Evaluate ML model performance
	@echo "📈 Evaluating ML models..."
	@cd ml-detector/training && python evaluate.py
	@echo "✅ Evaluation complete!"

generate-keys: ## Generate consensus node keys
	@echo "🔑 Generating consensus node keys..."
	@./scripts/generate-keys.sh
	@echo "✅ Keys generated!"

##@ Cleanup Commands

clean: ## Remove generated files and Docker artifacts
	@echo "🧹 Cleaning up..."
	@docker-compose down -v
	@rm -rf ml-detector/models/*.pkl
	@rm -rf zkp-layer/params/*.bin
	@rm -rf benchmarks/results/*.csv
	@rm -rf consensus/config/node_keys/*/priv_validator_key.json
	@find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	@find . -type d -name target -exec rm -rf {} + 2>/dev/null || true
	@echo "✅ Cleanup complete!"

clean-data: ## Remove all persistent data
	@echo "🧹 Removing all persistent data..."
	@docker volume rm -f distributed-waf-capstone_consensus-node0-data || true
	@docker volume rm -f distributed-waf-capstone_consensus-node1-data || true
	@docker volume rm -f distributed-waf-capstone_consensus-node2-data || true
	@docker volume rm -f distributed-waf-capstone_consensus-node3-data || true
	@docker volume rm -f distributed-waf-capstone_taxii-data || true
	@docker volume rm -f distributed-waf-capstone_site1-db-data || true
	@docker volume rm -f distributed-waf-capstone_site3-db-data || true
	@echo "✅ All data removed!"

reset: clean clean-data build up ## Complete reset: clean, rebuild, and restart

##@ Utility Commands

shell-zkp: ## Open shell in ZKP container
	@docker-compose exec zkp-layer /bin/bash

shell-consensus: ## Open shell in consensus node 0
	@docker-compose exec consensus-node0 /bin/sh

shell-ml: ## Open shell in ML detector container
	@docker-compose exec ml-detector /bin/bash

shell-taxii: ## Open shell in TAXII server container
	@docker-compose exec taxii-server /bin/bash

shell-orchestrator: ## Open shell in orchestrator container
	@docker-compose exec orchestrator /bin/sh

ps: ## List all running containers
	@docker-compose ps

top: ## Show container resource usage
	@docker stats --no-stream

##@ Paper & Documentation Commands

paper-draft: ## Open paper draft in editor
	@${EDITOR:-nano} docs/PAPER_DRAFT.md

architecture: ## View architecture documentation
	@cat docs/ARCHITECTURE.md

api-docs: ## View API documentation
	@cat docs/API.md

##@ Help

help: ## Display this help message
	@echo "Distributed WAF - Makefile Commands"
	@echo ""
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)
	@echo ""
	@echo "Quick Start:"
	@echo "  1. make setup          # First time setup"
	@echo "  2. make build          # Build all images"
	@echo "  3. make up             # Start core services"
	@echo "  4. make test-e2e       # Run end-to-end test"
	@echo "  5. make demo           # Run full demonstration"
	@echo ""
	@echo "Service URLs:"
	@echo "  ML Detector:  http://localhost:8082"
	@echo "  ZKP Service:  http://localhost:8080"
	@echo "  Consensus:    http://localhost:8081"
	@echo "  TAXII Server: http://localhost:8083"
	@echo ""