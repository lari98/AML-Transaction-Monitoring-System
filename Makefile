# =============================================================================
# AML Monitoring System — Makefile
# Production commands for Swiss/German banking compliance platform
# =============================================================================

.PHONY: help install dev test lint format build up down logs clean migrate seed

DOCKER_COMPOSE = docker-compose
PYTHON = python3
PIP = pip3
PROJECT_NAME = aml-monitoring

# ── Colors ───────────────────────────────────────────────────────────────────
RED    = \033[0;31m
GREEN  = \033[0;32m
YELLOW = \033[1;33m
CYAN   = \033[0;36m
RESET  = \033[0m

help: ## Show this help
	@echo "$(CYAN)AML Transaction Monitoring System$(RESET)"
	@echo "$(YELLOW)Available commands:$(RESET)"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  $(GREEN)%-20s$(RESET) %s\n", $$1, $$2}'

# ── Setup ────────────────────────────────────────────────────────────────────
install: ## Install all Python dependencies
	$(PIP) install -r backend/requirements.txt --break-system-packages
	$(PIP) install -r streaming/requirements.txt --break-system-packages
	$(PIP) install -r tests/requirements-test.txt --break-system-packages

env: ## Copy env template
	cp .env.example .env
	@echo "$(YELLOW)⚠ Edit .env before running!$(RESET)"

# ── Development ──────────────────────────────────────────────────────────────
dev: ## Run backend in dev mode (hot reload)
	cd backend && uvicorn main:app --reload --host 0.0.0.0 --port 8000

dev-stream: ## Run transaction stream simulator
	cd streaming && $(PYTHON) simulator.py --mode dev --tps 10

seed-data: ## Generate sample transactions (Swiss/German banks)
	$(PYTHON) data/generators/transaction_generator.py --records 50000 --output data/sample_transactions.csv
	$(PYTHON) data/generators/aml_pattern_generator.py --inject-rate 0.05

# ── Testing ──────────────────────────────────────────────────────────────────
test: ## Run full test suite
	$(PYTHON) -m pytest tests/ -v --tb=short --cov=backend --cov-report=html --cov-report=term-missing

test-unit: ## Run unit tests only
	$(PYTHON) -m pytest tests/unit/ -v --tb=short

test-integration: ## Run integration tests
	$(PYTHON) -m pytest tests/integration/ -v --tb=short -m "not slow"

test-security: ## Run security & GDPR tests
	$(PYTHON) -m pytest tests/integration/test_api_security.py tests/integration/test_gdpr_compliance.py -v

test-performance: ## Run load & performance tests
	$(PYTHON) -m pytest tests/performance/ -v --tb=short

test-coverage: ## Generate coverage report
	$(PYTHON) -m pytest tests/ --cov=backend --cov-report=html
	@echo "$(GREEN)Coverage report: htmlcov/index.html$(RESET)"

# ── Code Quality ─────────────────────────────────────────────────────────────
lint: ## Run linters (ruff, mypy, bandit)
	ruff check backend/ streaming/ tests/
	mypy backend/ --ignore-missing-imports
	bandit -r backend/ -ll

format: ## Auto-format code
	ruff format backend/ streaming/ tests/
	isort backend/ streaming/ tests/

security-scan: ## Run security vulnerability scan
	safety check -r backend/requirements.txt
	bandit -r backend/ -f json -o reports/bandit_report.json

# ── Docker ───────────────────────────────────────────────────────────────────
build: ## Build all Docker images
	$(DOCKER_COMPOSE) build --no-cache

up: ## Start all services
	$(DOCKER_COMPOSE) up -d
	@echo "$(GREEN)Services running:$(RESET)"
	@echo "  API:       http://localhost:8000"
	@echo "  Docs:      http://localhost:8000/docs"
	@echo "  Grafana:   http://localhost:3000"
	@echo "  Prometheus: http://localhost:9090"

down: ## Stop all services
	$(DOCKER_COMPOSE) down

logs: ## Tail logs
	$(DOCKER_COMPOSE) logs -f --tail=100

restart: ## Restart backend only
	$(DOCKER_COMPOSE) restart backend

ps: ## Show running containers
	$(DOCKER_COMPOSE) ps

# ── Database ─────────────────────────────────────────────────────────────────
migrate: ## Run database migrations
	cd backend && alembic upgrade head

migrate-down: ## Rollback last migration
	cd backend && alembic downgrade -1

migrate-create: ## Create new migration (usage: make migrate-create NAME=add_alerts_table)
	cd backend && alembic revision --autogenerate -m "$(NAME)"

# ── Monitoring ───────────────────────────────────────────────────────────────
monitor-up: ## Start Prometheus + Grafana only
	$(DOCKER_COMPOSE) up -d prometheus grafana

monitor-reload: ## Reload Prometheus config
	curl -X POST http://localhost:9090/-/reload

# ── Cleanup ──────────────────────────────────────────────────────────────────
clean: ## Remove build artifacts
	find . -type f -name "*.pyc" -delete
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type d -name ".pytest_cache" -exec rm -rf {} +
	find . -type d -name "htmlcov" -exec rm -rf {} +
	rm -rf dist/ build/ *.egg-info

clean-docker: ## Remove all Docker artifacts
	$(DOCKER_COMPOSE) down -v --remove-orphans
	docker system prune -f

# ── CI/CD ────────────────────────────────────────────────────────────────────
ci: lint test security-scan ## Run full CI pipeline locally

deploy-staging: ## Deploy to staging (requires Azure credentials)
	./scripts/deploy.sh staging

deploy-prod: ## Deploy to production (requires approvals)
	./scripts/deploy.sh production
