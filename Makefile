.DEFAULT_GOAL := help
.PHONY: help setup check lint format typecheck imports test zizmor compose-env up down

COMPOSE := docker compose -f deploy/compose/compose.yaml

help: ## Show available targets
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-12s %s\n", $$1, $$2}'

setup: ## Install the locked workspace and git hooks
	uv sync --locked
	uv run pre-commit install

check: lint typecheck imports test zizmor ## Everything CI runs

lint: ## Ruff lint + format check
	uv run ruff check .
	uv run ruff format --check .

format: ## Auto-format and auto-fix
	uv run ruff format .
	uv run ruff check --fix .

typecheck: ## mypy (strict)
	uv run mypy

imports: ## Architecture contract: the decision path never imports sentinel_ai
	uv run lint-imports

test: ## Unit and contract tests
	uv run pytest

zizmor: ## Static security audit of GitHub Actions workflows
	uv run zizmor --offline --min-severity low .github/workflows

compose-env: ## Create deploy/compose/.env with random local credentials (git-ignored, never overwritten)
	uv run python deploy/compose/make_env.py

up: compose-env ## Start the local platform; COMPOSE_PROFILES=ai,observability adds Ollama, Prometheus, Grafana
	$(COMPOSE) up --detach --build --wait

down: ## Stop the local platform (volumes are kept; `docker compose ... down --volumes` wipes them)
	$(COMPOSE) down
