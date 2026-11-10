.DEFAULT_GOAL := help
.PHONY: help setup check lint format typecheck imports policy test zizmor tools tools-verify compose-env up down \
	kind-up kind-policy kind-down

# OPA is a pinned binary, not a Python package: `uv run sentinel tools install opa` (tools.lock.toml).
OPA ?= $(or $(SENTINEL_OPA),opa)
COMPOSE := docker compose -f deploy/compose/compose.yaml

help: ## Show available targets
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-12s %s\n", $$1, $$2}'

setup: ## Install the locked workspace and git hooks
	uv sync --locked
	uv run pre-commit install

check: lint typecheck imports policy test zizmor ## Everything CI runs

lint: ## Ruff lint + format check
	uv run ruff check .
	uv run ruff format --check .

format: ## Auto-format and auto-fix
	uv run ruff format .
	uv run ruff check --fix .
	$(OPA) fmt --write policies

typecheck: ## mypy (strict)
	uv run mypy

imports: ## Architecture contract: the decision path never imports sentinel_ai
	uv run lint-imports

policy: ## Rego format, strict compile and unit tests (deterministic built-ins only), coverage >= 90%
	$(OPA) fmt --list --fail policies
	uv run sentinel policy capabilities --opa "$$(command -v $(OPA))" --out out/opa-capabilities.json
	$(OPA) check --strict --capabilities out/opa-capabilities.json policies
	$(OPA) test --capabilities out/opa-capabilities.json policies
	$(OPA) test --capabilities out/opa-capabilities.json --coverage --threshold 90 policies > /dev/null

test: ## Unit and contract tests
	uv run pytest

zizmor: ## Static security audit of GitHub Actions workflows
	uv run zizmor --offline --min-severity low .github/workflows

tools: ## Download, hash-check and install the pinned scanners into .sentinel/tools
	uv run sentinel tools install

tools-verify: ## Fail closed unless installed scanners match tools.lock.toml (writes out/tools-manifest.json)
	uv run sentinel tools verify --report out/tools-manifest.json

compose-env: ## Create deploy/compose/.env with random local credentials (git-ignored, never overwritten)
	uv run python deploy/compose/make_env.py

up: compose-env ## Start the local platform; COMPOSE_PROFILES=ai,observability adds Ollama, Prometheus, Grafana
	$(COMPOSE) up --detach --build --wait

down: ## Stop the local platform (volumes are kept; `docker compose ... down --volumes` wipes them)
	$(COMPOSE) down

# The demo cluster (A5b, deploy/kind): needs Docker, kubectl and the pinned kind (`uv run sentinel tools install kind`).
kind-up: ## Create the demo kind cluster: its registry on 127.0.0.1:5001 and Kyverno (safe to run twice)
	uv run python deploy/kind/cluster.py up

kind-policy: ## Apply the release admission policy, rendered from deploy/keys/release.pub (KEY=... to change it)
	uv run python deploy/kind/cluster.py policy $(if $(KEY),--key $(KEY))

kind-down: ## Delete the demo kind cluster and its registry
	uv run python deploy/kind/cluster.py down
