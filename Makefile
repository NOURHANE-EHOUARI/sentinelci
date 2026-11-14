.DEFAULT_GOAL := help
.PHONY: help setup check lint format typecheck imports policy test zizmor web eval tools tools-verify compose-env up down eval-replay

# OPA is a pinned binary, not a Python package: `uv run sentinel tools install opa` (tools.lock.toml).
OPA ?= $(or $(SENTINEL_OPA),opa)
COMPOSE := docker compose -f deploy/compose/compose.yaml

help: ## Show available targets
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-12s %s\n", $$1, $$2}'

setup: ## Install the locked workspace and git hooks
	uv sync --locked
	uv run pre-commit install

check: lint typecheck imports policy test zizmor web ## Everything CI runs

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

web: ## Dashboard: locked install (no package scripts), typed client up to date, types, tests, build
	cd platform/web && npm ci && npm run check

# The scanners come from SENTINEL_TOOLS_DIR (default .sentinel/tools); DB_DIR=<grype-db dir> measures SCA too.
EVAL_TOOLS ?= $(or $(SENTINEL_TOOLS_DIR),.sentinel/tools)
eval: ## Detection report of demo-shop (B8): out/eval/detection.json and detection.md
	uv run python eval/detection/run.py --tools-dir $(EVAL_TOOLS) $(if $(DB_DIR),--db-dir $(DB_DIR))

eval-replay: ## Replay identity (B8): record the corpus and make eval's decision, replay them, out/eval/replay.md
	uv run python eval/replay/run.py $(if $(wildcard out/eval/findings/gitleaks.ndjson),--findings out/eval/findings)

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
