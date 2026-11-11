.DEFAULT_GOAL := help
.PHONY: help setup check lint format typecheck imports policy test zizmor tools tools-verify compose-env up down \
	release release-block release-key self-gate release-sentinelci

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

# Releases are made on the laptop that holds the release key (ADR-0011, deploy/release/release.py): from a clean
# checkout of origin/main, with Docker (buildx) and the pinned tools (`make tools`). The password is asked.
release: ## Build, decide on and sign shop-api's release image (KEY=~/.sentinelci/release.key) -> out/release/bundle
	uv run --locked python deploy/release/release.py $(if $(KEY),--key $(KEY))

release-block: ## The demo's BLOCK image: the gate must block it, nothing is signed -> out/release/block-image
	uv run --locked python deploy/release/release.py --requirements requirements.block.txt --expect-block

release-key: ## Make the release key pair (~/.sentinelci/release.key) and deploy/keys/release.pub, to commit
	uv run --locked python deploy/release/release.py key $(if $(KEY),--key $(KEY))

self-gate: ## SentinelCI's release gate on its own tree at main, without demo-shop (A10) -> out/self-gate
	uv run --locked python deploy/release/release.py self-gate

release-sentinelci: ## SentinelCI's own release VERSION=X.Y.Z: self-gate, build twice, sign, verify, tag (A10)
	uv run --locked python deploy/release/release.py sentinelci --version $(VERSION) $(if $(KEY),--key $(KEY))
