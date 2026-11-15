.DEFAULT_GOAL := help
.PHONY: help setup check lint format typecheck imports policy test zizmor web eval tools tools-verify compose-env up down \
	eval-correlation eval-correlation-calibrate remediate-code release release-block release-key self-gate \
	release-sentinelci kind-up kind-policy kind-down demo-release

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
	uv run zizmor --offline --ignore-lockfile --min-severity low .github/workflows

web: ## Dashboard: locked install (no package scripts), typed client up to date, types, tests, build
	cd platform/web && npm ci && npm run check

# The scanners come from SENTINEL_TOOLS_DIR (default .sentinel/tools); DB_DIR=<grype-db dir> measures SCA too.
EVAL_TOOLS ?= $(or $(SENTINEL_TOOLS_DIR),.sentinel/tools)
eval: ## Detection report of demo-shop (B8): out/eval/detection.json and detection.md
	uv run python eval/detection/run.py --tools-dir $(EVAL_TOOLS) $(if $(DB_DIR),--db-dir $(DB_DIR))

# The correlator on make eval's findings (A7), with the pinned embedding model on a local Ollama (ADR-0009).
eval-correlation: ## Correlation on demo-shop's test half (A7): out/eval/correlation.json and .md, after make eval
	uv run python eval/correlation/run.py

eval-correlation-calibrate: ## Calibrate stage 2b on the calibration half (A7): eval/correlation/threshold.json
	uv run python eval/correlation/run.py --calibrate

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

remediate-code: ## LLM fixes of main's SAST findings, verified (ADR-0014): TEST_IMAGE=<pinned> [FINDING=] [PUBLISH=1] [API_URL=]
	uv run python deploy/remediate/remediate_code.py --test-image "$(TEST_IMAGE)" \
		$(if $(FINDING),--finding "$(FINDING)") $(if $(PUBLISH),--publish) $(if $(API_URL),--api-url "$(API_URL)")

# Releases are made on the laptop that holds the release key (ADR-0011, deploy/release/release.py): from a clean
# checkout of origin/main, with Docker (buildx) and the pinned tools (`make tools`). The password is asked.
release: ## Build, decide on and sign shop-api's release image (KEY=~/.sentinelci/release.key) -> out/release/bundle
	uv run --locked python deploy/release/release.py $(if $(KEY),--key $(KEY))

release-block: ## The demo's BLOCK image: the gate must block it, nothing is signed -> out/release/block-image
	uv run --locked python deploy/release/release.py --requirements requirements.block.txt --expect-block

release-key: ## Make the release key pair (~/.sentinelci/release.key) and deploy/keys/release.pub, to commit
	uv run --locked python deploy/release/release.py key $(if $(KEY),--key $(KEY))

self-gate: ## SentinelCI's release gate on main, run from a pipeline commit (a vX.Y.Z tag, or PIPELINE=<HEAD>) (A10)
	uv run --locked python deploy/release/release.py self-gate $(if $(PIPELINE),--pipeline $(PIPELINE))

release-sentinelci: ## SentinelCI's own release VERSION=X.Y.Z of main, judged from a pipeline commit (PIPELINE=) (A10)
	uv run --locked python deploy/release/release.py sentinelci --version $(VERSION) $(if $(KEY),--key $(KEY)) $(if $(PIPELINE),--pipeline $(PIPELINE))

# The demo cluster (A5b, deploy/kind): needs Docker, kubectl, git and the pinned kind and Cosign
# (`uv run sentinel tools install kind cosign`).
kind-up: ## Create the demo cluster: registry (127.0.0.1:5001), Kyverno, Argo CD, GitOps server (safe to run twice)
	uv run python deploy/kind/cluster.py up

kind-policy: ## Apply the release admission policy, rendered from deploy/keys/release.pub (KEY=... to change it)
	uv run python deploy/kind/cluster.py policy $(if $(KEY),--key $(KEY))

kind-down: ## Delete the demo kind cluster and its registry (the GitOps repository in .sentinel/gitops is kept)
	uv run python deploy/kind/cluster.py down

demo-release: ## Deploy a release bundle through GitOps (BUNDLE=out/release/bundle, KEY=deploy/keys/release.pub)
	uv run python deploy/kind/demo.py release $(if $(BUNDLE),--bundle $(BUNDLE)) $(if $(KEY),--key $(KEY))
