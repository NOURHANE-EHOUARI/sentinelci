.DEFAULT_GOAL := help
.PHONY: help setup check lint format typecheck imports test zizmor tools tools-verify

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

tools: ## Download, hash-check and install the pinned scanners into .sentinel/tools
	uv run sentinel tools install

tools-verify: ## Fail closed unless installed scanners match tools.lock.toml (writes out/tools-manifest.json)
	uv run sentinel tools verify --report out/tools-manifest.json
