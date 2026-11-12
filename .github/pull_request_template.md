## What and why

<!-- Task id (e.g. A2, B4) and a short description. -->

## How it was verified

- [ ] `make check` passes locally
- [ ] Tests added or updated (golden files / fixtures where relevant)
- [ ] Contracts in `schemas/` unchanged, or bumped to a new version with fixtures

## Security checklist

- [ ] No real secret, token or key added anywhere
- [ ] New dependencies justified below (name, why, maintainer, alternatives)
- [ ] New GitHub Actions pinned by full commit SHA with a version comment
- [ ] Tool bump in `tools.lock.toml`: the real-tool tests ran with `SENTINEL_TOOLS_DIR` (for Trivy, `cli/tests/scanners/test_trivy_exposing.py`), result below
- [ ] No policy, test or scanner rule weakened to make CI pass
- [ ] Decision path (`risk`, `policy`, `enrich`, `normalize`) does not import `sentinel_ai`

## New dependencies

<!-- None, or a short justification per dependency. -->
