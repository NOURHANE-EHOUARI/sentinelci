# SentinelCI — instructions for coding agents

## What this repository is

SentinelCI is an intelligent DevSecOps and software supply-chain security platform built by a two-person team.
It scans every change, decides with testable policy-as-code whether it may ship, signs artifacts with the
evidence behind that decision, and refuses to deploy anything without that evidence. AI explains and proposes
fixes; it never decides.

- Full specification: `docs/spec/SPEC.md` (section numbers are stable — tasks reference them).
- Contracts between the two tracks: `schemas/` (JSON Schema draft 2020-12, with valid/invalid fixtures).
- Architecture decisions: `docs/adr/`.

## Golden rules (non-negotiable)

1. **English only** — code, comments, docstrings, docs, commit messages, UI text.
2. **Deterministic decides, AI advises.** `cli/src/sentinelci/{risk,policy,enrich,normalize}` must never import
   `sentinel_ai`. This is enforced by `lint-imports`; never weaken that contract.
3. **Fail closed.** A scanner error, timeout or integrity mismatch must produce a BLOCK (rule SC-010), never an
   empty pass.
4. **Never weaken a policy, a test, a schema or a scanner rule to make CI pass.** Stop and explain instead.
5. **Everything is evidence.** Decisions record the digests of all inputs. Policies never read the clock:
   the evaluation time comes from `input.evaluated_at`.
6. **No real secrets anywhere.** Fake demo secrets live only under `demo-shop/` and must be obviously fake and
   listed in `demo-shop/ground-truth/`. Never print, log or commit tokens or keys (`*.key`, `.env` are ignored).
7. **Supply-chain hygiene.** Add Python dependencies only with `uv add` (lockfile with hashes) and justify each
   new dependency in the PR. Pin every GitHub Action by full commit SHA with a `# vX.Y.Z` comment. Give every
   workflow job the least privilege it needs (`permissions:`), `persist-credentials: false` on checkout.
8. **Contracts first.** If a change needs a different data shape, update the schema version and its fixtures in
   the same PR; never silently diverge from `schemas/`.

## Repository status: private phase

The repository stays private until the project is complete. Until then (see ADR-0006):
- Signing uses Cosign **key pairs** with no upload to the public transparency log (no keyless signing, because the
  keyless certificate would publish the repository identity).
- SLSA provenance is produced as a Cosign in-toto attestation (GitHub artifact attestations require a public repo).
- Scan results go to PR comments, workflow artifacts and our dashboard (no GitHub code-scanning upload).
- Kubernetes demos use the local registry of the kind cluster.
- GitHub Actions minutes are limited (Free plan): use path filters and caches; run the full image scan nightly on `main`.
- `main` has no server-side protection: never commit or push to `main` directly. Always work on a task branch
  and open a PR; the other team member reviews and merges only with
  a green CI, or a local `make check` report on the PR head while Actions cannot run.

## Commands

```bash
make setup      # uv sync --locked + pre-commit hooks
make check      # ruff, mypy (strict), import contract, pytest (incl. contracts), zizmor
make format     # auto-format
```

## Layout and ownership

| Path | Owner | Notes |
|---|---|---|
| `cli/src/sentinelci/{scanners,normalize,supplychain,report}` | Track A | A1, A2, A4, A3 |
| `cli/src/sentinelci/{enrich,risk,policy}` | Track B | B2, B3, B4 |
| `platform/api`, `platform/worker` | Track B (remediation jobs: A) | B1, A6 |
| `ai/src/sentinel_ai/correlate` | Track A | A7 |
| `ai/src/sentinel_ai/*` (rest) | Track B | B5, B6 |
| `platform/web` | B core, pages per owner | B7, A8 |
| `policies/` | Track B | Rego + tests + risk model |
| `deploy/compose/` (platform services) | Track B | B1 |
| `deploy/compose/{prometheus,grafana}/` | Track A | A8 |
| `deploy/{kind,helm,kyverno,argocd}/`, `.github/workflows/sentinel-*.yml` | Track A | A3, A4, A5 |
| `eval/` | Track B | B8 |
| `demo-shop/` | A (infra, deps, secrets) + B (app code) | INTENTIONALLY VULNERABLE |
| `schemas/`, `docs/` | Shared | |

## How to work on a task

1. One task (e.g. `A2`) = one branch (`a2/<short-name>`) = one session.
2. Read the task card in `docs/spec/SPEC.md` section 15 and the contract it touches in `schemas/`.
3. Plan first, then write tests first (golden files / fixtures), then implement.
4. Run `make check` before committing. Conventional Commits (`feat(normalize): ...`).
5. Open a PR using the template; the other team member reviews (CODEOWNERS).

## Never do

- Run code from `demo-shop/` outside a container, or expose it beyond localhost.
- Use `pull_request_target`, or give a job that executes repository code access to secrets or write tokens.
- Let any AI output change a verdict, create a waiver, or merge a PR.
- Let the scanned repository configure or silence a scanner (config files, ignore files, inline allow
  comments). Scanner configuration belongs to SentinelCI; exceptions are waivers.
