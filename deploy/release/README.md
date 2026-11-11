# Releases on the laptop (ADR-0011)

While the repository is private, the laptop that holds the release key is the only signer: the key never
reaches GitHub. `release.py` builds shop-api's release image, decides on it with the release gate, and signs it
only when the gate lets it through. Its docstring lists every step and what each one refuses.

Needs Docker with buildx, `uv`, and the pinned tools (`make tools`, or `SENTINEL_TOOLS_DIR`).

## Once: the key pair

```bash
make release-key     # ~/.sentinelci/release.key (password asked twice), and deploy/keys/release.pub
```

Commit `deploy/keys/release.pub` through a pull request: the admission policy (`make kind-policy`) and
`sentinel verify` trust exactly that key. The private key and its password stay on this laptop; `*.key` is
git-ignored, and a key is never overwritten.

## Each release

From a clean checkout of `main`, as it is on GitHub:

```bash
make release         # asks the key password, then: build, decide, sign, verify, save
make release-block   # the demo's BLOCK image (requirements.block.txt): the gate must block it
```

| Output | What it is | Read by |
|---|---|---|
| `out/release/bundle` | the image, its signature and its four attestations (`cosign save`) | `make demo-release` |
| `out/release/evidence` | decision, findings, SBOMs, tool status, Sigstore bundles, evidence store, trust reports | `sentinel verify --evidence`, `sentinel replay` |
| `out/release/block-image` | the BLOCK image's OCI layout, never signed | `make demo-attack` |
| `out/release/block-evidence` | the BLOCK decision and its inputs | |

Exit codes: 0 released (or, for `release-block`, blocked as expected); 1 the gate blocked the release (or did
not block the BLOCK image); 3 the release could not be made. Nothing is signed unless the decision is PASS or
WARN, and nothing signed is kept unless `sentinel verify` trusts it.

What it refuses before anything runs: a working tree that is not clean, a `HEAD` that is not `origin/main`, an
`origin` that is not this repository, `COSIGN_PASSWORD` in the environment, a key that is not the pair of
`deploy/keys/release.pub` or a wrong password.

## The self-gate: SentinelCI on itself (A10)

SPEC principle P4, practice what we preach: the same release gate, on SentinelCI's own tree.

```bash
make self-gate       # out/self-gate/evidence: the decision and every input it was made on
```

Like a release, it runs from a clean checkout of `main` as it is on GitHub. It scans the commit's own files
(exported from the commit and checked blob by blob) without `demo-shop/`, the intentionally vulnerable target,
which its own workflow gates. The five scanners of the gate run on them: Gitleaks, Opengrep, Trivy, zizmor, and
Grype on the SBOM of the lockfiles (so it needs Grype's database, like a release). The waivers are the commit's
`.sentinel/waivers.yaml`, never the working tree's. Nothing is signed. Exit codes: 0 PASS or WARN, 1 BLOCK,
3 no decision.

Its first run, on this branch, found five things in SentinelCI itself, now fixed or waived:
- four `CREATE DATABASE` statements built with f-strings in the API tests (`python-sql-built-from-strings`):
  now `psycopg.sql.Identifier`;
- a test helper written with PEP 695 type parameters, which Opengrep cannot parse yet, so its SAST was not
  done (`sentinel-sast-not-analysed`): now a `TypeVar`;
- three fake, fingerprint-shaped values in test fixtures that Gitleaks reads as API keys: waived, each by
  its fingerprint, with an owner and an expiry, in `.sentinel/waivers.yaml`.
