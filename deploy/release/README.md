# Releases on the laptop (ADR-0011)

While the repository is private, the laptop that holds the release key is the only signer: the key never
reaches GitHub. `release.py` builds shop-api's release image, decides on it with the release gate, and signs
it
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
| `out/release/bundle` | the image, its signature and its four attestations (`cosign save`) | `make
demo-release` |
| `out/release/evidence` | decision, findings, SBOMs, tool status, Sigstore bundles, evidence store, trust
reports | `sentinel verify --evidence`, `sentinel replay` |
| `out/release/block-image` | the BLOCK image's OCI layout, never signed | `make demo-attack` |
| `out/release/block-evidence` | the BLOCK decision and its inputs | |

Exit codes: 0 released (or, for `release-block`, blocked as expected); 1 the gate blocked the release (or did
not block the BLOCK image); 3 the release could not be made. Nothing is signed unless the decision is PASS or
WARN, and nothing signed is kept unless `sentinel verify` trusts it.

What it refuses before anything runs: a working tree that is not clean, a tracked file git is told not to look
at (skip-worktree or assume-unchanged), a tracked file that is not HEAD's blob byte for byte (even when the
index's stat data says it is), a replace ref, a `GIT_DIR`-like variable that points git elsewhere, a file
that git ignores among the gate's inputs (`policies/`, `.sentinel/waivers.yaml`, `.sentinel/vex.json`,
`tools.lock.toml`: the gate would read it), a `HEAD` that is not `origin/main`, an `origin` that is not this
repository or that has more than one URL, `COSIGN_PASSWORD` in the environment, a key that is not the pair of
`deploy/keys/release.pub` or a wrong password. A scan that ends without writing its tool status stops the release
before the gate decides.

## The self-gate: SentinelCI on itself (A10)

SPEC principle P4, practice what we preach: the same release gate, on SentinelCI's own tree.

```bash
git switch --detach v1.0.0     # the pipeline: the last release (or a commit main was at, named)
make self-gate                 # judges origin's main; out/self-gate/evidence: the decision and its inputs
make self-gate PIPELINE=$(git rev-parse HEAD)   # when HEAD is no release tag, name it on purpose
```

The commit judged is not the one that judges, as in the workflow (ADR-0008). The checkout is the **pipeline
commit**: clean, a commit `main` was at (on `origin/main`'s first-parent line, so not a commit of a branch merged
into it), and a release tag `vX.Y.Z` or named with `PIPELINE=<HEAD>`. Its CLI, policies, `tools.lock.toml` and
`.sentinel/self-gate-waivers.yaml` decide. The **target** is `origin/main`, fetched now. Its own files (exported
from the commit and checked blob by blob) are scanned without `demo-shop/`, the intentionally vulnerable target,
which its own workflow gates. The five scanners of the gate run on them: Gitleaks, Opengrep, Trivy, zizmor, and
Grype on the SBOM of the lockfiles (so it needs Grype's database, like a release). So a change cannot bring the
waiver, the policy or the lock entry that lets it through: those count once they are in a pipeline commit. The
pipeline files changed between the two commits are printed and kept in `evidence/pipeline.json`. A target that is
its own pipeline (named on purpose) says so: that decision shows the commit passes its own gate, not one it did not
write.

The waivers are always named to `sentinel evaluate` and kept with the evidence (an empty file when the pipeline
has none); they are apart from `.sentinel/waivers.yaml`, which demo-shop's gates read. The VEX is
`.sentinel/self-gate-vex.json` when the pipeline has one. Nothing is signed. Exit codes: 0 PASS or WARN, 1
BLOCK, 3 no decision.

Its runs found these in SentinelCI itself, now fixed or waived:
- four `CREATE DATABASE` statements built with f-strings in the API tests (`python-sql-built-from-strings`):
  now `psycopg.sql.Identifier`;
- a test helper written with PEP 695 type parameters, which Opengrep cannot parse yet, so its SAST was not
  done (`sentinel-sast-not-analysed`): now a `TypeVar`. Three more PEP 695 regions (`guardrails.py`,
  `upload.py`) and a partial parse of `metrics.py` remain WARNs (SC-006), as the policy says;
- seven fake values in test fixtures and tests that Gitleaks reads as keys (fingerprint-shaped values, a key
  fingerprint, a `-----BEGIN ... PRIVATE KEY-----` header around `AAAA`, a test's unknown-shaped secret):
  waived, each by its fingerprint, with an owner and an expiry, in `.sentinel/self-gate-waivers.yaml`.

## SentinelCI's own release (A10)

```bash
make release-sentinelci VERSION=1.0.0   # asks the key password; out/release/sentinelci-1.0.0, tag v1.0.0
git push origin v1.0.0                  # publishing the tag is left to you
```

The same discipline as shop-api's image, applied to SentinelCI itself, run from a pipeline commit like the
self-gate (`PIPELINE=<HEAD>` when it is no release tag):
1. **Gated.** The self-gate runs first on `origin/main`, and a BLOCK builds and signs nothing.
2. **Reproducible.** It builds the wheel and source distribution of `sentinelci` and `sentinel-ai`, plus the
   policy bundle (`policies/` and `tools.lock.toml`). Everything is built twice, from the target's own files,
   with the commit's time as `SOURCE_DATE_EPOCH`, and the release is refused unless both builds are byte for
   byte the same. The build backend is pinned by hash: `uv build --build-constraints
   deploy/release/build-constraints.txt --require-hashes`, that file read from the pipeline commit.
3. **Signed and attested.** Each artifact and `SHA256SUMS` is signed with the release key. Each artifact is
   attested twice: SLSA provenance v1 (the commit, the build constraints' sha256, uv's version, the pipeline
   commit and the builder, no clock) and the self-gate's decision.
4. **Verified before it is kept.** Everything is verified with the committed public key only, offline, as
   anyone who downloads the release would. Only then is the release kept and the tag `vX.Y.Z` made, here.

A version is released once: its tag must not exist here or on origin, and both packages must declare it (bump
them through a pull request first).

To check a downloaded artifact:

```bash
cosign verify-blob --key deploy/keys/release.pub --insecure-ignore-tlog=true \
  --bundle sentinelci-1.0.0-py3-none-any.whl.sigstore.json sentinelci-1.0.0-py3-none-any.whl
cosign verify-blob-attestation --key deploy/keys/release.pub --insecure-ignore-tlog=true --type slsaprovenance1 \
  --bundle sentinelci-1.0.0-py3-none-any.whl.provenance.sigstore.json sentinelci-1.0.0-py3-none-any.whl
cosign verify-blob-attestation --key deploy/keys/release.pub --insecure-ignore-tlog=true \
  --type https://github.com/NOURHANE-EHOUARI/sentinelci/specs/release-decision/v1 \
  --bundle sentinelci-1.0.0-py3-none-any.whl.decision.sigstore.json sentinelci-1.0.0-py3-none-any.whl
```

The last one verifies the self-gate's decision attestation. Its predicate is the decision: once it verifies,
read the verdict, which must be `PASS` or `WARN`, and the commit judged, which must be the one the tag names:

```bash
jq -r '.dsseEnvelope.payload | @base64d | fromjson | .predicate | .verdict, .subject.commit' \
  sentinelci-1.0.0-py3-none-any.whl.decision.sigstore.json
git rev-parse 'v1.0.0^{commit}'
```

The signed provenance names the pipeline commit that judged the release (`pipeline.json` in the evidence says
it too, but no signature covers that file). Compare it with the tag's commit: if they are equal, the release
was judged by itself, which shows only that the commit passes its own gate (ADR-0011, decision 8).

```bash
jq -r '.dsseEnvelope.payload | @base64d | fromjson
       | .predicate.buildDefinition.internalParameters.gatePipeline.gitCommit' \
  sentinelci-1.0.0-py3-none-any.whl.provenance.sigstore.json
```

(`--insecure-ignore-tlog=true` because nothing goes to the public transparency log while the repository is
private, ADR-0006.)
