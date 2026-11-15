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

What it refuses before anything runs: a working tree that is not clean, a tracked file git is told not to look
at (skip-worktree or assume-unchanged), a tracked file that is not HEAD's blob byte for byte (even when the
index's stat data says it is), a replace ref, a `GIT_DIR`-like variable that points git elsewhere, a file
that git ignores among the gate's inputs (`policies/`, `.sentinel/waivers.yaml`, `.sentinel/vex.json`,
`tools.lock.toml`: the gate would read it), a `HEAD` that is not `origin/main`, an `origin` that is not this
repository or that has more than one URL, `COSIGN_PASSWORD` in the environment, a key that is not the pair of
`deploy/keys/release.pub` or a wrong password. A scan that ends without writing its tool status stops the release
before the gate decides.
