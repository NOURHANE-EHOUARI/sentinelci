# ADR-0015: Cache only what is verified after it is restored

- Status: proposed
- Date: 2026-11-11
- Builds on: ADR-0002 (GitHub Actions), ADR-0006 (private phase, GitHub Free minutes), ADR-0008 (the base
  branch's pipeline judges a pull request)

## Context

GitHub Free gives a limited number of Actions minutes, and every scan job downloads the scanners' release archives
again (Gitleaks, Trivy, Opengrep, Syft, Grype, OPA: hundreds of megabytes). SPEC §18 answers the minutes risk with caches. A
cache is also an input written by another run. GitHub scopes caches by ref: a pull request's runs can read the
base branch's caches and their own, never another pull request's, and the base branch never reads a pull request's.
All the workflows of one pull request share its scope, though. So a cache that `ci.yml` writes while it runs the
change's own code could be restored by the gate of that same pull request, if both used the same key.

## Decision

1. **A cache is kept only if what is restored is verified before it is used.** The scanners' release archives
   qualify. `sentinel tools install` reuses a cached archive only if its sha256 is the one `tools.lock.toml`
   names, downloads it again otherwise, and always extracts the binary again from the verified archive
   (`cli/tests/scanners/test_install_verify.py`). So an entry written by anyone can at most cost a download.
2. **Only `${{ runner.temp }}/sentinel-tools/cache` is cached**, with a key per job and per lock
   (`sentinel-tool-archives-<job>-<os>-<hashFiles(tools.lock.toml)>`), and the next step installs from it. The
   binaries (`bin/`) are never cached.
3. **Package-manager caches are explicit, and kept only where the change runs anyway.** setup-uv turns its cache
   on by default for hosted runners, so every step says `enable-cache`. Only `ci.yml` keeps uv's cache: its jobs
   run the change's own code, hold no write token, and no job that judges a change reads that cache. The gate,
   the remediation bot and the nightly replay keep it off, and npm's cache is off everywhere.
4. **No job that holds a write permission restores a cache.**

`tests/ci/test_caching.py` checks all four on every workflow.

## Consequences

- Each scan job downloads the archives once per lock change instead of once per run. A new `tools.lock.toml` is
  a new key, and so a fresh download.
- A poisoned or stale cache entry fails the sha256 check and is downloaded again: the cache can never change what
  runs, only how fast it starts.
- `ci.yml` stays as fast as before. It now says explicitly that it keeps uv's cache, and why that is safe there.
