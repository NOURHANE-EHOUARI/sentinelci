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
All the workflows of one pull request share its scope, though, and a key is only a string the run that saves an
entry chooses. So an entry that the pull request's own workflows save (`ci.yml`, or a workflow the change adds)
can be restored by the gate of that same pull request, under the gate's own key.

## Decision

1. **A cache is kept only if what is restored is verified before it is used.** The scanners' release archives
   qualify. `sentinel tools install` reuses a cached archive only if its sha256 is the one `tools.lock.toml`
   names, downloads it again otherwise, and always extracts the binary again from the verified archive
   (`cli/tests/scanners/test_install_verify.py`). That covers what `tools install` reads, not the restore
   itself: actions/cache extracts the whole entry with `tar -P` relative to the workspace before any of our
   steps runs, so an entry can write any file there, the pipeline checkout and the CLI's virtual environment
   included (#105 review). So a job that judges a change restores only where the base branch wrote the entry:
   the scan and the gate of `sentinel-scan.yml` restore nothing in a pull request
   (`if: github.event_name != 'pull_request'`, which also skips the post-job save). On a push to `main` only
   `main`'s own runs are in scope, and there an entry can at most cost a download. A manual run
   (`workflow_dispatch`) on another branch restores in that branch's scope, but it already runs that branch's
   workflows and pipeline (`github.sha`), so the cache gives it nothing it does not already have.
2. **Only `${{ runner.temp }}/sentinel-tools/cache` is cached**, with a key per job and per lock
   (`sentinel-tool-archives-<job>-<os>-<hashFiles(tools.lock.toml)>`), never with `restore-keys` (a prefix
   would restore another job's entry), and the next step installs from it. The binaries (`bin/`) are never
   cached.
3. **Package-manager caches are explicit, and kept only where the change runs anyway.** setup-uv turns its cache
   on by default for hosted runners, so every step says `enable-cache`. Only `ci.yml` keeps uv's cache: its jobs
   run the change's own code, hold no write token, and no job that judges a change reads that cache. The gate,
   the remediation bot and the nightly replay keep it off, and npm's cache is off everywhere.
4. **No job that holds a write permission restores a cache.**

`tests/ci/test_caching.py` checks all four on every workflow, and that the scan and the gate restore nothing in
a pull request (`test_a_job_that_judges_restores_no_cache_in_a_pull_request`).

## Consequences

- On a push to `main`, or a manual run, each scan job downloads the archives once per lock change instead of
  once per run. A new `tools.lock.toml` is a new key, and so a fresh download. A pull request's scan and gate download them
  every run, as before this ADR.
- Where the scan and the gate restore, only the base branch's runs wrote the entry, and a stale or corrupted
  archive fails the sha256 check and is downloaded again: there the cache changes only how fast a job starts. In
  a pull request, where the change's own workflows share the scope, nothing that judges it restores a cache.
- `ci.yml` stays as fast as before. It now says explicitly that it keeps uv's cache, and why that is safe there.
