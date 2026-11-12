# ADR-0011: Release pipeline and the path to the demo cluster

- Status: accepted (2026-11-01, review of #46 by Hiba: yes to the design, with the key kept off GitHub and the
  release image's own dependencies)
- Date: 2026-11-01
- Builds on: ADR-0006 (private phase), ADR-0008 (base-branch pipeline), ADR-0010 (release attestations); the
  commands of #35 (`sentinel attest`, `sentinel verify`), #36 (`sentinel sbom`), #44 (registry mode) and #45
  (`sentinel admission-policy`)
- Supersedes: ADR-0006 decision 1 (the signing key as a repository secret, referenced by the attest job); makes
  ADR-0006 decision 4 (a private GHCR package for CI images) optional. The SPEC lines that still put the key in
  CI (sections 4.3, 5 job isolation and the section 18 risk row) are updated with A4c.
- Amended: 2026-11-11 (A4c, the laptop release): the sequence is `deploy/release/release.py` (Python, like
  `deploy/kind/*.py`, so each refusal is tested), the provenance names it as the builder, and the key password
  is asked by the script (decisions 1 and 4; see "Implementation").

## Context

M2 needs "a signed image with SBOM, provenance and decision, and `sentinel verify`" (SPEC section 16), and M3 a
kind cluster where Kyverno admits only such images (SPEC section 7). The commands exist. What remains is how
they are chained, where the image lives at each step, and how a release reaches the kind cluster's local
registry (ADR-0006, decision 4). Facts checked with the pinned tools on 2026-11-01:

- `sentinel sbom` reads an OCI layout or archive and records the image's manifest digest (`--image-digest`),
  so analysis needs no registry.
- Cosign 3 stores the signature and the attestations as Sigstore bundles, OCI referrers of the image. `cosign
  save` writes the image with its referrers to an OCI layout. `cosign load` pushes that layout to another
  registry with the digest unchanged, and `cosign verify-attestation` then verifies the same statements there.
- crane's `registry serve` is an in-memory OCI registry, enough for `cosign attest` and `cosign save`. It
  needs no Docker daemon, and crane is pinned in `tools.lock.toml` (#44).
- Actions minutes are capped and blocked for now (ADR-0006, decision 5). The kind registry is on a laptop,
  out of reach of a hosted runner.
- **A repository secret is not protected by a job's condition here.** Every run triggered by a push or a
  `workflow_dispatch` on any branch can read it, because `workflow_dispatch` runs the workflow file of the
  selected ref. A branch can therefore carry an edited `sentinel-release.yml` that prints the key, and run it
  before anyone reviews `.github/`. GitHub Free offers no environment branch rules for a private repository.
  The only guard would be that just the two of us, and our Claude sessions, can push.
- The seeded `services/shop-api/Dockerfile` cannot build, by design: GT-IAC-006 pipes a remote script to a
  shell. The seeded `requirements.txt` would make any release BLOCK, since pyyaml 5.3.1 gives SC-002.

## Decision

1. **One release sequence, two runners.** `deploy/release/release.py` runs the sequence below, from the
   committed CLI, lock and policies.
   - `make release` runs it all on a laptop. During the private phase it is the only signer.
   - `.github/workflows/sentinel-release.yml` (`workflow_dispatch`, and pushes to `main` touching the release
     image, with path filters) runs decisions 2 and 3 with no secret, and stops before signing.

   The laptop release and the CI release are the same commands from the same commit. The CI runner is not
   written yet: Actions cannot run during the private phase's billing block, and it would only decide, never
   sign (decision 7).
2. **Build without a registry and without credentials:**
   `docker buildx build --output type=oci,dest=image.oci.tar --provenance=false --sbom=false`.
   - BuildKit's own attestations are off: SentinelCI's four statements are the evidence.
   - The release digest is the manifest digest in the layout's `index.json`.
3. **Analyse the layout, decide on its digest:**
   - `sentinel sbom` (oci-archive, `--image-digest`) gives CycloneDX and SPDX;
   - Grype scans the SBOM (CONTAINER findings, adapter A1) and the source scans run as in `sentinel-scan.yml`;
   - `sentinel evaluate --context release --image-digest <digest> --sbom <cyclonedx>` makes the decision.

   A BLOCK stops here: nothing is signed (ADR-0010, decision 1).
4. **Attest, on the laptop.** The attest step runs only after the decision, and never builds or runs
   repository code. It:
   - reads the manifest digest from the layout's `index.json` **again**, and refuses unless it is the
     decision's `subject.image_digest`. It never takes the digest from an earlier step's output: a different
     layout pushed under the right name would otherwise be signed, at least until `sentinel verify` runs;
   - starts `crane registry serve` on 127.0.0.1 and pushes the layout by digest (`crane push`);
   - runs `sentinel attest --push --registry-http`, then `sentinel verify` in registry mode, which are the
     checks Kyverno makes;
   - writes the **release bundle** with `cosign save`: an OCI layout holding the image, its signature and its
     four attestations, next to the evidence bundles.

   `make release` ends by printing the digest and the trust report (16/16 in registry mode). The ephemeral
   registry needs no registry credential; the private GHCR package of ADR-0006, decision 4, becomes optional.

   The laptop signer runs repository code too (`release.py`, the Makefile and the CLI of the checkout, in the
   session where the key password is typed), so `release.py` applies the laptop analog of ADR-0008: it
   refuses unless the working tree is clean and `HEAD` is `origin/main`. The key password is asked on the
   terminal; it is never stored in `.env` or exported to the environment, where any process of the session
   could read it (amended 2026-11-11: `release.py` asks for it, without echo, and gives it only to the two
   processes that use the key, see "Implementation").
5. **Deploy and attack from the bundle (A5b):**
   - `make demo-release` loads the bundle into the kind registry (`cosign load`, digest unchanged) and verifies
     it there. It then commits the new digest to the demo's GitOps repository and waits for
     `kubectl rollout status`. It fails if the verification or the rollout fails, and it is safe to run twice.
   - That GitOps repository is a local bare repository on the laptop, created from `deploy/argocd/` and served
     read-only to Argo CD inside kind. Nothing is pushed to GitHub: `main` is never written, and the cluster
     holds no GitHub credential. (`demo-shop/gitops/` stays a seeded scan target.)
   - The admission policy is rendered once per cluster with `sentinel admission-policy`, from the committed
     release public key, so Kyverno trusts exactly what `sentinel verify` trusts.
   - `make demo-attack` deploys the two refused cases and shows Kyverno's denials: an unsigned image, and the
     BLOCK image of decision 6, which `attest` refused to sign.

   With these, the M2/M3 demo is three commands, offline after the first `sentinel tools grype-db` (#52).
6. **The release image.** A hardened Dockerfile goes next to the seed (`services/shop-api/Dockerfile.release`,
   its build context an allow-list in `Dockerfile.release.dockerignore`):
   - Python 3.12-slim pinned by digest, updated by hand (Dependabot would bump the seeded Dockerfile in the
     same directory too);
   - UID 10001, port 8080;
   - writes only to `/tmp` (an `emptyDir` in the manifests), so `readOnlyRootFilesystem` and `drop: [ALL]`
     hold;
   - health at `GET /healthz` through the Kubernetes probes: no Dockerfile `HEALTHCHECK`, no curl.

   It installs `services/shop-api/requirements.release.txt`, which is hash-pinned (`--require-hashes`) with
   fixed versions and written by B9 with the application code. The demo's BLOCK image is the same Dockerfile
   with `--build-arg REQUIREMENTS=requirements.block.txt`: `requirements.release.txt` with pyyaml replaced by
   the seeded 5.3.1, hash-pinned (its sdist), which gives one BLOCK reason, GT-SCA-001 (SC-002, P0). The seeded
   `requirements.txt` cannot be the BLOCK image's: it has no hashes, and lxml 4.6.2 cannot be built on Python
   3.12 (review of #43). The ground truth gets a control for the release Dockerfile (no SC-011 on it). The
   seeded Dockerfile and `requirements.txt` stay scan targets, never built.
7. **The key stays off GitHub during the private phase.**
   - The release key pair lives on the laptop; the private key is password-protected and never committed.
   - The public key is committed (`deploy/keys/release.pub`), and the admission policy is rendered from it.
   - No workflow holds a signing secret. A CI signer would need its own key, and Kyverno would trust only the
     key that matches its cluster.
   - Signing in CI comes with the public phase and keyless signing (ADR-0006), where the identity is the
     workflow at `refs/heads/main` rather than a stored key.

## Implementation (A4c, 2026-11-11)

`make release` is `deploy/release/release.py`; `make release-block` builds the demo's BLOCK image with
`requirements.block.txt` and succeeds only when the gate blocks it; `make release-key` makes the key pair.

- **Preconditions.** `origin` must be `github.com/NOURHANE-EHOUARI/sentinelci`, the working tree clean (untracked
  files included, ignored ones not), and `HEAD` the `main` fetched from it now (`--no-fetch` compares with the
  last fetch). `COSIGN_PASSWORD` set in the environment is refused.
- **The key, before the long steps.** The password is asked once (`getpass`), then `cosign public-key` must open
  the key with it and derive exactly `deploy/keys/release.pub`: a wrong password or another key stops the
  release before the build. The password then reaches only `cosign public-key` and `sentinel attest`, which
  passes it only to Cosign; no other process (git, Docker, the scanners, crane) gets it. A BLOCK image
  (`--expect-block`) is never asked one.
- **The build context is the commit's.** `git archive HEAD` of `Dockerfile.release`, its `.dockerignore` and the
  files that allow-list admits. Only the allow-list form is understood (`*`, then `!path` or `!dir/` lines);
  anything else, a link in the context, or a requirements file outside it is refused. The working tree is never
  read, so an ignored or untracked file cannot reach the image or escape the scans.
- **What is scanned.** Secrets, SAST, IaC and CI workflows on that context (the same commands and tool statuses as
  `sentinel-scan.yml`), and the image itself (`sentinel scan image`, CONTAINER findings). The requirements files
  are not scanned as source: the image scan reads what was installed from the selected one (hash-pinned,
  `--no-deps`), while the context also holds the other one, which the build does not install. A failed scan
  leaves an empty findings file and its status, so the gate blocks (SC-010).
- **Provenance.** `sentinel attest --builder local-release` writes SLSA provenance whose builder is
  `https://github.com/NOURHANE-EHOUARI/sentinelci/deploy/release/release.py@refs/heads/main`, with build type
  `.../specs/local-release/v1`, the repository and commit as the source, and nothing about the machine (no host,
  user or path). `sentinel verify` and the admission policy are given that builder id; `sentinel attest`
  refuses `local-release` inside GitHub Actions.
- **Outputs.** Each run works in `out/release/work`. A release that passes writes `out/release/bundle` (the
  `cosign save` layout `make demo-release` reads) and `out/release/evidence` (decision, findings, SBOMs, tool
  status, the four Sigstore bundles, the evidence store and the trust reports); a BLOCK writes
  `out/release/block-image` (the OCI layout `make demo-attack` deploys) and `out/release/block-evidence`. Each
  replaces the previous one only once the run succeeded. Grype's database is kept in `out/grype-db`.

## Consequences

- A release is a file: the bundle can be verified offline (`sentinel verify --evidence`), loaded into any
  registry, and replayed in the demo without network access to GitHub. Kyverno re-verifies at admission, so
  carrying the bundle adds no trust: a modified bundle is refused.
- The demo runs fully on a laptop (`make release`, `make demo-release`, `make demo-attack`), which also saves
  Actions minutes. CI builds and decides with no secret, so a stolen workflow run cannot sign.
- A residual risk is named instead of hidden: whoever can push can read any repository secret. That is why
  there is none for signing.
- Track B's application code, `requirements.release.txt` and `requirements.block.txt` (B9) are a dependency of
  the M2 demo, and so is the release Dockerfile (A9).
- Not decided here: whether releases also publish to the private GHCR package (optional, decision 4). When the
  repository goes public, keyless signing in CI and GitHub artifact attestations replace the laptop key and the
  CLI-written provenance (ADR-0006).
