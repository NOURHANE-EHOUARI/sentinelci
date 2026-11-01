# ADR-0011: Release pipeline and the path to the demo cluster

- Status: proposed (Track A design for A4c and A5b; to agree with Track B before implementation)
- Date: 2026-11-01
- Builds on: ADR-0006 (private phase), ADR-0008 (base-branch pipeline), ADR-0010 (release attestations); the
  commands of #35 (`sentinel attest`, `sentinel verify`), #36 (`sentinel sbom`), #44 (registry mode) and #45
  (`sentinel admission-policy`)

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
  needs no Docker daemon.
- Actions minutes are capped (ADR-0006, decision 5), and the kind registry is on a laptop, out of reach of a
  hosted runner.
- The seeded `services/shop-api/Dockerfile` cannot build, by design: GT-IAC-006 pipes a remote script to a
  shell. It is a scan target, not a release.

## Decision (proposed)

1. **One release sequence, two runners.** `deploy/release/release.sh` runs the whole sequence below. It is
   called by `.github/workflows/sentinel-release.yml` (`workflow_dispatch`, and pushes to `main` touching the
   release image, with path filters) and by `make release` on a laptop. Both run the same commands from the
   same commit, so a local release is the CI release.
2. **Build without a registry and without credentials:**
   `docker buildx build --output type=oci,dest=image.oci.tar --provenance=false --sbom=false`.
   - BuildKit's own attestations are off: SentinelCI's four statements are the evidence.
   - The release digest is the manifest digest in the layout's `index.json`, read once and passed explicitly
     to every later step.
3. **Analyse the layout, decide on the digest.** These steps run in the job with no secret:
   - `sentinel sbom` (oci-archive, `--image-digest`) gives CycloneDX and SPDX;
   - Grype scans the SBOM (CONTAINER findings, adapter A1) and the source scans run as in `sentinel-scan.yml`;
   - `sentinel evaluate --context release --image-digest <digest> --sbom <cyclonedx>` makes the decision.

   A BLOCK stops here: nothing is signed (ADR-0010, decision 1).
4. **Attest in the only job that holds the key**, after the decision. That job never builds or runs
   repository code (ADR-0006, decision 1). It:
   - starts `crane registry serve` on 127.0.0.1;
   - pushes the layout by digest (`crane push`);
   - runs `sentinel attest --push --registry-http`, then `sentinel verify`, in registry mode, which are the
     checks Kyverno makes;
   - writes the **release bundle** with `cosign save`: an OCI layout holding the image, its signature and its
     four attestations;
   - uploads the release bundle and the evidence bundles as the release artifact.

   The ephemeral registry needs no registry credential at all. The private GHCR package of ADR-0006,
   decision 4, becomes optional: `cosign copy` can publish a release bundle there later, unchanged.
5. **Deploy from the bundle (A5b).** `make demo-release` runs these steps:
   - `cosign load` the bundle into the kind registry; the digest is unchanged, so the decision still names it;
   - bump the digest in `demo-shop/gitops/` (Argo CD);
   - render the admission policy once per cluster with `sentinel admission-policy`, from the committed release
     public key.

   Kyverno then checks the image against the kind registry, by the same rules as `sentinel verify`.
6. **The release image** is a hardened Dockerfile next to the seed: pinned base digest, non-root, no remote
   scripts. It has its own ground-truth controls. B9's application code goes into it, and the seeded
   Dockerfile stays a scan target. The demo's "attack" uses an unsigned image and an image whose decision is
   BLOCK; both are refused at admission.
7. **The key.** It is a repository secret (`COSIGN_PRIVATE_KEY`, `COSIGN_PASSWORD`), referenced only by the
   attest job, as in ADR-0006. GitHub Free gives a private repository no environment protection rules, so the
   job's condition (decision not BLOCK, `main`, this repository) and review of `.github/` are the guard. The
   public key is committed (`deploy/keys/release.pub`).

## Consequences

- A release is a file: the bundle can be verified offline (`sentinel verify --evidence`), loaded into any
  registry, and replayed in the demo without network access to GitHub.
- The demo runs fully on a laptop with `make release && make demo-release`, which also saves Actions minutes.
  CI releases stay possible and identical.
- Track B's application code (B9) and the release Dockerfile (A9) are a dependency of the M2 demo.
- Not decided here: whether CI releases also publish to the private GHCR package (optional, decision 4).
  When the repository goes public, keyless signing and GitHub artifact attestations replace the key and the
  CLI-written provenance (ADR-0006).
