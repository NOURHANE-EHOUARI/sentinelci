# ADR-0010: Release attestations and `sentinel verify`

- Status: proposed
- Date: 2026-10-31
- Task: A4 (SPEC sections 7, 13.2 and 15.1)

## Context

A release image may run only with the evidence behind its release decision (SPEC section 7). Kyverno checks that
evidence at admission (A5), `sentinel verify` checks it anywhere else (a laptop, the platform, an auditor), and
both must reach the same answer from the same signed statements. During the private phase (ADR-0006) signing
uses a Cosign key pair with no transparency-log upload, and the evidence must stay verifiable without network
access.

Cosign 3 signs an in-toto statement whose subject is a digest (`--hash`), writes it as a Sigstore bundle, and
verifies such a bundle offline against a public key and an expected subject digest
(`verify-blob-attestation --digest`). The same statements can also be attached to the image in its registry
(`cosign attest`), which is what Kyverno reads. Cosign re-serializes the predicate it signs (keys sorted), so the
signed predicate is not byte-identical to the file it came from.

## Decision

1. **Four attestations per release image**, each an in-toto statement with exactly one subject: the image's
   manifest digest, with the last segment of its name (`shop-api`) as the subject name. Trust is per digest:
   the name is informational, and `sentinel verify` ignores it, so the same content under another name is the
   same release (content addressing). They are signed by the `attest` job only, and only for a decision that
   is not BLOCK.

   | Attestation | Predicate type | Predicate |
   |---|---|---|
   | Release decision | `https://github.com/NOURHANE-EHOUARI/sentinelci/specs/release-decision/v1` | the Decision v1 record (`schemas/decision.v1.json`), context `release`, `subject.image_digest` = the image |
   | SBOM | `https://cyclonedx.org/bom` | the CycloneDX JSON SBOM of the image (Syft) |
   | Vulnerability scan | `https://cosign.sigstore.dev/attestation/vuln/v1` | Cosign's vulnerability predicate; `scanner.result` is a SentinelCI summary (`schemas/vuln-result.v1.json`) |
   | Provenance | `https://slsa.dev/provenance/v1` | SLSA v1, written by the CLI from the GitHub Actions context (ADR-0006, decision 2) |

2. **The signer binds the four together before signing**, and refuses otherwise (exit 3):
   - the decision is a valid Decision v1 for context `release`, its verdict is not BLOCK, and its
     `subject.image_digest` is the image being attested;
   - the findings file and the SBOM file are the ones the decision recorded: their sha256 equals
     `inputs.findings_digest` and `inputs.sbom_digest`;
   - the vulnerability result records the decision id, the findings digest, the SBOM digest and the SBOM's
     CycloneDX `serialNumber`; Cosign re-serializes the SBOM, so the serial number is what ties the signed SBOM
     to the result;
   - the provenance names the decision's repository and commit as its source.

3. **`sentinel verify <name>@sha256:<digest>`** checks every attestation and prints a trust report, one line per
   check. The image is trusted only if every check passes:
   - each of the four attestations is present, signed by the expected key, about exactly this digest, and of
     the expected predicate type (Cosign does the cryptography; the CLI re-checks the statement it parsed);
   - decision: a valid Decision v1 (the read model), context `release`, verdict not BLOCK, `subject.image_digest`
     equal to the image, `subject.repo` equal to `--repo`;
   - provenance: `runDetails.builder.id` equal to `--builder-id`, a source dependency
     `git+https://github.com/<repo>@<ref>` whose `gitCommit` is the decision's commit;
   - vulnerability result: it names the decision (`decision_id`), and its `findings_digest` is the decision's;
   - SBOM: a CycloneDX document whose `serialNumber` is the one the vulnerability result names.

   Exit codes: 0 trusted, 1 not trusted (any failed check), 3 the verification could not run (for example a
   Cosign binary that does not match `tools.lock.toml`). Both non-zero codes refuse the image.

4. **Two copies of the same statements.** The `attest` job attaches them to the image (`cosign attest`, read by
   Kyverno and by `sentinel verify` in registry mode) and also writes each one as a Sigstore bundle in the
   evidence artifact (`attestations/<kind>.sigstore.json`), which `sentinel verify --evidence <dir>` checks
   offline. The evidence mode came first (A4); the registry mode followed (A4d, `sentinel attest --push`,
   `sentinel verify` without `--evidence`), and the workflow follows in A4c. In registry mode:
   - the image itself is signed too (`cosign sign`), and `sentinel verify` requires that signature (SC-004).
     Cosign 3 stores each signature and each attestation as a Sigstore bundle, an OCI referrer of the image (or,
     on a registry without the referrers API, an entry of the `sha256-<hex>` tag index). The image signature is
     a DSSE statement of type `https://sigstore.dev/cosign/sign/v1`, and `cosign verify` accepts any statement
     the key signed about the digest as a signature: an attestation alone passes it. Kyverno's
     `verifyImageSignatures` behaves the same (A5). So `sentinel verify` looks for a statement of that type;
   - attestations are read with `cosign verify-attestation --type`, then re-checked on what Cosign printed
     (statement type, one subject, this digest). Identical statements count once, since a retried job
     attaches the same bytes (decision 6). Two different statements of one type make that attestation
     ambiguous: it fails;
   - a verification that ran and failed (Cosign exit codes 1 and 10 to 13), or an unreachable registry, is
     "not trusted" (exit 1). Plain HTTP only with `--registry-http`, for a local registry. Registry credentials
     reach Cosign only through `DOCKER_CONFIG`.

5. **Keys.** Private mode (now): a key pair, `--key` names the private key file or `env://VAR`; only that
   variable and `COSIGN_PASSWORD` reach the Cosign process (the runner's minimal environment drops the rest);
   no transparency log (`--tlog-upload=false` when signing, `--insecure-ignore-tlog` when verifying, because
   there is no log entry to check). Cosign 3.1.4 marks `--tlog-upload` and `--use-signing-config` deprecated
   (a warning on every attest): a Cosign bump that removes them means passing a `--signing-config` with no
   transparency log services instead, which the real-Cosign tests would show. GitHub mode (after going public): keyless, the identity being the release
   workflow; `sentinel verify` then takes `--certificate-identity` and `--certificate-oidc-issuer` instead of
   `--key`.

6. **Determinism.** The vulnerability predicate's `scanStartedOn` and `scanFinishedOn` are the decision's
   `evaluated_at`; nothing in a predicate reads the clock.

## Consequences

- One verifier for all four statements, testable offline with the real Cosign and a key generated per test:
  unsigned, wrong key, another image, a tampered bundle, a missing or BLOCK decision, a decision for another
  image, and provenance from another builder or repository are all refused.
- The SBOM binding relies on CycloneDX's `serialNumber`, which Syft always writes; an SBOM without one cannot
  be attested.
- Provenance written by the CLI in the attest job is a claim of the workflow, not a hardened builder: SLSA Build
  L2 at best until GitHub artifact attestations (L3 target) replace it in GitHub mode.
- Kyverno (A5) must require the same predicate types and the same decision conditions; its policy is checked
  against bundles produced by this code.
