# ADR-0007: SeaweedFS instead of MinIO for the evidence store

- Status: proposed (accepted when the Compose skeleton PR is merged)
- Date: 2026-10-28

## Context

The specification (§4.4) names MinIO as the S3-compatible evidence store. While building the Sprint 0 Compose
skeleton, MinIO turned out to have no maintained public image: `minio/minio` returns 404 on Docker Hub, the
`bitnami/minio` image is gone, and `quay.io/minio/minio` refuses anonymous pulls. Building MinIO from source
would make us maintain an unmaintained server. The platform only needs an S3 API: it stores content-addressed
evidence bundles (manifest, decision, findings, SBOMs, raw outputs).

Candidates with a pinnable, actively published image (checked on 2026-10-28):

| | Licence | Maturity | Setup |
|---|---|---|---|
| SeaweedFS | Apache-2.0 | since 2015, monthly releases | one container (`weed server -s3`); admin credentials from environment variables |
| RustFS | Apache-2.0 | 1.0 in 2026 | MinIO drop-in |
| Garage | AGPL-3.0 | since 2020 | needs a cluster-layout and key bootstrap step after start |

## Decision

Use **SeaweedFS** (`chrislusf/seaweedfs`, pinned by tag and digest) as the evidence store, through its S3
gateway only. Platform code talks plain S3 (boto3 or equivalent), so the store stays replaceable.

Hardening in `deploy/compose/compose.yaml`, all verified by tests and by hand:

- S3 requests are authenticated with credentials generated into the git-ignored `deploy/compose/.env`;
  anonymous and wrong-key requests get 403.
- The master, volume and filer HTTP APIs bind to the container's loopback (`-ip.bind=127.0.0.1`): the filer API
  would otherwise bypass S3 authentication for any container on the network.
- The Iceberg catalog (port 8181) and Lance namespace server (9101), on by default and unauthenticated, are
  turned off.

## Consequences

- SPEC §4.4, §11, §15.2 (B1) and the Sprint 0 checklist say SeaweedFS instead of MinIO.
- Any S3 client works; SeaweedFS-specific features (filer, Iceberg) are deliberately not used.
- If the decision is revisited, only the Compose service changes, not the platform code.
