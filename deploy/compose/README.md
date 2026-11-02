# Local platform (Docker Compose)

The SentinelCI control plane on your machine (SPEC §4.4). **Local only**: every port binds `127.0.0.1`.

```bash
make up                                      # postgres + pgvector, redis, seaweedfs (S3), api
COMPOSE_PROFILES=ai make up                  # + ollama
COMPOSE_PROFILES=ai,observability make up    # + prometheus, grafana
make down                                    # stop; data volumes are kept
```

`make up` first runs `make compose-env`, which creates `deploy/compose/.env` with random credentials
(owner-only permissions, git-ignored). An existing value is never changed; variables added by a later task are
appended to an older file. Read your credentials there. Compose refuses to start if a credential is missing:
there is no default password anywhere.

| Service | URL on the host | Profile | Purpose |
|---|---|---|---|
| api | http://127.0.0.1:8000/healthz | default | control-plane API (B1) |
| postgres | `127.0.0.1:5432`, user and database `sentinel` | default | PostgreSQL 18 + pgvector |
| redis | `127.0.0.1:6379` (password) | default | Celery broker (B1) |
| seaweedfs | http://127.0.0.1:8333 (S3, signed requests only) | default | evidence store, ADR-0007 |
| ollama | http://127.0.0.1:11434 | `ai` | local LLM (B5); no model pulled yet |
| prometheus | http://127.0.0.1:9090 | `observability` | metrics (A8) |
| grafana | http://127.0.0.1:3000, user `admin` | `observability` | dashboards as code (A8) |

Ports can be moved if one is taken, e.g. `POSTGRES_PORT=5433 make up` (also `REDIS_PORT`, `S3_PORT`, `API_PORT`,
`OLLAMA_PORT`, `PROMETHEUS_PORT`, `GRAFANA_PORT`).

Not here yet: the Celery worker (B1) and the web dashboard (B7) are added by their tasks.

## Platform API (B1)

The API applies its database migrations when it starts. Its contract is `schemas/openapi.yaml`; the interactive
docs are at http://127.0.0.1:8000/docs. Writes need the token `SENTINEL_API_TOKEN` from `.env`. The API itself
only receives its SHA-256 (`SENTINEL_API_TOKEN_SHA256`), so the token never sits in a container. Reads are open on
localhost.

```bash
set -a; . deploy/compose/.env; set +a
curl -s -X POST http://127.0.0.1:8000/api/v1/runs -H "Authorization: Bearer $SENTINEL_API_TOKEN" \
  -H 'Content-Type: application/json' -d '{"repo": "owner/name", "commit": "<40 hex>", "context": "local"}'
curl -s -X POST http://127.0.0.1:8000/api/v1/runs/<run id>/findings -H "Authorization: Bearer $SENTINEL_API_TOKEN" \
  -H 'Content-Type: application/x-ndjson' --data-binary @out/findings.ndjson    # once per run, all or nothing
curl -s 'http://127.0.0.1:8000/api/v1/findings?severity=CRITICAL'
```

Every finding must be a valid Finding v1 document of that run (same `repo`, `commit` and `context`). A run's
findings are recorded once: a second upload is refused (409), so recorded evidence is never replaced; after a lost
response, compare `findings_sha256` from `GET /api/v1/runs/<run id>` with your file's sha256. The database itself
refuses any change to a recorded run or its findings, and refuses to delete it. A CI run is recorded once: a
second `POST /api/v1/runs` with the same `repo`, `commit`, `context` and `run_id` (a re-run of the upload step)
is answered 409 with the existing run in `run`, so the client uploads its findings only if `findings_sha256` is
null. A run without `run_id` (a local run) is always new. Bodies are capped before
authentication: 64 KiB for JSON, `SENTINEL_API_MAX_UPLOAD_BYTES` (32 MiB by default) for a findings upload. To
rotate the token, delete both `SENTINEL_API_TOKEN` lines from `.env` and run `make compose-env`.

## Security rules (tested in `tests/deploy/test_compose.py`)

- Images pinned by tag **and** digest; Dependabot proposes updates after a 7-day cooldown.
- Ports on `127.0.0.1` only; `no-new-privileges` and a healthcheck on every service.
- Credentials only through `.env`, and a missing one stops Compose instead of falling back to a default.
- SeaweedFS exposes only its authenticated S3 gateway (internal APIs on loopback, Iceberg and Lance off).
- The API image runs as an unprivileged user on a read-only root filesystem with all capabilities dropped;
  its build context is an allow-list (`.dockerignore`): never `.git`, `.env` files or `demo-shop/`.

## Common tasks

```bash
docker compose -f deploy/compose/compose.yaml ps                 # status and health
docker compose -f deploy/compose/compose.yaml logs -f api        # follow one service
docker compose -f deploy/compose/compose.yaml exec postgres psql -U sentinel -d sentinel
docker compose -f deploy/compose/compose.yaml down --volumes     # wipe all local data (irreversible)
```

S3 with the AWS CLI: `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` from `.env`, `--endpoint-url http://127.0.0.1:8333`.

## Troubleshooting

- `toomanyrequests` / `429` while pulling: Docker Hub's anonymous pull limit. Run `docker login`, or configure a
  registry mirror. Pins are digests, so a mirror serves exactly the same images.
- Windows: run everything from WSL 2 with Docker Desktop's WSL integration enabled.
- Ollama runs on CPU by default. GPU passthrough needs the NVIDIA Container Toolkit and a `deploy.resources`
  device reservation; we add it once the local model is chosen (Sprint 0 checklist item 10).
