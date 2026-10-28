# Local platform (Docker Compose)

The SentinelCI control plane on your machine (SPEC §4.4). **Local only**: every port binds `127.0.0.1`.

```bash
make up                                      # postgres + pgvector, redis, seaweedfs (S3), api
COMPOSE_PROFILES=ai make up                  # + ollama
COMPOSE_PROFILES=ai,observability make up    # + prometheus, grafana
make down                                    # stop; data volumes are kept
```

`make up` first runs `make compose-env`, which creates `deploy/compose/.env` with random credentials
(owner-only permissions, git-ignored, never overwritten). Read your credentials there. Compose refuses to start
if a credential is missing: there is no default password anywhere.

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
