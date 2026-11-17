# Argo CD for the demo cluster

Task A5b, ADR-0011 decision 5. How the demo-shop release is deployed through GitOps: see
[`deploy/kind/README.md`](../kind/README.md), "What `make demo-release` does".

| File | Applied by | What |
|---|---|---|
| `git-server.yaml` | `make kind-up` | The read-only `git daemon` serving the local GitOps repository to Argo CD's repo server only |
| `demo-shop-namespace.yaml` | `make kind-up` | Where the release runs: Pod Security "restricted", and the API server's policy that admits images of `kind-registry:5000/demo-shop/` only |
| `project.yaml` | `make demo-release` | The AppProject: one repository, one namespace, the chart's three kinds, nothing cluster-scoped |
| `application.yaml` | `make demo-release` | The Application: the chart at `demo-shop/`, with `release.yaml` (the digest), synced automatically |

Argo CD itself is Argo CD core 3.6.1, pinned by sha256 in `deploy/kind/cluster.toml`: no UI, API server or
login. The demo watches it with `kubectl` (`kubectl -n argocd get applications`).
