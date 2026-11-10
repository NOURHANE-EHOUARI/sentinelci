# The demo cluster (kind)

Task A5b, SPEC §7, ADR-0011 decision 5. A local Kubernetes cluster where only SentinelCI releases run: the
Kyverno admission controller admits an image only if `sentinel verify` would trust it, with the policy that
`sentinel admission-policy` renders (#45).

## Prerequisites

- Docker and `kubectl`, from the machine.
- kind, pinned by sha256 in `tools.lock.toml`: `uv run sentinel tools install kind` (or `make tools`). The
  setup verifies it again before it runs.

## Commands

```bash
make kind-up        # registry, cluster, registry configuration on the nodes, Kyverno (safe to run twice)
make kind-policy    # render the release admission policy from deploy/keys/release.pub and apply it
make kind-down      # delete the cluster and its registry
```

`make kind-policy KEY=path/to/release.pub` uses another public key. The release key pair is made with the
release pipeline (A4c); until then, a test key does.

## What `make kind-up` does

1. Starts the registry container (`kind-registry`), published on **127.0.0.1:5001 only**.
2. Creates the cluster `sentinel` from `kind-config.yaml` (kubectl context `kind-sentinel`). Its API server
   listens on 127.0.0.1.
3. Tells containerd on each node that `kind-registry:5000` and `localhost:5001` are that registry, over plain
   HTTP (`/etc/containerd/certs.d/<host>/hosts.toml`, pull and resolve only).
4. Connects the registry to the cluster's network and documents it (KEP-1755's `local-registry-hosting`
   ConfigMap).
5. Installs Kyverno from its release manifest and waits until its deployments are available.

**Registry names:**
- From the host, the registry is `127.0.0.1:5001`: that is where `sentinel attest --push --registry-http`
  pushes.
- In the cluster, the same images are `kind-registry:5000/...`. The manifests use that name, and the admission
  policy matches it, rendered with `--image-glob 'kind-registry:5000/demo-shop/*' --registry-http`.
- The attestations bind a release to its digest and its source repository, not to a registry host. So a
  release pushed from the host is verified by Kyverno under the cluster's name.

## Pins

| What | Where | How |
|---|---|---|
| kind 0.33.0 | `tools.lock.toml` | sha256 of each release binary, from its `.sha256sum` file |
| Node image (Kubernetes 1.37.0) | `kind-config.yaml` | digest: kind 0.33.0's default (`pkg/apis/config/defaults/image.go`) |
| Registry (`registry:3.1.2`) | `cluster.toml` | digest of the official image index (docker-library/repo-info) |
| Kyverno 1.19.2 | `cluster.toml` | sha256 of the release's `install.yaml` |

`tests/deploy/test_kind.py` checks every pin:
- the images are pinned by tag and digest;
- the manifest is the release asset of its version, with a sha256;
- the cluster's Kyverno is the release of the Kyverno CLI that the admission tests run.

A downloaded manifest whose sha256 differs is deleted and refused, before anything is applied. To upgrade, change
the version and the pin together in one PR, and say in its description where each value comes from.

## Tests

- **`tests/deploy/test_kind.py`** needs no Docker. It checks the pins, and the commands `up`, `down` and
  `policy` run, against a recording fake:
  - the loopback binding;
  - both registry names on the nodes;
  - a second `up` that keeps what exists;
  - a manifest that is not the pinned one, refused before anything is applied.
- **`cli/tests/supplychain/test_kind_admission.py`** runs on a real cluster. It is opt-in
  (`SENTINEL_KIND_CONTEXT=kind-sentinel` and `SENTINEL_TOOLS_DIR`). On server-side dry runs, the Kyverno
  admission controller:
  - **admits** a release that `sentinel attest --push` attested;
  - **denies**, each with the policy's own message:
    - an unsigned image;
    - a BLOCK decision signed with the release key;
    - a Deployment with an unsigned image.
- **The `sentinel-kind` workflow** creates the cluster with `make kind-up` and runs that test. It runs by
  hand, and on pull requests that change the cluster's setup or the admission policy. It takes about ten
  minutes, so it does not run on every push (GitHub Free minutes).

## Limits

- Kyverno's install manifest names its images by tag (`reg.kyverno.io/...:v1.19.2`). The manifest itself is
  pinned by sha256; the images are not pinned by digest yet.
- Kyverno's default install does not check its own namespace (`kyverno`) or `kube-system`. Whoever can create
  Pods there is out of the policy's reach.
- Next steps (A5b): the demo-shop Helm chart, Argo CD reading a local GitOps repository, `make demo-release`
  and `make demo-attack`.
