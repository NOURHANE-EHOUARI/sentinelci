"""The Kyverno admission policy of SentinelCI releases (task A5, SPEC section 7, ADR-0010).

`render_policy` fills `kyverno/release-evidence.yaml` from the parameters `sentinel verify` takes (the release
public key, the repository and the release workflow), so admission and `sentinel verify` trust exactly the
same images. The predicate types come from `attestations.KINDS`. Every value is checked before it goes into
the policy: it lands in YAML and in CEL string literals, where a quote would change the policy's meaning.
"""

import re
from importlib.resources import files
from pathlib import Path
from string import Template
from typing import get_args

from sentinelci.contracts.decision import Decision
from sentinelci.supplychain.attestations import GITHUB, KINDS, AttestationError
from sentinelci.supplychain.cosign import SIGNATURE_TYPE, check_local_registry, check_public_key

POLICY_NAME = "sentinel-release-evidence"
_REPO = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
_BUILDER = re.compile(
    r"https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/\.github/workflows/[A-Za-z0-9_./-]+@[A-Za-z0-9_./-]+"
)
# `<registry>/<path>*`: one trailing `*`. It is matched as a prefix of the lower-cased reference, since
# registry host names ignore case (a glob would let `LOCALHOST:5000/...` through unchecked).
_GLOB = re.compile(r"(?P<prefix>[a-z0-9][a-z0-9._:/-]{0,253})\*")
_ONE_PUBLIC_KEY = re.compile(r"-----BEGIN PUBLIC KEY-----\n[A-Za-z0-9+/=\n]+-----END PUBLIC KEY-----")
_KEY_INDENT = " " * 12
# The Decision v1 versions the contract knows: rendered into the policy, so the two can never drift.
DECISION_VERSIONS: tuple[str, ...] = get_args(Decision.model_fields["schema_version"].annotation)


def _template() -> str:
    return files("sentinelci.supplychain").joinpath("kyverno", "release-evidence.yaml").read_text("utf-8")


def render_policy(*, public_key: Path, image_glob: str, repo: str, builder_id: str, allow_http: bool) -> str:
    """The ImageValidatingPolicy for images matching `image_glob`; AttestationError for a bad parameter."""
    check_public_key(public_key)
    if _REPO.fullmatch(repo) is None:
        raise AttestationError(f"--repo {repo!r} is not owner/name")
    if _BUILDER.fullmatch(builder_id) is None:
        raise AttestationError(
            f"--builder-id {builder_id!r} is not https://github.com/<owner>/<repo>/.github/workflows/<file>@<ref>"
        )
    glob = _GLOB.fullmatch(image_glob)
    if glob is None or "/" not in glob["prefix"]:
        raise AttestationError(
            f"--image-glob {image_glob!r} is not <registry>/<path>* (lowercase, one trailing *)"
        )
    if allow_http:
        check_local_registry(glob["prefix"])
    key = public_key.read_text(encoding="ascii").replace("\r\n", "\n").strip()
    if _ONE_PUBLIC_KEY.fullmatch(key) is None:  # a private key next to it would be published in the policy
        raise AttestationError(f"{public_key} must hold exactly one PEM public key, and nothing else")
    return Template(_template()).substitute(
        image_prefix=glob["prefix"],
        allow_http="true" if allow_http else "false",
        public_key="\n".join(_KEY_INDENT + line.strip() for line in key.splitlines()),
        decision_versions=", ".join(f"'{version}'" for version in DECISION_VERSIONS),
        signature_type=SIGNATURE_TYPE,
        decision_type=KINDS["decision"],
        sbom_type=KINDS["sbom"],
        vuln_type=KINDS["vuln"],
        provenance_type=KINDS["provenance"],
        repo=repo,
        builder_id=builder_id,
        source_prefix=f"git+{GITHUB}/{repo}@",
    )
