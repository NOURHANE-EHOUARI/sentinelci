"""Thin wrapper around a pinned OPA binary.

Every failure (missing binary, non-zero exit, timeout, unparsable or undefined result) raises
`OpaError`: the caller must treat it as "no decision", never as a pass (principle P2, fail closed).
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

OPA_ENV_VAR = "SENTINEL_OPA"
DEFAULT_TIMEOUT_S = 60.0
_VERSION_LINE = re.compile(r"^Version:\s*(\S+)\s*$", re.MULTILINE)


class OpaError(Exception):
    """OPA could not produce a result."""


@dataclass(frozen=True)
class OpaRunner:
    binary: Path
    timeout_s: float = DEFAULT_TIMEOUT_S

    @classmethod
    def locate(cls, explicit: Path | None = None) -> OpaRunner:
        """Use `explicit`, else $SENTINEL_OPA, else `opa` on PATH."""
        candidate = explicit or (Path(env) if (env := os.environ.get(OPA_ENV_VAR)) else None)
        if candidate is None:
            found = shutil.which("opa")
            if found is None:
                raise OpaError(f"OPA binary not found: pass --opa, set {OPA_ENV_VAR} or put opa on PATH")
            candidate = Path(found)
        if not candidate.is_file():
            raise OpaError(f"OPA binary not found: {candidate}")
        return cls(binary=candidate)

    def _run(self, args: Sequence[str], stdin: str | None = None) -> str:
        try:
            # The binary is chosen by the operator (flag, env or PATH) and arguments are never
            # passed through a shell. An empty environment: policies cannot read the job's variables
            # (opa.runtime().env), which may hold tokens.
            proc = subprocess.run(  # noqa: S603
                [str(self.binary), *args],
                input=stdin,
                env={},
                capture_output=True,
                text=True,
                encoding="utf-8",
                timeout=self.timeout_s,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise OpaError(f"OPA timed out after {self.timeout_s:g}s") from exc
        except OSError as exc:
            raise OpaError(f"cannot run OPA: {exc}") from exc
        if proc.returncode != 0:
            raise OpaError(f"OPA exited with {proc.returncode}: {proc.stderr.strip()}")
        return proc.stdout

    def version(self) -> str:
        match = _VERSION_LINE.search(self._run(["version"]))
        if match is None:
            raise OpaError("cannot read the OPA version")
        return match.group(1)

    def eval(self, query: str, policies: Sequence[Path], input_doc: Any) -> Any:
        """Evaluate `query` against `policies` with `input_doc`; return the single result value."""
        args = ["eval", "--format", "json", "--stdin-input"]
        for path in policies:
            args += ["--data", str(path)]
        args.append(query)
        return parse_eval_output(self._run(args, stdin=json.dumps(input_doc)))


def parse_eval_output(stdout: str) -> Any:
    """Extract the value of `opa eval --format json`; an undefined result is an error."""
    try:
        return json.loads(stdout)["result"][0]["expressions"][0]["value"]
    except (ValueError, KeyError, IndexError, TypeError) as exc:
        raise OpaError("OPA returned no result (undefined query or unexpected output)") from exc
