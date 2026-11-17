"""Detection metrics of the demo-shop benchmark (task B8, SPEC section 17): recall per category and false
positives on the clean controls, from SentinelCI's own findings (Finding v1) and the ground truth.

The matching rules are the ground truth's (demo-shop/ground-truth/README.md):
- a seed is detected only by a finding of its own category, and when that finding is one of its listed
  `(tool, rule)` pairs and reports it in the seed's file
  (its `location` or one of its `other_locations`); a secret must also be on the seed's line;
- an SCA or CONTAINER seed is detected when its vulnerability is reported on its package (the purl),
  wherever (in an image, the path is one of the image's own);
- a seed with `known_miss` lists no detection: it counts as a miss in its category's recall, never excluded;
- a finding by a tool a control lists in `must_not_detect`, in the control's file, is a false positive;
- any other finding is real but unlisted: it counts neither as a hit nor as a false positive, and is listed.

A category is measured only if every tool its seeds list ran a scan of that category: grype scanning
manifests (SCA) says nothing about images (CONTAINER). A tool that could not run (no Grype database, a CLI
without the command) leaves its categories "not measured", never at a recall of 0. A category whose seeds are
all known misses lists no tool, and is measured: its recall is 0.

Pure functions: the same ground truth, findings and tool statuses give the same result, byte for byte.
Owner: Track B (B8).
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

SCAN_ROOT = "demo-shop/"


# The categories each scan of `make eval` covers (eval/detection/run.py). The image scan (`--images`) is
# another run of grype, labelled "grype (images)", that covers CONTAINER.
SCAN_CATEGORIES: dict[str, tuple[str, ...]] = {
    "gitleaks": ("SECRET",),
    "trivy": ("IAC",),
    "zizmor": ("PIPELINE",),
    "opengrep": ("SAST",),
    "grype": ("SCA",),
}


@dataclass(frozen=True)
class ToolRun:
    """One scanner's run: `ok` with its version, or why it did not run (`failed`, `skipped`); and the
    categories it scanned (by default, those of its scan in SCAN_CATEGORIES). `label` names it in the report
    when one tool runs twice (grype on the manifests, then on the images)."""

    tool: str
    status: str  # ok | failed | skipped
    version: str | None = None
    reason: str | None = None
    categories: tuple[str, ...] | None = None
    label: str | None = None

    def scanned(self) -> tuple[str, ...]:
        if self.status != "ok":
            return ()
        return self.categories if self.categories is not None else SCAN_CATEGORIES.get(self.tool, ())


def _places(finding: Mapping[str, Any]) -> set[str]:
    """The finding's files, relative to demo-shop/ (the ground truth's paths)."""
    places = [finding.get("location"), *(finding.get("other_locations") or [])]
    return {
        place["path"].removeprefix(SCAN_ROOT)
        for place in places
        if isinstance(place, Mapping) and isinstance(place.get("path"), str)
    }


def _line(finding: Mapping[str, Any]) -> int | None:
    location = finding.get("location")
    return location.get("start_line") if isinstance(location, Mapping) else None


def _tool(finding: Mapping[str, Any]) -> str:
    tool = finding.get("tool")
    return str(tool.get("name", "")) if isinstance(tool, Mapping) else ""


def _purl(finding: Mapping[str, Any]) -> str | None:
    package = finding.get("package")
    return package.get("purl") if isinstance(package, Mapping) else None


def detects(seed: Mapping[str, Any], finding: Mapping[str, Any]) -> bool:
    """Whether `finding` reports `seed`, by one of the seed's listed (tool, rule) pairs."""
    if finding.get("category") != seed["category"]:
        return False
    pairs = {(d["tool"], d["rule"]) for d in seed["expected"]["detections"]}
    if (_tool(finding), finding.get("rule_id")) not in pairs:
        return False
    if seed["category"] in ("SCA", "CONTAINER"):  # a package: wherever it is reported (in an image, a path
        return _purl(finding) == seed["package"]  # inside the image's file system)
    if seed["location"]["path"] not in _places(finding):
        return False
    if seed["category"] == "SECRET":
        return _line(finding) == seed["location"].get("line")
    return True


def _tools_of(seeds: Iterable[Mapping[str, Any]]) -> set[str]:
    return {d["tool"] for seed in seeds for d in seed["expected"]["detections"]}


def score(truth: Mapping[str, Any], findings: list[Mapping[str, Any]], runs: list[ToolRun]) -> dict[str, Any]:
    """The detection report: per category, per control, and the unlisted findings."""
    ran = {run.tool for run in runs if run.status == "ok"}
    scanned = {(run.tool, category) for run in runs for category in run.scanned()}
    seeds: list[Mapping[str, Any]] = truth["seeds"]
    controls: list[Mapping[str, Any]] = truth["controls"]
    hits: dict[str, list[int]] = {}  # seed id -> indexes of the findings that detect it
    for seed in seeds:
        hits[seed["id"]] = [i for i, finding in enumerate(findings) if detects(seed, finding)]

    categories: dict[str, Any] = {}
    for category in sorted({seed["category"] for seed in seeds}):
        members = [seed for seed in seeds if seed["category"] == category]
        tools = sorted(_tools_of(members))
        missing = [
            tool if tool not in ran else f"{tool} did not scan {category}"
            for tool in tools
            if (tool, category) not in scanned
        ]
        all_known_misses = all("known_miss" in seed for seed in members)
        entry: dict[str, Any] = {"seeds": len(members), "tools": tools}
        if missing or (not tools and not all_known_misses):
            entry |= {"measured": False, "reason": f"not run: {', '.join(missing) or 'no tool listed'}"}
        else:
            detected = sorted(seed["id"] for seed in members if hits[seed["id"]])
            missed = [
                {"id": seed["id"], **({"known_miss": True} if "known_miss" in seed else {})}
                for seed in members
                if not hits[seed["id"]]
            ]
            entry |= {
                "measured": True,
                "detected": len(detected),
                "recall": round(len(detected) / len(members), 4),
                "missed": missed,
            }
        categories[category] = entry

    false_positives: list[dict[str, Any]] = []
    flagged: set[int] = set()
    control_results: dict[str, Any] = {}
    for control in controls:
        listed = sorted(control["must_not_detect"])
        unmeasured = [tool for tool in listed if tool not in ran]
        found = [
            i
            for i, finding in enumerate(findings)
            if _tool(finding) in listed and control["location"]["path"] in _places(finding)
        ]
        flagged.update(found)
        for i in found:
            false_positives.append(
                {"control": control["id"], "tool": _tool(findings[i]), "rule": findings[i].get("rule_id")}
            )
        control_results[control["id"]] = {
            "must_not_detect": listed,
            "false_positives": len(found),
            **({"not_run": unmeasured} if unmeasured else {}),
        }

    detected_ids = {i for indexes in hits.values() for i in indexes}
    seeded_files = {seed["location"]["path"] for seed in seeds} | {
        path for seed in seeds for path in seed.get("also_in", [])
    }
    unlisted: dict[str, dict[str, int]] = {}
    for i, finding in enumerate(findings):
        if i in detected_ids or i in flagged:
            continue
        where = "in_seeded_files" if _places(finding) & seeded_files else "elsewhere"
        per = unlisted.setdefault(
            str(finding.get("category", "UNKNOWN")), {"in_seeded_files": 0, "elsewhere": 0}
        )
        per[where] += 1

    measured = [entry for entry in categories.values() if entry["measured"]]
    return {
        "tools": {
            run.label or run.tool: _run_out(run) for run in sorted(runs, key=lambda r: r.label or r.tool)
        },
        "categories": categories,
        "overall": {
            "seeds_measured": sum(entry["seeds"] for entry in measured),
            "detected": sum(entry["detected"] for entry in measured),
            "categories_not_measured": sorted(
                name for name, entry in categories.items() if not entry["measured"]
            ),
        },
        "controls": control_results,
        "false_positives": sorted(
            false_positives, key=lambda fp: (fp["control"], fp["tool"], str(fp["rule"]))
        ),
        "unlisted_findings": {name: unlisted[name] for name in sorted(unlisted)},
        "canaries": {
            "planted": len(truth.get("canaries", [])),
            "measured": False,
            "reason": "no AI step reads demo-shop yet (B5): measured with the explanations",
        },
    }


def _run_out(run: ToolRun) -> dict[str, Any]:
    out: dict[str, Any] = {"status": run.status}
    if run.version:
        out["version"] = run.version
    if run.reason:
        out["reason"] = run.reason
    return out
