import { screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { asRelease } from "../api/release";
import { fakeApi, renderAt } from "../test-utils";

const DIGEST = `sha256:${"5c".repeat(32)}`;
const BLOCKED = `sha256:${"ab".repeat(32)}`;
const DECISION = "0193f2c4-7a1e-7b3c-9d2e-4f5a6b7c8d9f";
const SUMMARY = {
  decision_id: DECISION, repo: "NOURHANE-EHOUARI/sentinelci", commit: "4b825dc642cb6eb9a060e54bf8d69288fbee4904",
  ref: "refs/heads/main", image_digest: DIGEST, verdict: "WARN", trusted: true,
  evaluated_at: "2026-11-11T10:05:00Z", created_at: "2026-11-11T10:06:00Z", sha256: "1".repeat(64),
};
const BLOCK_SUMMARY = { ...SUMMARY, decision_id: "0193f2c4-7a1e-7b3c-9d2e-4f5a6b7c8da0", image_digest: BLOCKED,
  verdict: "BLOCK", trusted: null };
const UNVERIFIED = { ...SUMMARY, decision_id: "0193f2c4-7a1e-7b3c-9d2e-4f5a6b7c8da1", verdict: "PASS", trusted: null };
const check = (name: string, ok = true, detail = "signed by the key") => ({ name, ok, detail });
const REPORT = {
  schema_version: "1.0", image: { name: "127.0.0.1:5001/demo-shop/shop-api", digest: DIGEST }, mode: "registry",
  repo: "NOURHANE-EHOUARI/sentinelci", key_sha256: "9f86d081".repeat(8), verified_at: "2026-11-11T16:30:12Z",
  builder_id: "https://github.com/NOURHANE-EHOUARI/sentinelci/deploy/release/release.py@refs/heads/main",
  trusted: true, checks: [check("signature: the image itself"), check("decision: verdict is not BLOCK", true, "verdict WARN")],
};
const EVIDENCE = {
  schema_version: "1.0",
  decision: {
    decision_id: DECISION, verdict: "WARN", evaluated_at: "2026-11-11T10:05:00Z",
    subject: { repo: SUMMARY.repo, commit: SUMMARY.commit, ref: "refs/heads/main", image_digest: DIGEST, context: "release" },
    violations: [{ rule: "SC-006", effect: "WARN", finding_ids: ["a".repeat(64), "b".repeat(64)], message: "P1 finding" }],
    waivers_applied: [],
    inputs: { findings_digest: `sha256:${"1".repeat(64)}`, sbom_digest: `sha256:${"2".repeat(64)}`,
      risk_model_version: "1.0.0", tool_versions: { gitleaks: "8.30.1", trivy: "0.76.1" } },
  },
  trust_reports: [REPORT, { ...REPORT, mode: "evidence", trusted: false,
    checks: [check("signature: provenance (SLSA v1)", false, '<img src=x onerror="alert(1)">')] }],
};

describe("Releases", () => {
  it("lists each release with its verdict and what verify found", async () => {
    fakeApi({ "/api/v1/releases?limit=50&offset=0": {
      body: { items: [SUMMARY, BLOCK_SUMMARY, UNVERIFIED], total: 3, limit: 50, offset: 0 } } });
    renderAt("/releases");
    const rows = await screen.findAllByRole("row");
    expect(rows).toHaveLength(4);
    // Review of #86: nobody verified the PASS, which does not mean it was not signed.
    expect(within(rows[3]!).getByText("not verified")).toBeTruthy();
    expect(within(rows[3]!).queryByText("not signed")).toBeNull();
    expect(within(rows[1]!).getByText("WARN")).toBeTruthy();
    expect(within(rows[1]!).getByText("✓ trusted")).toBeTruthy();
    expect(within(rows[2]!).getByText("BLOCK")).toBeTruthy();
    expect(within(rows[2]!).getByText("not signed")).toBeTruthy();
    const link = within(rows[1]!).getByRole("link");
    expect(link.getAttribute("href")).toBe(`/releases/${encodeURIComponent(DIGEST)}?decision=${DECISION}`);
  });

  it("says when nothing is recorded yet", async () => {
    fakeApi({ "/api/v1/releases?limit=50&offset=0": { body: { items: [], total: 0, limit: 50, offset: 0 } } });
    renderAt("/releases");
    expect(await screen.findByText(/No release recorded yet/)).toBeTruthy();
  });
});

describe("Release detail", () => {
  it("shows the decision, then each trust report check by check, as text", async () => {
    fakeApi({ [`/api/v1/releases/${encodeURIComponent(DIGEST)}/evidence?decision_id=${DECISION}`]: { body: EVIDENCE } });
    const { container } = renderAt(`/releases/${encodeURIComponent(DIGEST)}?decision=${DECISION}`);
    expect(await screen.findByRole("heading", { name: DIGEST })).toBeTruthy();
    // One report does not trust it, so neither does the release: the heading and that report say so.
    expect(screen.getAllByText("✗ not trusted")).toHaveLength(2);
    const registry = screen.getByRole("article", { name: "Trust report: registry" });
    expect(within(registry).getByText("2/2 checks · 2026-11-11 16:30 UTC")).toBeTruthy();
    const offline = screen.getByRole("article", { name: "Trust report: evidence" });
    expect(within(offline).getByText("FAIL")).toBeTruthy();
    expect(within(offline).getByText('<img src=x onerror="alert(1)">')).toBeTruthy();
    expect(container.querySelector("img")).toBeNull();
    expect(screen.getByText(/P1 finding/)).toBeTruthy();
    expect(screen.getByText("gitleaks 8.30.1 · trivy 0.76.1")).toBeTruthy();
  });

  it("says a BLOCK was never signed", async () => {
    const block = { ...EVIDENCE, decision: { ...EVIDENCE.decision, verdict: "BLOCK",
      subject: { ...EVIDENCE.decision.subject, image_digest: BLOCKED } }, trust_reports: [] };
    fakeApi({ [`/api/v1/releases/${encodeURIComponent(BLOCKED)}/evidence`]: { body: block } });
    renderAt(`/releases/${encodeURIComponent(BLOCKED)}`);
    expect(await screen.findByText(/the gate blocked this image, so nothing was signed/)).toBeTruthy();
    expect(screen.getByText("not signed")).toBeTruthy(); // the heading
  });

  it("says a PASS without a report was not verified, never that it was not signed", async () => {
    const unverified = { ...EVIDENCE, decision: { ...EVIDENCE.decision, verdict: "PASS", violations: [] }, trust_reports: [] };
    fakeApi({ [`/api/v1/releases/${encodeURIComponent(DIGEST)}/evidence`]: { body: unverified } });
    renderAt(`/releases/${encodeURIComponent(DIGEST)}`);
    expect(await screen.findByText(/No trust report: none was recorded/)).toBeTruthy();
    expect(screen.getByText("not verified")).toBeTruthy();
    expect(screen.queryByText(/nothing was signed/)).toBeNull();
    expect(screen.queryByText("not signed")).toBeNull();
  });

  it("never trusts a release one of whose reports could not be read", async () => {
    const odd = { ...EVIDENCE, trust_reports: [{ ...REPORT, mode: "evidence", trusted: "false" }, REPORT] };
    fakeApi({ [`/api/v1/releases/${encodeURIComponent(DIGEST)}/evidence`]: { body: odd } });
    renderAt(`/releases/${encodeURIComponent(DIGEST)}`);
    expect(await screen.findByText(/1 trust report\(s\) could not be read/)).toBeTruthy();
    // The heading is unknown; only the readable report says trusted.
    expect(screen.getAllByText("✓ trusted")).toHaveLength(1);
    expect(screen.getByText("not verified")).toBeTruthy();
  });

  it("shows the whole key sha256 on hover", async () => {
    fakeApi({ [`/api/v1/releases/${encodeURIComponent(DIGEST)}/evidence?decision_id=${DECISION}`]: { body: EVIDENCE } });
    renderAt(`/releases/${encodeURIComponent(DIGEST)}?decision=${DECISION}`);
    const key = (await screen.findAllByTitle("9f86d081".repeat(8)))[0]!;
    expect(key.textContent).toBe(`${"9f86d081".repeat(2)}…`);
  });

  it("says when the image has no release", async () => {
    fakeApi({});
    renderAt(`/releases/${encodeURIComponent(DIGEST)}`);
    expect((await screen.findByRole("alert")).textContent).toBe("The API answered 404.");
  });
});

describe("asRelease", () => {
  it("reads only fields of the expected type", () => {
    const view = asRelease({ decision: { verdict: 7, subject: "x", violations: [null, { rule: "SC-010" }] },
      trust_reports: [{ trusted: "yes" }, { trusted: false, checks: [{ name: "n", ok: "no" }] }] });
    expect(view.verdict).toBe("UNKNOWN");
    expect(view.imageDigest).toBe("");
    expect(view.violations).toEqual([{ rule: "SC-010", effect: "", message: "", findings: 0 }]);
    expect(view.reports).toHaveLength(1);
    expect(view.reports[0]!.checks).toEqual([]);
    expect(view.unreadableReports).toBe(1);
  });
});
