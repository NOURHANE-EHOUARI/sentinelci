import { describe, expect, it } from "vitest";
import { asDecision, asVerdict } from "./decision";

describe("asDecision", () => {
  it("reads the fields the dashboard shows", () => {
    const view = asDecision({
      decision_id: "d", verdict: "WARN", evaluated_at: "2026-11-12T08:00:00Z", engine_version: "0.1.0",
      violations: [{ rule: "SC-006", effect: "WARN", message: "High priority", finding_ids: ["a", 7] }],
      waivers_applied: ["W-1", null],
      inputs: { risk_model_version: "1.0.0", findings_digest: "sha256:x", tool_versions: { a: "1" } },
    });
    expect(view.verdict).toBe("WARN");
    expect(view.violations).toEqual([{ rule: "SC-006", effect: "WARN", message: "High priority", findingIds: ["a"] }]);
    expect(view.waiversApplied).toEqual(["W-1"]);
    expect(view.inputs).toEqual([
      ["findings_digest", "sha256:x"], ["risk_model_version", "1.0.0"], ["tool_versions.a", "1"],
    ]);
  });

  it("lists every input, tool_versions as one row per tool, and a value of another type as unreadable", () => {
    // The inputs of schemas/fixtures/decision/valid/block-release.json (Vite reads only this folder).
    const view = asDecision({
      inputs: {
        findings_digest: `sha256:${"1".repeat(64)}`, sbom_digest: `sha256:${"2".repeat(64)}`,
        enrichment_snapshot_digest: `sha256:${"3".repeat(64)}`, policy_bundle_digest: `sha256:${"4".repeat(64)}`,
        risk_model_version: "1.0.0", tool_versions: { opa: "1.21.4", gitleaks: "8.24.0", grype: "0.92.0" },
      },
    });
    expect(view.inputs.map(([name]) => name)).toEqual([
      "enrichment_snapshot_digest", "findings_digest", "policy_bundle_digest", "risk_model_version", "sbom_digest",
      "tool_versions.gitleaks", "tool_versions.grype", "tool_versions.opa",
    ]);
    expect(view.inputs.at(-1)).toEqual(["tool_versions.opa", "1.21.4"]);
    const odd = asDecision({ inputs: { findings_digest: 7, tool_versions: { opa: 1, trivy: "0.76.1" }, baseline_digest: null } });
    expect(odd.inputs).toEqual([
      ["baseline_digest", "unreadable"], ["findings_digest", "unreadable"],
      ["tool_versions.opa", "unreadable"], ["tool_versions.trivy", "0.76.1"],
    ]);
  });

  it("never trusts a field of another type", () => {
    for (const document of [null, [], "BLOCK", { verdict: "pass" }, { verdict: 1, violations: "x", inputs: [] }]) {
      const view = asDecision(document);
      expect(view.verdict).toBeNull();
      expect(view.violations).toEqual([]);
      expect(view.inputs).toEqual([]);
    }
  });

  it("knows only the three verdicts", () => {
    expect(["PASS", "WARN", "BLOCK"].map(asVerdict)).toEqual(["PASS", "WARN", "BLOCK"]);
    expect([null, undefined, "", "ALLOW", "pass"].map(asVerdict)).toEqual([null, null, null, null, null]);
  });
});
