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
    expect(view.inputs).toEqual([["findings_digest", "sha256:x"], ["risk_model_version", "1.0.0"]]);
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
