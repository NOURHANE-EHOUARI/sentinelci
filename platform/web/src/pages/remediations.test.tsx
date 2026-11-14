import { screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { asAttempt } from "../api/remediation";
import { remediationAttempts, successByStrategy } from "../metrics";
import { fakeApi, renderAt } from "../test-utils";

const ID = "0193f2c5-0000-7000-8000-000000000003";
const SUMMARY = {
  proposal_id: ID, repo: "NOURHANE-EHOUARI/sentinelci", strategy: "deterministic:kubernetes", attempt: 1,
  finding_count: 2, outcome: "VERIFIED", verdict: "PASS", build_ok: true, tests_ok: true, target_resolved: true,
  new_finding_count: 0, pull_request: 81, proposed_at: "2026-11-11T09:00:00Z", verified_at: "2026-11-11T09:12:00Z",
  created_at: "2026-11-11T09:13:00Z", sha256: "1".repeat(64),
};
const METRICS = [
  'sentinel_remediation_attempts_total{strategy="deterministic:kubernetes",outcome="VERIFIED"} 3',
  'sentinel_remediation_attempts_total{strategy="deterministic:kubernetes",outcome="REJECTED"} 1',
  'sentinel_remediation_attempts_total{strategy="llm:code",outcome="FAILED"} 0',
].join("\n");
const ATTEMPT = {
  schema_version: "1.0", repo: "NOURHANE-EHOUARI/sentinelci",
  proposal: { proposal_id: ID, finding_ids: ["b".repeat(64)], strategy: "llm:code", attempt: 2,
    diff: 'diff --git a/x b/x\n+<script>alert("diff")</script>\n', files: ["demo-shop/services/shop-api/app/db.py"],
    rationale: "Use a parameterized query.", model: { name: "local-code-model", version: "q4", prompt_version: "p" },
    created_at: "2026-11-11T09:00:00Z" },
  result: { proposal_id: ID, attempt: 2, build_ok: true, tests_ok: false, target_resolved: true, new_findings: [],
    verdict: "PASS", outcome: "REJECTED", pull_request: 43, verified_at: "2026-11-11T09:31:00Z" },
};

describe("Remediation", () => {
  it("lists the attempts and the success of each strategy", async () => {
    fakeApi({
      "/api/v1/remediations?limit=50&offset=0": { body: { items: [SUMMARY], total: 1, limit: 50, offset: 0 } },
      "/metrics": { body: METRICS },
    });
    renderAt("/remediations");
    const row = (await screen.findAllByRole("row"))[1]!;
    expect(within(row).getByText("VERIFIED")).toBeTruthy();
    expect(within(row).getByText("#81")).toBeTruthy();
    expect(within(row).getByRole("link").getAttribute("href")).toBe(`/remediations/${ID}`);
    const success = await screen.findByRole("list", { name: "Remediation success" });
    expect(within(success).getByText("75 %")).toBeTruthy();
    expect(within(success).getByText("3 verified of 4")).toBeTruthy();
    expect(within(success).queryByText("llm:code")).toBeNull(); // no attempt: no rate
  });

  it("shows the gate's conditions, the model, and the diff as text", async () => {
    fakeApi({ [`/api/v1/remediations/${ID}`]: { body: ATTEMPT } });
    const { container } = renderAt(`/remediations/${ID}`);
    const gate = await screen.findByRole("list", { name: "Verification gate" });
    expect(within(gate).getByText("Its tests pass").firstChild?.textContent).toBe("FAIL");
    expect(within(gate).getByText("It builds").firstChild?.textContent).toBe("ok");
    expect(screen.getByText(/Written by a model \(local-code-model q4\)/)).toBeTruthy();
    expect(screen.getByLabelText("Diff").textContent).toContain('<script>alert("diff")</script>');
    expect(container.querySelector("script")).toBeNull();
    expect(screen.getByText("pull request #43")).toBeTruthy();
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("says a VERIFIED attempt with a condition it can't read contradicts itself", async () => {
    const verified = { ...ATTEMPT, result: { ...ATTEMPT.result, tests_ok: 1, outcome: "VERIFIED" } };
    fakeApi({ [`/api/v1/remediations/${ID}`]: { body: verified } });
    renderAt(`/remediations/${ID}`);
    const gate = await screen.findByRole("list", { name: "Verification gate" });
    expect(within(gate).getByText("Its tests pass").firstChild?.textContent).toBe("unknown");
    expect(screen.getByRole("alert").textContent).toMatch(/^This document contradicts itself/);
    expect(screen.getByRole("heading", { level: 1 }).textContent).toBe("VERIFIED?llm:code");
  });
});

describe("remediation readers", () => {
  it("count each strategy's attempts from the metric", () => {
    const counts = remediationAttempts(METRICS);
    expect(counts).toHaveLength(3);
    expect(Object.fromEntries(successByStrategy(counts!))).toEqual({
      "deterministic:kubernetes": { verified: 3, attempted: 4 },
    });
    expect(remediationAttempts("")).toBeNull();
    expect(remediationAttempts('sentinel_remediation_attempts_total{strategy="s",outcome="VERIFIED"} NaN')).toBeNull();
  });

  it("read nothing as passed that is not a boolean true", () => {
    const view = asAttempt({ proposal: { strategy: 4 }, result: { build_ok: "true", new_findings: "none", verdict: "BLOCK" } });
    expect(view.strategy).toBe("unknown");
    expect(view.conditions.map((condition) => condition.ok)).toEqual([null, null, null, null, false]);
  });

  it("read a condition of another type, or an unknown verdict, as unknown", () => {
    const view = asAttempt({ result: { build_ok: true, tests_ok: false, target_resolved: 1, new_findings: [], verdict: "MAYBE",
      outcome: "VERIFIED" } });
    expect(view.conditions.map((condition) => condition.ok)).toEqual([true, false, null, true, null]);
    expect(view.contradicts).toBe(true);
    expect(asAttempt(ATTEMPT).contradicts).toBe(false); // REJECTED with a failed test says what it is
  });
});
