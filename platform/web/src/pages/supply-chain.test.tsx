import { screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import type { TrustReportView } from "../api/release";
import { fakeApi, renderAt } from "../test-utils";
import { carried, COLUMNS } from "./SupplyChain";

const digest = (c: string) => `sha256:${c.repeat(64)}`;
const summary = (n: number, verdict: string, trusted: boolean | null) => ({
  decision_id: `0193f2c4-7a1e-7b3c-9d2e-4f5a6b7c8d9${n}`, repo: "NOURHANE-EHOUARI/sentinelci", commit: "a".repeat(40),
  ref: "refs/heads/main", image_digest: digest(String(n)), verdict, trusted, evaluated_at: "2026-11-11T10:00:00Z",
  created_at: "2026-11-11T10:00:00Z", sha256: "1".repeat(64),
});
const ALL_CHECKS = COLUMNS.flatMap((column) => column.checks);
const report = (failing: string[] = [], mode = "registry") => ({
  mode, trusted: failing.length === 0, verified_at: "2026-11-11T10:05:00Z", image: { name: "r/x" }, builder_id: "b",
  key_sha256: "9".repeat(64), checks: ALL_CHECKS.map((name) => ({ name, ok: !failing.includes(name), detail: "d" })),
});
const evidence = (n: number, verdict: string, reports: unknown[]) => ({
  schema_version: "1.0", decision: { decision_id: summary(n, verdict, null).decision_id, verdict,
    subject: { image_digest: digest(String(n)) } }, trust_reports: reports,
});
const url = (n: number) =>
  `/api/v1/releases/${encodeURIComponent(digest(String(n)))}/evidence?decision_id=${summary(n, "", null).decision_id}`;

describe("Supply chain", () => {
  it("shows what each release carries, as verify found it in the registry", async () => {
    fakeApi({
      "/api/v1/releases?limit=20": { body: { items: [summary(1, "WARN", true), summary(2, "PASS", false),
        summary(3, "BLOCK", null)], total: 3, limit: 20, offset: 0 } },
      [url(1)]: { body: evidence(1, "WARN", [report([], "evidence"), report()]) },
      [url(2)]: { body: evidence(2, "PASS", [report(["signature: provenance (SLSA v1)"])]) },
      [url(3)]: { body: evidence(3, "BLOCK", []) },
    });
    renderAt("/supply-chain");
    expect((await screen.findByLabelText("Compliance")).textContent).toContain("1 of 2");
    const rows = screen.getAllByRole("row");
    await within(rows[3]!).findAllByText("not signed");
    expect(within(rows[1]!).getAllByText("✓")).toHaveLength(5);
    expect(within(rows[2]!).getAllByText("✓")).toHaveLength(4);
    expect(within(rows[2]!).getByText("✗")).toBeTruthy();
    expect(within(rows[3]!).getAllByText("not signed")).toHaveLength(5);
  });
});

describe("carried", () => {
  const view = (names: string[], ok = true): TrustReportView => ({
    mode: "registry", trusted: ok, verifiedAt: null, imageName: "", builderId: "", keySha256: "",
    checks: names.map((name) => ({ name, ok, detail: "" })),
  });

  it("needs every check of a column, and a report", () => {
    expect(carried(null)).toEqual([null, null, null, null, null]);
    expect(carried(view(ALL_CHECKS))).toEqual([true, true, true, true, true]);
    expect(carried(view(["signature: the image itself", "signature: release decision"]))).toEqual([
      true, false, null, null, null,
    ]); // a column with some of its checks missing is not carried
  });
});
