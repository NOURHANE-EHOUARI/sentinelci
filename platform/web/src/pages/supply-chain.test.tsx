import { screen, waitFor, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import type { TrustReportView } from "../api/release";
import { fakeApi, renderAt } from "../test-utils";
import { carried, complete, COLUMNS } from "./SupplyChain";

const digest = (c: string) => `sha256:${c.repeat(64)}`;
const summary = (n: number, verdict: string, trusted: boolean | null) => ({
  decision_id: `0193f2c4-7a1e-7b3c-9d2e-4f5a6b7c8d9${n}`, repo: "NOURHANE-EHOUARI/sentinelci", commit: "a".repeat(40),
  ref: "refs/heads/main", image_digest: digest(String(n)), verdict, trusted, evaluated_at: "2026-11-11T10:00:00Z",
  created_at: "2026-11-11T10:00:00Z", sha256: "1".repeat(64),
});
const ALL_CHECKS = COLUMNS.flatMap((column) => column.checks);
// The 16 checks `sentinel verify` writes (supplychain/verify.py), each in exactly one column.
const VERIFY_CHECKS = [
  "signature: the image itself", "signature: release decision", "signature: SBOM (CycloneDX)",
  "signature: vulnerability scan", "signature: provenance (SLSA v1)", "decision: valid Decision v1",
  "decision: release context", "decision: verdict is not BLOCK", "decision: about this image",
  "decision: from the expected repository", "provenance: built by the expected workflow",
  "provenance: built from the decision's commit", "vulnerability scan: names this decision",
  "vulnerability scan: the decision's findings", "vulnerability scan: the decision's SBOM",
  "SBOM: the one the vulnerability scan names",
];
const report = (failing: string[] = [], mode = "registry", extra: string[] = []) => ({
  mode, trusted: failing.length === 0, verified_at: "2026-11-11T10:05:00Z", image: { name: "r/x" }, builder_id: "b",
  key_sha256: "9".repeat(64),
  checks: [...ALL_CHECKS, ...extra].map((name) => ({ name, ok: !failing.includes(name), detail: "d" })),
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
    const compliance = await screen.findByLabelText("Compliance");
    await waitFor(() => expect(compliance.textContent).toContain("1 of 2"));
    const rows = screen.getAllByRole("row");
    await within(rows[3]!).findAllByText("not signed");
    expect(within(rows[1]!).getAllByText("✓")).toHaveLength(5);
    expect(within(rows[2]!).getAllByText("✓")).toHaveLength(4);
    expect(within(rows[2]!).getByText("✗")).toBeTruthy();
    expect(within(rows[3]!).getAllByText("not signed")).toHaveLength(5);
  });

  it("judges a release on its registry report, whatever the order of its reports", async () => {
    fakeApi({
      "/api/v1/releases?limit=20": { body: { items: [summary(1, "PASS", false)], total: 1, limit: 20, offset: 0 } },
      [url(1)]: { body: evidence(1, "PASS", [report(["signature: the image itself"], "evidence"), report()]) },
    });
    renderAt("/supply-chain");
    const rows = await screen.findAllByRole("row");
    expect(await within(rows[1]!).findAllByText("✓")).toHaveLength(5);
  });

  it("counts only what Kyverno would admit: every check of a column, and a trusted report", async () => {
    const trustedButFailing = { ...report(), trusted: false }; // verify did not trust it, whatever the columns say
    fakeApi({
      "/api/v1/releases?limit=20": { body: { items: [1, 2, 3].map((n) => summary(n, "PASS", false)), total: 3,
        limit: 20, offset: 0 } },
      [url(1)]: { body: evidence(1, "PASS", [report(["decision: about this image"])]) },
      [url(2)]: { body: evidence(2, "PASS", [report(["provenance: a check verify adds later"], "registry",
        ["provenance: a check verify adds later"])]) },
      [url(3)]: { body: evidence(3, "PASS", [trustedButFailing]) },
    });
    renderAt("/supply-chain");
    const compliance = await screen.findByLabelText("Compliance");
    await waitFor(() => expect(compliance.textContent).toContain("0 of 3"));
    const rows = screen.getAllByRole("row");
    const cells = (row: HTMLElement) => within(row).getAllByRole("cell").slice(2).map((cell) => cell.textContent);
    expect(cells(rows[1]!)).toEqual(["✓", "✗", "✓", "✓", "✓"]); // the decision is about another image
    expect(cells(rows[2]!)).toEqual(["✓", "✓", "✓", "✓", "✗"]); // a provenance check no column lists
    expect(cells(rows[3]!)).toEqual(["✓", "✓", "✓", "✓", "✓"]);
  });

  it("gives no count before every release's evidence is in, nor when a request fails", async () => {
    fakeApi({
      "/api/v1/releases?limit=20": { body: { items: [summary(1, "PASS", true), summary(2, "PASS", true)], total: 2,
        limit: 20, offset: 0 } },
      [url(1)]: { body: evidence(1, "PASS", [report()]) },
      [url(2)]: { status: 500, body: { detail: "boom" } },
    });
    renderAt("/supply-chain");
    const compliance = await screen.findByLabelText("Compliance");
    expect(compliance.textContent).toMatch(/^— releases/); // first render: nothing loaded yet
    const failed = await screen.findByText("The evidence could not be read.");
    expect(failed.closest("tr")?.textContent).toContain("PASS");
    expect(compliance.textContent).toMatch(/^— releases/);
    expect(compliance.textContent).toContain("The evidence of a release could not be read.");
    expect(within(screen.getAllByRole("row")[1]!).getAllByText("✓")).toHaveLength(5);
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

  it("reads every check verify writes, each in one column", () => {
    expect([...ALL_CHECKS].sort()).toEqual([...VERIFY_CHECKS].sort());
    for (const name of VERIFY_CHECKS) {
      expect(carried(view([name], false)).filter((value) => value === false)).toHaveLength(1);
    }
  });

  it("is complete only for a trusted report with every column carried", () => {
    expect(complete(view(ALL_CHECKS))).toBe(true);
    expect(complete({ ...view(ALL_CHECKS), trusted: false })).toBe(false);
    expect(complete(view([...ALL_CHECKS, "SBOM: a later check"].slice(1)))).toBe(false);
    expect(complete(null)).toBe(false);
  });
});
