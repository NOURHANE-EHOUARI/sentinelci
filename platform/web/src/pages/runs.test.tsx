import { fireEvent, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { fakeApi, renderAt } from "../test-utils";

const RUN = "22222222-2222-4222-8222-222222222222";
const PENDING = "33333333-3333-4333-8333-333333333333";
const PASSED = "44444444-4444-4444-8444-444444444444";
const FINDING = "a".repeat(64);
const run = (id: string, extra: Record<string, unknown>) => ({
  id, repo: "acme/shop", commit: "b".repeat(40), context: "release", ref: "refs/heads/main", run_id: "17/1",
  created_at: "2026-11-12T08:00:00Z", finding_count: 2, findings_sha256: "c".repeat(64),
  findings_uploaded_at: "2026-11-12T08:01:00Z", verdict: null, ...extra,
});
const BLOCKED = run(RUN, { verdict: "BLOCK" });
const NO_DECISION = run(PENDING, { verdict: null, findings_sha256: null, finding_count: 0, findings_uploaded_at: null });
const PASS = run(PASSED, { verdict: "PASS", context: "pr", ref: "refs/pull/7/head" });
const PAGE = { items: [BLOCKED, NO_DECISION, PASS], total: 3, limit: 50, offset: 0 };
const DECISION = {
  schema_version: "1.0", decision_id: "0193f2c4-7a1e-7b3c-9d2e-4f5a6b7c8d9e", evaluated_at: "2026-11-12T08:02:00Z",
  subject: { repo: "acme/shop", commit: "b".repeat(40), context: "release" }, verdict: "BLOCK",
  violations: [{ rule: "SC-001", effect: "BLOCK", finding_ids: [FINDING], message: "Hard-coded secret" }],
  waivers_applied: ["W-7"], engine_version: "0.1.0",
  inputs: { findings_digest: `sha256:${"c".repeat(64)}`, risk_model_version: "1.0.0", tool_versions: { gitleaks: "8" } },
};

describe("Runs", () => {
  it("lists the runs with their verdict, and a run without a decision is never a PASS", async () => {
    fakeApi({ "/api/v1/runs?limit=50&offset=0": { body: PAGE } });
    renderAt("/runs");
    const rows = await screen.findAllByRole("row");
    expect(rows).toHaveLength(4);
    expect(within(rows[1]!).getByText("BLOCK")).toBeTruthy();
    expect(within(rows[2]!).getByText("No decision")).toBeTruthy();
    expect(within(rows[2]!).queryByText("PASS")).toBeNull();
    expect(within(rows[2]!).getByText("not uploaded")).toBeTruthy();
    expect(within(rows[3]!).getByText("PASS")).toBeTruthy();
    const link = within(rows[1]!).getByRole("link");
    expect(link.getAttribute("href")).toBe(`/runs/${RUN}`);
  });

  it("filters by context through the URL", async () => {
    const calls = fakeApi({
      "/api/v1/runs?limit=50&offset=0": { body: PAGE },
      "/api/v1/runs?context=pr&limit=50&offset=0": { body: { ...PAGE, items: [PASS], total: 1 } },
    });
    renderAt("/runs");
    await screen.findAllByText("BLOCK");
    fireEvent.change(screen.getByLabelText("Context"), { target: { value: "pr" } });
    await screen.findByText("refs/pull/7/head");
    expect(calls).toContain("/api/v1/runs?context=pr&limit=50&offset=0");
  });

  it("pages forward and back, and a fractional offset in the URL is a whole one", async () => {
    const many = { ...PAGE, total: 120 };
    const calls = fakeApi({
      "/api/v1/runs?limit=50&offset=0": { body: many },
      "/api/v1/runs?limit=50&offset=50": { body: { ...many, offset: 50 } },
      "/api/v1/runs?limit=50&offset=1": { body: many },
    });
    renderAt("/runs?offset=1.5");
    await screen.findByText(/of 120/);
    expect(calls).toContain("/api/v1/runs?limit=50&offset=1");
    fireEvent.click(screen.getByRole("button", { name: "Previous" }));
    await screen.findByText("1–3 of 120");
    fireEvent.click(screen.getByRole("button", { name: "Next" }));
    await screen.findByText("51–53 of 120");
  });

  it("an unknown verdict value is no decision, not a verdict", async () => {
    fakeApi({ "/api/v1/runs?limit=50&offset=0": { body: { ...PAGE, items: [run(RUN, { verdict: "ALLOW" })], total: 1 } } });
    renderAt("/runs");
    expect(await screen.findByText("No decision")).toBeTruthy();
    expect(screen.queryByText("ALLOW")).toBeNull();
  });

  it("shows text from runs as text", async () => {
    const hostile = run(RUN, { ref: '<img src=x onerror="alert(1)">' });
    fakeApi({ "/api/v1/runs?limit=50&offset=0": { body: { ...PAGE, items: [hostile], total: 1 } } });
    const { container } = renderAt("/runs");
    expect(await screen.findByText(hostile.ref)).toBeTruthy();
    expect(container.querySelector("img")).toBeNull();
  });

  it("says when there is no run", async () => {
    fakeApi({ "/api/v1/runs?limit=50&offset=0": { body: { items: [], total: 0, limit: 50, offset: 0 } } });
    renderAt("/runs");
    expect(await screen.findByText("No run matches.")).toBeTruthy();
  });

  it("says when the API fails", async () => {
    fakeApi({ "/api/v1/runs?limit=50&offset=0": { status: 503, body: "" } });
    renderAt("/runs");
    expect((await screen.findByRole("alert")).textContent).toBe("The API answered 503.");
  });
});

describe("Run detail", () => {
  it("shows the run and its decision: verdict, violations linked to their findings, waivers, inputs", async () => {
    fakeApi({ [`/api/v1/runs/${RUN}`]: { body: BLOCKED }, [`/api/v1/runs/${RUN}/decision`]: { body: DECISION } });
    renderAt(`/runs/${RUN}`);
    const decision = await screen.findByRole("region", { name: "Decision" });
    expect(within(decision).getByText("Hard-coded secret")).toBeTruthy();
    expect(within(decision).getByText("SC-001")).toBeTruthy();
    expect(within(decision).getByText("W-7")).toBeTruthy();
    expect(within(decision).getByText("0.1.0")).toBeTruthy();
    expect(within(decision).getByRole("link", { name: FINDING.slice(0, 12) }).getAttribute("href")).toBe(
      `/findings/${FINDING}`,
    );
    expect(within(decision).getByText(`sha256:${"c".repeat(64)}`)).toBeTruthy();
    const findings = screen.getByRole("link", { name: "2 finding(s)" });
    expect(findings.getAttribute("href")).toBe(`/findings?run_id=${RUN}`);
  });

  it("says no decision is recorded, never a PASS, when the API has none (404)", async () => {
    fakeApi({ [`/api/v1/runs/${PENDING}`]: { body: NO_DECISION } });
    renderAt(`/runs/${PENDING}`);
    const decision = await screen.findByRole("region", { name: "Decision" });
    expect(within(decision).getByText("No decision recorded")).toBeTruthy();
    expect(screen.queryByText("PASS")).toBeNull();
    expect(screen.getByText("not uploaded yet")).toBeTruthy();
  });

  it("says when the run does not exist", async () => {
    fakeApi({});
    renderAt(`/runs/${RUN}`);
    expect((await screen.findByRole("alert")).textContent).toBe("The API answered 404.");
  });

  it("says when the decision cannot be read, rather than show none", async () => {
    fakeApi({ [`/api/v1/runs/${RUN}`]: { body: BLOCKED }, [`/api/v1/runs/${RUN}/decision`]: { status: 503, body: "" } });
    renderAt(`/runs/${RUN}`);
    expect((await screen.findByRole("alert")).textContent).toBe("The API answered 503.");
    expect(screen.queryByText("No decision recorded")).toBeNull();
  });
});

describe("Findings of a run", () => {
  it("filters the findings by the run in the URL", async () => {
    const calls = fakeApi({
      [`/api/v1/findings?run_id=${RUN}&limit=50&offset=0`]: { body: { items: [], total: 0, limit: 50, offset: 0 } },
    });
    renderAt(`/findings?run_id=${RUN}`);
    expect(await screen.findByText("No finding matches.")).toBeTruthy();
    expect(calls).toContain(`/api/v1/findings?run_id=${RUN}&limit=50&offset=0`);
    expect(screen.getByRole("button", { name: `Run ${RUN.slice(0, 8)} ✕` })).toBeTruthy();
  });
});
