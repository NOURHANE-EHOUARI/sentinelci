import { fireEvent, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { fakeApi, renderAt } from "../test-utils";

const ID = "f".repeat(64);
const FINDING = {
  id: ID, title: "PyYAML 5.3.1: code execution through full_load", severity: "CRITICAL", category: "SCA",
  rule_id: "GHSA-8q59-q68h-6hv4", tool: { name: "grype" }, message: "pyyaml 5.3.1 is affected",
  location: { path: "demo-shop/services/shop-api/requirements.txt" }, risk: { priority: "P0", score: 91 },
  cve: ["CVE-2020-14343"],
};
const RUN = "11111111-1111-4111-8111-111111111111";
const PAGE = { items: [{ run_id: RUN, finding: FINDING }], total: 1, limit: 50, offset: 0 };

describe("Overview", () => {
  it("shows the open findings by priority", async () => {
    fakeApi({
      "/metrics": {
        body: 'sentinel_findings_open{priority="P0",category="SECRET"} 5\nsentinel_findings_open{priority="P2",category="IAC"} 16\n',
      },
    });
    renderAt("/");
    expect((await screen.findByTestId("priority-P0")).textContent).toBe("5");
    expect(screen.getByTestId("priority-P2").textContent).toBe("16");
    expect(screen.getByTestId("priority-P1").textContent).toBe("0");
  });

  it("says there is no data yet rather than show zeros", async () => {
    fakeApi({ "/metrics": { body: "" } });
    renderAt("/");
    expect(await screen.findByText(/No data yet/)).toBeTruthy();
    expect(screen.queryByTestId("priority-P0")).toBeNull();
  });

  it("says when the API fails", async () => {
    fakeApi({ "/metrics": { status: 503, body: "" } });
    renderAt("/");
    expect((await screen.findByRole("alert")).textContent).toBe("The API answered 503.");
  });
});

describe("Findings", () => {
  it("lists findings and filters them through the URL", async () => {
    const calls = fakeApi({
      "/api/v1/findings?limit=50&offset=0": { body: PAGE },
      "/api/v1/findings?category=SCA&limit=50&offset=0": { body: PAGE },
    });
    renderAt("/findings");
    const link = await screen.findByRole("link", { name: FINDING.title });
    expect(link.getAttribute("href")).toBe(`/findings/${ID}`);
    fireEvent.change(screen.getByLabelText("Category"), { target: { value: "SCA" } });
    await screen.findByRole("link", { name: FINDING.title });
    expect(calls).toContain("/api/v1/findings?category=SCA&limit=50&offset=0");
  });

  it("shows text from findings as text", async () => {
    const hostile = { ...FINDING, title: '<img src=x onerror="alert(1)">' };
    fakeApi({ "/api/v1/findings?limit=50&offset=0": { body: { ...PAGE, items: [{ run_id: RUN, finding: hostile }] } } });
    const { container } = renderAt("/findings");
    expect(await screen.findByText(hostile.title)).toBeTruthy();
    expect(container.querySelector("img")).toBeNull();
  });
});

describe("Finding detail", () => {
  const detail = {
    finding: FINDING, occurrence_count: 1,
    occurrences: [{ run_id: RUN, repo: "acme/shop", commit: "a".repeat(40), context: "release", created_at: "2026-11-11T10:00:00Z" }],
  };

  it("shows the finding, where it was seen, and its root-cause group as advisory", async () => {
    fakeApi({
      [`/api/v1/findings/${ID}`]: { body: detail },
      [`/api/v1/runs/${RUN}/correlations`]: {
        body: { groups: [{ group_id: "g", finding_ids: [ID, "e".repeat(64)], stage: "structural", labelled_by: "llm",
          title: "pyyaml", root_cause: "One old package.", single_fix: "Upgrade pyyaml to 5.4." }] },
      },
    });
    renderAt(`/findings/${ID}`);
    expect(await screen.findByRole("heading", { name: FINDING.title })).toBeTruthy();
    expect(screen.getByText("CVE-2020-14343")).toBeTruthy();
    const group = await screen.findByRole("complementary", { name: "Root-cause group" });
    expect(within(group).getByText(/advisory, never part of the gate · written by a model/)).toBeTruthy();
    expect(within(group).getByText("Upgrade pyyaml to 5.4.")).toBeTruthy();
  });

  it("shows no group of one finding: it would only repeat the finding", async () => {
    fakeApi({
      [`/api/v1/findings/${ID}`]: { body: detail },
      [`/api/v1/runs/${RUN}/correlations`]: {
        body: { groups: [{ group_id: "g", finding_ids: [ID], stage: "dedup", labelled_by: "template",
          title: "t", root_cause: "r", single_fix: null }] },
      },
    });
    renderAt(`/findings/${ID}`);
    await screen.findByRole("heading", { name: FINDING.title });
    await new Promise((resolve) => setTimeout(resolve, 50));
    expect(screen.queryByRole("complementary", { name: "Root-cause group" })).toBeNull();
  });

  it("shows no group when the run has no correlation", async () => {
    fakeApi({ [`/api/v1/findings/${ID}`]: { body: detail } });
    renderAt(`/findings/${ID}`);
    await screen.findByRole("heading", { name: FINDING.title });
    expect(screen.queryByRole("complementary", { name: "Root-cause group" })).toBeNull();
  });
});
