import { screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { alertReduction, correlationOf } from "../api/correlation";
import { fakeApi, renderAt } from "../test-utils";
import LLM_LABELLED from "../../../../schemas/fixtures/root-cause-group/valid/llm-labelled.json";

const RUN = "11111111-1111-4111-8111-111111111111";
const [A, B, C, D] = ["a", "b", "c", "d"].map((c) => c.repeat(64)) as [string, string, string, string];
const RUN_OUT = {
  id: RUN, repo: "acme/shop", commit: "4b825dc642cb6eb9a060e54bf8d69288fbee4904", context: "release", ref: null,
  run_id: null, created_at: "2026-11-11T10:00:00Z", findings_sha256: "e".repeat(64), finding_count: 4,
};
const group = (ids: string[], extra: Record<string, unknown> = {}) => ({
  schema_version: "1.0", group_id: ids.join("").slice(0, 64), finding_ids: ids, stage: "structural",
  labelled_by: "template", title: `${ids.length} finding(s)`, root_cause: "One old package.", single_fix: null, ...extra,
});
const CORRELATION = {
  schema_version: "1.0", findings_sha256: "e".repeat(64), correlator: { version: "0.3.0", stages: ["dedup", "structural"] },
  // The model-labelled group is the contract's own valid fixture, with the run's findings and an untrusted text.
  groups: [group([D]), { ...LLM_LABELLED, finding_ids: [A, B, C], title: "PyYAML 5.3.1",
    root_cause: '<img src=x onerror="alert(1)">', single_fix: "Upgrade pyyaml to 5.4." }],
};
const finding = (id: string, title: string) => ({ id, title, severity: "CRITICAL", category: "SCA", rule_id: "r",
  tool: { name: "grype" }, location: { path: "requirements.txt" } });
const FINDINGS = { items: [A, B, C, D].map((id, n) => ({ run_id: RUN, finding: finding(id, `finding ${n}`) })),
  total: 4, limit: 500, offset: 0 };

function api(correlation: unknown = CORRELATION) {
  return fakeApi({
    [`/api/v1/runs/${RUN}`]: { body: RUN_OUT },
    ...(correlation === null ? {} : { [`/api/v1/runs/${RUN}/correlations`]: { body: correlation } }),
    [`/api/v1/findings?run_id=${RUN}&limit=500&offset=0`]: { body: FINDINGS },
  });
}

describe("Root-cause groups", () => {
  it("shows the groups of more than one finding, with their members, as advisory text", async () => {
    api();
    const { container } = renderAt(`/runs/${RUN}/groups`);
    const pyyaml = await screen.findByRole("article", { name: "Group: PyYAML 5.3.1" });
    const label = pyyaml.firstElementChild?.textContent;
    expect(label).toBe("3 findings · stage structural · written by a model (ollama gemma4:12b-it-qat)");
    expect(within(pyyaml).getByText('<img src=x onerror="alert(1)">')).toBeTruthy();
    expect(container.querySelector("img")).toBeNull();
    const members = await within(pyyaml).findAllByRole("link");
    expect(members.map((link) => link.getAttribute("href"))).toEqual([A, B, C].map((id) => `/findings/${id}`));
    expect(screen.getByText("1 finding(s) stand alone.")).toBeTruthy();
    const summary = screen.getByRole("list", { name: "Correlation summary" });
    expect(within(summary).getByText("50 %")).toBeTruthy(); // 1 − 2 groups ÷ 4 findings
    expect(within(summary).getByText("0.3.0 · dedup + structural")).toBeTruthy();
    expect(screen.getByText(/Advisory: the gate never reads these groups/)).toBeTruthy();
  });

  it("gives no alert reduction when a group could not be read", async () => {
    api({ ...CORRELATION, groups: [...CORRELATION.groups, { finding_ids: [A], title: 7, root_cause: "r" }] });
    renderAt(`/runs/${RUN}/groups`);
    const summary = await screen.findByRole("list", { name: "Correlation summary" });
    expect(within(summary).getByText("Alert reduction").nextSibling?.textContent).toBe("—");
    expect(screen.getByRole("alert").textContent).toBe("1 group(s) of this correlation could not be read and are not shown.");
  });

  it("says when the run has no correlation", async () => {
    api(null);
    renderAt(`/runs/${RUN}/groups`);
    expect(await screen.findByText("No correlation recorded for this run.")).toBeTruthy();
  });

  it("says when the run does not exist", async () => {
    fakeApi({});
    renderAt(`/runs/${RUN}/groups`);
    expect((await screen.findByRole("alert")).textContent).toBe("The API answered 404.");
  });
});

describe("Finding detail", () => {
  it("links its group to every group of the run", async () => {
    const detail = { finding: finding(A, "finding 0"), occurrence_count: 1,
      occurrences: [{ run_id: RUN, repo: "acme/shop", commit: "a".repeat(40), context: "release", created_at: "2026-11-11T10:00:00Z" }] };
    fakeApi({ [`/api/v1/findings/${A}`]: { body: detail }, [`/api/v1/runs/${RUN}/correlations`]: { body: CORRELATION } });
    renderAt(`/findings/${A}`);
    const aside = await screen.findByRole("complementary", { name: "Root-cause group" });
    expect(within(aside).getByRole("link", { name: "Every group of this run →" }).getAttribute("href")).toBe(
      `/runs/${RUN}/groups`,
    );
  });
});

describe("correlationOf", () => {
  it("keeps only groups it can read whole, largest first", () => {
    const view = correlationOf({ correlator: { version: 3, stages: ["dedup", 4] },
      groups: [group([A]), { finding_ids: [B], title: 1, root_cause: "r" }, group([C, D]), null] });
    expect(view?.groups.map((g) => g.members)).toEqual([2, 1]);
    expect(view?.unread).toBe(2);
    expect(view?.version).toBe("");
    expect(view?.stages).toEqual(["dedup"]);
    expect(correlationOf({ groups: "none" })).toBeNull();
  });

  it("names a group's model by its provider and name, and nothing else as a model", () => {
    const named = (model: unknown) => correlationOf({ groups: [{ ...LLM_LABELLED, model }] })?.groups[0]?.model;
    expect(named(LLM_LABELLED.model)).toBe("ollama gemma4:12b-it-qat");
    expect(named({ name: "gemma4:12b-it-qat" })).toBe("gemma4:12b-it-qat");
    expect(named("qwen2.5:7b")).toBeNull(); // a string is not Root-cause group v1
    expect(named({ provider: "ollama", name: 4 })).toBeNull();
  });

  it("computes the alert reduction of SPEC section 10", () => {
    expect(alertReduction(3, 12)).toBe(0.75);
    expect(alertReduction(0, 0)).toBeNull();
  });
});
