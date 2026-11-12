import { fireEvent, screen, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { fakeApi, renderAt } from "../test-utils";

const RUN = "22222222-2222-4222-8222-222222222222";
const FINDING = "a".repeat(64);
const IMAGE = `sha256:${"d".repeat(64)}`;
const waiver = (index: number, extra: Record<string, unknown>) => ({
  index, id: `w-${index}`, finding_id: null, vulnerability: null, purl: null, owner: "hiba",
  justification: "Accepted.", expires_at: "2027-01-31T00:00:00Z", applied: false, ...extra,
});
const SHOP = {
  repo: "acme/shop", commit: "b".repeat(40), ref: "refs/heads/main", source: "run", run_id: RUN, image_digest: null,
  decision_id: "0193f2c4-7a1e-7b3c-9d2e-4f5a6b7c8d9e", verdict: "WARN", evaluated_at: "2026-11-19T10:00:00Z",
  engine_version: "0.1.0", policy_bundle_digest: `sha256:${"4".repeat(64)}`, waivers_digest: `sha256:${"5".repeat(64)}`,
  applied: ["fixture-key"], invalid_waivers: [],
  waivers: [
    waiver(0, { id: "fixture-key", finding_id: FINDING, justification: "Test key.\nNever deployed.", applied: true,
      expires_at: "2026-11-25T00:00:00Z" }),
    waiver(1, { id: "pyyaml", vulnerability: "CVE-2020-14343", purl: "pkg:pypi/pyyaml", owner: "nourhane",
      expires_at: "2026-11-01T00:00:00Z" }),
    waiver(2, { id: null, owner: null, justification: null, expires_at: "2026-12-31" }),
  ],
};
const page = (...items: unknown[]) => ({ items });
const RULES = {
  decisions: 4,
  items: [
    { rule: "SC-006", effect: "WARN", context: "pr", decisions: 2, last_evaluated_at: "2026-11-18T00:00:00Z" },
    { rule: "SC-006", effect: "BLOCK", context: "release", decisions: 1, last_evaluated_at: "2026-11-19T10:00:00+01:00" },
    { rule: "SC-099", effect: "BLOCK", context: "release", decisions: 1, last_evaluated_at: "2026-11-02T00:00:00Z" },
  ],
};

beforeEach(() => {
  vi.useFakeTimers({ toFake: ["Date"] });
  vi.setSystemTime(new Date("2026-11-20T00:00:00Z"));
});
afterEach(() => vi.useRealTimers());

function rowOf(name: string): HTMLElement {
  const cell = screen.getAllByRole("cell").find((c) => c.textContent === name);
  if (!cell) throw new Error(`no cell ${name}`);
  return cell.closest("tr")!;
}

describe("Policies & waivers", () => {
  it("shows each repository's latest release decision and the waivers it read, as written", async () => {
    fakeApi({ "/api/v1/waivers": { body: page(SHOP) }, "/api/v1/rules": { body: RULES } });
    renderAt("/policies");
    const card = await screen.findByRole("article", { name: "acme/shop" });
    expect(within(card).getByText("WARN")).toBeTruthy();
    expect(within(card).getByRole("link", { name: "run" }).getAttribute("href")).toBe(`/runs/${RUN}`);

    const key = rowOf("fixture-key");
    expect(within(key).getByRole("link").getAttribute("href")).toBe(`/findings/${FINDING}`);
    expect(within(key).getByText("applied")).toBeTruthy();
    expect(within(key).getByText((_, el) => el?.textContent === "Test key.\nNever deployed.")).toBeTruthy();
    expect(within(key).getByText("in 5 days")).toBeTruthy();
    expect(within(key).getByText("in 5 days").parentElement!.className).toContain("amber");

    const pyyaml = rowOf("pyyaml");
    expect(within(pyyaml).getByText("CVE-2020-14343", { exact: false })).toBeTruthy();
    expect(within(pyyaml).getByText("pkg:pypi/pyyaml")).toBeTruthy();
    expect(within(pyyaml).getByText("not applied")).toBeTruthy();
    expect(within(pyyaml).getByText("19 days ago")).toBeTruthy();
    expect(within(pyyaml).getByText(/^expired/).className).toContain("red");

    const odd = rowOf("#3");
    expect(within(odd).getByText("2026-12-31")).toBeTruthy();
    expect(within(odd).getByText("(not a date-time)", { exact: false })).toBeTruthy();
    expect(within(odd).getAllByText("—")).toHaveLength(3);
  });

  it("a waivers file not uploaded is unknown, never 'No waivers'", async () => {
    fakeApi({ "/api/v1/waivers": { body: page({ ...SHOP, waivers: null }) }, "/api/v1/rules": { body: RULES } });
    renderAt("/policies");
    const card = await screen.findByRole("article", { name: "acme/shop" });
    expect(within(card).getByText(/Waivers file not uploaded/)).toBeTruthy();
    expect(within(card).getByText(/applied fixture-key/)).toBeTruthy();
    expect(within(card).queryByText(/No waivers/)).toBeNull();
    expect(within(card).queryByRole("table")).toBeNull();
  });

  it("an empty file is no waivers, and a Decision 1.0 does not say which file it read", async () => {
    const older = { ...SHOP, repo: "acme/api", waivers_digest: null, waivers: null, applied: [] };
    fakeApi({
      "/api/v1/waivers": { body: page(older, { ...SHOP, waivers: [], applied: [] }) },
      "/api/v1/rules": { body: RULES },
    });
    renderAt("/policies");
    const shop = await screen.findByRole("article", { name: "acme/shop" });
    expect(within(shop).getByText(/No waivers: the decision read an empty waivers file/)).toBeTruthy();
    const api = screen.getByRole("article", { name: "acme/api" });
    expect(within(api).getByText(/does not record which waivers file it read/)).toBeTruthy();
    expect(within(api).queryByText(/No waivers/)).toBeNull();
  });

  it("shows the decision's SC-005 reasons, and a release links to its evidence", async () => {
    const release = { ...SHOP, source: "release", run_id: null, image_digest: IMAGE, verdict: "BLOCK",
      invalid_waivers: ["Invalid waiver w-9: owner must be a non-empty string"] };
    fakeApi({ "/api/v1/waivers": { body: page(release) }, "/api/v1/rules": { body: RULES } });
    renderAt("/policies");
    const card = await screen.findByRole("article", { name: "acme/shop" });
    expect(within(card).getByRole("alert").textContent).toBe("SC-005: Invalid waiver w-9: owner must be a non-empty string");
    expect(within(card).getByRole("link", { name: "release" }).getAttribute("href")).toBe(`/releases/${encodeURIComponent(IMAGE)}`);
    expect(within(card).getByText("BLOCK")).toBeTruthy();
  });

  it("filters by repository through the URL, and the chip clears it", async () => {
    const calls = fakeApi({
      "/api/v1/waivers?repo=acme%2Fshop": { body: page(SHOP) },
      "/api/v1/waivers": { body: page(SHOP, { ...SHOP, repo: "acme/api" }) },
      "/api/v1/rules": { body: RULES },
    });
    renderAt("/policies?repo=acme%2Fshop");
    await screen.findByRole("article", { name: "acme/shop" });
    expect(screen.queryByRole("article", { name: "acme/api" })).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "acme/shop ✕" }));
    await screen.findByRole("article", { name: "acme/api" });
    expect(calls).toContain("/api/v1/waivers?repo=acme%2Fshop");
    expect(calls).toContain("/api/v1/waivers");
  });

  it("renders a waiver's text as text", async () => {
    const hostile = { ...SHOP, waivers: [waiver(0, { owner: "<img src=x onerror=alert(1)>", justification: "<b>bold</b>",
      finding_id: "javascript:alert(1)" })] };
    fakeApi({ "/api/v1/waivers": { body: page(hostile) }, "/api/v1/rules": { body: RULES } });
    const { container } = renderAt("/policies");
    await screen.findByText("<img src=x onerror=alert(1)>");
    expect(container.querySelector("img")).toBeNull();
    expect(container.querySelector("b")).toBeNull();
    const row = rowOf("w-0");
    expect(within(row).queryByRole("link")).toBeNull();
    expect(within(row).getByText("javascript:alert(1)")).toBeTruthy();
  });

  it("lists the catalogue with how often each rule fired, and a rule it does not know", async () => {
    fakeApi({ "/api/v1/waivers": { body: page() }, "/api/v1/rules": { body: RULES } });
    renderAt("/policies");
    await screen.findByText("No release decision of a default branch is recorded.");
    await screen.findByText(/of the 4 recorded decisions/);
    const p1 = rowOf("SC-006");
    expect(within(p1).getByText("pr: 2 decisions")).toBeTruthy();
    expect(within(p1).getByText("release: 1 decision (BLOCK)")).toBeTruthy();
    expect(within(p1).getByText("2026-11-19 09:00 UTC")).toBeTruthy();
    expect(within(rowOf("SC-001")).getByText("never")).toBeTruthy();
    expect(within(rowOf("SC-010")).queryByText(/`/)).toBeNull();
    const unknown = rowOf("SC-099");
    expect(within(unknown).getByText(/Not in this dashboard's catalogue/)).toBeTruthy();
    expect(screen.getAllByRole("row")).toHaveLength(1 + 11 + 1);
  });

  it("a failed waivers request is an error, and the rules still show", async () => {
    fakeApi({ "/api/v1/waivers": { status: 503, body: { detail: "no database" } }, "/api/v1/rules": { body: RULES } });
    renderAt("/policies");
    expect((await screen.findByRole("alert")).textContent).toContain("503");
    await screen.findByText("pr: 2 decisions");
  });
});
