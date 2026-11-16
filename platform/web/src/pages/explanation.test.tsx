import { screen, waitFor, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { fakeApi, renderAt } from "../test-utils";

const ID = "f".repeat(64);
const RUN = "11111111-1111-4111-8111-111111111111";
const FINDING = {
  id: ID, title: "PyYAML 5.3.1: code execution through full_load", severity: "CRITICAL", category: "SCA",
  rule_id: "GHSA-8q59-q68h-6hv4", tool: { name: "grype" }, message: "pyyaml 5.3.1 is affected",
  location: { path: "requirements.txt" }, risk: { priority: "P0", score: 91 }, cve: ["CVE-2020-14343"],
};
const detail = (finding: Record<string, unknown> = FINDING) => ({
  finding, occurrence_count: 1,
  occurrences: [{ run_id: RUN, repo: "acme/shop", commit: "a".repeat(40), context: "release", created_at: "2026-11-11T10:00:00Z" }],
});
const EXPLANATION = {
  schema_version: "1.0", finding_id: ID,
  summary: "PyYAML before 5.4 runs code from a crafted YAML document.",
  impact: "An attacker who controls a YAML document can run code as the service.",
  exploit_scenario: "A document with a python/object tag given to full_load runs a command.",
  fix_guidance: "Upgrade PyYAML to 5.4 or later and load untrusted YAML with safe_load.",
  references: ["CVE-2020-14343", "https://nvd.nist.gov/vuln/detail/CVE-2020-14343", "https://evil.example/x"],
  confidence: 0.8,
  model: { provider: "ollama", name: "gemma4:12b-it-qat", digest: `sha256:${"3".repeat(64)}`,
    prompt_sha256: "1".repeat(64), input_sha256: "2".repeat(64) },
  created_at: "2026-11-12T09:00:00Z",
};
const URL = `/api/v1/findings/${ID}/explanation`;

/** The explanation's panel, once it has finished loading. */
async function panel() {
  const aside = await screen.findByRole("complementary", { name: "Explanation" });
  await waitFor(() => expect(within(aside).queryByText("Loading…")).toBeNull());
  return aside;
}

describe("A finding's explanation", () => {
  it("is shown as advisory, naming its model, with only canonical references as links", async () => {
    fakeApi({ [`/api/v1/findings/${ID}`]: { body: detail() }, [URL]: { body: EXPLANATION } });
    renderAt(`/findings/${ID}`);
    const aside = await panel();
    expect(within(aside).getByText(/Advisory: written by a model, never read by the gate/)).toBeTruthy();
    expect(within(aside).getByText(/gemma4:12b-it-qat/)).toBeTruthy();
    expect(within(aside).getByText(/sha256:333333333333/)).toBeTruthy();
    expect(within(aside).getByText(/confidence 80 %/)).toBeTruthy();
    expect(within(aside).getByText(/2026-11-12 09:00 UTC/)).toBeTruthy();
    expect(within(aside).getByText(EXPLANATION.summary)).toBeTruthy();
    expect(within(aside).getByText(EXPLANATION.impact)).toBeTruthy();
    expect(within(aside).getByText(EXPLANATION.exploit_scenario)).toBeTruthy();
    expect(within(aside).getByText(EXPLANATION.fix_guidance)).toBeTruthy();
    const links = within(aside).getAllByRole("link");
    expect(links.map((link) => link.getAttribute("href"))).toEqual(["https://nvd.nist.gov/vuln/detail/CVE-2020-14343"]);
    expect(links[0]!.getAttribute("rel")).toBe("noreferrer noopener");
    expect(within(aside).getByText("CVE-2020-14343")).toBeTruthy();
    expect(within(aside).getByText("https://evil.example/x")).toBeTruthy(); // text, never a link
  });

  it("without one, says none is recorded and how it is asked for: never an empty explanation", async () => {
    fakeApi({ [`/api/v1/findings/${ID}`]: { body: detail() } });
    renderAt(`/findings/${ID}`);
    const aside = await panel();
    expect(within(aside).getByText(/No explanation recorded/)).toBeTruthy();
    expect(within(aside).getByText(`POST /api/v1/findings/${ID}/explain`)).toBeTruthy();
  });

  it("for a secret, says it is never sent to a model", async () => {
    const calls = fakeApi({ [`/api/v1/findings/${ID}`]: { body: detail({ ...FINDING, category: "SECRET" }) } });
    renderAt(`/findings/${ID}`);
    const aside = await panel();
    expect(within(aside).getByText(/never sent to a model: rotate the secret/)).toBeTruthy();
    expect(calls).not.toContain(URL); // not even asked
    expect(within(aside).queryByText(/explain$/)).toBeNull();
  });

  it("an explanation that cannot be read is an error, never 'none'", async () => {
    fakeApi({ [`/api/v1/findings/${ID}`]: { body: detail() }, [URL]: { status: 503, body: { detail: "down" } } });
    renderAt(`/findings/${ID}`);
    const aside = await panel();
    expect((await within(aside).findByRole("alert")).textContent).toContain("503");
    expect(within(aside).queryByText(/No explanation recorded/)).toBeNull();
    expect(screen.getByRole("heading", { name: FINDING.title })).toBeTruthy(); // the finding still shows
  });

  it("an explanation about another finding is not shown", async () => {
    fakeApi({ [`/api/v1/findings/${ID}`]: { body: detail() }, [URL]: { body: { ...EXPLANATION, finding_id: "e".repeat(64) } } });
    renderAt(`/findings/${ID}`);
    const aside = await panel();
    expect(within(aside).getByText(/about another finding: not shown/)).toBeTruthy();
    expect(within(aside).queryByText(EXPLANATION.summary)).toBeNull();
  });

  it("renders the model's text as text, and a field of another type as absent", async () => {
    const hostile = { ...EXPLANATION, summary: "<img src=x onerror=alert(1)>", impact: 7, confidence: "high",
      model: { ...EXPLANATION.model, name: "<b>m</b>", digest: null } };
    fakeApi({ [`/api/v1/findings/${ID}`]: { body: detail() }, [URL]: { body: hostile } });
    const { container } = renderAt(`/findings/${ID}`);
    const aside = await panel();
    expect(within(aside).getByText("<img src=x onerror=alert(1)>")).toBeTruthy();
    expect(container.querySelector("img")).toBeNull();
    expect(container.querySelector("aside b")).toBeNull();
    expect(within(aside).getByText(/confidence —/)).toBeTruthy();
    expect(within(aside).getByText(/Impact/).nextSibling?.textContent).toBe("—");
  });
});
