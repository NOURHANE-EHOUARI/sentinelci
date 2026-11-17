import { describe, expect, it } from "vitest";
import { asExplanation, referenceLink } from "./explanation";

describe("asExplanation", () => {
  it("reads the fields it shows, and a field of another type is absent", () => {
    const view = asExplanation({
      finding_id: "a".repeat(64), summary: "S", impact: 3, exploit_scenario: null, fix_guidance: "F",
      references: ["CWE-89", 7, "https://cwe.mitre.org/data/definitions/89.html"], confidence: "0.9",
      model: { provider: "ollama", name: "gemma4:12b-it-qat", digest: 5 }, created_at: "2026-11-12T09:00:00Z",
    });
    expect(view).toEqual({
      findingId: "a".repeat(64), summary: "S", impact: null, exploitScenario: null, fixGuidance: "F",
      references: ["CWE-89", "https://cwe.mitre.org/data/definitions/89.html"], confidence: null,
      modelName: "gemma4:12b-it-qat", modelDigest: null, provider: "ollama", createdAt: "2026-11-12T09:00:00Z",
    });
  });

  it("takes only a confidence from 0 to 1", () => {
    expect(asExplanation({ confidence: 0 }).confidence).toBe(0);
    expect(asExplanation({ confidence: 1 }).confidence).toBe(1);
    for (const bad of [-0.1, 1.5, Number.NaN, Number.POSITIVE_INFINITY, true]) {
      expect(asExplanation({ confidence: bad }).confidence).toBeNull();
    }
  });

  it("reads anything that is not a document as empty", () => {
    for (const value of [null, "x", [], 3]) {
      expect(asExplanation(value).summary).toBeNull();
      expect(asExplanation(value).references).toEqual([]);
    }
  });
});

describe("referenceLink", () => {
  it("links only the canonical pages of a CWE, CVE or advisory", () => {
    for (const url of [
      "https://cwe.mitre.org/data/definitions/89.html",
      "https://nvd.nist.gov/vuln/detail/CVE-2020-14343",
      "https://github.com/advisories/GHSA-8q59-q68h-6hv4",
      "https://osv.dev/vulnerability/CVE-2020-14343",
      "https://osv.dev/vulnerability/GHSA-8q59-q68h-6hv4",
    ]) {
      expect(referenceLink(url)).toBe(url);
    }
  });

  it("never links an id, another host or a look-alike", () => {
    for (const text of [
      "CWE-89",
      "CVE-2020-14343",
      "https://evil.example/cwe.mitre.org/data/definitions/89.html",
      "https://cwe.mitre.org.evil.example/data/definitions/89.html",
      "https://cwe.mitre.org/data/definitions/89.html?next=https://evil.example",
      "http://nvd.nist.gov/vuln/detail/CVE-2020-14343",
      "javascript:alert(1)",
      "https://osv.dev/vulnerability/../../x",
    ]) {
      expect(referenceLink(text)).toBeNull();
    }
  });
});
