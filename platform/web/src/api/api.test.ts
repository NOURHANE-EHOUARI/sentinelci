import { describe, expect, it } from "vitest";
import { fakeApi } from "../test-utils";
import { ApiError, apiUrl, getCorrelation, listFindings } from "./client";
import { groupOf } from "./correlation";
import { asFinding } from "./finding";

describe("the API client", () => {
  it("encodes filters and leaves out the empty ones", () => {
    expect(apiUrl("/api/v1/findings", { category: "SCA", tool: "", repo: "a/b c", offset: 0 })).toBe(
      "/api/v1/findings?category=SCA&repo=a%2Fb+c&offset=0",
    );
  });

  it("turns an error status into an ApiError", async () => {
    fakeApi({ "/api/v1/findings?limit=50": { status: 503, body: { detail: "no database" } } });
    await expect(listFindings({ limit: 50 })).rejects.toEqual(new ApiError(503, "/api/v1/findings answered 503"));
  });

  it("reads a missing correlation as none", async () => {
    fakeApi({});
    await expect(getCorrelation("r1")).resolves.toBeNull();
  });
});

describe("asFinding", () => {
  it("reads the fields the dashboard shows", () => {
    const view = asFinding({
      id: "a".repeat(64), title: "t", severity: "HIGH", category: "SCA", rule_id: "GHSA-x",
      tool: { name: "grype" }, location: { path: "requirements.txt", start_line: 3 },
      risk: { priority: "P0", score: 93.5 }, cve: ["CVE-2020-14343", 7],
    });
    expect(view).toMatchObject({ severity: "HIGH", tool: "grype", path: "requirements.txt", line: 3, priority: "P0", score: 93.5 });
    expect(view.cves).toEqual(["CVE-2020-14343"]);
  });

  it("shows a field of the wrong type as absent, never as given", () => {
    const view = asFinding({ title: 7, location: { path: ["x"] }, risk: "P0", tool: null });
    expect(view).toMatchObject({ title: "(no title)", path: null, priority: null, tool: "" });
    expect(asFinding(null).severity).toBe("UNKNOWN");
  });
});

describe("groupOf", () => {
  const document = {
    groups: [
      { group_id: "g1", finding_ids: ["a", "b"], stage: "structural", labelled_by: "llm", title: "lodash",
        root_cause: "One package.", single_fix: "Upgrade lodash." },
      { group_id: "g2", finding_ids: ["c"], stage: "dedup", labelled_by: "template", title: "c", root_cause: "r",
        single_fix: null },
    ],
  };

  it("finds the group of a finding, and says when a model labelled it", () => {
    expect(groupOf(document, "b")).toEqual({
      groupId: "g1", title: "lodash", rootCause: "One package.", singleFix: "Upgrade lodash.",
      stage: "structural", labelledBy: "llm", members: 2,
    });
    expect(groupOf(document, "c")?.labelledBy).toBe("template");
  });

  it("finds nothing in anything else", () => {
    expect(groupOf(document, "z")).toBeNull();
    expect(groupOf({ groups: "no" }, "a")).toBeNull();
    expect(groupOf(null, "a")).toBeNull();
  });
});
