import { describe, expect, it } from "vitest";
import { openFindings, totalBy } from "./metrics";

const EXPOSITION = [
  "# HELP sentinel_findings_open Findings of each repository's latest release run, by priority and category.",
  "# TYPE sentinel_findings_open gauge",
  'sentinel_findings_open{priority="P0",category="SECRET"} 5',
  'sentinel_findings_open{priority="P1",category="IAC"} 1',
  'sentinel_findings_open{priority="P2",category="IAC"} 16',
  'sentinel_findings_open{priority="P2",category="SCA"} 0',
  'sentinel_gate_decisions_total{verdict="BLOCK",context="pr"} 3',
  "",
].join("\n");

describe("openFindings", () => {
  it("reads every sample of sentinel_findings_open and nothing else", () => {
    const samples = openFindings(EXPOSITION);
    expect(samples).toHaveLength(4);
    expect(totalBy(samples ?? [], "priority")).toEqual(new Map([["P0", 5], ["P1", 1], ["P2", 16]]));
    expect(totalBy(samples ?? [], "category")).toEqual(new Map([["SECRET", 5], ["IAC", 17], ["SCA", 0]]));
  });

  it("says no data, not zero, when the metric is absent", () => {
    expect(openFindings("")).toBeNull();
    expect(openFindings('sentinel_gate_decisions_total{verdict="PASS",context="pr"} 1\n')).toBeNull();
  });

  it("skips a sample it cannot read rather than guess", () => {
    const odd = ['sentinel_findings_open{priority="P0"} 2', 'sentinel_findings_open{priority="P1",category="IAC"} NaN'];
    expect(openFindings(odd.join("\n"))).toBeNull();
  });
});
