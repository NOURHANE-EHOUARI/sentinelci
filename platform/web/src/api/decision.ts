// What the dashboard shows of a Decision v1 document (schemas/decision.v1.json), served byte for byte by
// `GET /api/v1/runs/{id}/decision`. The API checked it before keeping it; the dashboard still reads only the
// fields it needs, and a field of another type is shown as absent, never trusted.

export const VERDICTS = ["PASS", "WARN", "BLOCK"] as const;
export type Verdict = (typeof VERDICTS)[number];

export interface ViolationView {
  rule: string;
  effect: string;
  message: string;
  findingIds: string[];
}

export interface DecisionView {
  decisionId: string;
  verdict: Verdict | null; // null: not one of the three, so it is never shown as one
  evaluatedAt: string | null;
  engineVersion: string | null;
  violations: ViolationView[];
  waiversApplied: string[];
  inputs: [string, string][]; // (name, digest or version), sorted by name
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function text(value: unknown): string | null {
  return typeof value === "string" ? value : null;
}

function texts(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === "string") : [];
}

export function asVerdict(value: unknown): Verdict | null {
  return (VERDICTS as readonly unknown[]).includes(value) ? (value as Verdict) : null;
}

export function asDecision(document: unknown): DecisionView {
  const decision = isRecord(document) ? document : {};
  const inputs = isRecord(decision.inputs) ? decision.inputs : {};
  const violations = Array.isArray(decision.violations) ? decision.violations.filter(isRecord) : [];
  return {
    decisionId: text(decision.decision_id) ?? "",
    verdict: asVerdict(decision.verdict),
    evaluatedAt: text(decision.evaluated_at),
    engineVersion: text(decision.engine_version),
    violations: violations.map((violation) => ({
      rule: text(violation.rule) ?? "",
      effect: text(violation.effect) ?? "",
      message: text(violation.message) ?? "",
      findingIds: texts(violation.finding_ids),
    })),
    waiversApplied: texts(decision.waivers_applied),
    inputs: Object.entries(inputs)
      .filter((entry): entry is [string, string] => typeof entry[1] === "string")
      .sort(([a], [b]) => a.localeCompare(b)),
  };
}
