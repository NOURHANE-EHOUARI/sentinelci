// What the dashboard shows of an Explanation v1 document (schemas/explanation.v1.json), served byte for byte
// by `GET /api/v1/findings/{id}/explanation` (B5c). Advisory: written by a model, never read by the gate. The
// API checks it before keeping it and again before serving it; the dashboard still reads only the fields it
// shows, and a field of another type is absent, never trusted. A reference becomes a link only when it is one
// of the canonical pages an explanation may cite (sentinel_ai.explain.allowed_references).

export interface ExplanationView {
  findingId: string | null;
  summary: string | null;
  impact: string | null;
  exploitScenario: string | null;
  fixGuidance: string | null;
  references: string[];
  confidence: number | null; // 0 to 1
  modelName: string | null;
  modelDigest: string | null;
  provider: string | null;
  createdAt: string | null;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function text(value: unknown): string | null {
  return typeof value === "string" ? value : null;
}

export function asExplanation(value: unknown): ExplanationView {
  const document = isRecord(value) ? value : {};
  const model = isRecord(document.model) ? document.model : {};
  const confidence = document.confidence;
  return {
    findingId: text(document.finding_id),
    summary: text(document.summary),
    impact: text(document.impact),
    exploitScenario: text(document.exploit_scenario),
    fixGuidance: text(document.fix_guidance),
    references: Array.isArray(document.references)
      ? document.references.filter((item): item is string => typeof item === "string")
      : [],
    confidence:
      typeof confidence === "number" && Number.isFinite(confidence) && confidence >= 0 && confidence <= 1
        ? confidence
        : null,
    modelName: text(model.name),
    modelDigest: text(model.digest),
    provider: text(model.provider),
    createdAt: text(document.created_at),
  };
}

const ADVISORY = "(CVE-[0-9]{4}-[0-9]{4,7}|GHSA(-[23456789cfghjmpqrvwx]{4}){3})";
const CANONICAL = [
  /^https:\/\/cwe\.mitre\.org\/data\/definitions\/[0-9]{1,5}\.html$/,
  /^https:\/\/nvd\.nist\.gov\/vuln\/detail\/CVE-[0-9]{4}-[0-9]{4,7}$/,
  /^https:\/\/github\.com\/advisories\/GHSA(-[23456789cfghjmpqrvwx]{4}){3}$/,
  new RegExp(`^https://osv\\.dev/vulnerability/${ADVISORY}$`),
];

/** The reference as a link when it is a canonical page (MITRE CWE, NVD, GitHub advisories, OSV), else null:
 * an id or any other text is shown as text. */
export function referenceLink(reference: string): string | null {
  return CANONICAL.some((pattern) => pattern.test(reference)) ? reference : null;
}
