// What the dashboard shows of a Finding v1 document (schemas/finding.v1.json). The API types the document as
// an object; this reads the fields it needs, and a field of another type is shown as absent, never trusted.

export const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] as const;
export const CATEGORIES = ["SECRET", "SAST", "SCA", "CONTAINER", "IAC", "PIPELINE", "LICENSE"] as const;
export const PRIORITIES = ["P0", "P1", "P2", "P3", "P4"] as const;

export interface FindingView {
  id: string;
  title: string;
  message: string | null;
  severity: string;
  category: string;
  ruleId: string;
  tool: string;
  path: string | null;
  line: number | null;
  priority: string | null;
  score: number | null;
  cves: string[];
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function text(value: unknown): string | null {
  return typeof value === "string" ? value : null;
}

function count(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

export function asFinding(document: unknown): FindingView {
  const finding = isRecord(document) ? document : {};
  const location = isRecord(finding.location) ? finding.location : {};
  const risk = isRecord(finding.risk) ? finding.risk : {};
  const tool = isRecord(finding.tool) ? finding.tool : {};
  const cves = Array.isArray(finding.cve) ? finding.cve.filter((cve): cve is string => typeof cve === "string") : [];
  return {
    id: text(finding.id) ?? "",
    title: text(finding.title) ?? "(no title)",
    message: text(finding.message),
    severity: text(finding.severity) ?? "UNKNOWN",
    category: text(finding.category) ?? "UNKNOWN",
    ruleId: text(finding.rule_id) ?? "",
    tool: text(tool.name) ?? "",
    path: text(location.path),
    line: count(location.start_line),
    priority: text(risk.priority),
    score: count(risk.score),
    cves,
  };
}
