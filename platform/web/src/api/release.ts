// What the Releases & evidence page shows of a Release evidence v1 document (schemas/release-evidence.v1.json,
// tasks A4 and A8). The platform checked it before keeping it; this still reads it field by field, and a field
// of another type is shown as absent, never trusted. Nothing here decides anything: the decision was made by
// the gate, the reports by `sentinel verify` on the release laptop, and Kyverno verifies again at admission.

export interface CheckView {
  name: string;
  ok: boolean;
  detail: string;
}

export interface TrustReportView {
  mode: string;
  trusted: boolean;
  verifiedAt: string | null;
  imageName: string;
  builderId: string;
  keySha256: string;
  checks: CheckView[];
}

export interface ViolationView {
  rule: string;
  effect: string;
  message: string;
  findings: number;
}

export interface ReleaseView {
  decisionId: string;
  verdict: string;
  repo: string;
  commit: string;
  ref: string | null;
  imageDigest: string;
  evaluatedAt: string | null;
  violations: ViolationView[];
  inputs: [string, string][];
  toolVersions: [string, string][];
  waiversApplied: string[];
  reports: TrustReportView[];
  // Reports that could not be read (a field of another type): the release is then of unknown trust.
  unreadableReports: number;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function text(value: unknown, fallback = ""): string {
  return typeof value === "string" ? value : fallback;
}

function record(value: unknown): Record<string, unknown> {
  return isRecord(value) ? value : {};
}

function list(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function strings(value: unknown): [string, string][] {
  return Object.entries(record(value)).filter((entry): entry is [string, string] => typeof entry[1] === "string");
}

function report(value: unknown): TrustReportView | null {
  if (!isRecord(value) || typeof value.trusted !== "boolean") return null;
  const checks = list(value.checks).flatMap((check): CheckView[] =>
    isRecord(check) && typeof check.ok === "boolean" && typeof check.name === "string"
      ? [{ name: check.name, ok: check.ok, detail: text(check.detail) }]
      : [],
  );
  return {
    mode: text(value.mode, "unknown"),
    trusted: value.trusted,
    verifiedAt: typeof value.verified_at === "string" ? value.verified_at : null,
    imageName: text(record(value.image).name),
    builderId: text(value.builder_id),
    keySha256: text(value.key_sha256),
    checks,
  };
}

export function asRelease(document: unknown): ReleaseView {
  const evidence = record(document);
  const decision = record(evidence.decision);
  const subject = record(decision.subject);
  const inputs = record(decision.inputs);
  return {
    decisionId: text(decision.decision_id),
    verdict: text(decision.verdict, "UNKNOWN"),
    repo: text(subject.repo),
    commit: text(subject.commit),
    ref: typeof subject.ref === "string" ? subject.ref : null,
    imageDigest: text(subject.image_digest),
    evaluatedAt: typeof decision.evaluated_at === "string" ? decision.evaluated_at : null,
    violations: list(decision.violations).flatMap((violation): ViolationView[] =>
      isRecord(violation)
        ? [{
            rule: text(violation.rule), effect: text(violation.effect), message: text(violation.message),
            findings: list(violation.finding_ids).length,
          }]
        : [],
    ),
    inputs: strings(inputs).filter(([name]) => name.endsWith("_digest") || name === "risk_model_version"),
    toolVersions: strings(inputs.tool_versions),
    waiversApplied: list(decision.waivers_applied).filter((id): id is string => typeof id === "string"),
    reports: list(evidence.trust_reports).flatMap((value) => {
      const parsed = report(value);
      return parsed ? [parsed] : [];
    }),
    unreadableReports: list(evidence.trust_reports).filter((value) => report(value) === null).length,
  };
}

/** Every report trusts the image: true; one does not: false; no report, or one that could not be read: null
 * (unknown, never trusted by default). */
export function releaseTrust(release: ReleaseView): boolean | null {
  if (release.reports.length === 0 || release.unreadableReports > 0) return null;
  return release.reports.every((one) => one.trusted);
}
