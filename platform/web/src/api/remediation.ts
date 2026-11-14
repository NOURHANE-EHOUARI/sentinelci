// What the Remediation pages show of a Remediation attempt v1 document (schemas/remediation-attempt.v1.json,
// tasks A6 and A8): the proposal the loop made and what its verification gate found. Read field by field: a
// field of another type is shown as absent, never trusted, and a condition that can't be read is unknown, not
// passed and not failed. A VERIFIED attempt is a pull request a person still reviews: the bot never merges.

export interface AttemptView {
  proposalId: string;
  repo: string;
  strategy: string;
  attempt: number | null;
  findingIds: string[];
  files: string[];
  rationale: string;
  diff: string;
  model: string | null;
  proposedAt: string | null;
  outcome: string;
  verdict: string;
  pullRequest: number | null;
  verifiedAt: string | null;
  /** Each condition of the gate: true when it holds, false when it fails, null when the document can't say. */
  conditions: { name: string; ok: boolean | null }[];
  /** VERIFIED, yet a condition of the gate does not hold or can't be read: the document contradicts itself. */
  contradicts: boolean;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function record(value: unknown): Record<string, unknown> {
  return isRecord(value) ? value : {};
}

function text(value: unknown, fallback = ""): string {
  return typeof value === "string" ? value : fallback;
}

function strings(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === "string") : [];
}

function flag(value: unknown): boolean | null {
  return typeof value === "boolean" ? value : null;
}

/** The gate's verdict as a condition: PASS and WARN let the patch through, BLOCK does not, anything else is unknown. */
function notBlocked(verdict: unknown): boolean | null {
  if (verdict === "PASS" || verdict === "WARN") return true;
  return verdict === "BLOCK" ? false : null;
}

function count(value: unknown): number | null {
  return typeof value === "number" && Number.isInteger(value) ? value : null;
}

export function asAttempt(document: unknown): AttemptView {
  const attempt = record(document);
  const proposal = record(attempt.proposal);
  const result = record(attempt.result);
  const model = record(proposal.model);
  const newFindings = Array.isArray(result.new_findings) ? result.new_findings.length : null;
  const verdict = text(result.verdict, "UNKNOWN");
  const outcome = text(result.outcome, "UNKNOWN");
  // SPEC section 9.2, in its order: VERIFIED only when every one holds.
  const conditions = [
    { name: "It builds", ok: flag(result.build_ok) },
    { name: "Its tests pass", ok: flag(result.tests_ok) },
    { name: "The findings it targets are gone", ok: flag(result.target_resolved) },
    { name: "No new finding (MEDIUM or higher)", ok: newFindings === null ? null : newFindings === 0 },
    { name: "The gate does not block it", ok: notBlocked(result.verdict) },
  ];
  return {
    proposalId: text(proposal.proposal_id),
    repo: text(attempt.repo),
    strategy: text(proposal.strategy, "unknown"),
    attempt: count(proposal.attempt),
    findingIds: strings(proposal.finding_ids),
    files: strings(proposal.files),
    rationale: text(proposal.rationale),
    diff: text(proposal.diff),
    model: typeof model.name === "string" ? [model.name, model.version].filter((v) => typeof v === "string").join(" ") : null,
    proposedAt: typeof proposal.created_at === "string" ? proposal.created_at : null,
    outcome,
    verdict,
    pullRequest: count(result.pull_request),
    verifiedAt: typeof result.verified_at === "string" ? result.verified_at : null,
    conditions,
    contradicts: outcome === "VERIFIED" && conditions.some((condition) => condition.ok !== true),
  };
}
