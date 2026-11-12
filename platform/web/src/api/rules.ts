// The gate's rule catalogue, as SPEC section 6.3 states it (tests/web/test_rule_catalogue.py keeps the two
// identical). Shown next to how often each rule fired; the policy (policies/gate.rego) is what decides.
export interface Rule {
  rule: string;
  verdict: "BLOCK" | "WARN";
  condition: string;
}

export const RULE_CATALOGUE: readonly Rule[] = [
  { rule: "SC-001", verdict: "BLOCK", condition: "Secret detected (new in PR, or anywhere in a release image), not waived" },
  { rule: "SC-002", verdict: "BLOCK", condition: "Any P0 finding without valid waiver" },
  { rule: "SC-003", verdict: "BLOCK", condition: "KEV-listed vulnerability with a fix, internet-facing service (an unknown exposure counts as internet-facing)" },
  { rule: "SC-004", verdict: "BLOCK", condition: "Release image missing signature, SBOM or provenance" },
  { rule: "SC-005", verdict: "BLOCK", condition: "Invalid waiver (no owner / justification / expiry, or expiry > 90 days)" },
  { rule: "SC-006", verdict: "WARN", condition: "P1 findings (BLOCK above threshold in strict profile)" },
  { rule: "SC-007", verdict: "WARN", condition: "Base image not pinned by digest, or container runs as root" },
  { rule: "SC-008", verdict: "WARN", condition: "Copyleft licence in a distributed component" },
  { rule: "SC-009", verdict: "BLOCK", condition: "High-severity CI workflow issue introduced by the PR" },
  { rule: "SC-010", verdict: "BLOCK", condition: "Scanner failure, timeout or tool-integrity mismatch; a required scanner (`policies/required_tools.rego`) missing from the tool status, or no tool status where one is required (`pr`, `release`); malformed gate input" },
  { rule: "SC-011", verdict: "BLOCK", condition: "Misconfiguration that exposes the service by itself, introduced by the PR (privileged pod, host namespaces, root mounts or kernel modules; a public bucket, database or dataset; SSH, RDP or database ports open to the internet): a short list of Trivy rule ids in `policies/exposing.rego`, matched on Trivy findings only, whatever the finding's score" },
];

/** Within this many days of its expiry, a waiver is shown as expiring soon. */
export const EXPIRES_SOON_DAYS = 14;
const DAY_MS = 24 * 60 * 60 * 1000;
// RFC 3339 date-time, as schemas/waivers.v1.json requires (`format: date-time`): a date alone is not one.
const RFC3339 = /^\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(\.\d+)?([Zz]|[+-]\d{2}:\d{2})$/;

export type Expiry =
  | { kind: "unreadable" }
  | { kind: "expired" | "soon" | "later"; at: Date; days: number };

/** Where a waiver's `expires_at` stands against `now` (the viewer's clock; the gate uses the decision's
 * `evaluated_at`). `days` is whole days left, or whole days since it expired. Text that is not an RFC 3339
 * date-time is "unreadable", never a date guessed from it. */
export function expiry(expiresAt: string | null, now: number): Expiry {
  if (expiresAt === null || !RFC3339.test(expiresAt)) return { kind: "unreadable" };
  const at = new Date(expiresAt);
  const time = at.getTime();
  if (Number.isNaN(time)) return { kind: "unreadable" };
  if (time <= now) return { kind: "expired", at, days: Math.floor((now - time) / DAY_MS) };
  const days = Math.floor((time - now) / DAY_MS);
  return { kind: days < EXPIRES_SOON_DAYS ? "soon" : "later", at, days };
}
