import { ApiError } from "../api/client";
import { asVerdict } from "../api/decision";

const SEVERITY_STYLE: Record<string, string> = {
  CRITICAL: "bg-red-700 text-white",
  HIGH: "bg-red-100 text-red-800",
  MEDIUM: "bg-amber-100 text-amber-800",
  LOW: "bg-sky-100 text-sky-800",
  INFO: "bg-slate-100 text-slate-700",
};

export function Badge({ value }: { value: string | null }) {
  const style = (value && SEVERITY_STYLE[value]) ?? "bg-slate-100 text-slate-700";
  return <span className={`rounded px-1.5 py-0.5 text-xs font-medium ${style}`}>{value ?? "—"}</span>;
}

export function Failure({ error }: { error: unknown }) {
  const reason = error instanceof ApiError ? `The API answered ${error.status}.` : "The API could not be reached.";
  return (
    <p role="alert" className="rounded border border-red-200 bg-red-50 p-3 text-sm text-red-800">
      {reason}
    </p>
  );
}

export function Loading() {
  return <p className="text-sm text-slate-500">Loading…</p>;
}

const VERDICT_STYLE: Record<string, string> = {
  PASS: "bg-emerald-100 text-emerald-800",
  WARN: "bg-amber-100 text-amber-800",
  BLOCK: "bg-red-700 text-white",
};

/** The gate's verdict on a release. */
export function Verdict({ value }: { value: string }) {
  const style = VERDICT_STYLE[value] ?? "bg-slate-100 text-slate-700";
  return <span className={`rounded px-1.5 py-0.5 text-xs font-semibold ${style}`}>{value}</span>;
}

/** What `sentinel verify` found on the release laptop: trusted, not trusted, or nothing signed (a BLOCK). */
export function Trust({ trusted }: { trusted: boolean | null }) {
  if (trusted === null) return <span className="text-xs text-slate-500">not signed</span>;
  return trusted ? (
    <span className="text-xs font-medium text-emerald-700">✓ trusted</span>
  ) : (
    <span className="text-xs font-medium text-red-700">✗ not trusted</span>
  );
}

/** A sha256 digest, shortened for a table; the full value stays in the title. */
export function Digest({ value }: { value: string }) {
  const short = value.startsWith("sha256:") ? `${value.slice(0, 19)}…` : value;
  return (
    <span className="font-mono text-xs" title={value}>
      {short}
    </span>
  );
}

export function utc(value: string | null): string {
  if (value === null) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "—" : `${date.toISOString().slice(0, 16).replace("T", " ")} UTC`;
}

const OUTCOME_STYLE: Record<string, string> = {
  VERIFIED: "bg-emerald-100 text-emerald-800",
  REJECTED: "bg-amber-100 text-amber-800",
  FAILED: "bg-red-100 text-red-800",
};

/** The outcome of a remediation attempt. */
export function Outcome({ value }: { value: string }) {
  const style = OUTCOME_STYLE[value] ?? "bg-slate-100 text-slate-700";
  return <span className={`rounded px-1.5 py-0.5 text-xs font-semibold ${style}`}>{value}</span>;
}

/** The gate's verdict. A run without a decision, or a value that is not a verdict, reads "No decision":
 * never a PASS by default. */
export function VerdictBadge({ value }: { value: unknown }) {
  const verdict = asVerdict(value);
  if (verdict === null) {
    return <span className="rounded border border-dashed border-slate-300 px-1.5 py-0.5 text-xs text-slate-600">No decision</span>;
  }
  return <span className={`rounded px-1.5 py-0.5 text-xs font-medium ${VERDICT_STYLE[verdict]}`}>{verdict}</span>;
}
