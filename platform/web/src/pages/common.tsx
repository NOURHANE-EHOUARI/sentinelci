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

/** The gate's verdict. A run without a decision, or a value that is not a verdict, reads "No decision":
 * never a PASS by default. */
export function VerdictBadge({ value }: { value: unknown }) {
  const verdict = asVerdict(value);
  if (verdict === null) {
    return <span className="rounded border border-dashed border-slate-300 px-1.5 py-0.5 text-xs text-slate-600">No decision</span>;
  }
  return <span className={`rounded px-1.5 py-0.5 text-xs font-medium ${VERDICT_STYLE[verdict]}`}>{verdict}</span>;
}

/** A timestamp as UTC, to the minute; "—" when there is none or it cannot be read (never a blank page). The same
 * as A8's (#86), so the two merge as one. */
export function utc(value: string | null): string {
  if (value === null) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "—" : `${date.toISOString().slice(0, 16).replace("T", " ")} UTC`;
}
