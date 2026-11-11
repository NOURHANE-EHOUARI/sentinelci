import { ApiError } from "../api/client";

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
