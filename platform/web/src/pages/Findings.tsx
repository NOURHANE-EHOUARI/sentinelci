import { useQuery } from "@tanstack/react-query";
import { Link, useSearchParams } from "react-router";
import { listFindings } from "../api/client";
import { CATEGORIES, SEVERITIES, asFinding } from "../api/finding";
import { Badge, Failure, Loading } from "./common";

export const PAGE_SIZE = 50;

/** Findings as each run reported them, newest run first, filtered in the URL (so a view can be shared). */
export function FindingsPage() {
  const [params, setParams] = useSearchParams();
  const filters = {
    category: params.get("category") ?? undefined,
    severity: params.get("severity") ?? undefined,
    tool: params.get("tool") ?? undefined,
    repo: params.get("repo") ?? undefined,
    run_id: params.get("run_id") ?? undefined,
  };
  const offset = Math.max(0, Number(params.get("offset") ?? 0) || 0);
  const page = useQuery({
    queryKey: ["findings", filters, offset],
    queryFn: () => listFindings({ ...filters, limit: PAGE_SIZE, offset }),
  });

  function set(key: string, value: string) {
    const next = new URLSearchParams(params);
    if (value) next.set(key, value);
    else next.delete(key);
    next.delete("offset");
    setParams(next);
  }

  function goTo(nextOffset: number) {
    const next = new URLSearchParams(params);
    next.set("offset", String(nextOffset));
    setParams(next);
  }

  return (
    <section>
      <h1 className="mb-4 text-xl font-semibold">Findings</h1>
      <div className="mb-4 flex flex-wrap gap-3 text-sm">
        <Select label="Category" value={filters.category} options={CATEGORIES} onChange={(v) => set("category", v)} />
        <Select label="Severity" value={filters.severity} options={SEVERITIES} onChange={(v) => set("severity", v)} />
        {filters.run_id && (
          <button className="rounded border bg-white px-2 py-1" onClick={() => set("run_id", "")}>
            Run {filters.run_id.slice(0, 8)} ✕
          </button>
        )}
      </div>
      {page.isPending ? (
        <Loading />
      ) : page.isError ? (
        <Failure error={page.error} />
      ) : page.data.items.length === 0 ? (
        <p className="text-sm text-slate-600">No finding matches.</p>
      ) : (
        <>
          <table className="w-full border-collapse bg-white text-sm">
            <thead>
              <tr className="border-b text-left text-slate-500">
                <th className="p-2">Severity</th>
                <th className="p-2">Priority</th>
                <th className="p-2">Finding</th>
                <th className="p-2">Rule</th>
                <th className="p-2">Where</th>
              </tr>
            </thead>
            <tbody>
              {page.data.items.map((item) => {
                const finding = asFinding(item.finding);
                return (
                  <tr key={`${item.run_id}/${finding.id}`} className="border-b align-top">
                    <td className="p-2">
                      <Badge value={finding.severity} />
                    </td>
                    <td className="p-2">{finding.priority ?? "—"}</td>
                    <td className="p-2">
                      <Link className="text-sky-700 hover:underline" to={`/findings/${finding.id}`}>
                        {finding.title}
                      </Link>
                      <div className="text-xs text-slate-500">{finding.category}</div>
                    </td>
                    <td className="p-2 font-mono text-xs">
                      {finding.tool} {finding.ruleId}
                    </td>
                    <td className="p-2 font-mono text-xs">
                      {finding.path ?? "—"}
                      {finding.line !== null ? `:${finding.line}` : ""}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
          <div className="mt-3 flex items-center gap-3 text-sm">
            <span>
              {offset + 1}–{offset + page.data.items.length} of {page.data.total}
            </span>
            <button className="rounded border px-2 py-1 disabled:opacity-40" disabled={offset === 0}
              onClick={() => goTo(Math.max(0, offset - PAGE_SIZE))}>
              Previous
            </button>
            <button className="rounded border px-2 py-1 disabled:opacity-40"
              disabled={offset + PAGE_SIZE >= page.data.total} onClick={() => goTo(offset + PAGE_SIZE)}>
              Next
            </button>
          </div>
        </>
      )}
    </section>
  );
}

function Select(props: {
  label: string;
  value: string | undefined;
  options: readonly string[];
  onChange: (value: string) => void;
}) {
  return (
    <label className="flex items-center gap-2">
      {props.label}
      <select className="rounded border bg-white px-2 py-1" value={props.value ?? ""}
        onChange={(event) => props.onChange(event.target.value)}>
        <option value="">All</option>
        {props.options.map((option) => (
          <option key={option} value={option}>
            {option}
          </option>
        ))}
      </select>
    </label>
  );
}
