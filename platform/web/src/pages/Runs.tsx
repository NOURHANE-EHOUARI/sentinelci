import { useQuery } from "@tanstack/react-query";
import { Link, useSearchParams } from "react-router";
import { listRuns } from "../api/client";
import { Failure, Loading, utc, VerdictBadge } from "./common";

export const PAGE_SIZE = 50;
const CONTEXTS = ["pr", "release", "local"] as const;

/** Recorded runs, newest first, with the gate's verdict: "No decision" until one is recorded, never a PASS. */
export function RunsPage() {
  const [params, setParams] = useSearchParams();
  const filters = {
    repo: params.get("repo") ?? undefined,
    context: params.get("context") ?? undefined,
    ref: params.get("ref") ?? undefined,
  };
  const offset = Math.max(0, Math.floor(Number(params.get("offset") ?? 0)) || 0);
  const page = useQuery({
    queryKey: ["runs", filters, offset],
    queryFn: () => listRuns({ ...filters, limit: PAGE_SIZE, offset }),
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
      <h1 className="mb-4 text-xl font-semibold">Runs</h1>
      <div className="mb-4 flex flex-wrap gap-3 text-sm">
        <label className="flex items-center gap-2">
          Context
          <select className="rounded border bg-white px-2 py-1" value={filters.context ?? ""}
            onChange={(event) => set("context", event.target.value)}>
            <option value="">All</option>
            {CONTEXTS.map((context) => (
              <option key={context} value={context}>
                {context}
              </option>
            ))}
          </select>
        </label>
        {filters.repo && (
          <button className="rounded border bg-white px-2 py-1" onClick={() => set("repo", "")}>
            {filters.repo} ✕
          </button>
        )}
        {filters.ref && (
          <button className="rounded border bg-white px-2 py-1 font-mono text-xs" onClick={() => set("ref", "")}>
            {filters.ref} ✕
          </button>
        )}
      </div>
      {page.isPending ? (
        <Loading />
      ) : page.isError ? (
        <Failure error={page.error} />
      ) : page.data.items.length === 0 ? (
        <p className="text-sm text-slate-600">No run matches.</p>
      ) : (
        <>
          <table className="w-full border-collapse bg-white text-sm">
            <thead>
              <tr className="border-b text-left text-slate-500">
                <th className="p-2">Verdict</th>
                <th className="p-2">Run</th>
                <th className="p-2">Context</th>
                <th className="p-2">Ref</th>
                <th className="p-2">Findings</th>
                <th className="p-2">Recorded</th>
              </tr>
            </thead>
            <tbody>
              {page.data.items.map((run) => (
                <tr key={run.id} className="border-b align-top">
                  <td className="p-2">
                    <VerdictBadge value={run.verdict} />
                  </td>
                  <td className="p-2">
                    <Link className="text-sky-700 hover:underline" to={`/runs/${encodeURIComponent(run.id)}`}>
                      {run.repo} @ <span className="font-mono text-xs">{run.commit.slice(0, 12)}</span>
                    </Link>
                    {run.run_id && <div className="text-xs text-slate-500">CI run {run.run_id}</div>}
                  </td>
                  <td className="p-2">{run.context}</td>
                  <td className="p-2 font-mono text-xs">{run.ref ?? "—"}</td>
                  <td className="p-2">{run.findings_sha256 === null ? "not uploaded" : run.finding_count}</td>
                  <td className="p-2">{utc(run.created_at)}</td>
                </tr>
              ))}
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
