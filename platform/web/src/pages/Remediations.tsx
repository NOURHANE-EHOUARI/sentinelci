import { useQuery } from "@tanstack/react-query";
import { Link, useSearchParams } from "react-router";
import { getMetrics, listRemediations } from "../api/client";
import { remediationAttempts, successByStrategy } from "../metrics";
import { Failure, Loading, Outcome, utc } from "./common";

export const PAGE_SIZE = 50;
const STRATEGIES = ["deterministic:dependency-bump", "deterministic:dockerfile", "deterministic:kubernetes", "llm:code"];
const OUTCOMES = ["VERIFIED", "REJECTED", "FAILED"];

/** Every attempt of the remediation loop the platform recorded, newest first, and its success per strategy
 * (SPEC section 10). A VERIFIED attempt is a pull request a person still reviews: the bot never merges. */
export function RemediationsPage() {
  const [params, setParams] = useSearchParams();
  const strategy = params.get("strategy") ?? undefined;
  const outcome = params.get("outcome") ?? undefined;
  const offset = Math.max(0, Math.floor(Number(params.get("offset") ?? 0)) || 0);
  const page = useQuery({
    queryKey: ["remediations", strategy, outcome, offset],
    queryFn: () => listRemediations({ strategy, outcome, limit: PAGE_SIZE, offset }),
  });
  const metrics = useQuery({ queryKey: ["metrics"], queryFn: getMetrics });
  const counts = metrics.data === undefined ? null : remediationAttempts(metrics.data);

  function set(key: string, value: string | null) {
    const next = new URLSearchParams(params);
    if (value) next.set(key, value);
    else next.delete(key);
    if (key !== "offset") next.delete("offset");
    setParams(next);
  }

  return (
    <section>
      <h1 className="mb-1 text-xl font-semibold">Remediation</h1>
      <p className="mb-4 text-sm text-slate-600">
        Each fix the remediation loop proposed, and what its verification gate found. A verified fix is a pull
        request a person reviews and merges: the bot never merges.
      </p>
      {counts && (
        <ul className="mb-6 grid grid-cols-2 gap-3 md:grid-cols-4" aria-label="Remediation success">
          {[...successByStrategy(counts)].map(([name, total]) => (
            <li key={name} className="rounded bg-white p-3 shadow-sm">
              <div className="text-xs text-slate-500">{name}</div>
              <div className="text-lg font-semibold">{Math.round((100 * total.verified) / total.attempted)} %</div>
              <div className="text-xs text-slate-500">
                {total.verified} verified of {total.attempted}
              </div>
            </li>
          ))}
        </ul>
      )}
      <div className="mb-4 flex flex-wrap gap-3 text-sm">
        <Choice label="Strategy" value={strategy} options={STRATEGIES} onChange={(v) => set("strategy", v)} />
        <Choice label="Outcome" value={outcome} options={OUTCOMES} onChange={(v) => set("outcome", v)} />
      </div>
      {page.isPending ? (
        <Loading />
      ) : page.isError ? (
        <Failure error={page.error} />
      ) : page.data.items.length === 0 ? (
        <p className="rounded border border-slate-200 bg-white p-4 text-sm">No attempt recorded yet.</p>
      ) : (
        <>
          <table className="w-full border-collapse bg-white text-sm">
            <thead>
              <tr className="border-b text-left text-slate-500">
                <th className="p-2">Outcome</th>
                <th className="p-2">Strategy</th>
                <th className="p-2">Attempt</th>
                <th className="p-2">Findings</th>
                <th className="p-2">Pull request</th>
                <th className="p-2">Repository</th>
                <th className="p-2">Verified</th>
              </tr>
            </thead>
            <tbody>
              {page.data.items.map((item) => (
                <tr key={item.proposal_id} className="border-b">
                  <td className="p-2">
                    <Link className="hover:underline" to={`/remediations/${encodeURIComponent(item.proposal_id)}`}>
                      <Outcome value={item.outcome} />
                    </Link>
                  </td>
                  <td className="p-2 font-mono text-xs">{item.strategy}</td>
                  <td className="p-2">{item.attempt} of 3</td>
                  <td className="p-2">{item.finding_count}</td>
                  <td className="p-2">{item.pull_request === null ? "—" : `#${item.pull_request}`}</td>
                  <td className="p-2">{item.repo}</td>
                  <td className="p-2">{utc(item.verified_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <div className="mt-3 flex items-center gap-3 text-sm">
            <span>
              {offset + 1}–{offset + page.data.items.length} of {page.data.total}
            </span>
            <button className="rounded border px-2 py-1 disabled:opacity-40" disabled={offset === 0}
              onClick={() => set("offset", String(Math.max(0, offset - PAGE_SIZE)))}>
              Previous
            </button>
            <button className="rounded border px-2 py-1 disabled:opacity-40"
              disabled={offset + PAGE_SIZE >= page.data.total} onClick={() => set("offset", String(offset + PAGE_SIZE))}>
              Next
            </button>
          </div>
        </>
      )}
    </section>
  );
}

function Choice(props: { label: string; value: string | undefined; options: string[]; onChange: (value: string) => void }) {
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
