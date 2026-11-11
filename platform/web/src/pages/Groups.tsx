import { useQuery } from "@tanstack/react-query";
import { Link, useParams } from "react-router";
import { getCorrelation, getRun, listFindings } from "../api/client";
import { alertReduction, correlationOf, type RunGroupView } from "../api/correlation";
import { asFinding, type FindingView } from "../api/finding";
import { Badge, Failure, Loading, utc } from "./common";

const MAX_FINDINGS = 500; // the API's page limit: a larger run lists its members by id

/** A run's root-cause groups (A7, SPEC section 8): which findings share one cause and one fix, from the run's
 * latest correlation. Advisory: the gate never reads them, and a group a model labelled says so. */
export function GroupsPage() {
  const { runId = "" } = useParams();
  const run = useQuery({ queryKey: ["run", runId], queryFn: () => getRun(runId) });
  const correlation = useQuery({ queryKey: ["correlation", runId], queryFn: () => getCorrelation(runId) });
  const findings = useQuery({
    queryKey: ["findings", { run_id: runId }, 0],
    queryFn: () => listFindings({ run_id: runId, limit: MAX_FINDINGS, offset: 0 }),
  });
  if (run.isPending || correlation.isPending) return <Loading />;
  if (run.isError) return <Failure error={run.error} />;
  if (correlation.isError) return <Failure error={correlation.error} />;
  const view = correlationOf(correlation.data);
  const byId = new Map<string, FindingView>(
    (findings.data?.items ?? []).map((item) => {
      const finding = asFinding(item.finding);
      return [finding.id, finding];
    }),
  );
  const shared = view?.groups.filter((group) => group.members > 1) ?? [];
  const alone = view ? view.groups.length - shared.length : 0;
  const reduction = view ? alertReduction(view.groups.length, run.data.finding_count) : null;
  return (
    <section>
      <h1 className="mb-1 text-xl font-semibold">Root-cause groups</h1>
      <p className="mb-4 text-sm text-slate-600">
        {run.data.repo} · <span className="font-mono text-xs">{run.data.commit.slice(0, 12)}</span> · {run.data.context}{" "}
        run · recorded {utc(run.data.created_at)}. Advisory: the gate never reads these groups.
      </p>
      {view === null ? (
        <p className="rounded border border-slate-200 bg-white p-4 text-sm">No correlation recorded for this run.</p>
      ) : (
        <>
          <ul className="mb-6 grid grid-cols-2 gap-3 md:grid-cols-4" aria-label="Correlation summary">
            <Stat label="Findings" value={String(run.data.finding_count)} />
            <Stat label="Groups" value={String(view.groups.length)} />
            <Stat label="Alert reduction" value={reduction === null ? "—" : `${Math.round(reduction * 100)} %`} />
            <Stat label="Correlator" value={`${view.version} · ${view.stages.join(" + ")}`} />
          </ul>
          {shared.length === 0 ? (
            <p className="text-sm text-slate-600">No two findings share a root cause in this run.</p>
          ) : (
            shared.map((group) => <Group key={group.groupId} group={group} findings={byId} />)
          )}
          {alone > 0 && <p className="mt-4 text-sm text-slate-600">{alone} finding(s) stand alone.</p>}
        </>
      )}
    </section>
  );
}

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <li className="rounded bg-white p-3 shadow-sm">
      <div className="text-xs text-slate-500">{label}</div>
      <div className="text-lg font-semibold">{value}</div>
    </li>
  );
}

function Group({ group, findings }: { group: RunGroupView; findings: Map<string, FindingView> }) {
  return (
    <article className="mb-4 rounded border border-indigo-200 bg-white p-3 text-sm" aria-label={`Group: ${group.title}`}>
      <div className="mb-1 text-xs uppercase tracking-wide text-indigo-700">
        {group.members} findings · stage {group.stage}
        {group.labelledBy === "llm" && " · written by a model"}
        {group.labelledBy === "llm" && group.model && <span className="normal-case"> ({group.model})</span>}
      </div>
      <div className="font-medium">{group.title}</div>
      <p className="mt-1">{group.rootCause}</p>
      {group.singleFix && (
        <p className="mt-1">
          <span className="font-medium">One fix: </span>
          {group.singleFix}
        </p>
      )}
      <ul className="mt-2 space-y-1" aria-label="Members">
        {group.findingIds.map((id) => {
          const finding = findings.get(id);
          return (
            <li key={id} className="flex items-center gap-2">
              {finding && <Badge value={finding.severity} />}
              <Link className="text-sky-700 hover:underline" to={`/findings/${encodeURIComponent(id)}`}>
                {finding ? finding.title : <span className="font-mono text-xs">{id.slice(0, 16)}…</span>}
              </Link>
              {finding?.path && <span className="font-mono text-xs text-slate-500">{finding.path}</span>}
            </li>
          );
        })}
      </ul>
    </article>
  );
}
