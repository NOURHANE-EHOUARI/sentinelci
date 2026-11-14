import { useQuery } from "@tanstack/react-query";
import { Link, useParams } from "react-router";
import { getCorrelation, getFinding } from "../api/client";
import { groupOf } from "../api/correlation";
import { asFinding } from "../api/finding";
import { Badge, Failure, Loading } from "./common";

/** One finding (its fingerprint): as the latest run reported it, where else it was seen, and its root-cause
 * group in that run's correlation (advisory). */
export function FindingDetailPage() {
  const { findingId = "" } = useParams();
  const detail = useQuery({ queryKey: ["finding", findingId], queryFn: () => getFinding(findingId) });
  if (detail.isPending) return <Loading />;
  if (detail.isError) return <Failure error={detail.error} />;
  const finding = asFinding(detail.data.finding);
  const latest = detail.data.occurrences[0];
  return (
    <section>
      <Link to="/findings" className="text-sm text-sky-700 hover:underline">
        ← Findings
      </Link>
      <h1 className="mt-2 text-xl font-semibold">{finding.title}</h1>
      <div className="mt-1 flex flex-wrap items-center gap-3 text-sm text-slate-600">
        <Badge value={finding.severity} />
        <span>{finding.category}</span>
        <span>Priority {finding.priority ?? "—"}{finding.score !== null ? ` (score ${finding.score})` : ""}</span>
        <span className="font-mono text-xs">{finding.tool} {finding.ruleId}</span>
      </div>
      {finding.message && <p className="mt-3 whitespace-pre-wrap rounded bg-white p-3 text-sm">{finding.message}</p>}
      <dl className="mt-3 grid grid-cols-[max-content_1fr] gap-x-4 gap-y-1 text-sm">
        <dt className="text-slate-500">Where</dt>
        <dd className="font-mono text-xs">{finding.path ?? "—"}{finding.line !== null ? `:${finding.line}` : ""}</dd>
        <dt className="text-slate-500">CVE</dt>
        <dd>{finding.cves.length ? finding.cves.join(", ") : "—"}</dd>
        <dt className="text-slate-500">Fingerprint</dt>
        <dd className="break-all font-mono text-xs">{finding.id}</dd>
      </dl>
      {latest && <Group runId={latest.run_id} findingId={finding.id} />}
      <h2 className="mb-2 mt-6 font-medium">Seen in {detail.data.occurrence_count} run(s)</h2>
      <table className="w-full border-collapse bg-white text-sm">
        <thead>
          <tr className="border-b text-left text-slate-500">
            <th className="p-2">Repository</th>
            <th className="p-2">Commit</th>
            <th className="p-2">Context</th>
            <th className="p-2">Recorded</th>
          </tr>
        </thead>
        <tbody>
          {detail.data.occurrences.map((run) => (
            <tr key={run.run_id} className="border-b">
              <td className="p-2">{run.repo}</td>
              <td className="p-2 font-mono text-xs">{run.commit.slice(0, 12)}</td>
              <td className="p-2">{run.context}</td>
              <td className="p-2">{new Date(run.created_at).toISOString().slice(0, 16).replace("T", " ")} UTC</td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  );
}

function Group({ runId, findingId }: { runId: string; findingId: string }) {
  const correlation = useQuery({ queryKey: ["correlation", runId], queryFn: () => getCorrelation(runId) });
  if (correlation.isPending || correlation.isError) return null;
  const group = groupOf(correlation.data, findingId);
  if (group === null || group.members < 2) return null; // a group of one adds nothing to the finding
  return (
    <aside className="mt-4 rounded border border-indigo-200 bg-indigo-50 p-3 text-sm" aria-label="Root-cause group">
      <div className="mb-1 text-xs uppercase tracking-wide text-indigo-700">
        Root-cause group · {group.members} finding(s) · advisory, never part of the gate
        {group.labelledBy === "llm" && " · written by a model"}
      </div>
      <div className="font-medium">{group.title}</div>
      <p className="mt-1">{group.rootCause}</p>
      {group.singleFix && <p className="mt-1"><span className="font-medium">One fix: </span>{group.singleFix}</p>}
      <Link to={`/runs/${encodeURIComponent(runId)}/groups`} className="mt-2 inline-block text-xs text-sky-700 hover:underline">
        Every group of this run →
      </Link>
    </aside>
  );
}
