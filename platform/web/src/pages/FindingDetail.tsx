import { useQuery } from "@tanstack/react-query";
import { Link, useParams } from "react-router";
import { getCorrelation, getExplanation, getFinding } from "../api/client";
import { groupOf } from "../api/correlation";
import { asExplanation, referenceLink } from "../api/explanation";
import { asFinding } from "../api/finding";
import { Badge, Failure, Loading, utc } from "./common";

/** One finding (its fingerprint): as the latest run reported it, where else it was seen, its root-cause group in
 * that run's correlation, and its latest explanation (both advisory). */
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
      <Explanation findingId={finding.id} secret={finding.category === "SECRET"} />
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

/** The finding's latest explanation (B5c): advisory, written by a model, never read by the gate. */
function Explanation({ findingId, secret }: { findingId: string; secret: boolean }) {
  const explanation = useQuery({
    queryKey: ["explanation", findingId],
    queryFn: () => getExplanation(findingId),
    enabled: !secret,
  });
  let body;
  if (secret) {
    body = <p>A secret&apos;s finding is never sent to a model: rotate the secret.</p>;
  } else if (explanation.isPending) {
    body = <Loading />;
  } else if (explanation.isError) {
    body = <Failure error={explanation.error} />;
  } else if (explanation.data === null) {
    body = (
      <p>
        No explanation recorded. An operator asks for one with <code>{`POST /api/v1/findings/${findingId}/explain`}</code>{" "}
        (the ingestion token): the dashboard never asks.
      </p>
    );
  } else {
    const view = asExplanation(explanation.data);
    if (view.findingId !== findingId) {
      body = <p>The recorded explanation is about another finding: not shown.</p>;
    } else {
      const fields: [string, string | null][] = [
        ["Impact", view.impact],
        ["How it would be exploited", view.exploitScenario],
        ["How to fix it", view.fixGuidance],
      ];
      body = (
        <>
          <p className="font-medium">{view.summary ?? "—"}</p>
          <dl className="mt-2 space-y-2">
            {fields.map(([label, value]) => (
              <div key={label}>
                <dt className="text-xs font-medium text-slate-600">{label}</dt>
                <dd>{value ?? "—"}</dd>
              </div>
            ))}
          </dl>
          {view.references.length > 0 && (
            <ul className="mt-2 flex flex-wrap gap-x-3 text-xs">
              {view.references.map((reference) => {
                const href = referenceLink(reference);
                return (
                  <li key={reference} className="break-all">
                    {href ? (
                      <a className="text-sky-700 hover:underline" href={href} rel="noreferrer noopener">
                        {reference}
                      </a>
                    ) : (
                      reference
                    )}
                  </li>
                );
              })}
            </ul>
          )}
          <p className="mt-2 text-xs text-slate-500">
            {view.provider ?? "—"} {view.modelName ?? "—"}
            {view.modelDigest && ` (${view.modelDigest.slice(0, 19)}…)`} · confidence{" "}
            {view.confidence === null ? "—" : `${Math.round(view.confidence * 100)} %`} · {utc(view.createdAt)}
          </p>
        </>
      );
    }
  }
  return (
    <aside className="mt-4 rounded border border-violet-200 bg-violet-50 p-3 text-sm" aria-label="Explanation">
      <div className="mb-1 text-xs uppercase tracking-wide text-violet-700">
        Explanation · Advisory: written by a model, never read by the gate
      </div>
      {body}
    </aside>
  );
}
