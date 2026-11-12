import { useQuery } from "@tanstack/react-query";
import { Link, useParams } from "react-router";
import { getDecision, getRun } from "../api/client";
import { asDecision } from "../api/decision";
import { Failure, Loading, utc, VerdictBadge } from "./common";

/** One run: what was scanned, its findings, and the gate's decision on them, as recorded (Decision v1). */
export function RunDetailPage() {
  const { runId = "" } = useParams();
  const run = useQuery({ queryKey: ["run", runId], queryFn: () => getRun(runId) });
  if (run.isPending) return <Loading />;
  if (run.isError) return <Failure error={run.error} />;
  const data = run.data;
  return (
    <section>
      <Link to="/runs" className="text-sm text-sky-700 hover:underline">
        ← Runs
      </Link>
      <h1 className="mt-2 flex items-center gap-3 text-xl font-semibold">
        {data.repo} @ <span className="font-mono text-base">{data.commit.slice(0, 12)}</span>
        <VerdictBadge value={data.verdict} />
      </h1>
      <dl className="mt-3 grid grid-cols-[max-content_1fr] gap-x-4 gap-y-1 text-sm">
        <dt className="text-slate-500">Context</dt>
        <dd>{data.context}</dd>
        <dt className="text-slate-500">Ref</dt>
        <dd className="font-mono text-xs">{data.ref ?? "—"}</dd>
        <dt className="text-slate-500">Commit</dt>
        <dd className="break-all font-mono text-xs">{data.commit}</dd>
        <dt className="text-slate-500">CI run</dt>
        <dd>{data.run_id ?? "—"}</dd>
        <dt className="text-slate-500">Recorded</dt>
        <dd>{utc(data.created_at)}</dd>
        <dt className="text-slate-500">Findings</dt>
        <dd>
          {data.findings_sha256 === null ? (
            "not uploaded yet"
          ) : (
            <>
              <Link className="text-sky-700 hover:underline" to={`/findings?run_id=${encodeURIComponent(data.id)}`}>
                {data.finding_count} finding(s)
              </Link>
              <span className="ml-2 break-all font-mono text-xs text-slate-500">sha256:{data.findings_sha256}</span>
            </>
          )}
        </dd>
      </dl>
      <Decision runId={data.id} />
    </section>
  );
}

function Decision({ runId }: { runId: string }) {
  const decision = useQuery({ queryKey: ["decision", runId], queryFn: () => getDecision(runId) });
  if (decision.isPending) return <Loading />;
  if (decision.isError) return <Failure error={decision.error} />;
  if (decision.data === null) {
    return (
      <section aria-label="Decision" className="mt-6 rounded border border-dashed border-slate-300 p-3 text-sm">
        <h2 className="font-medium">No decision recorded</h2>
        <p className="mt-1 text-slate-600">
          The gate's decision has not been uploaded for this run. This is not a PASS: nothing is known about it.
        </p>
      </section>
    );
  }
  const view = asDecision(decision.data);
  return (
    <section aria-label="Decision" className="mt-6">
      <h2 className="mb-2 flex items-center gap-2 font-medium">
        Gate decision <VerdictBadge value={view.verdict} />
      </h2>
      <dl className="grid grid-cols-[max-content_1fr] gap-x-4 gap-y-1 text-sm">
        <dt className="text-slate-500">Evaluated</dt>
        <dd>{view.evaluatedAt ? utc(view.evaluatedAt) : "—"}</dd>
        <dt className="text-slate-500">Engine</dt>
        <dd>{view.engineVersion ?? "—"}</dd>
        <dt className="text-slate-500">Decision</dt>
        <dd className="break-all font-mono text-xs">{view.decisionId}</dd>
        <dt className="text-slate-500">Waivers applied</dt>
        <dd>{view.waiversApplied.length ? view.waiversApplied.join(", ") : "none"}</dd>
      </dl>
      <h3 className="mb-2 mt-4 text-sm font-medium">Violations</h3>
      {view.violations.length === 0 ? (
        <p className="text-sm text-slate-600">None.</p>
      ) : (
        <ul className="space-y-2 text-sm">
          {view.violations.map((violation, index) => (
            <li key={`${violation.rule}-${index}`} className="rounded bg-white p-2">
              <span className="font-mono text-xs">{violation.rule}</span>{" "}
              <span className="rounded bg-slate-100 px-1.5 py-0.5 text-xs font-medium">{violation.effect || "—"}</span>{" "}
              {violation.message}
              {violation.findingIds.length > 0 && (
                <div className="mt-1 flex flex-wrap gap-2">
                  {violation.findingIds.map((id) => (
                    <Link key={id} className="font-mono text-xs text-sky-700 hover:underline"
                      to={`/findings/${encodeURIComponent(id)}`}>
                      {id.slice(0, 12)}
                    </Link>
                  ))}
                </div>
              )}
            </li>
          ))}
        </ul>
      )}
      <details className="mt-4 text-sm">
        <summary className="cursor-pointer text-slate-600">Inputs (the evidence the decision was made on)</summary>
        <dl className="mt-2 grid grid-cols-[max-content_1fr] gap-x-4 gap-y-1">
          {view.inputs.map(([name, value]) => (
            <div key={name} className="contents">
              <dt className="text-slate-500">{name}</dt>
              <dd className="break-all font-mono text-xs">{value}</dd>
            </div>
          ))}
        </dl>
      </details>
    </section>
  );
}
