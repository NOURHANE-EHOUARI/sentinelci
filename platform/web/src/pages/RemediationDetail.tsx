import { useQuery } from "@tanstack/react-query";
import { Link, useParams } from "react-router";
import { getRemediation } from "../api/client";
import { asAttempt } from "../api/remediation";
import { Failure, Loading, Outcome, utc, Verdict } from "./common";

/** One attempt: the verification gate's conditions, then the proposal (rationale, files, the diff as text). */
export function RemediationDetailPage() {
  const { proposalId = "" } = useParams();
  const attempt = useQuery({ queryKey: ["remediation", proposalId], queryFn: () => getRemediation(proposalId) });
  if (attempt.isPending) return <Loading />;
  if (attempt.isError) return <Failure error={attempt.error} />;
  const view = asAttempt(attempt.data);
  return (
    <section>
      <Link to="/remediations" className="text-sm text-sky-700 hover:underline">
        ← Remediation
      </Link>
      <h1 className="mt-2 flex flex-wrap items-center gap-3 text-xl font-semibold">
        <Outcome value={view.outcome} />
        <span className="font-mono text-base">{view.strategy}</span>
      </h1>
      <div className="mt-1 flex flex-wrap items-center gap-3 text-sm text-slate-600">
        <span>{view.repo}</span>
        <span>attempt {view.attempt ?? "—"} of 3</span>
        <span>{view.pullRequest === null ? "no pull request" : `pull request #${view.pullRequest}`}</span>
        <span>proposed {utc(view.proposedAt)}</span>
        <span>verified {utc(view.verifiedAt)}</span>
      </div>
      {view.model && (
        <p className="mt-3 rounded border border-indigo-200 bg-indigo-50 p-2 text-sm">
          Written by a model ({view.model}). Advisory: only the verification gate below decides, and a person
          reviews the pull request.
        </p>
      )}

      <h2 className="mb-2 mt-6 font-medium">Verification gate</h2>
      <ul className="space-y-1 text-sm" aria-label="Verification gate">
        {view.conditions.map((condition) => (
          <li key={condition.name} className="flex items-center gap-2">
            <span className={`w-10 text-xs font-semibold ${condition.ok ? "text-emerald-700" : "text-red-700"}`}>
              {condition.ok ? "ok" : "FAIL"}
            </span>
            {condition.name}
          </li>
        ))}
      </ul>
      <p className="mt-2 text-sm text-slate-600">
        Gate verdict on the patched commit: <Verdict value={view.verdict} />
      </p>

      <h2 className="mb-2 mt-6 font-medium">Proposal</h2>
      <p className="whitespace-pre-wrap rounded bg-white p-3 text-sm">{view.rationale}</p>
      <dl className="mt-3 grid grid-cols-[max-content_1fr] gap-x-4 gap-y-1 text-sm">
        <dt className="text-slate-500">Findings</dt>
        <dd>
          {view.findingIds.map((id) => (
            <Link key={id} to={`/findings/${encodeURIComponent(id)}`} className="mr-2 font-mono text-xs text-sky-700 hover:underline">
              {id.slice(0, 12)}…
            </Link>
          ))}
        </dd>
        <dt className="text-slate-500">Files</dt>
        <dd className="font-mono text-xs">{view.files.join(", ")}</dd>
        <dt className="text-slate-500">Proposal</dt>
        <dd className="font-mono text-xs">{view.proposalId}</dd>
      </dl>
      <pre className="mt-3 overflow-x-auto rounded bg-slate-900 p-3 text-xs text-slate-100" aria-label="Diff">
        {view.diff}
      </pre>
    </section>
  );
}
