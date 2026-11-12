import { useQuery } from "@tanstack/react-query";
import { Link, useParams, useSearchParams } from "react-router";
import { getReleaseEvidence } from "../api/client";
import { asRelease, releaseTrust, type TrustReportView } from "../api/release";
import { Failure, Loading, Trust, utc, Verdict } from "./common";

const MODE: Record<string, string> = {
  registry: "In the registry (what Kyverno checks at admission)",
  evidence: "From the evidence bundles (offline)",
};

/** One release: the gate's decision and the inputs it recorded, then each trust report, check by check. */
export function ReleaseDetailPage() {
  const { imageDigest = "" } = useParams();
  const [params] = useSearchParams();
  const decision = params.get("decision") ?? undefined;
  const evidence = useQuery({
    queryKey: ["release", imageDigest, decision],
    queryFn: () => getReleaseEvidence(imageDigest, decision),
  });
  if (evidence.isPending) return <Loading />;
  if (evidence.isError) return <Failure error={evidence.error} />;
  const release = asRelease(evidence.data);
  const trusted = releaseTrust(release);
  return (
    <section>
      <Link to="/releases" className="text-sm text-sky-700 hover:underline">
        ← Releases
      </Link>
      <h1 className="mt-2 break-all font-mono text-base font-semibold">{release.imageDigest}</h1>
      <div className="mt-1 flex flex-wrap items-center gap-3 text-sm text-slate-600">
        <Verdict value={release.verdict} />
        <Trust trusted={trusted} verdict={release.verdict} />
        <span>{release.repo}</span>
        <span className="font-mono text-xs">{release.commit}</span>
        {release.ref && <span className="font-mono text-xs">{release.ref}</span>}
        <span>decided {utc(release.evaluatedAt)}</span>
      </div>

      <h2 className="mb-2 mt-6 font-medium">Decision</h2>
      {release.violations.length === 0 ? (
        <p className="text-sm text-slate-600">No rule fired.</p>
      ) : (
        <ul className="space-y-1 text-sm" aria-label="Rules that fired">
          {release.violations.map((violation) => (
            <li key={`${violation.rule}-${violation.effect}`} className="rounded bg-white p-2">
              <span className="font-mono text-xs">{violation.rule}</span> <Verdict value={violation.effect} />{" "}
              {violation.message} <span className="text-xs text-slate-500">({violation.findings} finding(s))</span>
            </li>
          ))}
        </ul>
      )}
      <dl className="mt-3 grid grid-cols-[max-content_1fr] gap-x-4 gap-y-1 text-sm">
        <dt className="text-slate-500">Decision</dt>
        <dd className="font-mono text-xs">{release.decisionId}</dd>
        {release.inputs.map(([name, value]) => (
          <div key={name} className="contents">
            <dt className="text-slate-500">{name.replaceAll("_", " ")}</dt>
            <dd className="break-all font-mono text-xs">{value}</dd>
          </div>
        ))}
        <dt className="text-slate-500">Scanners</dt>
        <dd className="text-xs">
          {release.toolVersions.map(([tool, version]) => `${tool} ${version}`).join(" · ") || "—"}
        </dd>
        <dt className="text-slate-500">Waivers applied</dt>
        <dd className="text-xs">{release.waiversApplied.join(", ") || "none"}</dd>
      </dl>

      <h2 className="mb-2 mt-6 font-medium">Verification</h2>
      {release.unreadableReports > 0 && (
        <p className="mb-2 text-sm text-red-700">
          {release.unreadableReports} trust report(s) could not be read: the release is not shown as trusted.
        </p>
      )}
      {release.reports.length === 0 ? (
        <p className="text-sm text-slate-600">
          No trust report: {release.verdict === "BLOCK" ? "the gate blocked this image, so nothing was signed." : "none was recorded."}
        </p>
      ) : (
        release.reports.map((report) => <Report key={report.mode} report={report} />)
      )}
    </section>
  );
}

function Report({ report }: { report: TrustReportView }) {
  const passed = report.checks.filter((check) => check.ok).length;
  return (
    <article className="mb-4 rounded border border-slate-200 bg-white p-3" aria-label={`Trust report: ${report.mode}`}>
      <div className="mb-2 flex flex-wrap items-center gap-3 text-sm">
        <span className="font-medium">{MODE[report.mode] ?? report.mode}</span>
        <Trust trusted={report.trusted} />
        <span className="text-slate-500">
          {passed}/{report.checks.length} checks · {utc(report.verifiedAt)}
        </span>
      </div>
      <div className="mb-2 text-xs text-slate-500">
        Key{" "}
        <span className="font-mono" title={report.keySha256}>
          {report.keySha256.slice(0, 16)}…
        </span>{" "}
        · builder{" "}
        <span className="break-all font-mono">{report.builderId}</span>
      </div>
      <table className="w-full border-collapse text-sm">
        <tbody>
          {report.checks.map((check) => (
            <tr key={check.name} className="border-t align-top">
              <td className={`w-12 p-1 text-xs font-semibold ${check.ok ? "text-emerald-700" : "text-red-700"}`}>
                {check.ok ? "ok" : "FAIL"}
              </td>
              <td className="p-1">{check.name}</td>
              <td className="break-all p-1 font-mono text-xs text-slate-600">{check.detail}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </article>
  );
}
