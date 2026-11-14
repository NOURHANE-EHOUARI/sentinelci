import { useQueries, useQuery } from "@tanstack/react-query";
import { Link } from "react-router";
import { getReleaseEvidence, listReleases } from "../api/client";
import { asRelease, type TrustReportView } from "../api/release";
import { Digest, Failure, Loading, Verdict } from "./common";

const RECENT = 20;
// The checks of `sentinel verify` (supplychain/verify.py) by what they show a release carries. A column holds its
// signature check, every check its listed checks name, and every other check whose name starts with its prefix:
// a check verify adds later is read too, never skipped.
export const COLUMNS: { label: string; prefix: string | null; checks: string[] }[] = [
  { label: "Signed image", prefix: null, checks: ["signature: the image itself"] },
  {
    label: "Decision",
    prefix: "decision: ",
    checks: ["signature: release decision", "decision: valid Decision v1", "decision: release context",
      "decision: verdict is not BLOCK", "decision: about this image", "decision: from the expected repository"],
  },
  { label: "SBOM", prefix: "SBOM: ", checks: ["signature: SBOM (CycloneDX)", "SBOM: the one the vulnerability scan names"] },
  {
    label: "Vulnerability scan",
    prefix: "vulnerability scan: ",
    checks: ["signature: vulnerability scan", "vulnerability scan: names this decision",
      "vulnerability scan: the decision's findings", "vulnerability scan: the decision's SBOM"],
  },
  {
    label: "Provenance",
    prefix: "provenance: ",
    checks: ["signature: provenance (SLSA v1)", "provenance: built by the expected workflow",
      "provenance: built from the decision's commit"],
  },
];

function inColumn(column: (typeof COLUMNS)[number], name: string): boolean {
  return column.checks.includes(name) || (column.prefix !== null && name.startsWith(column.prefix));
}

/** The report a release is judged on here: the registry mode's, which is what Kyverno checks at admission. */
export function registryReport(reports: TrustReportView[]): TrustReportView | null {
  return reports.find((report) => report.mode === "registry") ?? null;
}

/** Each column for one report: all its listed checks present and every check of the column passed (true), a
 * check of it failed or is missing (false), or none of its checks was run (null). */
export function carried(report: TrustReportView | null): (boolean | null)[] {
  return COLUMNS.map((column) => {
    if (report === null) return null;
    const found = report.checks.filter((check) => inColumn(column, check.name));
    if (found.length === 0) return null;
    const listed = column.checks.every((name) => found.some((check) => check.name === name));
    return listed && found.every((check) => check.ok);
  });
}

/** What Kyverno would admit: a report verify trusted, with every column carried. */
export function complete(report: TrustReportView | null): boolean {
  return report !== null && report.trusted === true && carried(report).every((value) => value === true);
}

/** What each recent release carries: its signature and four attestations, as `sentinel verify` found them in the
 * registry. SPEC section 10's policy compliance counts running images; the platform does not see the cluster,
 * so this counts releases, and Kyverno decides what runs. */
export function SupplyChainPage() {
  const releases = useQuery({ queryKey: ["releases", undefined, 0, RECENT], queryFn: () => listReleases({ limit: RECENT }) });
  const evidence = useQueries({
    queries: (releases.data?.items ?? []).map((release) => ({
      queryKey: ["release", release.image_digest, release.decision_id],
      queryFn: () => getReleaseEvidence(release.image_digest, release.decision_id),
    })),
  });
  if (releases.isPending) return <Loading />;
  if (releases.isError) return <Failure error={releases.error} />;
  const rows = releases.data.items.map((release, index) => {
    const query = evidence[index];
    const report = query?.isSuccess ? registryReport(asRelease(query.data).reports) : null;
    return { release, state: query?.isSuccess ? "read" : query?.isError ? "failed" : "loading", report };
  });
  const passed = rows.filter((row) => row.release.verdict !== "BLOCK");
  // Unknown is not zero: the count waits for every release's evidence, and a failed request leaves it unknown.
  const known = rows.every((row) => row.state === "read");
  const carrying = passed.filter((row) => complete(row.report));
  return (
    <section>
      <h1 className="mb-1 text-xl font-semibold">Supply chain</h1>
      <p className="mb-4 text-sm text-slate-600">
        What the {RECENT} latest releases carry, as <code>sentinel verify</code> found it in the registry: the image's
        signature and its four attestations. Kyverno admits only an image that carries all of them.
      </p>
      {rows.length === 0 ? (
        <p className="rounded border border-slate-200 bg-white p-4 text-sm">No release recorded yet.</p>
      ) : (
        <>
          <p className="mb-4 rounded bg-white p-3 text-sm shadow-sm" aria-label="Compliance">
            <span className="text-lg font-semibold">{known ? `${carrying.length} of ${passed.length}` : "—"}</span>{" "}
            releases the gate let through carry a signed image and all four attestations, in a report{" "}
            <code>sentinel verify</code> trusted.
            {rows.some((row) => row.state === "failed") && " The evidence of a release could not be read."}
          </p>
          <table className="w-full border-collapse bg-white text-sm">
            <thead>
              <tr className="border-b text-left text-slate-500">
                <th className="p-2">Image</th>
                <th className="p-2">Verdict</th>
                {COLUMNS.map((column) => (
                  <th key={column.label} className="p-2">
                    {column.label}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {rows.map(({ release, state, report }) => (
                <tr key={release.decision_id} className="border-b">
                  <td className="p-2">
                    <Link className="text-sky-700 hover:underline"
                      to={`/releases/${encodeURIComponent(release.image_digest)}?decision=${encodeURIComponent(release.decision_id)}`}>
                      <Digest value={release.image_digest} />
                    </Link>
                  </td>
                  <td className="p-2">
                    <Verdict value={release.verdict} />
                  </td>
                  {state === "failed" ? (
                    <td colSpan={COLUMNS.length} className="p-2 text-xs text-red-700">
                      The evidence could not be read.
                    </td>
                  ) : (
                    carried(report).map((value, column) => (
                      <td key={COLUMNS[column]!.label} className="p-2 text-xs">
                        {state === "loading" ? "…" : value === true ? (
                          <span className="font-semibold text-emerald-700">✓</span>
                        ) : value === false ? (
                          <span className="font-semibold text-red-700">✗</span>
                        ) : (
                          <span className="text-slate-400">{release.verdict === "BLOCK" ? "not signed" : "not verified"}</span>
                        )}
                      </td>
                    ))
                  )}
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}
    </section>
  );
}
