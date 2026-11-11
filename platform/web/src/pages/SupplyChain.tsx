import { useQueries, useQuery } from "@tanstack/react-query";
import { Link } from "react-router";
import { getReleaseEvidence, listReleases } from "../api/client";
import { asRelease, type TrustReportView } from "../api/release";
import { Digest, Failure, Loading, Verdict } from "./common";

const RECENT = 20;
// The checks of `sentinel verify` that show what a release carries, by the name its trust report gives them.
export const COLUMNS: { label: string; checks: string[] }[] = [
  { label: "Signed image", checks: ["signature: the image itself"] },
  { label: "Decision", checks: ["signature: release decision", "decision: verdict is not BLOCK"] },
  { label: "SBOM", checks: ["signature: SBOM (CycloneDX)", "SBOM: the one the vulnerability scan names"] },
  { label: "Vulnerability scan", checks: ["signature: vulnerability scan", "vulnerability scan: names this decision"] },
  {
    label: "Provenance",
    checks: ["signature: provenance (SLSA v1)", "provenance: built by the expected workflow",
      "provenance: built from the decision's commit"],
  },
];

/** The report a release is judged on here: the registry mode's, which is what Kyverno checks at admission. */
export function registryReport(reports: TrustReportView[]): TrustReportView | null {
  return reports.find((report) => report.mode === "registry") ?? null;
}

/** Each column for one report: every check of the column passed (true), one failed (false), or none was run. */
export function carried(report: TrustReportView | null): (boolean | null)[] {
  return COLUMNS.map((column) => {
    if (report === null) return null;
    const found = report.checks.filter((check) => column.checks.includes(check.name));
    return found.length === column.checks.length ? found.every((check) => check.ok) : found.length ? false : null;
  });
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
    const document = evidence[index]?.data;
    const report = document === undefined ? undefined : registryReport(asRelease(document).reports);
    return { release, loaded: document !== undefined, report: report ?? null };
  });
  const passed = rows.filter((row) => row.release.verdict !== "BLOCK");
  const complete = passed.filter((row) => row.loaded && carried(row.report).every((value) => value === true));
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
            <span className="text-lg font-semibold">
              {complete.length} of {passed.length}
            </span>{" "}
            releases the gate let through carry a signed image and all four attestations.
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
              {rows.map(({ release, loaded, report }) => (
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
                  {carried(report).map((value, column) => (
                    <td key={COLUMNS[column]!.label} className="p-2 text-xs">
                      {!loaded ? "…" : value === true ? (
                        <span className="font-semibold text-emerald-700">✓</span>
                      ) : value === false ? (
                        <span className="font-semibold text-red-700">✗</span>
                      ) : (
                        <span className="text-slate-400">{release.verdict === "BLOCK" ? "not signed" : "not verified"}</span>
                      )}
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}
    </section>
  );
}
