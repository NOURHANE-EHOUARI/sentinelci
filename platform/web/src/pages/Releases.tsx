import { useQuery } from "@tanstack/react-query";
import { Link, useSearchParams } from "react-router";
import { listReleases } from "../api/client";
import { Digest, Failure, Loading, Trust, utc, Verdict } from "./common";

export const PAGE_SIZE = 50;
const VERDICTS = ["PASS", "WARN", "BLOCK"] as const;

/** Every release `make release` recorded, newest first: the gate's verdict, and whether `sentinel verify`
 * trusted the signed image. A BLOCK was never signed. */
export function ReleasesPage() {
  const [params, setParams] = useSearchParams();
  const verdict = params.get("verdict") ?? undefined;
  const offset = Math.max(0, Math.floor(Number(params.get("offset") ?? 0)) || 0);
  const page = useQuery({
    queryKey: ["releases", verdict, offset],
    queryFn: () => listReleases({ verdict, limit: PAGE_SIZE, offset }),
  });

  function set(key: string, value: string | null) {
    const next = new URLSearchParams(params);
    if (value) next.set(key, value);
    else next.delete(key);
    if (key !== "offset") next.delete("offset");
    setParams(next);
  }

  return (
    <section>
      <h1 className="mb-1 text-xl font-semibold">Releases & evidence</h1>
      <p className="mb-4 text-sm text-slate-600">
        Each release the gate decided on, and what <code>sentinel verify</code> found about the signed image.
        Kyverno verifies again at admission: this page shows the record, it admits nothing.
      </p>
      <label className="mb-4 flex items-center gap-2 text-sm">
        Verdict
        <select className="rounded border bg-white px-2 py-1" value={verdict ?? ""}
          onChange={(event) => set("verdict", event.target.value)}>
          <option value="">All</option>
          {VERDICTS.map((value) => (
            <option key={value} value={value}>
              {value}
            </option>
          ))}
        </select>
      </label>
      {page.isPending ? (
        <Loading />
      ) : page.isError ? (
        <Failure error={page.error} />
      ) : page.data.items.length === 0 ? (
        <p className="rounded border border-slate-200 bg-white p-4 text-sm">
          No release recorded yet: <code>make release</code> records one.
        </p>
      ) : (
        <>
          <table className="w-full border-collapse bg-white text-sm">
            <thead>
              <tr className="border-b text-left text-slate-500">
                <th className="p-2">Image</th>
                <th className="p-2">Verdict</th>
                <th className="p-2">Verified</th>
                <th className="p-2">Repository</th>
                <th className="p-2">Commit</th>
                <th className="p-2">Decided</th>
              </tr>
            </thead>
            <tbody>
              {page.data.items.map((release) => (
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
                  <td className="p-2">
                    <Trust trusted={release.trusted} />
                  </td>
                  <td className="p-2">{release.repo}</td>
                  <td className="p-2 font-mono text-xs">{release.commit.slice(0, 12)}</td>
                  <td className="p-2">{utc(release.evaluated_at)}</td>
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
