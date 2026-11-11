import { useQuery } from "@tanstack/react-query";
import { Bar, BarChart, CartesianGrid, Tooltip, XAxis, YAxis } from "recharts";
import { getMetrics } from "../api/client";
import { CATEGORIES, PRIORITIES } from "../api/finding";
import { openFindings, totalBy } from "../metrics";
import { Failure, Loading } from "./common";

const PRIORITY_STYLE: Record<string, string> = {
  P0: "border-red-600",
  P1: "border-orange-500",
  P2: "border-amber-400",
  P3: "border-sky-400",
  P4: "border-slate-300",
  unscored: "border-slate-200",
};

/** Open findings of the default branch's latest release runs (GET /metrics, `sentinel_findings_open`). */
export function OverviewPage() {
  const metrics = useQuery({ queryKey: ["metrics"], queryFn: getMetrics });
  if (metrics.isPending) return <Loading />;
  if (metrics.isError) return <Failure error={metrics.error} />;
  const samples = openFindings(metrics.data);
  return (
    <section>
      <h1 className="mb-1 text-xl font-semibold">Overview</h1>
      <p className="mb-4 text-sm text-slate-600">
        Open findings of each repository's latest release run of its default branch.
      </p>
      {samples === null ? (
        <p className="rounded border border-slate-200 bg-white p-4 text-sm">
          No data yet: no release run of the default branch has been recorded.
        </p>
      ) : (
        <Counts samples={samples} />
      )}
    </section>
  );
}

function Counts({ samples }: { samples: NonNullable<ReturnType<typeof openFindings>> }) {
  const byPriority = totalBy(samples, "priority");
  const byCategory = totalBy(samples, "category");
  const chart = CATEGORIES.map((category) => ({ category, findings: byCategory.get(category) ?? 0 }));
  return (
    <>
      <ul className="mb-6 grid grid-cols-3 gap-3 md:grid-cols-6" aria-label="Open findings by priority">
        {[...PRIORITIES, "unscored"].map((priority) => (
          <li key={priority} className={`rounded border-l-4 bg-white p-3 shadow-sm ${PRIORITY_STYLE[priority]}`}>
            <div className="text-xs text-slate-500">{priority}</div>
            <div className="text-2xl font-semibold" data-testid={`priority-${priority}`}>
              {byPriority.get(priority) ?? 0}
            </div>
          </li>
        ))}
      </ul>
      <h2 className="mb-2 font-medium">By category</h2>
      <BarChart width={720} height={240} data={chart} className="rounded bg-white">
        <CartesianGrid strokeDasharray="3 3" />
        <XAxis dataKey="category" />
        <YAxis allowDecimals={false} />
        <Tooltip />
        <Bar dataKey="findings" fill="#334155" />
      </BarChart>
    </>
  );
}
