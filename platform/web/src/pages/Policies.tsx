import { useQuery, type UseQueryResult } from "@tanstack/react-query";
import { Link, useSearchParams } from "react-router";
import { getRuleCounts, listWaiversInForce, type RuleCounts, type Waiver, type WaiversInForce } from "../api/client";
import { expiry, RULE_CATALOGUE } from "../api/rules";
import { Digest, Failure, Loading, utc, VerdictBadge } from "./common";

/** The waivers each repository's latest release decision read, and how often each rule fired. Read only: a
 * waiver is added or removed by a reviewed pull request to `.sentinel/waivers.yaml`, never here. */
export function PoliciesPage() {
  const [params, setParams] = useSearchParams();
  const repo = params.get("repo") ?? undefined;
  const waivers = useQuery({ queryKey: ["waivers", repo], queryFn: () => listWaiversInForce(repo) });
  const rules = useQuery({ queryKey: ["rules"], queryFn: getRuleCounts });

  return (
    <section>
      <h1 className="mb-1 text-xl font-semibold">Policies & waivers</h1>
      <p className="mb-6 text-sm text-slate-600">
        What the gate decided with, as recorded. Nothing here changes a verdict or a waiver: waivers are added and
        removed by reviewed pull requests to <code>.sentinel/waivers.yaml</code>.
      </p>

      <h2 className="mb-2 flex items-center gap-3 text-lg font-semibold">
        Waivers in force
        {repo && (
          <button className="rounded border bg-white px-2 py-1 text-sm font-normal" onClick={() => setParams({})}>
            {repo} ✕
          </button>
        )}
      </h2>
      <p className="mb-3 text-sm text-slate-600">
        For each repository, the waivers file its latest release decision of the default branch read.
      </p>
      {waivers.isPending ? (
        <Loading />
      ) : waivers.isError ? (
        <Failure error={waivers.error} />
      ) : waivers.data.items.length === 0 ? (
        <p className="text-sm text-slate-600">No release decision of a default branch is recorded.</p>
      ) : (
        waivers.data.items.map((item) => <RepositoryWaivers key={item.repo} item={item} />)
      )}

      <h2 className="mb-2 mt-8 text-lg font-semibold">Rules</h2>
      <Rules counts={rules} />
    </section>
  );
}

function RepositoryWaivers({ item }: { item: WaiversInForce }) {
  const source =
    item.source === "run" && item.run_id !== null ? (
      <Link className="text-sky-700 hover:underline" to={`/runs/${encodeURIComponent(item.run_id)}`}>
        run
      </Link>
    ) : item.image_digest !== null ? (
      <Link
        className="text-sky-700 hover:underline"
        // A rebuild can record a second release of the same image: the link names this decision.
        to={`/releases/${encodeURIComponent(item.image_digest)}?decision=${encodeURIComponent(item.decision_id)}`}
      >
        release
      </Link>
    ) : (
      item.source
    );
  return (
    <article className="mb-4 rounded border border-slate-200 bg-white p-3" aria-label={item.repo}>
      <header className="mb-2 flex flex-wrap items-center gap-x-3 gap-y-1 text-sm">
        <span className="font-semibold">{item.repo}</span>
        <VerdictBadge value={item.verdict} />
        <span>
          {source} @ <span className="font-mono text-xs">{item.commit.slice(0, 12)}</span>, evaluated{" "}
          {utc(item.evaluated_at)}
        </span>
        <span className="text-xs text-slate-500">
          engine {item.engine_version}
          {item.policy_bundle_digest !== null && (
            <>
              , policies <Digest value={item.policy_bundle_digest} />
            </>
          )}
        </span>
      </header>
      {item.invalid_waivers.length > 0 && (
        <ul role="alert" className="mb-2 rounded border border-red-200 bg-red-50 p-2 text-sm text-red-800">
          {item.invalid_waivers.map((message, index) => (
            <li key={index}>SC-005: {message}</li>
          ))}
        </ul>
      )}
      <WaiversTable item={item} />
    </article>
  );
}

function WaiversTable({ item }: { item: WaiversInForce }) {
  if (item.waivers_digest === null) {
    return (
      <p className="text-sm text-slate-600">
        This decision does not record which waivers file it read (Decision 1.0): its waivers are unknown.
      </p>
    );
  }
  if (item.waivers === null) {
    return (
      <p className="text-sm text-slate-600">
        Waivers file not uploaded: the decision read <Digest value={item.waivers_digest} />, which the platform
        does not hold, so its waivers are unknown.
        {item.applied.length > 0 && <> The decision applied {item.applied.join(", ")}.</>}
      </p>
    );
  }
  if (item.waivers.length === 0) {
    return <p className="text-sm text-slate-600">No waivers: the decision read an empty waivers file.</p>;
  }
  const now = Date.now();
  return (
    <table className="w-full border-collapse text-sm">
      <thead>
        <tr className="border-b text-left text-slate-500">
          <th className="p-2">Waiver</th>
          <th className="p-2">Waives</th>
          <th className="p-2">Owner</th>
          <th className="p-2">Justification</th>
          <th className="p-2">Expires</th>
          <th className="p-2">In this decision</th>
        </tr>
      </thead>
      <tbody>
        {item.waivers.map((waiver) => (
          <tr key={waiver.index} className="border-b align-top">
            <td className="p-2 font-mono text-xs">{waiver.id ?? `#${waiver.index + 1}`}</td>
            <td className="p-2">
              <Target waiver={waiver} />
            </td>
            <td className="p-2">{waiver.owner ?? "—"}</td>
            <td className="whitespace-pre-wrap p-2">{waiver.justification ?? "—"}</td>
            <td className="p-2">
              <Expires value={waiver.expires_at} now={now} />
            </td>
            <td className="p-2">
              {waiver.applied ? (
                <span className="text-xs font-medium text-emerald-700">applied</span>
              ) : (
                <span className="text-xs text-slate-500">not applied</span>
              )}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function Target({ waiver }: { waiver: Waiver }) {
  if (waiver.finding_id !== null && /^[a-f0-9]{64}$/.test(waiver.finding_id)) {
    return (
      <Link className="font-mono text-xs text-sky-700 hover:underline" to={`/findings/${waiver.finding_id}`}>
        finding {waiver.finding_id.slice(0, 12)}…
      </Link>
    );
  }
  if (waiver.vulnerability !== null || waiver.purl !== null) {
    return (
      <span>
        {waiver.vulnerability ?? "—"} in <span className="font-mono text-xs">{waiver.purl ?? "—"}</span>
      </span>
    );
  }
  return <span className="font-mono text-xs">{waiver.finding_id ?? "—"}</span>;
}

function Expires({ value, now }: { value: string | null; now: number }) {
  const state = expiry(value, now);
  if (state.kind === "unreadable") {
    return (
      <span className="text-xs text-red-700">
        {value === null ? "—" : <span className="font-mono">{value}</span>} (not a date-time)
      </span>
    );
  }
  const when = utc(state.at.toISOString());
  if (state.kind === "expired") {
    return (
      <span className="text-xs font-medium text-red-700">
        expired {when}
        <span className="block font-normal">{state.days === 0 ? "today" : `${state.days} days ago`}</span>
      </span>
    );
  }
  return (
    <span className={`text-xs ${state.kind === "soon" ? "font-medium text-amber-700" : "text-slate-700"}`}>
      {when}
      <span className="block font-normal">{state.days === 0 ? "within a day" : `in ${state.days} days`}</span>
    </span>
  );
}

const CONTEXT_ORDER = ["pr", "release", "local"];

function Rules({ counts }: { counts: UseQueryResult<RuleCounts> }) {
  if (counts.isPending) return <Loading />;
  if (counts.isError) return <Failure error={counts.error} />;
  const known = new Set(RULE_CATALOGUE.map((rule) => rule.rule));
  const others = [...new Set(counts.data.items.map((item) => item.rule))].filter((rule) => !known.has(rule)).sort();
  const rows = [
    ...RULE_CATALOGUE,
    ...others.map((rule) => ({ rule, verdict: null, condition: "Not in this dashboard's catalogue (SPEC 6.3)." })),
  ];
  return (
    <>
      <p className="mb-3 text-sm text-slate-600">
        The catalogue of SPEC 6.3, and how many of the {counts.data.decisions} recorded decisions each rule fired
        in.
      </p>
      <table className="w-full border-collapse bg-white text-sm">
        <thead>
          <tr className="border-b text-left text-slate-500">
            <th className="p-2">Rule</th>
            <th className="p-2">Effect</th>
            <th className="p-2">Condition</th>
            <th className="p-2">Fired in</th>
            <th className="p-2">Last fired</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => {
            const fired = counts.data.items
              .filter((item) => item.rule === row.rule)
              .sort(
                (a, b) =>
                  CONTEXT_ORDER.indexOf(a.context) - CONTEXT_ORDER.indexOf(b.context) ||
                  a.effect.localeCompare(b.effect),
              );
            const last = fired
              .map((item) => item.last_evaluated_at)
              .reduce<string | undefined>((a, b) => (a === undefined || Date.parse(b) > Date.parse(a) ? b : a), undefined);
            return (
              <tr key={row.rule} className="border-b align-top">
                <td className="p-2 font-mono text-xs">{row.rule}</td>
                <td className="p-2">{row.verdict ?? "—"}</td>
                <td className="p-2">{row.condition.replaceAll("`", "")}</td>
                <td className="p-2">
                  {fired.length === 0 ? (
                    <span className="text-slate-500">never</span>
                  ) : (
                    <ul>
                      {fired.map((item) => (
                        <li key={`${item.context}-${item.effect}`}>
                          {item.context}: {item.decisions} {item.decisions === 1 ? "decision" : "decisions"}
                          {item.effect !== row.verdict && ` (${item.effect})`}
                        </li>
                      ))}
                    </ul>
                  )}
                </td>
                <td className="p-2">{last === undefined ? "—" : utc(last)}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </>
  );
}
