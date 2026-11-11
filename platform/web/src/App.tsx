import { lazy, Suspense } from "react";
import { NavLink, Route, Routes } from "react-router";
import { Loading } from "./pages/common";

// Each page is its own chunk: the charts (Recharts) load only with the Overview.
const OverviewPage = lazy(() => import("./pages/Overview").then((m) => ({ default: m.OverviewPage })));
const FindingsPage = lazy(() => import("./pages/Findings").then((m) => ({ default: m.FindingsPage })));
const FindingDetailPage = lazy(() => import("./pages/FindingDetail").then((m) => ({ default: m.FindingDetailPage })));
const GroupsPage = lazy(() => import("./pages/Groups").then((m) => ({ default: m.GroupsPage })));
const RemediationsPage = lazy(() => import("./pages/Remediations").then((m) => ({ default: m.RemediationsPage })));
const RemediationDetailPage = lazy(() => import("./pages/RemediationDetail").then((m) => ({ default: m.RemediationDetailPage })));
const ReleasesPage = lazy(() => import("./pages/Releases").then((m) => ({ default: m.ReleasesPage })));
const ReleaseDetailPage = lazy(() => import("./pages/ReleaseDetail").then((m) => ({ default: m.ReleaseDetailPage })));

const link = ({ isActive }: { isActive: boolean }) =>
  `rounded px-3 py-1.5 text-sm ${isActive ? "bg-slate-900 text-white" : "text-slate-700 hover:bg-slate-200"}`;

export function App() {
  return (
    <div className="min-h-screen">
      <header className="border-b border-slate-200 bg-white">
        <nav className="mx-auto flex max-w-6xl items-center gap-2 px-4 py-3" aria-label="Main">
          <span className="mr-4 font-semibold">SentinelCI</span>
          <NavLink to="/" end className={link}>
            Overview
          </NavLink>
          <NavLink to="/findings" className={link}>
            Findings
          </NavLink>
          <NavLink to="/releases" className={link}>
            Releases
          </NavLink>
          <NavLink to="/remediations" className={link}>
            Remediation
          </NavLink>
        </nav>
      </header>
      <main className="mx-auto max-w-6xl px-4 py-6">
        <Suspense fallback={<Loading />}>
        <Routes>
          <Route path="/" element={<OverviewPage />} />
          <Route path="/findings" element={<FindingsPage />} />
          <Route path="/findings/:findingId" element={<FindingDetailPage />} />
          <Route path="/runs/:runId/groups" element={<GroupsPage />} />
          <Route path="/releases" element={<ReleasesPage />} />
          <Route path="/releases/:imageDigest" element={<ReleaseDetailPage />} />
          <Route path="/remediations" element={<RemediationsPage />} />
          <Route path="/remediations/:proposalId" element={<RemediationDetailPage />} />
          <Route path="*" element={<p>No such page.</p>} />
        </Routes>
        </Suspense>
      </main>
    </div>
  );
}
