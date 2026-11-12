# SentinelCI dashboard (task B7)

React, TypeScript, Vite, TanStack Query, Tailwind and Recharts (SPEC section 11). It reads the platform API only:
it never writes, and it holds no token.

| Page | Reads |
|---|---|
| Overview: open findings by priority and category | `GET /metrics` (`sentinel_findings_open`, the default branch's latest release runs). No data yet is said, never shown as zeros |
| Findings: filters in the URL, 50 per page | `GET /api/v1/findings` |
| Finding detail: the finding, the runs that saw it, and its root-cause group (advisory, and marked when a model wrote it) | `GET /api/v1/findings/{id}`, `GET /api/v1/runs/{id}/correlations` |

Track A adds its pages (Releases & evidence, Supply chain, Remediation) on the same layout and client.

```bash
cd platform/web
npm ci                      # exactly package-lock.json; no package script ever runs (.npmrc: ignore-scripts)
npm run dev                 # http://127.0.0.1:5173, /api and /metrics proxied to SENTINEL_API_URL (default http://127.0.0.1:8000)
npm run check               # client up to date with schemas/openapi.yaml, tsc (strict), vitest, build
npm run client              # regenerate src/api/schema.ts after an API change
```

`make check` runs the same (`make web`), and so does CI (`ci.yml`, job `dashboard`).

Rules:
- **Supply chain.** Exact versions and the lockfile with its integrity hashes. Install scripts are off, and
  Dependabot proposes updates after a 7-day cooldown. A new dependency is justified in its PR.
- **The contract is the API's.** `src/api/schema.ts` is generated from `schemas/openapi.yaml`, and the check fails
  when it is out of date. A Finding v1 document is read field by field (`src/api/finding.ts`): a field of another
  type is shown as absent, never trusted.
- **Text is text.** Findings carry text from scanned repositories (titles, messages, AI labels). It is rendered as
  React text only: no `dangerouslySetInnerHTML`, no link or HTML taken from a finding.
- **Advisory stays advisory.** A root-cause group is labelled as never part of the gate, and as written by a model
  when it was.

Still to come: serving the built app in Compose behind the API, with a Content-Security-Policy header (the Vite
dev server injects an inline script, so the policy goes on the served build); the Policies & waivers page; the
read token, when the API's reads need one.
