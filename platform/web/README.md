# SentinelCI dashboard (task B7)

React, TypeScript, Vite, TanStack Query, Tailwind and Recharts (SPEC section 11). It reads the platform API only:
it never writes, and it holds no token.

| Page | Reads |
|---|---|
| Overview: open findings by priority and category | `GET /metrics` (`sentinel_findings_open`, the default branch's latest release runs). No data yet is said, never shown as zeros |
| Findings: filters in the URL (also a run's, `?run_id=`), 50 per page | `GET /api/v1/findings` |
| Finding detail: the finding, the runs that saw it, its root-cause group (advisory, and marked when a model wrote it), and its latest explanation (advisory, naming its model; only the canonical CWE, NVD, GitHub advisory and OSV pages are links; none recorded, or a secret's finding, is said so) | `GET /api/v1/findings/{id}`, `GET /api/v1/runs/{id}/correlations`, `GET /api/v1/findings/{id}/explanation` |
| Releases (A8): each release `make release` recorded, its verdict, and whether `sentinel verify` trusted the signed image (a BLOCK: not signed) | `GET /api/v1/releases` |
| Release (A8): the decision (rules that fired, recorded input digests, scanner versions, waivers) and each trust report check by check (registry mode, what Kyverno checks; evidence mode) | `GET /api/v1/releases/{digest}/evidence` |
| Supply chain (A8): the latest releases, each with its signed image and four attestations as `sentinel verify` found them in the registry, and how many releases the gate let through carry all of them in a report verify trusted (unknown, never 0, until every release's evidence is read) | `GET /api/v1/releases`, `GET /api/v1/releases/{digest}/evidence` |
| Remediation (A8): each attempt of the remediation loop (outcome, strategy, attempt, pull request) and the success per strategy (SPEC §10, from `sentinel_remediation_attempts_total`) | `GET /api/v1/remediations`, `GET /metrics` |
| Remediation attempt (A8): the verification gate's conditions, the model when one wrote it, the rationale, the files and the diff (as text) | `GET /api/v1/remediations/{proposal_id}` |
| Root-cause groups (A7, A8): a run's groups of more than one finding (title, root cause, the one fix, members), the alert reduction of SPEC §10 and the correlator; advisory, and marked when a model wrote a label. Reached from a finding's group | `GET /api/v1/runs/{id}`, `GET /api/v1/runs/{id}/correlations`, `GET /api/v1/findings?run_id=` |
| Runs: newest first, the context, the repository and the ref in the URL, 50 per page, each with the gate's verdict. A run without a decision reads "No decision", never PASS | `GET /api/v1/runs` |
| Run detail: the run, its findings (a link to the Findings page), and its decision as recorded: verdict, violations linked to their findings, waivers applied, every input it records (tool versions included). Without a decision: "No decision recorded", which is not a PASS | `GET /api/v1/runs/{id}`, `GET /api/v1/runs/{id}/decision` |
| Policies & waivers: for each repository, the waivers its latest release decision of the default branch read (as written: target, owner, justification, expiry against your clock, applied or not, and the decision's SC-005 reasons), and the rule catalogue of SPEC 6.3 with how often each rule fired. A waivers file not uploaded is unknown, never "no waivers". Read only: waivers are added by pull request | `GET /api/v1/waivers`, `GET /api/v1/rules` |

Track A's pages use the same layout and client. The release pages
show a record: the platform verifies nothing itself, and Kyverno verifies again at admission. A Release
evidence document is read field by field too (`src/api/release.ts`).

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
dev server injects an inline script, so the policy goes on the served build); the read token, when the API's reads
need one.
