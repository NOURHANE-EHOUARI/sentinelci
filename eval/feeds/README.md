# Offline feed fixtures

Recorded answers of the three enrichment feeds (SPEC section 6.1) for a fixed set of findings, so demos, the
evaluation (B8) and tests use real feed data with no network and get the same answers every time.

| File | What |
|---|---|
| `findings.ndjson` | 7 SCA findings (Finding v1) for real, well-known vulnerable packages, built from `CASES` in `refresh.py` |
| `recordings/` | one file per feed request: the URL, the status, the response (gzip, base64) and its sha256 |
| `snapshot.json` | the enrichment snapshot these recordings give (`sentinel snapshot --offline`) |
| `refresh.py` | re-records everything from the live feeds (`refresh`), or checks the fixtures offline (`--check`) |

Each case in `refresh.py` states what it is there to cover (a KEV-listed CVE reached from a GHSA id, a CRITICAL
CVE that KEV does not list, a PYSEC id resolved through its aliases, npm, PyPI and Maven packages), and
`--check` fails when a fixture stops covering it.

## Use

```bash
uv run sentinel snapshot --findings eval/feeds/findings.ndjson --out out/snapshot.json --offline eval/feeds/recordings
uv run sentinel enrich --findings eval/feeds/findings.ndjson --snapshot eval/feeds/snapshot.json --out out/enriched.ndjson
uv run python eval/feeds/refresh.py --check      # offline: replay == snapshot.json, coverage holds
uv run python eval/feeds/refresh.py              # network: re-record (the KEV catalogue is about 2 MB)
```

To add a finding (for example the demo-shop dependency seeds of A9), add a `Case` and refresh. A request that
was never recorded makes `--offline` leave that feed out, never guess. A refresh records into
`recordings.new/` and swaps it in only when every feed answered, so a failed one changes nothing. Each refresh
adds about 260 KB to the git history (the KEV catalogue): refresh when the cases change, not routinely.

## Trust

Recordings are evidence inputs, like the policies and the waivers. Each one is checked against its sha256 on
replay, but a change that edits both could forge an EPSS or KEV answer, so in CI read them from the base commit or
a trusted store, and review a refresh like any other change to evidence (`git diff --stat` shows which feeds
changed; `snapshot.json` shows what changed in them).

## Sources and terms

Recorded on 2026-10-29 (`snapshot.json` holds the feed dates).

- **OSV** (`api.osv.dev`), as listed on the OSV.dev data sources page (https://google.github.io/osv.dev/data/):
  - GHSA records: GitHub Advisory Database, CC BY 4.0
    (https://github.com/github/advisory-database/blob/main/LICENSE.md);
  - PYSEC records: PyPI Advisory Database, CC BY 4.0 (https://github.com/pypa/advisory-database/blob/main/LICENSE);
  - CVE records (CVE-2020-14343, CVE-2021-23337, CVE-2021-28957, CVE-2021-44228, CVE-2021-44906, CVE-2022-22965,
    CVE-2023-32681): NVD CVE entries converted to OSV by OSV.dev. The OSV page states no licence for them; the
    CVE List is used under the CVE Terms of Use (https://www.cve.org/Legal/TermsOfUse), and this product uses
    NVD data but is not endorsed or certified by the NVD.

  CC BY 4.0: https://creativecommons.org/licenses/by/4.0/. `snapshot.json` is derived from these records (CVSS
  base scores computed from the vectors, fixed versions extracted from the ranges, aliases kept); the recordings
  are the records unchanged.
- **EPSS** (`api.first.org`): Exploit Prediction Scoring System by FIRST, https://www.first.org/epss/
  (scores and percentiles; cite FIRST when presenting them).
- **CISA KEV** (`www.cisa.gov`): Known Exploited Vulnerabilities catalogue, a U.S. Government work,
  https://www.cisa.gov/known-exploited-vulnerabilities-catalog.

Owner: Track B (B2, B8).
