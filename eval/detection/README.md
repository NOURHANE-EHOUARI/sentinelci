# Detection report (B8)

`make eval` scans demo-shop with SentinelCI's own scanners and scores their findings against
`demo-shop/ground-truth/findings.yaml`, with the ground truth's matching rules (its README). It writes
`out/eval/detection.json` and `out/eval/detection.md`.

```bash
make eval                                   # scanners from SENTINEL_TOOLS_DIR (default .sentinel/tools)
make eval DB_DIR=.sentinel/grype-db         # SCA too (a `sentinel tools grype-db` directory)
uv run python eval/detection/run.py --findings out/eval/findings   # score recorded findings files
```

What it reports:
- **Recall per category:** seeds detected over seeds listed. A `known_miss` counts as a miss, never left out.
- **False positives on the clean controls:** a finding by a tool a control names, in the control's file.
- **Unlisted findings:** real findings that match no seed and no control. They are listed, neither hits nor
  false positives.
- **Not measured:** a category whose tool did not run (no Grype database, or a CLI without the command) says
  so and why. It is never scored 0.
- **The benchmark's size** against SPEC section 17, and the canaries, which are measured with the AI
  explanations (B5).

The same inputs give the same report, byte for byte: there is no clock, and every input is named by its digest
(the ground truth, demo-shop's git tree, each tool's findings and version, Grype's database).
