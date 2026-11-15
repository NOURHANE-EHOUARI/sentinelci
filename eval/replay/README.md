# Replay identity (B8)

SPEC section 3 asks for "replay determinism: 100% identical". `make eval-replay` measures it and writes it as a
report, `out/eval/replay.json` and `out/eval/replay.md`.

```bash
make eval-replay                                         # the corpus, plus demo-shop if make eval ran
uv run python eval/replay/run.py                         # the corpus only
uv run python eval/replay/run.py --findings out/eval/findings   # plus a decision on demo-shop's findings
```

What it does:
1. records the replay corpus (`corpus.py`): nine release-gate cases built from the contract fixtures, each with
   the verdict it exists to cover, so the corpus cannot silently stop covering BLOCK or PASS;
2. with `--findings`, also records a `local` decision on the five findings files `make eval` wrote, so the
   replay covers real scanner output and not only fixtures. All five must be there;
3. replays every recorded decision with this checkout's engine (`sentinel replay --all`) and counts the
   identical ones.

It exits 1 when any decision differs, cannot be replayed, or is not reported by the replay at all, and 2 when it
cannot measure (no summary line, or a summary that disagrees with the lines above it). Each run starts from an
empty store under `out/eval/replay/`, so only that run's decisions are replayed.

Today: 10 of 10 decisions replay identically (100.0%).

**What it shows, and what it doesn't.** Every decision is recorded and replayed in the same run, with the same
engine, OPA and policies. So 100% shows that the store holds every input of a decision and that the engine
decides the same way twice in this environment. It cannot catch drift between the engine, OPA or policies that
recorded a decision and the ones that replay it later. That is what the nightly job
(`.github/workflows/replay-nightly.yml`) is for: it replays the previous night's corpus with the next day's
engine. `replay.md` says the same under its number.

**Across two checkouts.** Until the nightly job can run, the same measurement can be made by hand, split in two:
record on one checkout, replay on another (#124 review).

```bash
# On the checkout that records (say main), into an empty directory outside both checkouts:
uv run python eval/replay/run.py --record-to ../replay-main --findings out/eval/findings
# On the checkout that replays (say a pull request's):
uv run python eval/replay/run.py --replay-from ../replay-main
```

`--record-to` records and replays nothing. It writes `store/` and `recorded.json` (each decision's id and
verdict, and the recording checkout's commit and whether it had uncommitted changes), and refuses a directory
that holds anything. `--replay-from` replays that store with the replaying checkout's engine and OPA, and never
changes it. The report names both commits. A decision is replayed from its stored inputs and its stored policy
bundle, so this compares engines and OPA, not policies: a policy change is a new decision, not a replay.
Decisions the replaying engine skips (another engine or OPA version) are listed and not compared; if all are
skipped, nothing is measured and the run exits 2. In one run nothing may be skipped, so there a skip counts as
a failure.

What it saw, recorded on this branch and replayed on it with today's `main` merged in:
- 10 of 10 identical (no engine change between the two);
- with the replaying engine's violations sorted the other way, the 2 decisions that have several violations
  differ, and the run exits 1;
- with the replaying engine's version bumped, all 10 are skipped: not measured, exit 2.

The same inputs give the same report: decisions use fixed evaluation times, and demo-shop's findings are named
by their digests.
