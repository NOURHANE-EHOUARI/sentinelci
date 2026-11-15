# Explanation rubric (B8)

SPEC section 17 asks for "explanation rubric + LLM-judge agreement (Cohen's kappa)". This measures how good the
AI analyst's explanations are, as two people and an LLM judge rate them, and how far the raters agree.

```bash
make eval                                    # the findings (out/eval/findings)
make eval-explanations OLLAMA_URL=http://127.0.0.1:11434   # explanations, then the judge: about an hour on a CPU
# each person: copy out/eval/explanations/sheet.yaml to ratings-<name>.yaml, set `rater`, answer every item
make eval-rubric RATERS="hiba nourhane"      # out/eval/explanations/rubric.md
```

**What is rated.** One explanation per non-secret seed of `demo-shop/ground-truth/findings.yaml`, of the first
finding (by id) `make eval` reported for it, written through `sentinel_ai.explain` as the platform writes it,
with the pinned model and the code around the finding. A secret's finding is never sent to a model. On today's
`make eval`, 23 of the 24 non-secret seeds have a finding; GT-CONTAINER-001 needs the image scan, which `make eval`
does not run, and is listed as not found.

**The rubric:** four yes/no questions per explanation (`RUBRIC` in `run.py`, also written into the sheet):

| Criterion | Question |
|---|---|
| correct | The summary and the impact describe the weakness this finding is about, not another one. |
| grounded | Every file, package, version, CWE, CVE and URL it names is in the finding or the code shown. |
| fix | Doing what fix_guidance says would remove this finding without breaking what the code is for. |
| clear | A developer who has not seen the scanner's output understands what to change and why. |

**The raters.** Two people rate each explanation alone, without looking at the other's sheet. The LLM judge
(`judge`) answers the same questions; by default it is the pinned generation model, the explainer itself, so
it may favour its own answers. The report names it.

**The report.** Each rater's pass rate per criterion, and Cohen's kappa between the two people and between each
person and the judge, per criterion and pooled over the four. Kappa is undefined (0/0) when both raters give one
answer to every item; the report says so rather than showing 0 or 1. A sheet with a blank or non-boolean answer,
a missing item, or another explanation than the one generated (each item carries its explanation's sha256) is
refused, exit 2.

**Nothing here fills in a person's rating.** `generate` writes the sheet with every rating blank, and a test
keeps it so.
