# ADR-0009: Local models: Gemma 4 12B (QAT) for generation, Qwen3-Embedding 0.6B for embeddings

- Status: proposed (accepted when merged)
- Date: 2026-10-29

## Context

SPEC §8 asks for a local model through Ollama, 7–14B class and quantized, behind `LLMProvider`
(`complete` for Explanation, TriageHint and PatchProposal; `embed` for correlation, A7). The platform must run on a
16 GB laptop next to PostgreSQL, Redis and SeaweedFS. AI is advisory only (ADR-0004), but a model that follows
instructions planted in scanned code would still mislabel findings in the dashboard.

## Decision

- **Generation: `gemma4:12b-it-qat`**
  (Ollama digest `38044be4f923e5a55264ed7df4eaac2676651a905f735197c504045140c02bd3`, Apache-2.0).
- **Embeddings: `qwen3-embedding:0.6b`**
  (digest `ac6da0dfba84a81fdbfbaf330198c33cd77c4cdfc53e8bc50eb581914a15621d`, Apache-2.0, 1024 dimensions, within
  pgvector's HNSW limit of 2000).

Measured with `eval/model-selection/bench.py` (results and method in `eval/model-selection/README.md`):

| | Gemma 4 12B QAT | Qwen3.5 9B | Qwen2.5-Coder 7B |
|---|---|---|---|
| Tasks passed (final) | **6/6** | 4/6 | 4/6 |
| Prompt-injection canary | **resisted** | obeyed | obeyed |
| Patch applies and fixes the injection | **yes** | no | no |
| Output speed, 4 vCPU CPU-only | 4.7 tok/s | 4.2 tok/s | 4.4 tok/s |
| Memory when loaded | 8.5 GB | 6.3 GB | 5.1 GB |

Qwen3-Embedding separates root causes best (0.245 vs 0.216 for EmbeddingGemma and 0.176 for nomic-embed-text);
EmbeddingGemma was also excluded for its more restrictive licence.

## Consequences

- Models are pinned by Ollama digest. Pulling them is part of setting up the `ai` profile, and the pulled digest must
  match this ADR (a mismatch is treated like any other integrity failure).
- On a CPU-only machine an explanation takes about 2 minutes: AI work runs in background workers, never in the
  pipeline (already the design in SPEC §8).
- Gemma 4 needed one repair retry on 2 of 6 answers (`confidence` out of range): the SPEC §8 repair retry is
  required, not optional.
- Both Qwen models obeying the canary shows that the `<data>` delimiters and the system prompt alone do not stop
  injection. B5 keeps them, measures canaries on every model or prompt change, and treats any verdict-adjacent
  output as advisory.
- Revisit when a new model generation lands or when B8's larger evaluation set is ready; re-run the benchmark on
  each laptop for its own speed numbers.
