"""`sentinel-ai`: the AI layer's commands (advice only; the release gate never runs them)."""

import json
import os
from typing import Annotated

import typer

from sentinel_ai.correlate.models import EmbeddingModel
from sentinel_ai.correlate.stages import Embedder
from sentinel_ai.correlate.store import StoreError, correlate_and_store
from sentinelci.report.upload import TOKEN_VARIABLE, UploadError, platform_from

app = typer.Typer(
    help="SentinelCI's AI layer: advice next to the evidence, never a decision.", no_args_is_help=True
)
EXIT_NOT_STORED = 4  # never 1 or 3: advice that was not stored says nothing about a verdict


@app.callback()
def main() -> None:
    """SentinelCI's AI layer."""


@app.command("correlate")
def correlate_command(
    run: Annotated[str, typer.Option("--run", help="The platform's run id (its findings must be recorded).")],
    api_url: Annotated[
        str, typer.Option(help="The platform, https:// (or http://localhost for a local platform).")
    ],
    structural: Annotated[
        bool, typer.Option("--structural/--no-structural", help="Run stage 2a (shared keys) after dedup.")
    ] = True,
    embedding: Annotated[
        bool,
        typer.Option(
            "--embedding/--no-embedding",
            help="Run stage 2b with the pinned embedding model on the local Ollama (SENTINEL_OLLAMA_URL). "
            "If it is not served with its pinned digest, stages 1 and 2a are kept and 2b is recorded as "
            "skipped.",
        ),
    ] = False,
) -> None:
    """Correlate a run's recorded findings (stages 1 and 2a, and 2b with --embedding) and store the
    Correlation v1 document on the platform as a new version, or confirm the version it already has with the
    same bytes.

    The token comes only from the SENTINEL_API_TOKEN environment variable. Exit code 0 when the platform holds
    this version, 4 when it does not, for whatever reason (a correlation is advice: never 1 or 3).
    """
    try:
        embed, model = _embedder() if embedding else (None, None)
        stored = correlate_and_store(
            platform_from(api_url), run, structural=structural, embed=embed, embedding_model=model
        )
    except (StoreError, UploadError) as exc:
        said, token = str(exc), os.environ.get(TOKEN_VARIABLE, "").strip()
        said = said.replace(token, f"<{TOKEN_VARIABLE}>") if token else said
        typer.echo(f"sentinel-ai correlate: {said}\nthe correlation was not stored", err=True)
        raise typer.Exit(EXIT_NOT_STORED) from exc
    except Exception as exc:
        # Last resort: only the type is printed, an unexpected error's text could hold anything.
        typer.echo(
            f"sentinel-ai correlate: unexpected {type(exc).__name__}\nthe correlation was not stored",
            err=True,
        )
        raise typer.Exit(EXIT_NOT_STORED) from None
    typer.echo(
        json.dumps({
            "run_id": stored.run_id, "sha256": stored.sha256, "groups": stored.groups,
            "stages": list(stored.stages), "skipped": list(stored.skipped),
            "already_recorded": stored.already_recorded,
        })
    )  # fmt: skip


def _embedder() -> tuple[Embedder, EmbeddingModel]:
    """The pinned embedding model on the local Ollama. The provider checks the digest the server reports
    before each request, so a model that is not served fails inside stage 2b, which is then recorded as
    skipped: advice degrades, it never vanishes."""
    from sentinel_ai.providers.ollama import EMBEDDING, OllamaProvider

    provider = OllamaProvider.from_env()
    return provider.embed, EmbeddingModel(provider="ollama", name=EMBEDDING.name, digest=EMBEDDING.digest)


if __name__ == "__main__":
    app()
