"""Provider interface shared by the AI analyst (B5) and the correlator (A7).

We deliberately keep this layer thin instead of depending on a multi-provider gateway library:
fewer transitive dependencies means a smaller supply-chain attack surface.
"""

from typing import Protocol, TypeVar, runtime_checkable

from pydantic import BaseModel

SchemaT = TypeVar("SchemaT", bound=BaseModel)


@runtime_checkable
class LLMProvider(Protocol):
    """Minimal contract every model backend (Ollama by default) must implement."""

    name: str

    def complete(self, system: str, user: str, schema: type[SchemaT]) -> SchemaT:
        """Return a response validated against `schema`, or raise if it cannot be produced."""
        ...

    def embed(self, texts: list[str]) -> list[list[float]]:
        """Return one embedding vector per input text."""
        ...
