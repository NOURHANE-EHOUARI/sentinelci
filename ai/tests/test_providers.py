from typing import TypeVar

from pydantic import BaseModel

from sentinel_ai.providers import LLMProvider


class Echo(BaseModel):
    text: str


# A TypeVar, not PEP 695 syntax: Opengrep cannot parse `def f[T]` (tests/ci/test_python_syntax.py).
T = TypeVar("T", bound=BaseModel)


class FakeProvider:
    """Deterministic stand-in used by tests and by tracks that are waiting for B5."""

    name = "fake"

    def complete(self, system: str, user: str, schema: type[T]) -> T:
        return schema.model_validate({"text": user})

    def embed(self, texts: list[str]) -> list[list[float]]:
        return [[float(len(t))] for t in texts]


def test_fake_provider_satisfies_protocol() -> None:
    provider = FakeProvider()
    assert isinstance(provider, LLMProvider)
    assert provider.complete("sys", "hello", Echo).text == "hello"
    assert provider.embed(["ab", "abc"]) == [[2.0], [3.0]]
