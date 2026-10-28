from pydantic import BaseModel

from sentinel_ai.providers import LLMProvider


class Echo(BaseModel):
    text: str


class FakeProvider:
    """Deterministic stand-in used by tests and by tracks that are waiting for B5."""

    name = "fake"

    def complete[T: BaseModel](self, system: str, user: str, schema: type[T]) -> T:
        return schema.model_validate({"text": user})

    def embed(self, texts: list[str]) -> list[list[float]]:
        return [[float(len(t))] for t in texts]


def test_fake_provider_satisfies_protocol() -> None:
    provider = FakeProvider()
    assert isinstance(provider, LLMProvider)
    assert provider.complete("sys", "hello", Echo).text == "hello"
    assert provider.embed(["ab", "abc"]) == [[2.0], [3.0]]
