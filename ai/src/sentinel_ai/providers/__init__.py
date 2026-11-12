"""LLM provider abstraction (task B5, Track B): the interface, and Ollama as its default backend
(ADR-0009)."""

from sentinel_ai.providers.base import LLMProvider
from sentinel_ai.providers.ollama import OllamaProvider, PinnedModel, ProviderError

__all__ = ["LLMProvider", "OllamaProvider", "PinnedModel", "ProviderError"]
