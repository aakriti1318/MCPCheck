"""
LLM adapter for MCPCheck.

Uses LiteLLM for provider-agnostic LLM calls, supporting 100+ providers
including OpenAI, Anthropic, Google, Azure, Ollama, and more.
"""

from __future__ import annotations

from typing import Any

from mcpcheck.domain.exceptions import LlmAdapterError


class LlmAdapter:
    """
    Adapter for LLM operations using LiteLLM.

    LiteLLM provides a unified interface to 100+ LLM providers,
    making MCPCheck truly LLM-agnostic.
    """

    def __init__(
        self,
        model: str = "claude-haiku-4-5-20251001",
        api_key: str | None = None,
        api_base: str | None = None,
        timeout: float = 60.0,
    ) -> None:
        """
        Initialize the LLM adapter.

        Args:
            model: LiteLLM model identifier. Examples:
                - "gpt-4" (OpenAI)
                - "claude-3-opus-20240229" (Anthropic)
                - "gemini-pro" (Google)
                - "ollama/llama2" (Ollama local)
                - "azure/gpt-4" (Azure OpenAI)
            api_key: API key (if not set via environment).
            api_base: Custom API base URL.
            timeout: Request timeout in seconds.
        """
        self.model = model
        self.api_key = api_key
        self.api_base = api_base
        self.timeout = timeout

    async def complete(
        self,
        prompt: str,
        system: str | None = None,
        temperature: float = 0.0,
        max_tokens: int = 1000,
    ) -> str:
        """
        Generate a completion.

        Args:
            prompt: The user prompt.
            system: Optional system prompt.
            temperature: Sampling temperature (0 = deterministic).
            max_tokens: Maximum tokens in response.

        Returns:
            Generated text.

        Raises:
            LlmAdapterError: If the LLM call fails.
        """
        try:
            import litellm

            messages: list[dict[str, str]] = []

            if system:
                messages.append({"role": "system", "content": system})

            messages.append({"role": "user", "content": prompt})

            kwargs: dict[str, Any] = {
                "model": self.model,
                "messages": messages,
                "temperature": temperature,
                "max_tokens": max_tokens,
                "timeout": self.timeout,
            }

            if self.api_key:
                kwargs["api_key"] = self.api_key
            if self.api_base:
                kwargs["api_base"] = self.api_base

            response = await litellm.acompletion(**kwargs)

            content = response.choices[0].message.content
            return content or ""

        except ImportError:
            raise LlmAdapterError(
                "LiteLLM not installed. Run: pip install litellm",
                provider="litellm",
            )
        except Exception as e:
            raise LlmAdapterError(
                f"LLM call failed: {e}",
                provider=self.model,
            )

    def complete_sync(
        self,
        prompt: str,
        system: str | None = None,
        temperature: float = 0.0,
        max_tokens: int = 1000,
    ) -> str:
        """
        Synchronous version of complete.

        Args:
            prompt: The user prompt.
            system: Optional system prompt.
            temperature: Sampling temperature.
            max_tokens: Maximum tokens in response.

        Returns:
            Generated text.
        """
        try:
            import litellm

            messages: list[dict[str, str]] = []

            if system:
                messages.append({"role": "system", "content": system})

            messages.append({"role": "user", "content": prompt})

            kwargs: dict[str, Any] = {
                "model": self.model,
                "messages": messages,
                "temperature": temperature,
                "max_tokens": max_tokens,
                "timeout": self.timeout,
            }

            if self.api_key:
                kwargs["api_key"] = self.api_key
            if self.api_base:
                kwargs["api_base"] = self.api_base

            response = litellm.completion(**kwargs)

            content = response.choices[0].message.content
            return content or ""

        except ImportError:
            raise LlmAdapterError(
                "LiteLLM not installed. Run: pip install litellm",
                provider="litellm",
            )
        except Exception as e:
            raise LlmAdapterError(
                f"LLM call failed: {e}",
                provider=self.model,
            )

    @staticmethod
    def list_supported_providers() -> list[str]:
        """
        List commonly supported LLM providers.

        Returns:
            List of provider names.
        """
        return [
            "openai",
            "anthropic",
            "azure",
            "google",
            "cohere",
            "huggingface",
            "ollama",
            "replicate",
            "together_ai",
            "vertex_ai",
            "bedrock",
            "groq",
            "mistral",
            "perplexity",
            "fireworks_ai",
            "anyscale",
            "deepinfra",
        ]

    def estimate_cost(
        self,
        input_tokens: int,
        output_tokens: int,
    ) -> float:
        """
        Estimate the cost of a request.

        Note: This is a rough estimate. Actual costs may vary.

        Args:
            input_tokens: Estimated input tokens.
            output_tokens: Estimated output tokens.

        Returns:
            Estimated cost in USD.
        """
        # Rough pricing per 1K tokens (as of early 2026)
        pricing: dict[str, tuple[float, float]] = {
            # (input_per_1k, output_per_1k)
            "gpt-4": (0.03, 0.06),
            "gpt-4-turbo": (0.01, 0.03),
            "gpt-3.5-turbo": (0.0005, 0.0015),
            "claude-3-opus": (0.015, 0.075),
            "claude-3-sonnet": (0.003, 0.015),
            "claude-haiku-4-5-20251001": (0.00025, 0.00125),
            "gemini-pro": (0.00025, 0.0005),
        }

        # Find matching pricing
        for model_prefix, (input_price, output_price) in pricing.items():
            if model_prefix in self.model.lower():
                input_cost = (input_tokens / 1000) * input_price
                output_cost = (output_tokens / 1000) * output_price
                return input_cost + output_cost

        # Default estimate
        return (input_tokens + output_tokens) / 1000 * 0.002
