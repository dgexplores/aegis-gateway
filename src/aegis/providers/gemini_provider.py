"""Gemini via its documented OpenAI-compatible HTTP endpoint."""

from aegis.providers.groq_provider import GroqProvider


class GeminiProvider(GroqProvider):
    name = "gemini"
    env_key = "GEMINI_API_KEY"
    model_default = "gemini-2.5-flash"
    api_url = "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions"

    def extra_parameters(self, model: str) -> dict:
        return {"reasoning_effort": "none"} if model.startswith("gemini-2.5-") else {}
