"""Offline deterministic provider.

Zero external dependencies. Generates grounded answers from provided context
so the full pipeline (gateway -> RAG -> evals) runs in CI and local dev with
no API keys. Deterministic output = reproducible eval scores."""

import hashlib
import time

from aegis.providers.base import BaseProvider, Completion


class EchoProvider(BaseProvider):
    name = "echo"

    async def complete(self, messages: list[dict], model: str, max_tokens: int) -> Completion:
        start = time.perf_counter()
        system = next((m["content"] for m in messages if m["role"] == "system"), "")
        user_msgs = [m["content"] for m in messages if m["role"] == "user"]
        question = user_msgs[-1] if user_msgs else ""

        # Grounded mode: if context blocks are present, answer from them only.
        answer = self._compose(system, question)

        input_tokens = sum(len(str(m.get("content", ""))) // 4 + 1 for m in messages)
        output_tokens = len(answer) // 4 + 1
        latency = (time.perf_counter() - start) * 1000
        return Completion(
            text=answer,
            model=model,
            provider=self.name,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            latency_ms=round(latency, 2),
        )

    def _compose(self, system: str, question: str) -> str:
        context_blocks = []
        for line in system.splitlines():
            if line.startswith("[") and "]" in line:
                context_blocks.append(line)

        if context_blocks:
            cited = "\n".join(context_blocks[:3])
            return (
                "Based on the retrieved sources:\n"
                f"{cited}\n\n"
                f"Answering '{question.strip()[:200]}': the relevant passages above "
                f"(cited by [source id]) contain the requested information."
            )

        digest = hashlib.sha256(question.encode()).hexdigest()[:8]
        return f"[echo:{digest}] {question.strip()[:400]}"
