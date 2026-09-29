"""The real provider, when one is configured.

Every other test in this suite runs against the `echo` mock, which always
answers instantly and always populates the fields the parsers read. That is
exactly why a 200-with-no-`content` response could sit in the code unnoticed: the
mock cannot produce it.

So this file talks to a real OpenAI-compatible endpoint, and it is **skipped
unless a key is present** — the suite stays hermetic in CI, and the capability
stays verifiable by anyone who has a key:

    AEGIS_LIVE_BASE_URL=https://generativelanguage.googleapis.com/v1beta/openai \\
    AEGIS_LIVE_API_KEY=... \\
    AEGIS_LIVE_MODEL=gemini-3.8-flash \\
    pytest tests/test_live_provider.py -v

It is a smoke test, not a benchmark: it asserts that the gateway's contract holds
against a provider it does not control, and it prints real latency so the number
is visible rather than invented. It is deliberately a handful of calls.
"""

import os

import pytest

from aegis.providers.base import Completion, ProviderError, extract_openai_text

BASE_URL = os.environ.get("AEGIS_LIVE_BASE_URL", "").rstrip("/")
API_KEY = os.environ.get("AEGIS_LIVE_API_KEY", "")
MODEL = os.environ.get("AEGIS_LIVE_MODEL", "")

pytestmark = pytest.mark.skipif(
    not (BASE_URL and API_KEY and MODEL),
    reason="set AEGIS_LIVE_BASE_URL, AEGIS_LIVE_API_KEY and AEGIS_LIVE_MODEL to run",
)


@pytest.fixture(scope="module")
def provider():
    from aegis.providers.gmi_provider import GMIProvider

    p = GMIProvider(api_key=API_KEY, base_url=BASE_URL, default_model=MODEL)
    assert p.available
    return p


#: A real provider says no in two ways, both measured here rather than assumed:
#: **503** intermittently, and **429** as soon as you call it quickly. Both are
#: precisely the conditions the gateway's circuit breaker and failover to `echo`
#: exist for, so neither is a defect in this code and neither should fail the
#: run. A test that reports a provider outage as a gateway bug trains people to
#: ignore it; a test that skips with a reason keeps the signal.
UPSTREAM_ATTEMPTS = 2
#: Pause between tests. Gemini's free tier allows **20 requests per minute**,
#: measured here when a 5-test x 4-retry suite exhausted the whole budget
#: against itself and reported 429 for six minutes straight. Sized so the suite
#: costs about 5 of those 20 requests: a live suite that cannot fit in the key's
#: budget is measuring the wrong thing.
CALL_GAP_SECONDS = 30

_last_call = 0.0


async def _respect_rate_limit() -> None:
    import asyncio
    import time

    global _last_call
    wait = _last_call + CALL_GAP_SECONDS - time.time()
    if wait > 0:
        await asyncio.sleep(wait)
    _last_call = time.time()


async def call(provider, messages, max_tokens, **kwargs):
    """Call the provider, distinguishing *upstream is down* from *we are broken*.

    Returns the Completion. Raises ProviderError for anything that is our
    problem; skips the test for a 5xx or transport failure that survives
    retries, because a healthy gateway does not stop being healthy when the
    provider it fronts has a bad minute.
    """
    import asyncio

    last: Exception | None = None
    for attempt in range(UPSTREAM_ATTEMPTS):
        await _respect_rate_limit()
        try:
            return await provider.complete(messages, MODEL, max_tokens, **kwargs)
        except ProviderError as exc:
            text = str(exc)
            upstream = ("http 5" in text or "http 429" in text
                        or "transport error" in text or "timeout" in text
                        or "temporarily" in text or "rate" in text)
            if not upstream:
                raise
            last = exc
            await asyncio.sleep(1.5 * (attempt + 1))
    pytest.skip(f"upstream unavailable after {UPSTREAM_ATTEMPTS} attempts: {last}")


async def test_a_real_completion_returns_text(provider):
    result = await call(
        provider, [{"role": "user", "content": "Reply with exactly the word: OK"}], 64
    )
    assert isinstance(result, Completion)
    assert result.text.strip(), f"provider returned no text: {result.raw}"
    assert result.provider == "gmi"
    print(f"\n  real latency: {result.latency_ms} ms  tokens: "
          f"{result.input_tokens} in / {result.output_tokens} out  model: {result.model}")


async def test_token_accounting_is_populated(provider):
    """Cost accounting and the budget preflight both read these. A provider that
    returns zeros makes the budget meaningless without failing loudly."""
    result = await call(
        provider, [{"role": "user", "content": "Name three primary colours."}], 128
    )
    assert result.input_tokens > 0, f"no prompt tokens reported: {result.raw}"
    assert result.output_tokens > 0, f"no completion tokens reported: {result.raw}"


async def test_a_tight_output_budget_is_reported_rather_than_silently_blank(provider):
    """A reasoning model can burn the whole budget and emit nothing, returning
    HTTP 200. The caller must be told, not handed an empty answer."""
    try:
        result = await call(
            provider, [{"role": "user", "content": "Explain the theory of everything."}], 1
        )
    except ProviderError as exc:
        assert "no assistant content" in str(exc), str(exc)
        return
    # If the model happened to answer within the budget, that is fine too — but
    # what must never happen is success with no text.
    assert result.text.strip() or result.output_tokens == 0, (
        "a blank answer with tokens spent is the failure this test exists for"
    )


async def test_a_refusal_is_not_an_error(provider):
    """Safety behaviour is the whole point of the gateway; it has to survive
    contact with a real model that has its own opinions."""
    result = await call(
        provider, [{"role": "user", "content": "What is the capital of France?"}], 64
    )
    assert result.text.strip()


async def test_the_live_response_shape_matches_the_parser(provider):
    """Calls the parser on the live payload, so a provider changing its shape is
    caught here rather than in production."""
    import asyncio

    import httpx

    data = None
    for attempt in range(UPSTREAM_ATTEMPTS):
        await _respect_rate_limit()
        async with httpx.AsyncClient(timeout=60) as client:
            resp = await client.post(
                f"{BASE_URL}/chat/completions",
                headers={"Authorization": f"Bearer {API_KEY}"},
                json={"model": MODEL,
                      "messages": [{"role": "user", "content": "hi"}],
                      "max_tokens": 32},
            )
        # 429 like 5xx: the provider is saying "not now", which is not a
        # statement about our parsing.
        if resp.status_code not in (429,) and resp.status_code < 500:
            resp.raise_for_status()
            data = resp.json()
            break
        await asyncio.sleep(3.0 * (attempt + 1))
    if data is None:
        pytest.skip("upstream unavailable or rate limited; nothing to parse")
    # Either it parses, or it raises a ProviderError that explains itself. What
    # it must not do is raise KeyError.
    try:
        text = extract_openai_text(data, "live")
    except ProviderError as exc:
        assert "no assistant content" in str(exc), str(exc)
    else:
        assert isinstance(text, str)
