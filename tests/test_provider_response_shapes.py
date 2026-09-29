"""Parsing an OpenAI-compatible response that a real provider actually sent.

These cases were captured from live Gemini 3.8 responses, not invented. They
exist because the entire 366-test suite ran against the `echo` mock, which always
answers, so the `content` key was always present and the one class of failure
that matters most in production had no coverage at all.

The headline case: a reasoning model that spends its whole output budget returns
**HTTP 200 with no `content` key**. `data["choices"][0]["message"]["content"]`
raises KeyError on that — a 500 to the caller, from a request the provider
considered successful, on an ordinary input.
"""

import pytest

from aegis.providers.base import ProviderError, extract_openai_text


def test_ordinary_string_content():
    data = {"choices": [{"message": {"content": "hello"}}]}
    assert extract_openai_text(data, "gemini") == "hello"


def test_content_as_a_list_of_parts():
    """Seen in the wild on several OpenAI-compatible endpoints."""
    data = {"choices": [{"message": {"content": [{"text": "a"}, {"text": "b"}]}}]}
    assert extract_openai_text(data, "gemini") == "ab"


def test_answer_under_text_instead_of_message():
    """Legacy completions shape."""
    data = {"choices": [{"text": "hi"}]}
    assert extract_openai_text(data, "gmi") == "hi"


def test_a_thinking_model_that_used_its_whole_budget_raises_a_readable_error():
    """The real 200-with-no-content response, verbatim in shape.

    An empty string would be worse than useless here: the caller would send the
    user a blank answer and nobody would know why.
    """
    data = {"choices": [{"finish_reason": "length", "index": 0, "message": {"role": "assistant"}}]}
    with pytest.raises(ProviderError) as exc:
        extract_openai_text(data, "gemini")
    message = str(exc.value)
    assert "no assistant content" in message
    assert "length" in message, "the finish_reason is the clue; it belongs in the error"
    assert "max_tokens" in message, "and the fix, because that is what it is"


def test_the_hint_also_fires_when_the_provider_echoes_the_reasoning():
    data = {"choices": [{"finish_reason": "length", "message": {"reasoning_content": "thinking hard..."}}]}
    with pytest.raises(ProviderError, match="raise max_tokens"):
        extract_openai_text(data, "gemini")


def test_the_hint_does_not_depend_on_a_reasoning_field_being_echoed_back():
    """Gemini does not put reasoning in `reasoning_content` on the compat layer —
    it goes into a provider-specific `extra_content` blob. Gating the hint on a
    field that is usually absent would withhold the useful message exactly when
    it is needed."""
    data = {"choices": [{"finish_reason": "length", "message": {"role": "assistant"}}]}
    with pytest.raises(ProviderError, match="raise max_tokens"):
        extract_openai_text(data, "gemini")


def test_a_missing_content_that_is_not_a_budget_problem_says_nothing_specific():
    data = {"choices": [{"finish_reason": "stop", "message": {"role": "assistant"}}]}
    with pytest.raises(ProviderError) as exc:
        extract_openai_text(data, "gemini")
    assert "max_tokens" not in str(exc.value), "do not guess at a cause"
    assert "stop" in str(exc.value)


def test_a_genuinely_empty_answer_is_still_an_empty_string():
    """`stop` with empty content is a real (if odd) answer, not a parse failure."""
    data = {"choices": [{"finish_reason": "stop", "message": {"content": ""}}]}
    assert extract_openai_text(data, "gemini") == ""


def test_a_response_with_no_choices_at_all_does_not_crash():
    data = {"choices": []}
    with pytest.raises(ProviderError, match="no assistant content"):
        extract_openai_text(data, "gemini")


def test_extra_provider_specific_keys_do_not_break_extraction():
    """Gemini attaches `extra_content` with a thought signature; a parser that
    insisted on an exact message shape would break on it."""
    data = {
        "choices": [
            {
                "finish_reason": "stop",
                "message": {"content": "ok", "extra_content": {"google": {"thought_signature": "x"}}},
            }
        ]
    }
    assert extract_openai_text(data, "gemini") == "ok"
