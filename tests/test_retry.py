"""Unit tests for the shared provider retry (D-042, D-048): rate limits get their own budget, other errors 7 tries."""
import sys, pathlib

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "experiments/harness"))
import retry


class RateLimitError(Exception):
    pass


class StreamCutError(Exception):
    pass


class Resp:
    def __init__(self, ra): self.headers = {"retry-after": ra} if ra else {}


def flaky(errors):
    calls = []
    def fn():
        calls.append(1)
        if errors: raise errors.pop(0)
        return "ok"
    return fn, calls


@pytest.fixture
def slept(monkeypatch):
    s = []
    monkeypatch.setattr(retry.time, "sleep", s.append)
    return s


def test_rate_limits_do_not_use_up_tries(slept):
    fn, calls = flaky([RateLimitError("Error code: 429")] * 20)
    assert retry.with_retry(fn, tries=3) == "ok" and len(calls) == 21
    assert max(slept) <= 600 * 1.2


def test_rate_limit_budget_exhausted_raises(slept):
    fn, _ = flaky([RateLimitError("429")] * 1000)
    with pytest.raises(RateLimitError):
        retry.with_retry(fn, rl_window=3600)
    assert sum(slept) <= 3600


def test_retry_after_header_honoured(slept):
    e = RateLimitError("Error code: 429"); e.response = Resp("42")
    fn, _ = flaky([e])
    assert retry.with_retry(fn) == "ok" and slept == [42.0]


def test_other_transient_errors_keep_try_limit(slept):
    fn, calls = flaky([StreamCutError("cut")] * 10)
    with pytest.raises(StreamCutError):
        retry.with_retry(fn, tries=7)
    assert len(calls) == 7


def test_empty_choices_retried(slept):
    fn, calls = flaky([ValueError("API returned empty choices. Model: m")] * 2)
    assert retry.with_retry(fn) == "ok" and len(calls) == 3


def test_model_gone_raises_at_once(slept):
    fn, calls = flaky([ValueError("Error code: 410 - Gone")])
    with pytest.raises(ValueError):
        retry.with_retry(fn)
    assert len(calls) == 1 and slept == []


def test_non_transient_raises_at_once(slept):
    fn, calls = flaky([ValueError("bad request")])
    with pytest.raises(ValueError):
        retry.with_retry(fn)
    assert len(calls) == 1 and slept == []
