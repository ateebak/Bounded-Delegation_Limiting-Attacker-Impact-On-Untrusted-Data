"""Shared retry for provider calls (D-042). NIM's per-model rate limits differ (stage 4: nemotron returned 429 for most
calls with 6 parallel lanes; deepseek returned 504). Transient errors (429, 5xx, timeouts, connection resets) are
retried with exponential backoff (404 too: NIM returned 404 for every request during an 8-minute outage on
2026-10-14, which erased 58 stage-9 CaMeL episodes; and streams NIM cut off mid-generation, 2026-10-23; and empty-choices responses, D-049); every retry is printed so it shows in the lane log, and a call that still fails
after `tries` is re-raised (the episode then records a harness error, never a silent change)."""
import random, sys, time

TRANSIENT = ("RateLimitError", "InternalServerError", "APITimeoutError", "APIConnectionError", "ServiceUnavailableError",
             "Timeout", "ReadTimeout", "ConnectError", "RemoteProtocolError",
             "StreamCutError")  # NIM ending a streamed generation without finish_reason (runner NIM_STREAM, D-048)


def is_transient(e):
    n = type(e).__name__
    s = str(e)[:200]
    return n in TRANSIENT or any(code in s for code in ("Error code: 429", "Error code: 500", "Error code: 502",
                                                       "Error code: 503", "Error code: 504", "Error code: 404",
                                                       "status_code: 429", "API returned empty choices"))


def is_rate_limit(e):
    return type(e).__name__ == "RateLimitError" or any(c in str(e)[:200] for c in ("Error code: 429", "status_code: 429"))


def retry_after(e):
    """Seconds from a Retry-After header on the error's response, if the provider sent one."""
    try:
        return float(e.response.headers.get("retry-after"))
    except Exception:
        return None


def with_retry(fn, *a, tries=7, base=10, cap=180, label="call", rl_window=6 * 3600, rl_cap=600, **k):
    """Rate limits (429) have their own budget: they don't use up `tries`, back off to `rl_cap` with jitter (parallel
    lanes on one NIM model must not retry in lockstep), honour Retry-After, and give up only after `rl_window` seconds
    of waiting in total (stage 9: glm-5.3 returned 429 for 18 h on 2026-10-18; 7 short tries lost 29 episodes)."""
    i = rl = 0
    waited = 0.0
    while True:
        try:
            return fn(*a, **k)
        except Exception as e:
            if is_rate_limit(e):
                ra = retry_after(e)
                wait = min(3600, ra) if ra else min(rl_cap, base * 2 ** rl) * random.uniform(0.8, 1.2)
                if waited + wait > rl_window:
                    raise
                rl += 1
                waited += wait
                print(f"[retry] {label}: rate limited ({str(e)[:80]!r}); 429 #{rl}, {waited / 60:.0f} of "
                      f"{rl_window / 60:.0f} min budget used, sleeping {wait:.0f}s", file=sys.stderr, flush=True)
                time.sleep(wait)
                continue
            if not is_transient(e) or i == tries - 1:
                raise
            wait = min(cap, base * 2 ** i)
            print(f"[retry] {label}: {type(e).__name__} ({str(e)[:80]!r}); attempt {i + 1}/{tries}, sleeping {wait}s",
                  file=sys.stderr, flush=True)
            time.sleep(wait)
            i += 1
