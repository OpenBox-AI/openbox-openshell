"""Retry helper for agents in an OpenShell sandbox governed by OpenBox.

OpenShell cannot hold a request while a person decides, so OpenBox answers
"needs approval" with a 403 and expects the agent to send the identical
request again later (docs/agent-approvals.md). This module does that for any
HTTP client:

    from openbox_retry import with_openbox_retry

    response = with_openbox_retry(
        lambda: requests.post(url, json=payload, timeout=60),
        on_wait=lambda code, waited: print(f"waiting for approval ({waited:.0f}s)"),
    )

`send` must send the *same* request every time: the approval is matched on
the method, URL, query and body (headers do not count). Build the request
once, outside the lambda, and do not put a timestamp or nonce in the body.

Works with `requests`, `httpx` and `urllib` responses, or anything with a
`status_code` (or `status`) and a JSON body.

No dependencies. MIT licence, like the rest of openbox-openshell.
"""

from __future__ import annotations

import json
import random
import time
from dataclasses import dataclass
from typing import Any, Callable, Optional, TypeVar

T = TypeVar("T")

APPROVAL_REQUIRED = "openbox_approval_required"
PENDING = "openbox_pending"
BLOCKED = "openbox_blocked"
HALTED = "openbox_halted"
UNAVAILABLE = "openbox_unavailable"
CONSTRAIN_FAILED = "openbox_constrain_failed"
RESPONSE_BLOCKED = "openbox_response_blocked"

# Codes worth sending the identical request again for.
RETRY_CODES = {APPROVAL_REQUIRED, PENDING, UNAVAILABLE}


class OpenBoxDenied(Exception):
    """OpenBox denied the request and retrying will not help (or the wait
    ran out). `code` is the reason code; `response` the last response."""

    def __init__(self, code: str, response: Any, waited: float = 0.0):
        super().__init__(f"OpenBox denied the request: {code}")
        self.code = code
        self.response = response
        self.waited = waited


@dataclass
class RetryPolicy:
    # Between retries while a person decides. Each retry costs a call to
    # OpenBox, and approvals take a person's time: 10 to 30 s is right.
    approval_interval: float = 15.0
    # A verdict still being worked out (W3's openbox_pending): sooner.
    pending_interval: float = 2.0
    # OpenBox unreachable or slow: exponential backoff from this, capped.
    unavailable_first: float = 2.0
    unavailable_max: float = 60.0
    # Give up after this long in total (the default approval window is 30 min).
    max_wait: float = 1800.0


def reason_code(response: Any) -> Optional[str]:
    """The OpenBox reason code of a denied response, or None."""
    status = getattr(response, "status_code", None)
    if status is None:
        status = getattr(response, "status", None)
    if status != 403:
        return None
    body: Any = None
    try:
        body = response.json()
    except Exception:  # noqa: BLE001 - any client, any failure: read the text
        text = getattr(response, "text", None)
        if callable(text):
            text = text()
        if text is None and hasattr(response, "read"):
            text = response.read()
        if isinstance(text, (bytes, bytearray)):
            text = text.decode("utf-8", "replace")
        try:
            body = json.loads(text) if text else None
        except ValueError:
            body = None
    if isinstance(body, dict):
        code = body.get("reason_code")
        if isinstance(code, str) and code.startswith("openbox_"):
            return code
    return None


def with_openbox_retry(
    send: Callable[[], T],
    policy: RetryPolicy = RetryPolicy(),
    on_wait: Optional[Callable[[str, float], None]] = None,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
) -> T:
    """Sends the request, retrying the identical request while OpenBox waits
    for an approval or is unavailable. Returns the first response that is not
    an OpenBox denial. Raises OpenBoxDenied for blocked, halted and the other
    final codes, or when `policy.max_wait` runs out."""
    started = clock()
    backoff = policy.unavailable_first
    while True:
        response = send()
        code = reason_code(response)
        if code is None:
            return response
        waited = clock() - started
        if code not in RETRY_CODES:
            raise OpenBoxDenied(code, response, waited)
        if code == APPROVAL_REQUIRED:
            delay = policy.approval_interval
        elif code == PENDING:
            delay = policy.pending_interval
        else:
            delay = min(backoff, policy.unavailable_max) * (0.8 + 0.4 * random.random())
            backoff = min(backoff * 2, policy.unavailable_max)
        if waited + delay > policy.max_wait:
            raise OpenBoxDenied(code, response, waited)
        if on_wait is not None:
            on_wait(code, waited)
        sleep(delay)
