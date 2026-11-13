import json
import unittest

from openbox_retry import (
    APPROVAL_REQUIRED,
    BLOCKED,
    HALTED,
    UNAVAILABLE,
    OpenBoxDenied,
    RetryPolicy,
    reason_code,
    with_openbox_retry,
)


class Response:
    def __init__(self, status, body):
        self.status_code = status
        self._body = body

    def json(self):
        return json.loads(self._body)


def denied(code):
    return Response(403, json.dumps({"error": "middleware_denied", "middleware": "openbox", "reason_code": code}))


class Clock:
    def __init__(self):
        self.now = 0.0
        self.sleeps = []

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.now += seconds

    def __call__(self):
        return self.now


def run(responses, policy=RetryPolicy()):
    clock = Clock()
    sent = []

    def send():
        sent.append(1)
        return responses.pop(0)

    try:
        result = with_openbox_retry(send, policy, sleep=clock.sleep, clock=clock)
    except OpenBoxDenied as error:
        result = error
    return result, len(sent), clock.sleeps


class RetryTest(unittest.TestCase):
    def test_retries_the_identical_request_until_approved(self):
        ok = Response(200, "{}")
        result, sent, sleeps = run([denied(APPROVAL_REQUIRED), denied(APPROVAL_REQUIRED), ok])
        self.assertIs(result, ok)
        self.assertEqual(sent, 3)
        self.assertEqual(sleeps, [15.0, 15.0])

    def test_blocked_and_halted_are_final(self):
        for code in (BLOCKED, HALTED):
            result, sent, sleeps = run([denied(code)])
            self.assertIsInstance(result, OpenBoxDenied)
            self.assertEqual(result.code, code)
            self.assertEqual((sent, sleeps), (1, []))

    def test_unavailable_backs_off_with_a_cap(self):
        policy = RetryPolicy(unavailable_first=2, unavailable_max=8)
        responses = [denied(UNAVAILABLE)] * 5 + [Response(200, "{}")]
        result, sent, sleeps = run(responses, policy)
        self.assertEqual(result.status_code, 200)
        self.assertEqual(sent, 6)
        for got, base in zip(sleeps, [2, 4, 8, 8, 8]):
            self.assertTrue(0.8 * base <= got <= 1.2 * base, (got, base))

    def test_gives_up_after_max_wait(self):
        policy = RetryPolicy(approval_interval=10, max_wait=25)
        result, sent, _ = run([denied(APPROVAL_REQUIRED)] * 10, policy)
        self.assertIsInstance(result, OpenBoxDenied)
        self.assertEqual(result.code, APPROVAL_REQUIRED)
        self.assertEqual(sent, 3)

    def test_other_403s_are_not_openbox(self):
        self.assertIsNone(reason_code(Response(403, '{"error": "forbidden"}')))
        self.assertIsNone(reason_code(Response(403, "<html>no</html>")))
        self.assertIsNone(reason_code(Response(500, json.dumps({"reason_code": BLOCKED}))))
        self.assertEqual(reason_code(denied(BLOCKED)), BLOCKED)


if __name__ == "__main__":
    unittest.main()
