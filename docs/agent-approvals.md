# Approvals: guidance for agents

This page is for people who write agents that run in an OpenShell sandbox
governed by OpenBox. It explains what your agent sees when a request needs a
person's approval, and what it should do.

## What a denial looks like

OpenShell has no way to hold a request while a person decides. So when OpenBox
needs an approval, the request is denied at once and never reaches its
destination. Your agent receives `403 Forbidden` with this body:

```json
{
  "error": "middleware_denied",
  "detail": "Request rejected by configured middleware",
  "policy": "<network policy name>",
  "middleware": "openbox",
  "reason_code": "openbox_approval_required"
}
```

Read `reason_code`. It is the only field that tells you why. The door guard
uses four codes:

| `reason_code` | Meaning | What the agent should do |
|---|---|---|
| `openbox_approval_required` | A person must approve this action. | Tell the user, then retry the identical request later. |
| `openbox_blocked` | OpenBox policy forbids this action. | Do not retry. Choose another approach or report it. |
| `openbox_halted` | OpenBox halted this sandbox. | Stop. Every later request is denied too. |
| `openbox_unavailable` | OpenBox gave no verdict (Core unreachable or slower than 29 s). | Retry with backoff. Nothing was approved. |

If `error` is `middleware_failed` instead, the door guard did not answer at
all. Treat it like `openbox_unavailable`.

## Deny, then retry

1. Your agent sends a request. OpenBox decides it needs approval. The door
   guard denies it with `openbox_approval_required` and remembers the action.
2. A person sees the request in the OpenBox dashboard and approves or rejects
   it.
3. Your agent sends the identical request again.
   - Approved: the request goes through.
   - Still pending: denied again with `openbox_approval_required`. OpenBox does
     not score it again or open a second approval.
   - Rejected: OpenBox reports the rejection as a halt. The request is denied
     with `openbox_halted`, and the sandbox is stopped.

Retry no more often than every 10 to 30 seconds. Each retry costs one call to
OpenBox, and approvals take a person's time. Tell the user that an approval is
waiting, so they can go and give it.

## What "identical" means

The door guard matches a retry to its approval by a fingerprint of the action.
The fingerprint covers:

- the sandbox
- the scheme, host and port
- the method, path and query string
- the body. A JSON body is compared in a canonical form: object key order does
  not matter, array order does. Any other body must match byte for byte.

It leaves out what changes between two attempts without changing the action:

- every header (dates, trace ids, nonces)
- OpenShell's per-request id
- the JSON-RPC `id`, so an MCP `tools/call` retried with a new id still
  matches

Change anything the fingerprint covers, and the retry is a new action that
OpenBox scores again. It may need a new approval. In practice: resend the same
request. Do not add a timestamp to the body, reorder an array, or edit the
arguments.

A retry can arrive at any door guard replica. They share the record through
Redis, so this works across replicas.

## How long an approval waits

The door guard keeps a pending approval for as long as Core does. Core sends
its deadline with the verdict, as `approval_expiration_time`. That is the
agent's approval wait time in OpenBox, 30 minutes by default. The door guard
adds one minute for clock skew (PROD-890).

When Core sends no deadline, the door guard falls back to
`OPENBOX_APPROVAL_TTL_SECS`, 900 seconds by default. Builds without PROD-890
always use this fallback.

After the window closes, the next identical request is a new action. OpenBox
scores it again, and it may need a new approval.

If the door guard loses its record, for example because Redis restarted, the
same happens: the retry needs a new approval. A lost record never lets a
request through without one.

## What `halt` means

Halt is the strongest verdict. OpenBox halts a sandbox when policy says so, or
when a person rejects an approval.

- The request that triggered it is denied with `openbox_halted`.
- Every later request from that sandbox is denied with `openbox_halted`.
- The door guard stops the sandbox through the OpenShell gateway. It stops the
  sandbox and does not delete it, so the sandbox can be inspected and
  restarted. If the door guard has no gateway credential, it still denies all
  traffic but cannot stop the sandbox.

An agent that sees `openbox_halted` should stop work and report it. Retrying
does not help.

## Turning approvals into blocks

A sandbox policy can set `approval_mode: deny` in the `openbox` entry's
`config`. Every approval is then a block: `openbox_blocked`, with no retry
path. The default is `queue`, which this page describes.

The front desk writes `approval_mode: queue` when it creates the sandbox, so
set `deny` with a policy update afterwards. The front desk accepts `queue` or
`deny` there and refuses anything else. (PROD-892 keeps the author's
`approval_mode` at create time; until it lands, the update is the way.)
