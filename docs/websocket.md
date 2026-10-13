# WebSocket traffic in v1

Known finding: in v1, OpenBox does not give a verdict on WebSocket messages.
Once a WebSocket connection is open, its messages pass through without an
OpenBox verdict.

## What is governed

**The upgrade request.** A sandbox opens a WebSocket with an HTTP request
(`Upgrade: websocket`). OpenShell sends that request to the door guard like any
other HTTP request, before it contacts the destination. The door guard asks
OpenBox Core for a verdict:

- Core blocks or halts it: the upgrade is denied and no connection opens.
- Core asks for approval: the upgrade is denied with
  `openbox_approval_required`, and the identical retry follows the usual
  approval contract (`docs/agent-approvals.md`).
- Core allows it: the connection opens.

So OpenBox still decides whether a sandbox may talk to a WebSocket endpoint at
all, by host, path, query and headers.

## What is not governed

**The messages.** After the upgrade, OpenShell asks the door guard whether to
inspect the session. The door guard answers `SKIP`. OpenShell then passes every
message on that connection without asking the door guard again:

- text messages from the sandbox: no verdict, not recorded in OpenBox
- binary messages and messages from the destination: OpenShell never sends
  these to any middleware

The door guard's answer carries a finding, type `openbox.coverage`, label
`websocket_not_inspected`, so the gap shows in the evidence rather than
staying silent. OpenShell also logs the skip in its OCSF log as a WebSocket
middleware event.

## What this means

An agent that is allowed to open a WebSocket can send anything over it. If a
WebSocket endpoint can do something you want governed per action, either:

- deny the upgrade for that host in OpenBox policy, or
- reach the same service over HTTP or MCP, where every request gets a verdict.

## Why

OpenShell can send each outgoing text message to the middleware. Giving each
one a Core verdict needs a model of WebSocket actions (which message is a tool
call, which is chatter) that we have not built, and a Core round trip of
seconds per message would stall most WebSocket protocols. Per-message verdicts
are out of scope for v1.
