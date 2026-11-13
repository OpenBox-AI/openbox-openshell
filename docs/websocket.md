# WebSocket traffic

OpenBox governs a WebSocket in two places: the upgrade request, with a Core
verdict like any request, and the text messages the sandbox sends, which the
door guard scores itself.

## The upgrade request

A sandbox opens a WebSocket with an HTTP request (`Upgrade: websocket`).
OpenShell sends it to the door guard before it contacts the destination, and
the door guard asks OpenBox Core for a verdict:

- Core blocks or halts it: the upgrade is denied and no connection opens.
- Core asks for approval: the upgrade is denied with
  `openbox_approval_required`, and the identical retry follows the usual
  approval contract (`docs/agent-approvals.md`).
- Core allows it: the connection opens.

So OpenBox decides whether a sandbox may talk to a WebSocket endpoint at all,
by host, path, query and headers.

## The messages

After the upgrade, OpenShell asks the door guard whether to inspect the
session. What the door guard answers is the sandbox policy's `websocket`
setting in the `openbox` middleware config:

| `websocket` | Text messages from the sandbox |
|---|---|
| `findings` (default) | Each is scanned with the detectors in "What Core receives" (`docs/install.md`). The kinds found go to OpenShell's OCSF log and to the sandbox's session in OpenBox (a `websocket_message` signal with the counts, never the message). The message is delivered unchanged. |
| `enforce` | As `findings`, and a message carrying one of `response_kinds` is denied (or, with `responses: redact`, delivered with the matches replaced). The denial's reason code `openbox_websocket_blocked` goes to OCSF; OpenShell never puts it in a close frame. |
| `skip` | Not inspected. The skip is recorded as a finding (`openbox.coverage`, `websocket_not_inspected`) so the gap shows in the evidence. |

## What is still not governed

- **Binary messages** pass unchanged: there is no text to scan.
- **Messages from the destination** are never sent to any middleware by
  OpenShell.
- **No Core verdict per message.** Messages are scored by the door guard's
  detectors, locally and in microseconds; a Core round trip of seconds per
  message would stall most WebSocket protocols. Policy on what a sandbox may
  do over a WebSocket stays at the upgrade.

If a WebSocket endpoint can do something you want governed per action,
either deny the upgrade for that host in OpenBox policy, or reach the same
service over HTTP or MCP, where every request gets a Core verdict.
