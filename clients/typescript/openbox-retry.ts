// Retry helper for agents in an OpenShell sandbox governed by OpenBox.
//
// OpenShell cannot hold a request while a person decides, so OpenBox answers
// "needs approval" with a 403 and expects the agent to send the identical
// request again later (docs/agent-approvals.md). This module does that for
// `fetch`:
//
//   import { withOpenBoxRetry } from "./openbox-retry.ts";
//   const body = JSON.stringify(payload);            // build it once
//   const response = await withOpenBoxRetry(
//     () => fetch(url, { method: "POST", body, headers }),
//     { onWait: (code, waitedMs) => console.log(`waiting: ${code}`) },
//   );
//
// `send` must send the same request every time: the approval is matched on
// the method, URL, query and body (headers do not count). Do not put a
// timestamp or nonce in the body.
//
// No dependencies. MIT licence, like the rest of openbox-openshell.

export const APPROVAL_REQUIRED = "openbox_approval_required";
export const PENDING = "openbox_pending";
export const BLOCKED = "openbox_blocked";
export const HALTED = "openbox_halted";
export const UNAVAILABLE = "openbox_unavailable";
export const CONSTRAIN_FAILED = "openbox_constrain_failed";
export const RESPONSE_BLOCKED = "openbox_response_blocked";

const RETRY_CODES = new Set([APPROVAL_REQUIRED, PENDING, UNAVAILABLE]);

export interface RetryPolicy {
  /** Between retries while a person decides; 10 to 30 s is right. */
  approvalIntervalMs: number;
  /** A verdict still being worked out (openbox_pending). */
  pendingIntervalMs: number;
  /** OpenBox unreachable or slow: exponential backoff from this, capped. */
  unavailableFirstMs: number;
  unavailableMaxMs: number;
  /** Give up after this long in total (the default approval window is 30 min). */
  maxWaitMs: number;
  onWait?: (code: string, waitedMs: number) => void;
  sleep?: (ms: number) => Promise<void>;
  now?: () => number;
}

export const DEFAULT_POLICY: RetryPolicy = {
  approvalIntervalMs: 15_000,
  pendingIntervalMs: 2_000,
  unavailableFirstMs: 2_000,
  unavailableMaxMs: 60_000,
  maxWaitMs: 1_800_000,
};

/** OpenBox denied the request and retrying will not help (or the wait ran out). */
export class OpenBoxDenied extends Error {
  readonly code: string;
  readonly response: Response;
  readonly waitedMs: number;

  constructor(code: string, response: Response, waitedMs: number) {
    super(`OpenBox denied the request: ${code}`);
    this.name = "OpenBoxDenied";
    this.code = code;
    this.response = response;
    this.waitedMs = waitedMs;
  }
}

/** The OpenBox reason code of a denied response, or undefined. Reads a clone,
 * so the caller can still read the body. */
export async function reasonCode(response: Response): Promise<string | undefined> {
  if (response.status !== 403) return undefined;
  try {
    const body = (await response.clone().json()) as { reason_code?: unknown };
    const code = body?.reason_code;
    return typeof code === "string" && code.startsWith("openbox_") ? code : undefined;
  } catch {
    return undefined;
  }
}

/** Sends the request, retrying the identical request while OpenBox waits for
 * an approval or is unavailable. Resolves with the first response that is not
 * an OpenBox denial; rejects with OpenBoxDenied for blocked, halted and the
 * other final codes, or when maxWaitMs runs out. */
export async function withOpenBoxRetry(
  send: () => Promise<Response>,
  options: Partial<RetryPolicy> = {},
): Promise<Response> {
  const policy = { ...DEFAULT_POLICY, ...options };
  const sleep = policy.sleep ?? ((ms: number) => new Promise<void>((done) => setTimeout(done, ms)));
  const now = policy.now ?? (() => Date.now());
  const started = now();
  let backoff = policy.unavailableFirstMs;
  for (;;) {
    const response = await send();
    const code = await reasonCode(response);
    if (code === undefined) return response;
    const waited = now() - started;
    if (!RETRY_CODES.has(code)) throw new OpenBoxDenied(code, response, waited);
    let delay: number;
    if (code === APPROVAL_REQUIRED) {
      delay = policy.approvalIntervalMs;
    } else if (code === PENDING) {
      delay = policy.pendingIntervalMs;
    } else {
      delay = Math.min(backoff, policy.unavailableMaxMs) * (0.8 + 0.4 * Math.random());
      backoff = Math.min(backoff * 2, policy.unavailableMaxMs);
    }
    if (waited + delay > policy.maxWaitMs) throw new OpenBoxDenied(code, response, waited);
    policy.onWait?.(code, waited);
    await sleep(delay);
  }
}
