// node --experimental-strip-types --test clients/typescript/openbox-retry.test.ts
import { test } from "node:test";
import assert from "node:assert/strict";

import {
  APPROVAL_REQUIRED,
  BLOCKED,
  HALTED,
  OpenBoxDenied,
  UNAVAILABLE,
  reasonCode,
  withOpenBoxRetry,
} from "./openbox-retry.ts";

const denied = (code: string) =>
  new Response(JSON.stringify({ error: "middleware_denied", middleware: "openbox", reason_code: code }), {
    status: 403,
  });

function clock() {
  const state = { now: 0, sleeps: [] as number[] };
  return {
    state,
    now: () => state.now,
    sleep: async (ms: number) => {
      state.sleeps.push(ms);
      state.now += ms;
    },
  };
}

test("retries the identical request until approved", async () => {
  const replies = [denied(APPROVAL_REQUIRED), denied(APPROVAL_REQUIRED), new Response("ok")];
  const c = clock();
  let sent = 0;
  const response = await withOpenBoxRetry(async () => (sent++, replies.shift()!), c);
  assert.equal(await response.text(), "ok");
  assert.equal(sent, 3);
  assert.deepEqual(c.state.sleeps, [15_000, 15_000]);
});

test("blocked and halted are final", async () => {
  for (const code of [BLOCKED, HALTED]) {
    const c = clock();
    await assert.rejects(
      withOpenBoxRetry(async () => denied(code), c),
      (error: unknown) => error instanceof OpenBoxDenied && error.code === code,
    );
    assert.deepEqual(c.state.sleeps, []);
  }
});

test("unavailable backs off with a cap", async () => {
  const replies = [...Array(5)].map(() => denied(UNAVAILABLE)).concat(new Response("ok"));
  const c = clock();
  await withOpenBoxRetry(async () => replies.shift()!, { ...c, unavailableFirstMs: 2, unavailableMaxMs: 8 });
  [2, 4, 8, 8, 8].forEach((base, i) => {
    assert.ok(c.state.sleeps[i] >= 0.8 * base && c.state.sleeps[i] <= 1.2 * base);
  });
});

test("gives up after maxWaitMs", async () => {
  const c = clock();
  let sent = 0;
  await assert.rejects(
    withOpenBoxRetry(async () => (sent++, denied(APPROVAL_REQUIRED)), {
      ...c,
      approvalIntervalMs: 10,
      maxWaitMs: 25,
    }),
    OpenBoxDenied,
  );
  assert.equal(sent, 3);
});

test("other 403s are not OpenBox, and the body stays readable", async () => {
  assert.equal(await reasonCode(new Response('{"error":"forbidden"}', { status: 403 })), undefined);
  assert.equal(await reasonCode(new Response("<html/>", { status: 403 })), undefined);
  const blocked = denied(BLOCKED);
  assert.equal(await reasonCode(blocked), BLOCKED);
  assert.equal((await blocked.json()).reason_code, BLOCKED);
});
