import { test } from "node:test";
import assert from "node:assert/strict";
import { executorState, executorTimeLeft, isExecutorReady } from "../src/lib/executors.ts";

const now = Date.parse("2026-11-08T12:00:00Z");
const connected = {
  id: 1,
  name: "VPS",
  transport: "agent",
  status: "verified",
  host_key: "trusted",
  agent_connected: true,
  agent_expires_at: new Date(now + 7 * 86400000).toISOString(),
};
test("executor states and precise expiry never present unusable access as connected", () => {
  assert.equal(executorState(undefined, true, now), "No VPS selected");
  assert.equal(executorState(connected, true, now), "Connected");
  assert.equal(executorTimeLeft(connected, now), "Expires in 7 days");
  assert.equal(isExecutorReady(connected, true, now), true);
  const soon = { ...connected, agent_expires_at: new Date(now + 30 * 60000).toISOString() };
  assert.equal(executorState(soon, true, now), "Expiring soon");
  assert.equal(isExecutorReady(soon, true, now), true);
  const expired = { ...soon, agent_expires_at: new Date(now).toISOString() };
  assert.equal(executorState(expired, true, now), "Expired");
  assert.equal(isExecutorReady(expired, true, now), false);
  assert.equal(executorTimeLeft(expired, now), "Access expired");
  assert.equal(executorState({ ...connected, agent_connected: false }, true, now), "Disconnected");
  assert.equal(isExecutorReady({ ...connected, agent_connected: false }, true, now), false);
  assert.equal(executorState({ ...connected, status: "failed" }, true, now), "Needs attention");
  assert.equal(isExecutorReady({ ...connected, agent_expires_at: "invalid" }, true, now), false);
  assert.equal(isExecutorReady({ ...connected, host_key: "" }, true, now), false);
  assert.equal(executorState({ ...connected, transport: "ssh" }, true, now), "Legacy SSH");
  assert.equal(isExecutorReady({ ...connected, transport: "ssh" }, true, now), false);
  assert.equal(isExecutorReady({ ...connected, transport: "ssh" }, false, now), true);
});
