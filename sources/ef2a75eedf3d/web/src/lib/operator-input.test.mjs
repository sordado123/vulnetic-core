import assert from "node:assert/strict";
import { test } from "node:test";
import { runInNewContext } from "node:vm";
import { cookieExportHelper } from "./operator-input.ts";

test("cookie helper is origin-bound and local-only", () => {
  const script = cookieExportHelper("https://account.example.org/login?untrusted=ignored");
  assert.ok(script.includes('const expectedOrigin = "https://account.example.org"'));
  assert.ok(script.includes("location.origin !== expectedOrigin"));
  assert.ok(script.includes("document.cookie"));
  assert.ok(script.includes("HttpOnly cookies are not included"));
  assert.ok(script.includes("link.download"));
  assert.doesNotMatch(script, /fetch\(|XMLHttpRequest|sendBeacon|localStorage|sessionStorage|untrusted/);
});

test("helper exports synthetic cookies locally and refuses a different origin", async () => {
  let download, object;
  const context = {
    location: {origin: "https://account.example.org", hostname: "account.example.org", protocol: "https:"},
    document: {cookie: "demo=fixture-only; other=with=equals", createElement: () => ({click() { download = this.download; }})},
    Blob, URL: {createObjectURL: (blob) => {object = blob; return "blob:fixture";}, revokeObjectURL: () => {}},
    setTimeout: (callback) => callback(),
  };
  runInNewContext(cookieExportHelper(context.location.origin), context);
  assert.equal(download, "vulnetic-cookies.json");
  const data = JSON.parse(await object.text());
  assert.equal(data.cookies[1].value, "with=equals");
  assert.equal(data.origin, context.location.origin);
  assert.throws(() => runInNewContext(cookieExportHelper("https://different.example.org"), context), /requested site/);
});
