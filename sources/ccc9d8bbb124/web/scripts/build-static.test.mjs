import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { normalizeStaticExport } from "./build-static.mjs";

test("Windows segment files match the client's flat URLs; existing exports remain intact", () => {
  const root = mkdtempSync(join(tmpdir(), "vulnetic-export-"));
  try {
    const route = join(root, "function", "findings");
    const nested = join(route, "__next.!main", "function", "findings");
    mkdirSync(nested, { recursive: true });
    writeFileSync(join(nested, "__PAGE__.txt"), "flight-payload");
    writeFileSync(join(route, "__next._tree.txt"), "tree-payload");
    writeFileSync(join(route, "index.html"), "page-html");
    normalizeStaticExport(root);
    const flat = join(route, "__next.!main.function.findings.__PAGE__.txt");
    assert.equal(readFileSync(flat, "utf8"), "flight-payload");
    assert.equal(existsSync(join(nested, "__PAGE__.txt")), false);
    normalizeStaticExport(root);
    assert.equal(readFileSync(join(route, "__next._tree.txt"), "utf8"), "tree-payload");
    assert.equal(readFileSync(join(route, "index.html"), "utf8"), "page-html");
    writeFileSync(join(nested, "__PAGE__.txt"), "flight-payload");
    normalizeStaticExport(root);
    writeFileSync(join(nested, "__PAGE__.txt"), "different-payload");
    assert.throws(() => normalizeStaticExport(root), /Conflicting prefetch file/);
    assert.equal(readFileSync(flat, "utf8"), "flight-payload");
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
