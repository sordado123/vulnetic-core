import { readdirSync, readFileSync, renameSync } from "node:fs";
import { join, relative, resolve, sep } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";

export function normalizeStaticExport(root) {
  function visit(directory, segmentRoot) {
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      const source = join(directory, entry.name);
      if (entry.isDirectory()) {
        visit(source, segmentRoot ?? (entry.name.startsWith("__next.") ? directory : undefined));
      } else if (segmentRoot && entry.isFile() && entry.name.endsWith(".txt")) {
        // Next's Windows export uses backslashes where its client expects dots (vercel/next.js#85374).
        const target = join(segmentRoot, relative(segmentRoot, source).split(sep).join("."));
        try {
          if (!readFileSync(target).equals(readFileSync(source))) throw new Error(`Conflicting prefetch file: ${target}`);
        } catch (error) {
          if (error.code !== "ENOENT") throw error;
        }
        renameSync(source, target);
      }
    }
  }
  visit(root);
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  const web = fileURLToPath(new URL("..", import.meta.url));
  const result = spawnSync(process.execPath, [join(web, "node_modules/next/dist/bin/next"), "build"], {
    cwd: web, stdio: "inherit", env: { ...process.env, NEXT_EXPORT: "1" },
  });
  if (result.error) throw result.error;
  if (result.status !== 0) process.exit(result.status ?? 1);
  normalizeStaticExport(join(web, "out"));
}
