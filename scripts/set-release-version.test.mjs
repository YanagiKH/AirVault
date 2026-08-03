import assert from "node:assert/strict";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";

const scriptPath = resolve("scripts/set-release-version.mjs");

async function temporaryManifest() {
  const directory = await mkdtemp(join(tmpdir(), "airvault-release-version-"));
  const manifestPath = join(directory, "package.json");
  const manifest = {
    name: "@airvault/desktop",
    version: "0.1.0",
    dependencies: { "@airvault/protocol": "0.1.0" }
  };
  await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, "utf8");
  return manifestPath;
}

test("updates only the package version without resolving workspace dependencies", async () => {
  const manifestPath = await temporaryManifest();
  const result = spawnSync(process.execPath, [scriptPath, "1.2.3", manifestPath], { encoding: "utf8" });

  assert.equal(result.status, 0, result.stderr);
  const updated = JSON.parse(await readFile(manifestPath, "utf8"));
  assert.equal(updated.version, "1.2.3");
  assert.deepEqual(updated.dependencies, { "@airvault/protocol": "0.1.0" });
});

test("rejects invalid release versions without changing the manifest", async () => {
  const manifestPath = await temporaryManifest();
  const before = await readFile(manifestPath, "utf8");
  const result = spawnSync(process.execPath, [scriptPath, "v1/latest", manifestPath], { encoding: "utf8" });

  assert.notEqual(result.status, 0);
  assert.equal(await readFile(manifestPath, "utf8"), before);
});
