import { readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";

const SEMVER = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/;

const [version, manifestArgument = "apps/desktop/package.json"] = process.argv.slice(2);

if (!version || !SEMVER.test(version)) {
  throw new Error(`Expected a semantic version, received: ${version ?? "<missing>"}`);
}

const manifestPath = resolve(manifestArgument);
const original = await readFile(manifestPath, "utf8");
const manifest = JSON.parse(original);

if (typeof manifest.name !== "string" || manifest.name.length === 0) {
  throw new Error(`Package manifest has no valid name: ${manifestPath}`);
}

manifest.version = version;
await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, "utf8");
console.log(`Set ${manifest.name} release version to ${version}`);
