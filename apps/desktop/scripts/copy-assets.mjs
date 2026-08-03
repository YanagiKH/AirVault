import { cpSync, mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
mkdirSync(resolve(root, "dist/renderer"), { recursive: true });
cpSync(resolve(root, "src/renderer/index.html"), resolve(root, "dist/renderer/index.html"));
cpSync(resolve(root, "src/renderer/styles.css"), resolve(root, "dist/renderer/styles.css"));
