import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { lstat } from "node:fs/promises";
import { basename } from "node:path";
import { MAX_FILE_COUNT, MAX_TOTAL_BYTES, scanManifest, type FileManifestEntry } from "@airvault/protocol";

export async function buildManifest(paths: string[]): Promise<FileManifestEntry[]> {
  const unique = [...new Set(paths)];
  if (unique.length === 0 || unique.length > MAX_FILE_COUNT) throw new Error(`Select between 1 and ${MAX_FILE_COUNT} regular files`);
  const output: FileManifestEntry[] = [];
  let total = 0;
  for (const path of unique) {
    const info = await lstat(path);
    if (!info.isFile() || info.isSymbolicLink()) throw new Error(`${basename(path)} is not a regular file`);
    total += info.size;
    if (!Number.isSafeInteger(total) || total > MAX_TOTAL_BYTES) throw new Error("The transfer exceeds the 100 GiB safety limit");
    output.push({
      name: basename(path),
      relativePath: basename(path),
      size: info.size,
      sha256: await sha256File(path),
    });
  }
  const result = scanManifest(output);
  if (!result.safe) throw new Error(result.findings.map((finding) => `${finding.file}: ${finding.reason}`).join("; "));
  return output;
}

export async function sha256File(path: string): Promise<string> {
  const hash = createHash("sha256");
  await new Promise<void>((resolve, reject) => {
    const stream = createReadStream(path);
    stream.on("data", (chunk) => hash.update(chunk));
    stream.once("error", reject);
    stream.once("end", resolve);
  });
  return hash.digest("hex");
}
