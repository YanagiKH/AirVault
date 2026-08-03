import { startRelay } from "./server";

function parseOrigins(value: string | undefined): string[] {
  return value?.split(",").map((item) => item.trim()).filter(Boolean) ?? [];
}

if (require.main === module) {
  const portValue = process.env.AIRVAULT_RELAY_PORT ?? "8787";
  const maxConnectionsValue = process.env.AIRVAULT_MAX_CONNECTIONS ?? "1000";
  const port = Number.parseInt(portValue, 10);
  const host = process.env.AIRVAULT_RELAY_HOST ?? "0.0.0.0";
  const maxConnections = Number.parseInt(maxConnectionsValue, 10);
  if (!/^\d{1,5}$/.test(portValue) || !/^\d{1,6}$/.test(maxConnectionsValue)
      || !Number.isSafeInteger(port) || port < 0 || port > 65_535
      || !Number.isSafeInteger(maxConnections) || maxConnections < 1 || maxConnections > 100_000) {
    throw new Error("Invalid relay port or connection limit");
  }
  startRelay({ host, port, maxConnections, allowedOrigins: parseOrigins(process.env.AIRVAULT_ALLOWED_ORIGINS) })
    .then((relay) => process.stdout.write(`AirVault relay listening on ${relay.host}:${relay.port}\n`))
    .catch((error: unknown) => {
      process.stderr.write(`Relay startup failed: ${error instanceof Error ? error.message : "unknown error"}\n`);
      process.exitCode = 1;
    });
}

export { startRelay } from "./server";
