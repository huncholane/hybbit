// Starts the real Node backend (server/src/index.ts, unmodified) on NODE_PARITY_PORT
// instead of its hard-coded 3001, so this suite gets its own process: its own
// Better Auth rate-limit memory and TZ=UTC like production. HYGO_SERVER_DIR points at
// a server/ directory with node_modules installed (default: this checkout's).
import net from "node:net";
import { pathToFileURL } from "node:url";

const port = Number(process.env.NODE_PARITY_PORT ?? "3021");
const serverDir = process.env.HYGO_SERVER_DIR ?? new URL("../../../server", import.meta.url).pathname;
const originalListen = net.Server.prototype.listen;
net.Server.prototype.listen = function (this: net.Server, ...args: any[]) {
  if (args[0] && typeof args[0] === "object" && args[0].port === 3001) args[0] = { ...args[0], port };
  else if (args[0] === 3001) args[0] = port;
  return (originalListen as any).apply(this, args);
} as any;

await import(pathToFileURL(`${serverDir}/src/index.ts`).href);
