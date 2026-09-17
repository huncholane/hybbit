// Line-oriented RPC over stdin/stdout so a Rust test can alternate calls between
// Node's real identity code and the Rust port against the same parity stores.
// Responses are single lines prefixed with "RPC " (pino logs share stdout).
import { createInterface } from "node:readline";
import path from "node:path";
import { fileURLToPath } from "node:url";

// The Node backend whose code is the spec. It needs node_modules, so point
// HYGO_SERVER_DIR at a checkout that has them when running from a worktree.
const SERVER_DIR = process.env.HYGO_SERVER_DIR ?? path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../../../../server");
const server = (relative: string) => import(path.join(SERVER_DIR, relative));
const { identityRedis, sessionRedis, stickyResolve } = await server("src/db/redis/redis.ts");
const { sessionsService } = await server("src/services/sessions/sessionsService.ts");
const { handleIdentify } = await server("src/services/tracker/identifyService.ts");
const { identityBackfillQueue } = await server("src/services/tracker/identityBackfillQueue.ts");
const { resolveStickyUserId } = await server("src/services/userId/stickyUserId.ts");
const { userIdService } = await server("src/services/userId/userIdService.ts");

async function waitReady(client: { status: string }) {
  for (let i = 0; i < 200 && client.status !== "ready"; i++) await new Promise(resolve => setTimeout(resolve, 25));
}

async function handle(message: any): Promise<unknown> {
  switch (message.op) {
    case "ready": {
      await waitReady(identityRedis);
      await waitReady(sessionRedis);
      return {
        stickyResolveSha: (identityRedis as any).scriptsSet.stickyResolve.sha,
        sessionGetOrCreateSha: (sessionRedis as any).scriptsSet.sessionGetOrCreate.sha,
        sessionRefreshSha: (sessionRedis as any).scriptsSet.sessionRefresh.sha,
      };
    }
    case "stickyRaw":
      return await stickyResolve(message.input);
    case "sticky": {
      const { eligible, ...input } = message.input;
      return await resolveStickyUserId({ ...input, isDatacenterEgress: () => eligible });
    }
    case "userId":
      return await userIdService.generateUserId(message.ip, message.ua, message.siteId, {
        ...(message.salted === null ? {} : { saltUserIds: message.salted }),
        ...(message.receivedAt ? { receivedAt: new Date(message.receivedAt) } : {}),
      });
    case "updateSession":
      return await sessionsService.updateSession(message.input);
    case "refreshSession":
      return await sessionsService.refreshSession(message.input);
    case "identify": {
      const headers: Record<string, string> = {};
      if (message.userAgentHeader !== null) headers["user-agent"] = message.userAgentHeader;
      if (message.clientIp !== null) headers["x-real-ip"] = message.clientIp;
      const request = { body: message.missingBody ? undefined : message.body, headers, ip: "127.0.0.1", socket: { remoteAddress: "127.0.0.1" } };
      const reply = {
        statusCode: 200,
        payload: undefined as unknown,
        status(code: number) {
          this.statusCode = code;
          return this;
        },
        send(payload: unknown) {
          this.payload = payload;
          return this;
        },
      };
      await handleIdentify(request as any, reply as any);
      return { status: reply.statusCode, body: reply.payload };
    }
    case "backfillPending": {
      const out = [];
      for (const [days, group] of (identityBackfillQueue as any).pending as Map<number | null, Map<string, any>>) {
        for (const entry of group.values()) out.push({ days, siteId: entry.siteId, anonymousId: entry.anonymousId, userId: entry.userId, attempts: entry.attempts });
      }
      return out;
    }
    case "backfillReset":
      (identityBackfillQueue as any).pending = new Map();
      return true;
    case "backfillEnqueue":
      identityBackfillQueue.enqueue(message.assignment, message.days);
      return true;
    case "backfillFlush":
      await identityBackfillQueue.flush();
      return true;
    case "exit":
      setTimeout(() => process.exit(0), 10);
      return true;
    default:
      throw new Error(`unknown op ${message.op}`);
  }
}

const lines = createInterface({ input: process.stdin });
let queue = Promise.resolve();
lines.on("line", line => {
  // Serialise calls so ordering matches the Rust driver exactly
  queue = queue.then(async () => {
    const message = JSON.parse(line);
    try {
      const result = await handle(message);
      process.stdout.write(`RPC ${JSON.stringify({ id: message.id, result: result ?? null })}\n`);
    } catch (error) {
      process.stdout.write(`RPC ${JSON.stringify({ id: message.id, error: String((error as Error)?.stack ?? error) })}\n`);
    }
  });
});
lines.on("close", () => setTimeout(() => process.exit(0), 50));
