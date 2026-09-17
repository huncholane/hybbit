// A Fastify 5.8.5 instance configured like server/src/index.ts where it matters for
// POST /api/track before any store is touched: same factory options, the real /api
// error rewrite, and trackEvent's validation step. Valid payloads echo the parsed data
// instead of being ingested. /api/ipecho reports the client IP helpers.
import { createRequire } from "node:module";
import { registerApiErrorResponses } from "../../../server/src/lib/api-errors.ts";
import { collectCandidateClientIps, resolveClientIp } from "../../../server/src/services/tracker/resolveClientIp.ts";
import { trackingPayloadSchema } from "../../../server/src/services/tracker/trackingPayload.ts";
import { getIpAddress, getRequestUserAgent } from "../../../server/src/utils.ts";

const require = createRequire(new URL("../../../server/package.json", import.meta.url));
const Fastify = require("fastify");

const PORT = Number(process.argv[2] ?? 38101);

const server = Fastify({
  disableRequestLogging: true,
  logger: false,
  maxParamLength: 1500,
  trustProxy: true,
  bodyLimit: 10 * 1024 * 1024,
});
registerApiErrorResponses(server);

const encode = (data: unknown) =>
  JSON.stringify(data, function (key, value) {
    if (typeof value === "string") return value.toWellFormed();
    if (typeof value !== "number") return value;
    if (Object.is(value, -0) && key !== "_bs" && key !== "_bsm") return "num:-0";
    return `num:${String(value)}`;
  });

server.post("/api/track", async (request: any, reply: any) => {
  const validationResult = trackingPayloadSchema.safeParse(request.body);
  if (!validationResult.success) {
    return reply.status(400).send({
      success: false,
      error: "Invalid payload",
      details: validationResult.error.flatten(),
    });
  }
  return reply.status(200).send({ success: true, harness: encode(validationResult.data) });
});

server.post("/api/ipecho", async (request: any, reply: any) => {
  const resolvedDirect = resolveClientIp(request, { proxiedEdge: () => false });
  return reply.status(200).send({
    requestIp: request.ip,
    getIpAddress: getIpAddress(request),
    userAgent: getRequestUserAgent(request.headers),
    resolvedDirect,
    resolvedProxied: resolveClientIp(request, { proxiedEdge: () => true }),
    resolvedFirstParty: resolveClientIp(request, { firstPartyProxy: true }),
    candidates: collectCandidateClientIps(request, [resolvedDirect]),
  });
});

await server.listen({ port: PORT, host: "127.0.0.1" });
console.log(`harness listening on ${PORT}`);
