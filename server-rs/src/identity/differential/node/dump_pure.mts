// Computes Node's answers for the stateless identity functions over generated
// corpora and writes inputs plus answers (IDENTITY_DIFF_DIR/pure.json) for the
// Rust tests in ../pure.rs. Needs the parity stores (sites 65001 salted and 65002
// unsalted in Postgres) and BETTER_AUTH_SECRET from server-rs/parity/env.sh.
import { writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import net from "node:net";
import { UNICODE_BITS, dayBoundaryInstant, ipBucketCorpus, rng, userAgentCorpus, userIdIps, weirdUserIdIps, zoneIps } from "./corpus.mts";
import path from "node:path";
import { fileURLToPath } from "node:url";

// The Node backend whose code is the spec. It needs node_modules, so point
// HYGO_SERVER_DIR at a checkout that has them when running from a worktree.
const SERVER_DIR = process.env.HYGO_SERVER_DIR ?? path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../../../../server");
const server = (relative: string) => import(path.join(SERVER_DIR, relative));
const { lookupAsn } = await server("src/db/geolocation/asn.ts");
const { sessionsService } = await server("src/services/sessions/sessionsService.ts");
const { isDatacenterAsn } = await server("src/services/tracker/botBlocking/datacenterAsns.ts");
const { bucketIpForIdentity } = await server("src/services/userId/identityIpBucket.ts");
const { normalizeUserAgentForIdentity } = await server("src/services/userId/normalizeUserAgent.ts");
const { setStickyIdentityEnabledForTests } = await server("src/services/userId/stickyUserId.ts");
const { userIdService } = await server("src/services/userId/userIdService.ts");
const mmdbIp = createRequire(import.meta.url)(path.join(SERVER_DIR, "node_modules/mmdb-lib/lib/ip.js")).default;

const OUT = path.join(process.env.IDENTITY_DIFF_DIR ?? ".", "pure.json");

setStickyIdentityEnabledForTests(false);

const uaCorpus = userAgentCorpus(SERVER_DIR);
const userAgents = uaCorpus.map(({ source, value }) => ({ source, value, node: normalizeUserAgentForIdentity(value) }));

const ipBuckets = ipBucketCorpus().map(ip => {
  let node: string | null;
  try {
    node = bucketIpForIdentity(ip, () => true);
  } catch (error) {
    node = `THROW ${(error as Error).message}`;
  }
  return { ip, node };
});

const r = rng(1234567);
const uaValues = uaCorpus.map(entry => entry.value);
const userIds = [];
for (const { ip, kind } of [...userIdIps(r), ...weirdUserIdIps()]) {
  const ua = r.next() < 0.03 ? "" : r.pick(uaValues);
  const mode = r.int(5);
  // 65001 is salted and 65002 unsalted in the parity sites table
  const siteId = mode === 4 ? r.pick([65001, 65002]) : 1 + r.int(65000);
  const salted = mode === 4 ? null : mode % 2 === 0;
  const receivedAt = dayBoundaryInstant(r);
  const asn = lookupAsn(ip)?.asn ?? null;
  const node = await userIdService.generateUserId(ip, ua, siteId, {
    ...(salted === null ? {} : { saltUserIds: salted }),
    receivedAt: new Date(receivedAt),
  });
  userIds.push({ ip, kind, ua, siteId, salted, receivedAt, asn, datacenter: isDatacenterAsn(asn), bucket: bucketIpForIdentity(ip), node });
}

const clientIds = [];
for (let i = 0; i < 6000; i++) {
  const clientId = Array.from({ length: 1 + r.int(40) }, () => (r.next() < 0.1 ? r.pick(UNICODE_BITS) : "abcdefghijklmnopqrstuvwxyz0123456789-"[r.int(37)])).join("");
  const mode = r.int(5);
  const siteId = mode === 4 ? r.pick([65001, 65002]) : 1 + r.int(65000);
  const salted = mode === 4 ? null : mode % 2 === 0;
  const receivedAt = dayBoundaryInstant(r);
  const node = await userIdService.generateUserIdFromClientId(clientId, siteId, {
    ...(salted === null ? {} : { saltUserIds: salted }),
    receivedAt: new Date(receivedAt),
  });
  clientIds.push({ clientId, siteId, salted, receivedAt, node });
}

const sessionKeys = [];
for (let i = 0; i < 6000; i++) {
  const userId = r.next() < 0.7 ? Array.from({ length: 12 }, () => "0123456789abcdef"[r.int(16)]).join("") : r.pick(uaValues).slice(0, 30).toWellFormed();
  const identifiedUserId = r.next() < 0.4 ? "" : Array.from({ length: 1 + r.int(30) }, () => (r.next() < 0.1 ? r.pick([...UNICODE_BITS, "\0"]) : "abcdefghij@._"[r.int(13)])).join("");
  const siteId = 1 + r.int(65535);
  const node = (sessionsService as any).getSessionKey(userId, siteId, identifiedUserId);
  sessionKeys.push({ userId, siteId, identifiedUserId, node });
}

const netChecks = [];
{
  const nr = rng(99);
  const candidates = new Set([...ipBuckets.map(entry => entry.ip), ...userIds.map(entry => entry.ip), ...zoneIps(nr)]);
  for (const ip of candidates) {
    const version = net.isIP(ip);
    const bytes = version === 6 ? mmdbIp.parse(ip).slice(0, 16).map((b: number) => (b >>> 0) & 0xff) : null;
    netChecks.push({ ip, version, bytes, asn: lookupAsn(ip)?.asn ?? null });
  }
}

const datacenterAsns = [...Array(4_300_000).keys()].filter(asn => isDatacenterAsn(asn));

writeFileSync(OUT, JSON.stringify({ userAgents, ipBuckets, userIds, clientIds, sessionKeys, netChecks, datacenterAsns }));
console.log(
  JSON.stringify({
    userAgents: userAgents.length,
    ipBuckets: ipBuckets.length,
    userIds: userIds.length,
    datacenterUserIds: userIds.filter(entry => entry.datacenter).length,
    clientIds: clientIds.length,
    sessionKeys: sessionKeys.length,
    netChecks: netChecks.length,
    datacenterAsns: datacenterAsns.length,
    zoned: netChecks.filter(entry => entry.ip.includes("%") && entry.version === 6).length,
  })
);
process.exit(0);
