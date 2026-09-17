// Drives identical observation sequences through Node's anomaly scorer, against
// the parity Redis and against the in-process fallback, and dumps every result
// plus the Redis state each scenario leaves behind (then deletes it). The Rust
// differential test replays the same inputs and compares. Scenarios use site
// ids 65100 and up. See run.sh.
import { createHash } from "crypto";
import { writeFileSync } from "fs";
import { redis } from "../../../server/src/db/redis/redis.ts";
import {
  observeTrackingAnomaly,
  resetAnomalyScorerForTests,
  setRedisAnomalyEnabledForTests,
  type AnomalyInput,
} from "../../../server/src/services/tracker/botBlocking/anomalyScorer.ts";

const OUT = process.env.BOT_DIFF_DUMPS!;
if (!OUT) throw new Error("set BOT_DIFF_DUMPS");

let seed = 0x2545f491;
function random(): number {
  seed ^= seed << 13;
  seed ^= seed >>> 17;
  seed ^= seed << 5;
  return (seed >>> 0) / 0x100000000;
}
function pick<T>(items: readonly T[]): T {
  return items[Math.floor(random() * items.length)];
}

const BASE = 1_760_000_000_000;
const HOUR = 3_600_000;
const chrome = (version: number) =>
  `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${version}.0.0.0 Safari/537.36`;
const firefox = (version: number) =>
  `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:${version}.0) Gecko/20100101 Firefox/${version}.0`;
const safari = (version: number) =>
  `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/${version}.0 Safari/605.1.15`;

type Scenario = { name: string; inputs: AnomalyInput[] };
const scenarios: Scenario[] = [];
let nextSite = 65100;
function scenario(name: string, build: (siteId: number) => AnomalyInput[]) {
  const siteId = nextSite++;
  scenarios.push({ name, inputs: build(siteId) });
}

const base = (siteId: number): AnomalyInput => ({
  siteId,
  ipAddress: "203.0.113.10",
  userAgent: "Mozilla/5.0 Chrome/120 Safari/537.36",
  hostname: "example.com",
  pathname: "/",
  eventType: "pageview",
  hasClientBotScore: true,
  nowMs: BASE,
});

scenario("tuple burst then expiry", siteId => [
  ...Array.from({ length: 35 }, (_, i) => ({ ...base(siteId), nowMs: BASE + i })),
  { ...base(siteId), nowMs: BASE + 70_000 },
]);

scenario("path crawl", siteId =>
  Array.from({ length: 30 }, (_, i) => ({ ...base(siteId), pathname: `/Docs/${i} `, nowMs: BASE + i }))
);

scenario("interaction burst", siteId =>
  Array.from({ length: 105 }, (_, i) => ({ ...base(siteId), eventType: "button_click", nowMs: BASE + i }))
);

scenario("missing client score", siteId =>
  Array.from({ length: 25 }, (_, i) => ({ ...base(siteId), hasClientBotScore: false, nowMs: BASE + i * 2_000 }))
);

scenario("rolling cap above 512", siteId =>
  Array.from({ length: 600 }, (_, i) => ({ ...base(siteId), pathname: `/p/${i % 600}`, nowMs: BASE + i * 50 }))
);

scenario("cohort uniformity", siteId =>
  Array.from({ length: 480 }, (_, i) => ({
    ...base(siteId),
    ipAddress: `198.51.100.${i % 254}`,
    userAgent: chrome(103 + (i % 16)),
    pathname: `/summoners/${i}`,
    screenWidth: 1280,
    screenHeight: 1200,
    language: "en-US",
    nowMs: BASE + i,
  }))
);

scenario("distribution field cap above 128", siteId =>
  Array.from({ length: 400 }, (_, i) => ({
    ...base(siteId),
    ipAddress: `198.51.${Math.floor(i / 200)}.${i % 200}`,
    userAgent: chrome(i % 150),
    pathname: `/v/${i}`,
    screenWidth: 1920,
    screenHeight: 1080,
    language: " EN-us ",
    nowMs: BASE + i * 10,
  }))
);

scenario("mixed families", siteId => {
  const builders = [chrome, firefox, safari];
  return Array.from({ length: 300 }, (_, i) => ({
    ...base(siteId),
    ipAddress: `198.51.100.${i % 254}`,
    userAgent: builders[i % 3](i % 100 < 85 ? 120 : 100 + (i % 7)),
    pathname: `/article/${i}`,
    screenWidth: 1440,
    screenHeight: 900,
    language: "de",
    nowMs: BASE + i * 1000,
  }));
});

const enumerationBucket = (siteId: number, start: number) =>
  Array.from({ length: 320 }, (_, i) => ({
    ...base(siteId),
    ipAddress: `198.51.${Math.floor(i / 254)}.${i % 254}`,
    pathname: `/status/online/page/${start}-${i}`,
    screenWidth: 1920,
    screenHeight: 1080,
    language: "en-US",
    referrer: "",
    nowMs: start + i,
  }));
const enumerationStart = Math.floor(BASE / 900_000) * 900_000;
scenario("enumeration sustained", siteId => [
  ...enumerationBucket(siteId, enumerationStart),
  ...enumerationBucket(siteId, enumerationStart + 900_000),
]);
scenario("enumeration gap", siteId => [
  ...enumerationBucket(siteId, enumerationStart),
  ...enumerationBucket(siteId, enumerationStart + 3 * 900_000),
]);

const floodStart = Math.floor(BASE / 600_000) * 600_000;
scenario("one-shot fleet flood", siteId =>
  Array.from({ length: 130 }, (_, i) => ({
    ...base(siteId),
    siteBaseline: { events10m: 0, eligible: true },
    ipAddress: `203.0.${Math.floor(i / 250)}.${i % 250}`,
    userAgent: chrome(118 + (i % 4)),
    screenWidth: 1920,
    screenHeight: 1080,
    language: "en-US",
    pathname: `/showcase/${i % 70}`,
    referrer: undefined,
    nowMs: floodStart + i * 1_000,
  }))
);

scenario("hosting actor flood", siteId =>
  Array.from({ length: 260 }, (_, i) => ({
    ...base(siteId),
    siteBaseline: { events10m: 0, eligible: true },
    ipAddress: "20.0.0.5",
    isHostingAsn: true,
    asn: 8075,
    screenWidth: 1920,
    screenHeight: 1080,
    language: "en-US",
    nowMs: floodStart + i * 2_000,
  }))
);

scenario("hosting actor day volume and sase", siteId =>
  Array.from({ length: 1100 }, (_, i) => ({
    ...base(siteId),
    ipAddress: "20.0.0.9",
    isHostingAsn: true,
    asn: i < 1050 ? 8075 : 13150,
    siteBaseline: null,
    pathname: `/x/${i % 3}`,
    nowMs: BASE + i * 70_000,
  }))
);

scenario("crowd rules", siteId =>
  Array.from({ length: 260 }, (_, i) => ({
    ...base(siteId),
    ipAddress: "100.64.0.1",
    userAgent: chrome(100 + (i % 15)),
    hostname: `host${i % 9}.example.com`,
    pathname: `/c/${i % 4}`,
    nowMs: BASE + i * 100,
  }))
);

scenario("random mix", siteId => {
  const ips = ["203.0.113.1", "203.0.113.2", "2001:DB8::1", " 198.51.100.7 "];
  const agents = [chrome(120), chrome(55), firefox(130), safari(17), "curl/8.4.0", "", "Mozilla/5.0 \u{1F600} Chrome/99"];
  const paths = ["/", "/a", "/b", "/A ", undefined, ""];
  const hosts = ["example.com", "EXAMPLE.com", undefined, ""];
  const referrers = [undefined, "", "https://google.com/", "  "];
  const types = ["pageview", "custom_event", "button_click", "copy", "input_change", undefined];
  const screens: [number | undefined, number | undefined][] = [[1920, 1080], [390, 844], [0, 0], [undefined, undefined], [1920, undefined]];
  const languages = ["en-US", "", undefined, "fr"];
  const baselines = [undefined, null, { events10m: 1, eligible: true }, { events10m: 0.5, eligible: false }];
  let now = BASE - 3_000;
  return Array.from({ length: 1500 }, () => {
    now += Math.floor(random() * 900);
    const [screenWidth, screenHeight] = pick(screens);
    return {
      siteId,
      ipAddress: pick(ips),
      userAgent: pick(agents),
      hostname: pick(hosts),
      pathname: pick(paths),
      eventType: pick(types),
      referrer: pick(referrers),
      hasClientBotScore: random() < 0.5,
      screenWidth,
      screenHeight,
      language: pick(languages),
      isHostingAsn: random() < 0.3,
      asn: pick([undefined, 8075, 22616, 16509]),
      siteBaseline: pick(baselines),
      nowMs: now,
    };
  });
});

async function redisState(siteId: number) {
  const keys = (await redis.keys(`bot:*:${siteId}:*`)).sort();
  const state: Record<string, unknown> = {};
  for (const key of keys) {
    const type = await redis.type(key);
    const pttl = await redis.pttl(key);
    let value: unknown;
    if (type === "zset") {
      const flat = await redis.zrange(key, 0, -1, "WITHSCORES");
      const pairs: [string, string][] = [];
      for (let i = 0; i < flat.length; i += 2) pairs.push([flat[i], flat[i + 1]]);
      const tokenMembers = /^bot:a:(te10|te60|ti10|ie60|sue|mcs):/.test(key);
      value = tokenMembers
        ? { count: pairs.length, scores: pairs.map(([, score]) => score).sort() }
        : { members: pairs.sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0)) };
    } else if (type === "hash") {
      value = await redis.hgetall(key);
    } else if (type === "string") {
      const raw = await redis.getBuffer(key);
      value = /^bot:(f:sa|f:ca|e:pa|e:ac):/.test(key) ? { hll: raw?.toString("hex") } : raw?.toString("utf8");
    } else {
      value = type;
    }
    state[key] = { type, pttl, value };
  }
  return { keys, state };
}

async function deleteSite(siteId: number) {
  const keys = await redis.keys(`bot:*:${siteId}:*`);
  if (keys.length > 0) await redis.del(...keys);
}

const output: unknown[] = [];
for (const { name, inputs } of scenarios) {
  const siteId = inputs[0].siteId;
  await deleteSite(siteId);

  resetAnomalyScorerForTests();
  setRedisAnomalyEnabledForTests(true);
  const redisResults = [];
  for (const input of inputs) redisResults.push(await observeTrackingAnomaly({ ...input }));
  const { state } = await redisState(siteId);
  const finishedAt = Date.now();
  await deleteSite(siteId);

  resetAnomalyScorerForTests();
  setRedisAnomalyEnabledForTests(false);
  const localResults = [];
  for (const input of inputs) localResults.push(await observeTrackingAnomaly({ ...input }));

  output.push({ name, inputs, redis: redisResults, local: localResults, state, finishedAt });
  console.log(name, { events: inputs.length, keys: Object.keys(state).length });
}

const sha = (redis as any).scriptsSet?.anomalyObserve?.sha;
writeFileSync(`${OUT}/anomaly.json`, JSON.stringify({ scriptSha: sha, scenarios: output }));
console.log("script sha", sha, "lua sha1 check", createHash("sha1").update((redis as any).scriptsSet?.anomalyObserve?.lua ?? "").digest("hex"));
await redis.quit();
process.exit(0);
