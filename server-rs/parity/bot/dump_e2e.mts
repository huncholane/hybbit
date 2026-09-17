// End-to-end: Node's checkBotBlocking over varied requests, with the real
// GeoLite2 ASN lookups and in-process anomaly counters. Dumps each case's inputs
// and result, plus the detection stats at the end.
import { readFileSync, writeFileSync } from "fs";
import { IncomingMessage } from "http";
import { Socket } from "net";
import { lookupAsn } from "../../../server/src/db/geolocation/asn.ts";
import { redis } from "../../../server/src/db/redis/redis.ts";
import {
  resetAnomalyScorerForTests,
  setRedisAnomalyEnabledForTests,
} from "../../../server/src/services/tracker/botBlocking/anomalyScorer.ts";
import {
  getBotDetectionStats,
  resetBotDetectionStatsForTests,
} from "../../../server/src/services/tracker/botBlocking/botDetectionStats.ts";
import { checkBotBlocking } from "../../../server/src/services/tracker/botBlocking/index.ts";

// Reads the user agents dump_stateless.mts wrote. Run from server/ so the
// GeoLite2-ASN database next to it is the one both sides load.
const OUT = process.env.BOT_DIFF_DUMPS!;
if (!OUT) throw new Error("set BOT_DIFF_DUMPS");

let seed = 0x1b873593;
function random(): number {
  seed ^= seed << 13;
  seed ^= seed >>> 17;
  seed ^= seed << 5;
  return (seed >>> 0) / 0x100000000;
}
function pick<T>(items: readonly T[]): T {
  return items[Math.floor(random() * items.length)];
}

const allUas = readFileSync(`${OUT}/ua.jsonl`, "utf8")
  .split("\n")
  .filter(Boolean)
  .map(line => JSON.parse(line).ua as string);
const bots = allUas.filter((_, i) => i % 7 === 0);

// A spread of addresses: documentation and private ranges (no ASN), cloud and
// hosting networks, scanner and AI provider space, access networks, IPv6, and
// strings that are not addresses at all. Whatever GeoLite2 says about each is
// what both sides see.
const ips = [
  "203.0.113.10",
  "18.0.0.1",
  "3.5.140.2",
  "8.8.8.8",
  "1.1.1.1",
  "20.0.0.5",
  "57.154.0.1",
  "160.79.104.10",
  "23.102.140.112",
  "162.142.125.10",
  "167.94.138.35",
  "71.6.135.131",
  "98.97.10.10",
  "86.12.40.1",
  "2a01:4f8::1",
  "2001:4860:4860::8888",
  "not-an-ip",
  "",
  "10.0.0.1",
];

const headerValues: Record<string, string[]> = {
  "Accept-Language": ["en-US,en;q=0.9", "", "de"],
  Accept: ["*/*", "", "text/html"],
  "Accept-Encoding": ["gzip, deflate, br", "", "br"],
  "Sec-Fetch-Site": ["cross-site", "", "same-origin"],
  "Sec-Fetch-Mode": ["cors", "navigate", ""],
};

function rawHeaders(ua: string | undefined): string[] {
  const raw: string[] = [];
  const full = random() < 0.4;
  for (const [name, values] of Object.entries(headerValues)) {
    if (full) {
      raw.push(name, values[0]);
      continue;
    }
    if (random() < 0.3) continue;
    raw.push(name, pick(values));
    if (random() < 0.05) raw.push(name.toLowerCase(), pick(values));
  }
  // What Node's parser would hand over for a UTF-8 user agent on the wire: bytes
  // decoded as latin1, surrounding whitespace trimmed, and no control characters
  // (a request carrying those is rejected before any handler runs).
  if (ua !== undefined) {
    const wire = Buffer.from(ua, "utf8").toString("latin1").replace(/^[ \t]+|[ \t]+$/g, "");
    if (!/[\x00-\x08\x0a-\x1f\x7f]/.test(wire)) raw.push("User-Agent", wire);
  }
  return raw;
}

function nodeHeaders(raw: string[]) {
  const message = new IncomingMessage(new Socket());
  (message as any)._addHeaderLines(raw, raw.length);
  return message.headers;
}

const screens: [number | undefined, number | undefined][] = [
  [undefined, undefined],
  [1920, 1080],
  [1512, 982],
  [800, 600],
  [1024, 768],
  [1280, 1200],
  [2000, 2000],
  [1, 1],
  [390, 844],
  [1920, undefined],
  [0, 0],
];

type Case = {
  raw: string[];
  blockBots: boolean;
  trusted: boolean;
  mobile: boolean;
  repeat: number;
  payload: Record<string, unknown>;
};

const cases: Case[] = [];
for (let index = 0; index < 6000; index++) {
  const ua = random() < 0.5 ? pick(bots) : pick(allUas);
  const headerUa = random() < 0.8 ? ua : undefined;
  const payloadUa = pick([undefined, "", ua, ua]);
  const [screenWidth, screenHeight] = pick(screens);
  const repeat = random() < 0.02 ? 35 : 1;
  cases.push({
    raw: rawHeaders(headerUa),
    blockBots: random() < 0.5,
    trusted: random() < 0.1,
    mobile: random() < 0.1,
    repeat,
    payload: {
      siteId: 65300 + index,
      userAgent: payloadUa,
      clientBotScore: pick([undefined, 0, 1, 2, 3, 5, 10]),
      clientBotSignalMask: pick([undefined, 0, 1, 2, 12, 16, 128, 2048, 4096, 8191, Math.floor(random() * 8192)]),
      screenWidth,
      screenHeight,
      language: pick([undefined, "en-US", ""]),
      hostname: pick([undefined, "example.com"]),
      pathname: pick([undefined, "/", "/pricing"]),
      eventType: pick(["pageview", "custom_event", "button_click"]),
      referrer: pick([undefined, "", "https://google.com/"]),
      ipAddress: pick(ips),
    },
  });
}

resetAnomalyScorerForTests();
setRedisAnomalyEnabledForTests(false);
resetBotDetectionStatsForTests();

const results: unknown[] = [];
for (const testCase of cases) {
  const headers = nodeHeaders(testCase.raw);
  let result = null;
  for (let i = 0; i < testCase.repeat; i++) {
    result = await checkBotBlocking({
      headers,
      blockBots: testCase.blockBots,
      trustedServerSideIngestion: testCase.trusted,
      isMobileSite: testCase.mobile,
      payload: testCase.payload as any,
      lookupAsn,
    });
  }
  results.push(result);
}

writeFileSync(
  `${OUT}/e2e.json`,
  JSON.stringify({ cases, results, stats: getBotDetectionStats() })
);
console.log("cases", cases.length, "detections", results.filter(Boolean).length);
await redis.quit();
process.exit(0);
