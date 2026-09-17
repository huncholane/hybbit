// Dumps Node's answers for the stateless bot rules (classifyUA,
// classifyStaleBrowserVersion, detectBot over Node-built headers,
// classifyBotAsn, the screen-geometry rules) over a large user-agent corpus,
// for server-rs/src/bot/differential.rs. See run.sh.
import { readdirSync, readFileSync, statSync, writeFileSync } from "fs";
import { IncomingMessage } from "http";
import { Socket } from "net";
import { join } from "path";
import { fileURLToPath } from "url";
import { getScreenDimensionSignals, isDesktopUserAgent } from "../../../shared/src/botSignalContract.ts";
import { classifyBotAsn } from "../../../server/src/services/tracker/botBlocking/botProviderAsns.ts";
import { detectBot } from "../../../server/src/services/tracker/botBlocking/headerHeuristics.ts";
import { classifyStaleBrowserVersion } from "../../../server/src/services/tracker/botBlocking/staleBrowserVersion.ts";
import { ALL_BOT_PATTERNS } from "../../../server/src/services/tracker/botBlocking/uaBots/patterns.ts";
import { classifyUA } from "../../../server/src/services/tracker/botBlocking/uaBots/index.ts";

/** Clones of ua-parser-js (tag 2.0.3), isbot and crawler-user-agents. */
const SCRATCH = process.env.BOT_CORPUS_DIR!;
const OUT = process.env.BOT_DIFF_DUMPS!;
if (!SCRATCH || !OUT) throw new Error("set BOT_CORPUS_DIR and BOT_DIFF_DUMPS");
const BOT_BLOCKING_DIR = fileURLToPath(new URL("../../../server/src/services/tracker/botBlocking", import.meta.url));

// Deterministic PRNG so the corpus is reproducible.
let seed = 0x9e3779b9;
function random(): number {
  seed ^= seed << 13;
  seed ^= seed >>> 17;
  seed ^= seed << 5;
  return (seed >>> 0) / 0x100000000;
}
function pick<T>(items: readonly T[]): T {
  return items[Math.floor(random() * items.length)];
}

const corpus = new Set<string>();
function add(ua: unknown) {
  if (typeof ua !== "string") return;
  if (!(ua as any).isWellFormed()) return;
  corpus.add(ua);
}

function walk(dir: string, visit: (file: string) => void) {
  for (const name of readdirSync(dir)) {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) walk(path, visit);
    else visit(path);
  }
}

// 1. ua-parser-js 2.0.3 test fixtures.
walk(`${SCRATCH}/ua-parser-js/test/data/ua`, file => {
  if (!file.endsWith(".json")) return;
  for (const entry of JSON.parse(readFileSync(file, "utf8"))) add(entry.ua);
});
const uaParserCount = corpus.size;

// 2. isbot fixtures: browsers.yml, crawlers.yml and the downloaded lists.
for (const file of ["browsers.yml", "crawlers.yml"]) {
  for (const line of readFileSync(`${SCRATCH}/isbot/fixtures/${file}`, "utf8").split("\n")) {
    const match = line.match(/^\s+- (.*)$/);
    if (!match) continue;
    let value = match[1];
    if ((value.startsWith("'") && value.endsWith("'")) || (value.startsWith('"') && value.endsWith('"'))) {
      value = value.slice(1, -1);
    }
    add(value);
  }
}
for (const name of readdirSync(`${SCRATCH}/isbot/fixtures/downloaded`)) {
  if (!name.endsWith(".json")) continue;
  for (const ua of JSON.parse(readFileSync(`${SCRATCH}/isbot/fixtures/downloaded/${name}`, "utf8"))) add(ua);
}
const isbotCount = corpus.size - uaParserCount;

// 3. monperrus crawler-user-agents instances.
for (const entry of JSON.parse(readFileSync(`${SCRATCH}/crawler-user-agents/crawler-user-agents.json`, "utf8"))) {
  for (const ua of entry.instances ?? []) add(ua);
}

// 4. Every string literal in the botBlocking and anomaly test files.
walk(BOT_BLOCKING_DIR, file => {
  if (!file.endsWith(".test.ts")) return;
  for (const match of readFileSync(file, "utf8").matchAll(/"((?:[^"\\\n]|\\.)*)"/g)) add(match[1]);
});

// 5. Synthetic: pattern names/operators, version sweeps and JS-semantics traps.
for (const pattern of ALL_BOT_PATTERNS) {
  if (pattern.name) {
    add(pattern.name);
    add(`Mozilla/5.0 (compatible; ${pattern.name}/1.0)`);
    add(pattern.name.toUpperCase());
  }
  if (pattern.operator) add(`Mozilla/5.0 (${pattern.operator})`);
  // The literal text of each pattern with regex syntax stripped, in a few cases.
  const literal = pattern.pattern.replace(/\\[bwdsW]|[\\^$()?:!<|\[\]{}*+]/g, "");
  add(literal);
  add(literal.toUpperCase());
  add(`Mozilla/5.0 ${literal}`);
  add(`Mozilla/5.0 x${literal}x`);
}
const tokens = ["Chrome", "Firefox", "Edg", "EdgA", "EdgiOS", "Edge", "CriOS", "FxiOS", "OPR", "SamsungBrowser", "HeadlessChrome", "Version"];
for (const token of tokens) {
  for (const version of [0, 1, 9, 39, 40, 60, 69, 70, 71, 75, 76, 79, 80, 120, 999, 1000, 9999, 12345]) {
    add(`Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) ${token}/${version}.0.0.0 Safari/537.36`);
    add(`Mozilla/5.0 (Linux; Android 8.0; wv) ${token}/${version}.0`);
    add(`Mozilla/5.0 (Linux; Android 8.0;wv) ${token}/${version}.0`);
    add(`Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) ${token}/${version}`);
    add(`Mozilla/5.0 (Macintosh; Intel Mac OS X 11.2) ${token}/${String(version).padStart(4, "0")}`);
    add(`${token}/${version}`);
  }
}
const traps = [
  "Kurl/7", // Kelvin sign: toLowerCase maps it to k, regex /i does not
  "oKhttp/4.9",
  "ſpider",
  "SPIDER",
  "İnsight",
  "googlebot",
  "Mozilla/5.0 (Linux; Android 10; Pixel) Chrome/120 Mobile Safari \u{1F600}",
  "x".repeat(49),
  "x".repeat(50),
  "\u{1F600}".repeat(25),
  "\u{1F600}".repeat(24) + "x",
  "a".repeat(48) + "\u{1F600}",
  " leading space",
  "﻿bom",
  "ébot",
  "cubot",
  "a cubot",
  "Mozilla/5.0 (Linux; Android 13; cubot) AppleWebKit",
  "Mozilla/5.0 channel/google",
  "Mozilla/5.0 google/google",
  "Mozilla/5.0 googleapp",
  "Mozilla/5.0 GooglePixel",
  "Mozilla/5.0 google pixel",
  "libhttp",
  "camscanner",
  "java;",
  "javascript",
  "news sapphire",
  "gnews",
  "Mozilla/5.0 (compatible;)",
  "Mozilla/5.0 (compatible; foo-bar.baz/1.2)",
  "Mozilla/5.0 (compatible;foo/1.2)",
  "Mozilla/5.0 foo-bar",
  "Mozilla/5.0 foo bar",
  "Dalvik/2.1.0 (Linux; U; Android 11)",
  "App/1.0 (build 12)",
  "Foo/1.2.3, bar",
  "Foo/v1.2.3.4",
  "a(b)c:d%e/1",
  "abc/()",
  "abc/de",
  "abc/de f",
  "123abc",
  "-dash",
  "Mozilla/5.0 (Windows NT 10.0) Chrome/76 Safari",
  "Mozilla/5.0 (Windows NT 9.0) Chrome/50 Safari",
  "Mozilla/5.0 (Windows NT 20.0) Chrome/50 Safari",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15) Chrome/50",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9) Chrome/50",
  "Chrome/0",
  "Chrome/" + "9".repeat(400),
  "Chrome/00079 Windows NT 10",
  "x wv",
  "x;wv)",
  "x; wv)",
  "xwv",
  "wv",
  "",
];
for (const trap of traps) add(trap);

// 6. Random mutations of corpus entries: case flips, affixes, truncation.
const base = [...corpus];
for (let i = 0; i < 6000; i++) {
  const ua = pick(base);
  const kind = Math.floor(random() * 6);
  if (kind === 0) add(ua.toUpperCase());
  else if (kind === 1) add(ua.toLowerCase());
  else if (kind === 2) add(ua.slice(0, Math.floor(random() * ua.length)));
  else if (kind === 3) add(`${pick(base).slice(0, 30)} ${ua}`);
  else if (kind === 4) add(ua.replace(/ /g, ""));
  else add(ua.replace(/k/g, "K").replace(/s/g, "ſ"));
}

const uas = [...corpus];
console.log("corpus", { total: uas.length, uaParser: uaParserCount, isbot: isbotCount });

// UA classification and stale version.
const uaLines: string[] = [];
for (const ua of uas) {
  const c = classifyUA(ua);
  const s = classifyStaleBrowserVersion(ua);
  uaLines.push(
    JSON.stringify({
      ua,
      classify: [c.isBot, c.category, c.matchedPattern, c.name, c.operator, c.purpose],
      stale: [s.isStale, s.matchedVersion, s.majorVersion],
      desktop: isDesktopUserAgent(ua),
      ...(() => {
        const width = pick([800, 1024, 1280, 2000, 199, 8192, 8193, 1512, NaN]);
        const height = pick([600, 768, 1200, 2000, 200, 982, NaN]);
        return {
          screenDims: [Number.isNaN(width) ? null : width, Number.isNaN(height) ? null : height],
          screen: getScreenDimensionSignals(width, height, ua),
        };
      })(),
    })
  );
}
writeFileSync(`${OUT}/ua.jsonl`, uaLines.join("\n") + "\n");

// Header heuristics over raw header lists turned into IncomingHttpHeaders the
// way Node's HTTP layer does it.
const headerValues: Record<string, string[]> = {
  "Accept-Language": ["en-US,en;q=0.9", "", "de", "café"],
  Accept: ["*/*", "", "text/html", "application/json"],
  "Accept-Encoding": ["gzip, deflate, br", "", "br", "identity", "GZIP", "x-gzip"],
  "Sec-Fetch-Site": ["cross-site", "", "same-origin"],
  "Sec-Fetch-Mode": ["cors", "navigate", "", "Navigate", "no-cors"],
  "User-Agent": ["header-agent", "curl/8"],
};
const headerNames = Object.keys(headerValues);

function randomRawHeaders(): string[] {
  const raw: string[] = [];
  for (const name of headerNames) {
    const roll = random();
    if (roll < 0.25) continue; // absent
    const count = roll > 0.9 ? 2 : 1; // sometimes duplicated
    for (let i = 0; i < count; i++) {
      const spelled = random() < 0.5 ? name : name.toLowerCase();
      raw.push(spelled, pick(headerValues[name]));
    }
  }
  if (random() < 0.2) raw.push("X-Other", "1");
  return raw;
}

function nodeHeaders(raw: string[]) {
  const message = new IncomingMessage(new Socket());
  (message as any)._addHeaderLines(raw, raw.length);
  return message.headers;
}

const fullBrowserHeaders = [
  "Accept", "*/*",
  "Accept-Encoding", "gzip, br",
  "Accept-Language", "en-US,en;q=0.9",
  "Sec-Fetch-Site", "cross-site",
];

const headerLines: string[] = [];
for (const [index, ua] of uas.entries()) {
  const sets = [randomRawHeaders(), [], fullBrowserHeaders];
  if (index < 800) for (let i = 0; i < 20; i++) sets.push(randomRawHeaders());
  for (const raw of sets) {
    const headers = nodeHeaders(raw);
    const result = detectBot(headers, ua);
    headerLines.push(
      JSON.stringify({ ua, raw, headers, detect: [result.isBot, result.score, result.reason ?? null] })
    );
  }
}
writeFileSync(`${OUT}/headers.jsonl`, headerLines.join("\n") + "\n");

// Bot ASN classification over every ASN below 500k plus some high ones.
const asnHits: unknown[] = [];
const asnChecked: number[] = [];
const extraAsns = [4200000000, 4294967294, 4294967295, 2147483647, 2147483648];
for (let asn = 0; asn < 500_000; asn++) {
  const match = classifyBotAsn(asn);
  if (match.isBotInfrastructure) asnHits.push([asn, match.source, match.provider ?? null, match.category ?? null, match.note ?? null]);
}
for (const asn of extraAsns) {
  asnChecked.push(asn);
  const match = classifyBotAsn(asn);
  if (match.isBotInfrastructure) asnHits.push([asn, match.source, match.provider ?? null, match.category ?? null, match.note ?? null]);
}
writeFileSync(`${OUT}/asn.json`, JSON.stringify({ rangeEnd: 500_000, extra: extraAsns, hits: asnHits }));

console.log("written", { ua: uaLines.length, headers: headerLines.length, asnHits: asnHits.length });
