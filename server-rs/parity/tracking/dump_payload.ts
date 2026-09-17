// Generates tracking payloads (as JSON text, so duplicate keys, overflowing numbers
// and lone surrogate escapes survive) and dumps trackingPayloadSchema.safeParse for
// each: success, parsed data and error.flatten().
import { writeFileSync } from "node:fs";
import { trackingPayloadSchema } from "../../../server/src/services/tracker/trackingPayload.ts";

const OUT = process.argv[2];
const COUNT = Number(process.argv[3] ?? 8000);
// "valid" mode leans on well-formed values so parsed data gets compared more often
const VALID = process.argv[4] === "valid";

let seed = VALID ? 0xbeef : 0xc0ffee;
function rand() {
  seed |= 0;
  seed = (seed + 0x6d2b79f5) | 0;
  let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
  t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
  return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
}
const pick = <T>(items: T[]): T => items[Math.floor(rand() * items.length)];
const chance = (p: number) => rand() < p;
const S = (value: string) => JSON.stringify(value);

const TYPES = ["pageview", "custom_event", "performance", "outbound", "error", "button_click", "copy", "form_submit", "input_change", "heartbeat"];

// A string of exactly `units` UTF-16 units in one of several alphabets
function sized(units: number): string {
  if (units <= 0) return "";
  const style = rand();
  if (style < 0.5) return "a".repeat(units);
  if (style < 0.7) return "é".repeat(units);
  if (style < 0.9) return "😀".repeat(Math.floor(units / 2)) + (units % 2 ? "x" : "");
  return "ab".repeat(Math.ceil(units / 2)).slice(0, units);
}

const WRONG_TYPES = ["0", "-1", "1.5", "true", "false", "null", "[]", "{}", '["a"]', '{"a":1}', S("123"), "1e400"];
const NUMBERS = [
  "0", "-0", "1", "1.5", "-1", "1e400", "-1e400", "1e300", "9007199254740993", "2048", "2047", "8191", "8192",
  "10", "11", "10.5", "4294967296", "1e-7", "1e-400", "-1e-400", "0.0", "1E3", "123456789012345678901", S("5"), "null", "true",
];
const IPS = [
  "1.2.3.4", "255.255.255.255", "256.1.1.1", "01.2.3.4", "1.2.3", " 1.2.3.4", "1.2.3.4 ", "::1", "::", "2001:db8::1",
  "2001:DB8::1", "fe80::1%eth0", "fe80::1%", "::ffff:1.2.3.4", "::ffff:01.2.3.4", "1:2:3:4:5:6:7:8", "1:2:3:4:5:6:7:8:9",
  "1::2::3", "gggg::1", "", "localhost", "1.2.3.4/24", "2001:db8::/32", "::ffff:0:1.2.3.4", "1:2:3:4::1.2.3.4",
  "fe80::a:b:c:d%en0", "fe80:0:0:0:0:0:0:1%1", "0.0.0.0", "00.0.0.0", "192.168.1.256",
];

function lengthCase(max: number, min = 0): string {
  const options = [0, 1, max - 1, max, max + 1, Math.floor(rand() * (max + 20))];
  if (min > 0) options.push(min - 1, min);
  let units = pick(options);
  if (units < 0) units = 0;
  if (chance(0.05)) return S(sized(Math.max(units - 1, 0))).slice(0, -1) + "\\ud800\"";
  return S(sized(units));
}

function stringValue(max: number, min = 0): string {
  if (VALID && chance(0.9)) return S(sized(Math.max(min, Math.floor(rand() * Math.min(max, 40)))));
  const r = rand();
  if (r < 0.55) return S(pick(["example.com", "/pricing", "?a=1", "en-US", "Title", "https://google.com/", "user-1", "tag"]));
  if (r < 0.85) return lengthCase(max, min);
  return pick(WRONG_TYPES);
}

function numberValue(): string {
  if (VALID && chance(0.85)) return pick([String(Math.floor(rand() * 11)), "0", "-0", "10", "1.0", "1e1"]);
  return chance(0.4) ? String(Math.floor(rand() * 3000)) : pick(NUMBERS);
}

function featureFlags(): string {
  const r = rand();
  if (!VALID && r < 0.15) return pick(WRONG_TYPES);
  const entries: string[] = [];
  const count = Math.floor(rand() * 4);
  for (let i = 0; i < count; i++) {
    const key = pick([S("flag"), S("b"), S("2"), S("1"), S("01"), S(sized(100)), S(VALID ? "10" : sized(101)), S("4294967295"), S("x".repeat(3)), S("0")]);
    const value = VALID ? pick([S("on"), S(""), S("variant-b"), S(sized(2048))]) : pick([S("on"), S(""), S(sized(2048)), S(sized(2049)), "5", "null", "{}", "[]", "true"]);
    entries.push(`${key}:${value}`);
  }
  return `{${entries.join(",")}}`;
}

const JSON_PROPERTIES = [
  "{}", "[]", "null", "5", '"s"', "{", "", " {} ", '{"a":1}', '{"a":"\\ud800"}', "\ufeff{}", '{"a":1,}', "tru", "1e400",
  '{"deep":' + "[".repeat(50) + "]".repeat(50) + "}",
];
const OUTBOUND = [
  '{"url":"https://example.com"}', '{"url":""}', '{"url":5}', "{}", '{"url":"not a url"}', '{"url":"example.com"}',
  '{"url":"https://example.com","text":"Go","target":"_blank"}', '{"url":"https://example.com","text":1}',
  '{"url":"https://example.com","text":0}', '{"url":"https://example.com","text":""}', '{"url":"https://example.com","target":{}}',
  '{"url":"https://example.com","target":null}', '{"url":"https://example.com","target":false}', '{"url":"https://example.com","text":[]}',
  '{"url":"mailto:a@b.c"}', '{"url":"javascript:void(0)"}', '{"url":"//example.com"}', '{"url":"http://[::1"}',
  '{"url":"https://exa mple.com"}', '{"url":"https://bücher.de"}', '{"url":"http://a:b@c:99999"}', "null", "[]", '"x"',
  '{"url":"https://example.com","url":""}', '{"url":"tel:+1"}', '{"url":"https://xn--/"}', '{"url":"https://a..b/"}',
  '{"url":"http://%zz/"}', '{"url":"file:///x"}', '{"url":"https:example.com"}', '{"url":"HTTP://EXAMPLE.COM"}',
  '{"url":" https://example.com "}', '{"url":"https://example.com/\\t"}', '{"url":"http://0x7f.1"}', '{"url":"http://1.2.3.4.5"}',
];
const ERRORS = [
  '{"message":"boom"}', '{"message":5}', "{}", '{"message":"x","stack":1}', '{"message":"x","stack":0}', '{"message":"x","stack":"s"}',
  '{"message":"x","fileName":true}', '{"message":"x","lineNumber":"5"}', '{"message":"x","lineNumber":0}', '{"message":"x","lineNumber":"0"}',
  '{"message":"x","lineNumber":5,"columnNumber":6}', '{"message":"x","columnNumber":{}}', '{"message":"x","columnNumber":null}',
  '{"message":"' + "m".repeat(600) + '","stack":"' + "s".repeat(3000) + '"}', "null", "[]", '{"message":null}', '{"message":""}',
];
const COPIES = [
  '{"sourceElement":"p"}', '{"sourceElement":"p","text":"hi","textLength":2}', '{"sourceElement":"p","text":null}',
  '{"sourceElement":"p","textLength":-1}', '{"sourceElement":"p","textLength":-0}', '{"sourceElement":"p","textLength":"3"}',
  '{"sourceElement":"p","textLength":0}', '{"sourceElement":1}', "{}", '{"sourceElement":"p","text":5}', '{"sourceElement":"p","textLength":-1e400}',
  '{"sourceElement":"p","textLength":1e400}', "null",
];
const FORMS = [
  '{"formId":"f","formName":"n","formAction":"/a","method":"post","fieldCount":3}', '{"formId":"f","formName":"n","formAction":"/a","method":"post","fieldCount":-1}',
  '{"formId":"f","formName":"n","formAction":"/a","method":"post","fieldCount":"3"}', '{"formId":"f","formName":"n","formAction":"/a","method":"post"}',
  '{"formId":1,"formName":"n","formAction":"/a","method":"post","fieldCount":0}', '{"formId":"f","formName":"n","formAction":"/a","method":"post","fieldCount":-0}',
  "{}", "[]",
];
const INPUTS = ['{"element":"input","inputName":"email"}', '{"element":"input"}', '{"element":1,"inputName":"x"}', "{}", '{"inputName":"x","element":"select","value":"v"}'];

function propertiesFor(type: string): string {
  const pool =
    type === "outbound" ? OUTBOUND : type === "error" ? ERRORS : type === "copy" ? COPIES : type === "form_submit" ? FORMS : type === "input_change" ? INPUTS : JSON_PROPERTIES;
  if (VALID && chance(0.8)) return S(pool[Math.floor(rand() * Math.min(pool.length, 3))]);
  const r = rand();
  if (r < 0.75) return S(pick(pool));
  if (r < 0.85) return pick(WRONG_TYPES);
  // Oversized, sometimes still valid JSON
  const limit = type === "error" ? 4096 : 2048;
  const filler = "x".repeat(limit + pick([-20, -12, -11, -10, 0, 1, 5]));
  return S(pick([`{"url":"https://example.com","message":"m","sourceElement":"s","formId":"f","formName":"n","formAction":"a","method":"m","fieldCount":1,"element":"e","inputName":"i","pad":"${filler}"}`, filler]));
}

const BASE_FIELDS: Array<[string, () => string]> = [
  ["hostname", () => stringValue(253)],
  ["pathname", () => stringValue(2048)],
  ["querystring", () => stringValue(2048)],
  ["screenWidth", numberValue],
  ["screenHeight", numberValue],
  ["language", () => stringValue(35)],
  ["page_title", () => stringValue(512)],
  ["referrer", () => stringValue(2048)],
  ["anonymous_id", () => stringValue(255, 1)],
  ["user_id", () => stringValue(255)],
  ["tag", () => stringValue(256)],
  ["feature_flags", featureFlags],
  ["ip_address", () => (chance(0.8) ? S(pick(IPS)) : pick(WRONG_TYPES))],
  ["user_agent", () => stringValue(512)],
  ["_bs", numberValue],
  ["_bsm", numberValue],
];

function eventNameFor(type: string): string | undefined {
  if (type === "heartbeat") return chance(0.5) ? undefined : pick([S(""), S("x"), "null", "0", S(" ")]);
  const required = type === "custom_event" || type === "error";
  if (required && chance(0.85)) return stringValue(256, 1);
  return chance(0.5) ? undefined : stringValue(256, required ? 1 : 0);
}

function generate(): string {
  const r = rand();
  if (!VALID && r < 0.01) return pick(["null", "[]", '"x"', "5", "true", "{}", '[{"type":"pageview"}]']);

  const entries: string[] = [];
  const type = VALID || chance(0.95) ? pick(TYPES) : pick(["Pageview", "", "unknown"]);
  if (VALID || chance(0.97)) entries.push(`"type":${chance(0.97) ? S(type) : pick(WRONG_TYPES)}`);
  if (VALID || chance(0.95)) entries.push(`"site_id":${VALID || chance(0.9) ? S(pick(["1", "abc123", "site_abc"])) : pick([S(""), ...WRONG_TYPES])}`);

  const fieldChance = pick([0.05, 0.2, 0.5]);
  for (const [name, value] of BASE_FIELDS) {
    if (chance(fieldChance)) entries.push(`${S(name)}:${value()}`);
  }

  const eventName = eventNameFor(type);
  if (eventName !== undefined) entries.push(`"event_name":${eventName}`);
  const needsProperties = ["outbound", "error", "copy", "form_submit", "input_change"].includes(type);
  if ((needsProperties && chance(0.9)) || chance(type === "heartbeat" ? 0.1 : 0.4)) entries.push(`"properties":${propertiesFor(type)}`);
  if (type === "performance" || chance(0.03)) {
    for (const metric of ["lcp", "cls", "inp", "fcp", "ttfb"]) {
      if (chance(0.5)) entries.push(`${S(metric)}:${pick(["0", "1.5", "-1", "null", "1e400", "-0", S("1"), "2500", "0.1", "-1e-400"])}`);
    }
  }
  if (chance(0.08)) entries.push(`${pick([S("extra"), S("1"), S("0"), S("zzz"), S("Type"), S("constructor"), S("toString"), S("screenwidth")])}:1`);
  if (chance(0.03)) entries.push(`"type":${S(pick(TYPES))}`);
  if (chance(0.03)) entries.push(`"site_id":${S("dup")}`);

  for (let i = entries.length - 1; i > 0 && chance(0.3); i--) {
    const j = Math.floor(rand() * (i + 1));
    [entries[i], entries[j]] = [entries[j], entries[i]];
  }
  return `{${entries.join(",")}}`;
}

// Numbers compared as JavaScript prints them, -0 kept apart, except the two integer bot
// fields, which the Rust side stores as u32 (so -0 is 0 there, as it serialises in Node)
// Lone surrogates cannot exist in a Rust string; the port holds U+FFFD instead
const encode = (data: unknown) =>
  JSON.stringify(data, function (key, value) {
    if (typeof value === "string") return value.toWellFormed();
    if (typeof value !== "number") return value;
    if (Object.is(value, -0) && key !== "_bs" && key !== "_bsm") return "num:-0";
    return `num:${String(value)}`;
  });

const cases = [];
const seen = new Set<string>();
while (cases.length < COUNT) {
  const text = generate();
  if (seen.has(text)) continue;
  seen.add(text);
  const result = trackingPayloadSchema.safeParse(JSON.parse(text));
  cases.push(
    result.success
      ? { text, success: true, data: encode(result.data) }
      : { text, success: false, errors: JSON.stringify(result.error.flatten()) }
  );
}

writeFileSync(`${OUT}/${VALID ? "payload_corpus_valid.json" : "payload_corpus.json"}`, JSON.stringify(cases));
const byType: Record<string, [number, number]> = {};
for (const c of cases) {
  let type = "?";
  try {
    type = String(JSON.parse(c.text).type);
  } catch {}
  byType[type] ??= [0, 0];
  byType[type][c.success ? 0 : 1]++;
}
console.log({ cases: cases.length, accepted: cases.filter(c => c.success).length, byType });
process.exit(0);
