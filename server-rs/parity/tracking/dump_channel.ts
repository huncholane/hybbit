// Builds the channel/URL differential corpus (real parity tuples plus synthetic edge
// cases) and dumps Node's outputs for getChannel, getUTMParams, getAllUrlParams,
// clearSelfReferrer, URLSearchParams, URL hostname, getSourceType, getMediumType and
// isPaidTraffic.
//
// Real tuples come from <out dir>/real_tuples.jsonl when present, exported from the
// parity ClickHouse with:
//   SELECT DISTINCT referrer, querystring, hostname FROM (SELECT referrer, querystring,
//   hostname FROM events UNION ALL SELECT referrer, querystring, hostname FROM bot_events)
//   FORMAT JSONEachRow
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { getChannel } from "../../../server/src/services/tracker/getChannel.ts";
import { getMediumType, getSourceType, isPaidTraffic } from "../../../server/src/services/tracker/const.ts";
import { clearSelfReferrer, getAllUrlParams, getUTMParams } from "../../../server/src/services/tracker/utils.ts";

const OUT = process.argv[2];

let seed = 0x5eed1234;
function rand() {
  seed |= 0;
  seed = (seed + 0x6d2b79f5) | 0;
  let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
  t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
  return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
}
const pick = <T>(items: T[]): T => items[Math.floor(rand() * items.length)];
const chance = (p: number) => rand() < p;

const realFile = `${OUT}/real_tuples.jsonl`;
const real = (existsSync(realFile) ? readFileSync(realFile, "utf8") : "")
  .split("\n")
  .filter(Boolean)
  .map(line => JSON.parse(line) as { referrer: string; querystring: string; hostname: string });

const lists = readFileSync(
  new URL("../../src/tracking/channel_lists.rs", import.meta.url),
  "utf8"
);
const listValues = [...lists.matchAll(/^\s+"((?:[^"\\]|\\.)*)",$/gm)].map(m => JSON.parse(`"${m[1]}"`) as string);
const domains = listValues.filter(v => v.includes(".") && !v.startsWith("com.") && !/^[a-z]+\.[a-z]+\.[a-z]/.test(v) || v.endsWith("."));

const realReferrers = [...new Set(real.map(r => r.referrer))];
const realQuerystrings = [...new Set(real.map(r => r.querystring))];
const realHostnames = [...new Set(real.map(r => r.hostname))];

const weirdReferrers = [
  "",
  "not a url",
  "//google.com/",
  "https://",
  "http://a b.com/",
  "https://bücher.de/path",
  "https://xn--bcher-kva.de/",
  "https://EXAMPLE.com/",
  "HTTPS://WWW.GOOGLE.COM/search?q=1",
  "  https://www.bing.com/  ",
  "\thttps://duckduckgo.com/\n",
  "https://goo\tgle.com/",
  "http://[::1]:8080/",
  "http://[2001:db8::1]/",
  "http://127.0.0.1:3000/",
  "http://0x7f.1/",
  "http://2130706433/",
  "https://example.com:99999/",
  "https://user:pass@www.facebook.com/",
  "android-app://com.google.android.gm/",
  "android-app://com.linkedin.android/",
  "ios-app://com.apple.mobilemail",
  "file:///etc/passwd",
  "javascript:alert(1)",
  "about:blank",
  "data:text/html,hi",
  "mailto:someone@example.com",
  "https://exa%41mple.com/",
  "https://ex ample.com/",
  "http://[::1/",
  "https://google.com.evil.com/",
  "https://chat.openai.com/c/1",
  "https://www.perplexity.ai/search",
  "https://gemini.google.com/app",
  "https://m.facebook.com/",
  "https://l.instagram.com/",
  "https://t.co/abc",
  "https://news.ycombinator.com/item?id=1",
  "https://www.youtube.com/watch?v=1",
  "https://www.amazon.co.uk/dp/1",
  "https://search.yahoo.co.jp/",
  "https://yandex.ru/search",
  "https://mail.google.com/",
  "https://outlook.live.com/",
  "https://a.b.c.d.example.co.uk/",
  "https://localhost/",
  "https://www./",
  "https://www.www.example.com/",
  "https://ΕΛΛΑΣ.gr/",
  "https://☃.net/",
  "https://example.com./",
  "https://%E2%98%83.com/",
  "https://xn--/",
  "https://a..b/",
  "http://%zz.com/",
  "https://[::ffff:1.2.3.4]/",
  "foo://ABC.def/x",
  "https://exam­ple.com/",
  "https://ex​ample.com/",
  "https://example.com\\path",
  "https:example.com",
  "https:\\\\example.com",
  "http://example.com:0/",
  "ws://google.com/",
  "blob:https://google.com/uuid",
  "https://1.1.1.1/",
  "https://999.1.1.1/",
  "https://1.2.3/",
];

const sourceValues = [
  ...listValues,
  "google",
  "Google",
  "GOOGLE ADS",
  "facebook ads",
  "my_app",
  "gsuite_extension",
  "direct",
  "(direct)",
  "com.google.android.gm",
  "COM.FACEBOOK.KATANA",
  "com.facebook.katana",
  "com.unknown.app",
  "com.google.Gmail",
  "a.b",
  "a..b",
  "newsletter",
  "chatgpt.com",
  "",
  "é",
  "ΑΣ",
];
const mediumValues = [
  ...listValues.filter(v => !v.includes(".")),
  "cpc",
  "CPC",
  "paid_social",
  "broadcast",
  "adwords",
  "promotion",
  "sponsored-post",
  "organic",
  "",
  "referral",
  "Email",
];
const campaignValues = [
  "ai",
  "spring-ai-launch",
  "ai_launch",
  "maintenance",
  "chatgpt-promo",
  "claude",
  "video",
  "shopping-cart",
  "workshop",
  "creator",
  "sponsored",
  "webinar",
  "conference",
  "event",
  "facebook",
  "social",
  "cross-network",
  "brand",
  "éai",
  "aï",
  "llm",
  "",
  "AI",
];

function encodeComponent(value: string): string {
  const r = rand();
  if (r < 0.5) return encodeURIComponent(value);
  if (r < 0.7) return value.replace(/ /g, "+");
  if (r < 0.8) return value.toUpperCase();
  return value;
}

const syntheticQuerystrings: string[] = [
  "",
  "?",
  "??utm_source=google",
  "???utm_source=google",
  "&&",
  "=",
  "utm_source",
  "utm_source=",
  "?utm_source=google&utm_source=bing",
  "?UTM_SOURCE=google",
  "?utm_Source=Google&utm_MEDIUM=CPC",
  "?gclid=abc",
  "?gad_source=1",
  "?gclid=",
  "?utm_source=%zz",
  "?utm_source=%E2%82",
  "?utm_source=é%41%zz",
  "?utm_source=%41%zz€",
  "?utm_source=%FF+x",
  "?utm_source=%ED%A0%80",
  "?utm_source=%F0%9F%98%80",
  "?utm_source=%c3%a9",
  "?utm_source=a%2Bb+c",
  "?utm_source=%4+1",
  "?utm_source=%%41",
  "?utm_source=%4%41",
  "?a=1&b=2&1=x&0=y&__proto__=z&__PROTO__=w&constructor=v",
  "?4294967294=a&4294967295=b&01=c&10=d&2=e",
  "?a=b=c&&=x&y",
  "?x=%",
  "?x=%2",
  "?x=a%",
  "?q=%E4%BD%A0%E5%A5%BD",
  "?q=你好&utm_source=百度",
  "?utm_campaign=cross-network&utm_source=google",
  "?utm_source=com.google.android.gm&utm_medium=cpc",
  "?utm_medium=email",
  "?utm_source=twitter&utm_medium=paid",
  "#utm_source=google",
  "?utm_source=google#frag",
  "utm_source=google&utm_medium=cpc&utm_campaign=brand",
];

const pathRe = /\/[a-z]{0,8}/;
function randomReferrer(): string {
  const r = rand();
  if (r < 0.35) return pick(realReferrers);
  if (r < 0.5) return pick(weirdReferrers);
  const domain = pick(domains).replace(/\.$/, ".com").replace(/\/.*$/, "");
  const prefix = pick(["", "www.", "m.", "l.", "www.www.", "search.", "news."]);
  const scheme = pick(["https://", "http://", "https://", "HTTPS://"]);
  const path = chance(0.5) ? pick(["/", "/search?q=x", "/a/b", "", "/?utm_source=x"]) : "/";
  return scheme + (chance(0.1) ? (prefix + domain).toUpperCase() : prefix + domain) + path;
}

function randomQuerystring(): string {
  const r = rand();
  if (r < 0.3) return pick(realQuerystrings);
  if (r < 0.4) return pick(syntheticQuerystrings);
  const params: string[] = [];
  if (chance(0.6)) params.push(`utm_source=${encodeComponent(pick(sourceValues))}`);
  if (chance(0.5)) params.push(`utm_medium=${encodeComponent(pick(mediumValues))}`);
  if (chance(0.4)) params.push(`utm_campaign=${encodeComponent(pick(campaignValues))}`);
  if (chance(0.1)) params.push(`gclid=${pick(["abc", "", "X"])}`);
  if (chance(0.1)) params.push(`gad_source=${pick(["1", "", "5"])}`);
  if (chance(0.2)) params.push(`${pick(["fbclid", "ref", "q", "1", "UTM_TERM", "utm_content"])}=${encodeComponent(pick(sourceValues))}`);
  if (chance(0.1)) params.push(pick(["&", "", "=", "%zz", "a+b"]));
  for (let i = params.length - 1; i > 0; i--) {
    const j = Math.floor(rand() * (i + 1));
    [params[i], params[j]] = [params[j], params[i]];
  }
  return (chance(0.7) ? "?" : "") + params.join("&");
}

function randomHostname(referrer: string): string {
  const r = rand();
  if (r < 0.25) {
    try {
      const host = new URL(referrer).hostname;
      return pick([host, host.replace(/^www\./, ""), `www.${host}`, `sub.${host}`, host.toUpperCase()]);
    } catch {
      return "";
    }
  }
  if (r < 0.5) return pick(realHostnames);
  if (r < 0.7) return "";
  return pick(["example.com", "www.example.com", "google.com", "localhost", "hygo.ai", "app.hygo.ai", "com"]);
}

type Tuple = { referrer: string; querystring: string; hostname: string; source: "real" | "synthetic" };
const tuples = new Map<string, Tuple>();
const add = (t: Tuple) => {
  const key = JSON.stringify([t.referrer, t.querystring, t.hostname]);
  if (!tuples.has(key)) tuples.set(key, t);
};
for (const t of real) add({ ...t, source: "real" });
for (const referrer of [...realReferrers, ...weirdReferrers]) {
  for (const querystring of ["", ...syntheticQuerystrings.slice(0, 12)]) add({ referrer, querystring, hostname: "", source: "synthetic" });
}
for (const querystring of [...realQuerystrings, ...syntheticQuerystrings]) {
  add({ referrer: "", querystring, hostname: "", source: "synthetic" });
  add({ referrer: "https://www.google.com/", querystring, hostname: "example.com", source: "synthetic" });
}
while (tuples.size < 26000) {
  const referrer = randomReferrer();
  add({ referrer, querystring: randomQuerystring(), hostname: randomHostname(referrer), source: "synthetic" });
}

const urlHost = (input: string) => {
  try {
    return new URL(input).hostname;
  } catch {
    return null;
  }
};

const rows = [...tuples.values()].map(t => ({
  ...t,
  channel: getChannel(t.referrer, t.querystring, t.hostname || undefined),
  utm: Object.entries(getUTMParams(t.querystring)),
  all: Object.entries(getAllUrlParams(t.querystring)),
  cleared: clearSelfReferrer(t.referrer, t.hostname),
  searchParams: [...new URLSearchParams(t.querystring).entries()],
  referrerHost: urlHost(t.referrer),
}));

const classifierInputs = [...new Set([...sourceValues, ...mediumValues, ...campaignValues, ...realHostnames, ...rows.map(r => r.referrerHost ?? "")])];
const classifiers = classifierInputs.map(value => ({
  value,
  sourceType: getSourceType(value),
  mediumType: getMediumType(value),
  paidAsMedium: isPaidTraffic(value, ""),
  paidAsSource: isPaidTraffic("", value),
}));

writeFileSync(`${OUT}/channel_corpus.json`, JSON.stringify({ rows, classifiers }));
console.log({
  tuples: rows.length,
  real: rows.filter(r => r.source === "real").length,
  classifiers: classifiers.length,
  channels: Object.entries(rows.reduce<Record<string, number>>((acc, r) => ((acc[r.channel] = (acc[r.channel] ?? 0) + 1), acc), {})),
});
// utils.ts pulls in the user id service, whose store clients keep the loop alive
process.exit(0);
