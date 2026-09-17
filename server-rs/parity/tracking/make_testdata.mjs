// Writes the small, synthetic-only fixtures committed under server-rs/src/tracking/testdata.
// Anything drawn from the parity snapshot (real referrers, querystrings, hostnames) is
// left out; the full dumps stay outside git and run through TRACKING_PARITY_DIR.
// Usage: node make_testdata.mjs <out dir holding the dumps and real_tuples.jsonl>
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";

const OUT = process.argv[2];
const DEST = new URL("../../src/tracking/testdata", import.meta.url).pathname;
mkdirSync(DEST, { recursive: true });

const read = name => JSON.parse(readFileSync(`${OUT}/${name}`, "utf8"));
const write = (name, value) => {
  const text = JSON.stringify(value);
  writeFileSync(`${DEST}/${name}`, text);
  console.log(name, text.length);
};
const every = (items, step, limit = Infinity) => items.filter((_, index) => index % step === 0).slice(0, limit);

const realRows = readFileSync(`${OUT}/real_tuples.jsonl`, "utf8").split("\n").filter(Boolean).map(line => JSON.parse(line));
const realReferrers = new Set(realRows.map(r => r.referrer).filter(Boolean));
const realQueries = new Set(realRows.map(r => r.querystring).filter(Boolean));
const realHosts = new Set(realRows.map(r => r.hostname).filter(Boolean));
const realReferrerHosts = new Set(
  [...realReferrers].map(r => {
    try {
      return new URL(r).hostname;
    } catch {
      return null;
    }
  })
);
// Keep well-known public referrers (search engines, social sites); drop customer domains
const PUBLIC = /google|bing|duckduckgo|yahoo|facebook|t\.co|chatgpt|claude|copilot|perplexity|kagi|ecosia|brave|stripe|instagram|linkedin|reddit|youtube|yandex|baidu/;
const isBareOrigin = text => {
  try {
    const url = new URL(text);
    return (url.pathname === "/" || url.pathname === "") && !url.search && !url.hash;
  } catch {
    return false;
  }
};
const isPrivateText = text =>
  realQueries.has(text) ||
  realHosts.has(text) ||
  (realReferrers.has(text) && !(PUBLIC.test(text) && isBareOrigin(text))) ||
  (realReferrerHosts.has(text) && !PUBLIC.test(text));

const channel = read("channel_corpus.json");
const syntheticRows = channel.rows.filter(
  r => r.source === "synthetic" && !isPrivateText(r.referrer) && !isPrivateText(r.querystring) && !isPrivateText(r.hostname.toLowerCase().replace(/^(www\.|sub\.)/, "")) && !isPrivateText(r.hostname.toLowerCase())
);
write("channel_corpus.json", {
  rows: every(syntheticRows, Math.ceil(syntheticRows.length / 900)),
  classifiers: every(channel.classifiers.filter(c => !isPrivateText(c.value) && ![...realHosts, ...[...realReferrerHosts].filter(h => h && !PUBLIC.test(h))].some(h => c.value.includes(h))), 3),
});

const small = cases => cases.filter(c => c.text.length < 1200);
write("payload_corpus.json", [...every(small(read("payload_corpus.json")), 14, 450), ...read("payload_corpus.json").filter(c => c.text.length >= 1200).slice(0, 12)]);
write("payload_corpus_valid.json", every(small(read("payload_corpus_valid.json")), 7, 400));

const ip = read("ip_corpus.json");
write("ip_corpus.json", {
  validations: every(ip.validations, 8),
  cidr: every(ip.cidr, 10),
  range: every(ip.range, 10),
  clientCases: every(ip.clientCases, 12),
});

write("http_cases.json", read("http_cases.json"));

const fuzz = read("url_fuzz.json");
write("url_fuzz.json", { urlCases: every(fuzz.urlCases, 12), queryCases: every(fuzz.queryCases, 20) });

write("exclusion_corpus.json", every(read("exclusion_corpus.json"), 12));
