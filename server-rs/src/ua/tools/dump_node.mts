// Dumps what the Node server itself reports for every corpus UA: the real
// parseUserAgent (with its LRU) and getDeviceType at a few screen sizes. Run from
// the server directory so its node_modules resolve:
//
//   cd server && npx tsx ../server-rs/src/ua/tools/dump_node.mts ../corpus.json ../node-dump.json
//
// Importing the tracker utils loads the server's Redis clients and GeoIP readers
// as a side effect (nothing is written), so run it against a local environment only.
import fs from "node:fs";
import path from "node:path";

const [corpusPath, outPath] = process.argv.slice(2);
if (!outPath) {
  console.error("usage: dump_node.mts <corpus.json> <out.json>");
  process.exit(2);
}
const { parseUserAgent } = await import(path.resolve("src/services/tracker/utils.ts"));
const { getDeviceType } = await import(path.resolve("src/utils.ts"));
const corpus: string[] = JSON.parse(fs.readFileSync(corpusPath, "utf8"));

const SCREENS: Array<[number, number]> = [
  [0, 0],
  [1920, 1080],
  [390, 844],
  [1024, 768],
  [800, 1280],
  [1366, 1024],
  [1024.5, 600],
];

// Rust Strings cannot hold lone surrogates (only produced when UA_MAX_LENGTH
// truncation splits a surrogate pair); the port drops them, so strip them here.
const clean = (v: unknown): string | null => {
  if (v === undefined) return null;
  if (typeof v !== "string") throw new Error(`non-string field ${String(v)}`);
  return v.isWellFormed() ? v : v.replace(/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/g, "");
};

const out = corpus.map((ua) => {
  const r = parseUserAgent(ua);
  const again = parseUserAgent(ua);
  if (again !== r) throw new Error("cache miss on second lookup");
  const keys = Object.keys(r).sort().join(",");
  if (keys !== "browser,cpu,device,engine,os,ua") throw new Error(`unexpected result keys ${keys}`);
  return {
    input: ua,
    ua: clean(r.ua),
    browser: { name: clean(r.browser.name), version: clean(r.browser.version), major: clean(r.browser.major), type: clean(r.browser.type) },
    cpu: { architecture: clean(r.cpu.architecture) },
    device: { type: clean(r.device.type), model: clean(r.device.model), vendor: clean(r.device.vendor) },
    engine: { name: clean(r.engine.name), version: clean(r.engine.version) },
    os: { name: clean(r.os.name), version: clean(r.os.version) },
    deviceTypes: SCREENS.map(([w, h]) => getDeviceType(w, h, r)),
  };
});

fs.writeFileSync(outPath, JSON.stringify({ screens: SCREENS, cases: out }));
console.log(`dumped ${out.length} cases`);
process.exit(0);
