// Shared input generation for the identity differential tests. Deterministic:
// everything comes from a seeded PRNG plus fixed files.
import { createRequire } from "node:module";
import { readdirSync, readFileSync, statSync } from "node:fs";
import path from "node:path";

const require = createRequire(import.meta.url);

export function rng(seed: number) {
  let a = seed >>> 0;
  const next = () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
  const int = (n: number) => Math.floor(next() * n);
  const pick = <T,>(items: readonly T[]): T => items[int(items.length)];
  return { next, int, pick };
}

type Rng = ReturnType<typeof rng>;

function walk(dir: string, out: string[] = []) {
  for (const name of readdirSync(dir)) {
    const full = path.join(dir, name);
    if (statSync(full).isDirectory()) walk(full, out);
    else if (full.endsWith(".ts")) out.push(full);
  }
  return out;
}

/** String literals in the Node sources that look like user agents. */
function sourceUserAgents(serverDir: string): string[] {
  const found = new Set<string>();
  const literal = /"((?:[^"\\\n]|\\.){6,400})"|`([^`\n]{6,400})`/g;
  for (const file of walk(path.join(serverDir, "src"))) {
    const text = readFileSync(file, "utf8");
    for (const match of text.matchAll(literal)) {
      const value = match[1] ?? match[2];
      if (!value || value.includes("${")) continue;
      if (/Mozilla|AppleWebKit|Android|iPhone|[Bb]ot\b|curl|okhttp|Dalvik|CFNetwork|python|Gecko|Electron|Build\/|rv:/.test(value)) {
        try {
          found.add(JSON.parse(`"${value.replace(/"/g, '\\"')}"`));
        } catch {
          found.add(value);
        }
      }
    }
  }
  return [...found];
}

/**
 * Real-world user agents from the `user-agents` npm package, when
 * USER_AGENTS_DATASET points at its dist/index.js (install it anywhere outside
 * the repo, e.g. `npm install --prefix <scratch dir> user-agents@1`).
 */
function datasetUserAgents(): string[] {
  if (!process.env.USER_AGENTS_DATASET) return [];
  const UserAgent = require(process.env.USER_AGENTS_DATASET);
  const Ctor = UserAgent.default ?? UserAgent;
  const found = new Set<string>();
  for (let i = 0; i < 120000 && found.size < 8000; i++) found.add(new Ctor().toString());
  return [...found].sort();
}

function v(r: Rng, parts: number, max = 200, sep = ".") {
  return Array.from({ length: parts }, () => String(r.int(max))).join(sep);
}

function templateUserAgents(r: Rng, count: number): string[] {
  const androidModels = ["SM-S928N", "SM-A536N", "Pixel 8 Pro", "Nokia 6.1 Plus", "Nokia 8.3 Plus", "M2101K6G", "CPH2451", "moto g(60)", "Redmi Note 9 Pro", "HUAWEI P30", "V2025", "RMX3085", "2201117TY", "SM-J320F", "LM-Q720", "ONEPLUS A6013", "K"];
  const chromeOs = ["x86_64", "aarch64", "armv7l"];
  const out: string[] = [];
  for (let i = 0; i < count; i++) {
    const kind = r.int(22);
    const chrome = `${r.int(160)}.0.${r.int(9000)}.${r.int(300)}`;
    const webkit = r.pick(["537.36", "605.1.15", "604.1", "600.1.4"]);
    const ios = r.pick([`${r.int(27)}_${r.int(9)}`, `${r.int(27)}_${r.int(9)}_${r.int(9)}`, `${r.int(27)}`]);
    const model = r.pick(androidModels);
    switch (kind) {
      case 0:
        out.push(`Mozilla/5.0 (Windows NT ${r.pick(["10.0", "6.1", "6.3", "11.0", "5.1"])}; Win64; x64) AppleWebKit/${webkit} (KHTML, like Gecko) Chrome/${chrome} Safari/${webkit}`);
        break;
      case 1:
        out.push(`Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:${r.int(160)}.0) Gecko/20100101 Firefox/${r.int(160)}.${r.int(3)}`);
        break;
      case 2:
        out.push(`Mozilla/5.0 (iPhone; CPU iPhone OS ${ios} like Mac OS X) AppleWebKit/${webkit} (KHTML, like Gecko) Version/${r.int(27)}.${r.int(9)} Mobile/${r.pick(["15E148", "16B92", "22A3354", "13G36"])} Safari/604.1`);
        break;
      case 3:
        out.push(`Mozilla/5.0 (iPad; CPU OS ${ios} like Mac OS X) AppleWebKit/${webkit} (KHTML, like Gecko) CriOS/${chrome} Mobile/15E148 Safari/604.1`);
        break;
      case 4:
        out.push(`Mozilla/5.0 (Linux; Android ${r.pick([`${r.int(16)}`, `${r.int(16)}.${r.int(3)}`, `${r.int(16)}.${r.int(3)}.${r.int(3)}`])}; ${model} Build/${r.pick(["AP3A.240905.015", "QKQ1.190828.002", "UP1A.231005.007", "RP1A.200720.012", "TP1A.220624.014_NONFRP"])}; wv) AppleWebKit/${webkit} (KHTML, like Gecko) Version/4.0 Chrome/${chrome} Mobile Safari/${webkit}`);
        break;
      case 5:
        out.push(`Mozilla/5.0 (Macintosh; Intel Mac OS X ${r.pick(["10_15_7", "10_14_6", "14_5", "10.15", "13_0"])}) AppleWebKit/${webkit} (KHTML, like Gecko) Version/${r.int(19)}.${r.int(9)} Safari/${webkit}`);
        break;
      case 6:
        out.push(`Mozilla/5.0 (X11; CrOS ${r.pick(chromeOs)} ${r.int(16000)}.${r.int(100)}.${r.int(10)}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${chrome} Safari/537.36`);
        break;
      case 7:
        out.push(`Mozilla/5.0 (Windows Phone ${r.pick(["8.1", "10.0"])}; Android 6.0.1; Microsoft; Lumia 950) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.116 Mobile Safari/537.36 Edge/15.15063`);
        break;
      case 8:
        out.push(`Mozilla/5.0 (compatible; MSIE 10.0; Windows Phone OS ${r.int(9)}.${r.int(9)}; Trident/6.0; IEMobile/10.0; ARM; Touch; NOKIA; Lumia 920)`);
        break;
      case 9:
        out.push(`Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) opgg-electron-app/${v(r, 3, 10)} Chrome/${chrome} Electron/${v(r, 3, 40)} Safari/537.36`);
        break;
      case 10:
        out.push(`Mozilla/5.0 (iPhone; CPU iPhone OS ${ios} like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) HygoReactNative/${v(r, 3, 10)} ${v(r, 2 + r.int(3), 20)}`);
        break;
      case 11:
        out.push(`Mozilla/5.0 (iPhone; CPU iPhone OS ${ios} like Mac OS X) AppleWebKit/605.1.15 [FBAN/FBIOS;FBDV/iPhone${r.int(17)},${r.int(9)};FBMD/iPhone;FBSN/iOS;FBSV/${ios.replace(/_/g, ".")};FBSS/3;FBID/phone;FBLC/en_US;FBOP/5;FBAV/${v(r, 5, 500)}]`);
        break;
      case 12:
        out.push(`Mozilla/5.0 (Linux; Android ${r.int(15)}; ${model}) AppleWebKit/537.36 [FBAN/EMA;FBDV/${model};FBCA/armeabi-v7a:armeabi;FBAV/${v(r, 5, 500)};]`);
        break;
      case 13:
        out.push(`Instagram ${v(r, 5, 400)} Android (${r.int(35)}/${r.int(15)}; ${r.int(600)}dpi; ${r.int(2000)}x${r.int(3000)}; samsung; ${model}; a53x; s5e8825; en_US; ${r.int(999999999)})`);
        break;
      case 14:
        out.push(r.pick(["curl/8.4.0", "python-requests/2.31.0", "Go-http-client/1.1", "okhttp/4.12.0", "Dalvik/2.1.0 (Linux; U; Android 13; SM-G991B Build/TP1A.220624.014)", "HygoApp/12 CFNetwork/1498.700.2 Darwin/23.6.0", "Mediapartners-Google", "Googlebot/2.1 (+http://www.google.com/bot.html)"]));
        break;
      case 15:
        out.push(`Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html) Chrome/${chrome} Safari/537.36`);
        break;
      case 16:
        out.push(`Mozilla/5.0 (Linux; U; Android ${r.int(12)}; en-us; ${model} Build/${r.pick(["KOT49H", "LMY47V", "N2G47H"])}) AppleWebKit/534.30 (KHTML, like Gecko) Version/4.0 UCBrowser/${v(r, 4, 20)} Mobile Safari/534.30`);
        break;
      case 17:
        out.push(`Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:${r.int(130)}.0) Gecko/20100101 Firefox/${r.int(130)}.0`);
        break;
      case 18:
        out.push(`Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${chrome} Safari/537.36 Edg/${chrome} OPR/${v(r, 4, 120)}`);
        break;
      case 19:
        out.push(`MyApp/v${v(r, 3, 10)} (${model}; Android/${v(r, 2, 15)}) Mobile/${r.pick(["15E148", "ABC-12.x"])} ${v(r, 3 + r.int(3), 100)}`);
        break;
      case 20:
        out.push(`Mozilla/5.0 (Linux; Android ${r.int(15)}; ${model} Build/${r.pick(["AP3A.240905.015", "QKQ1"])}; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/${chrome} Mobile Safari/537.36 Line/${v(r, 3, 20)}/IAB`);
        break;
      default:
        out.push(`Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 Version/${r.int(20)}.${r.int(9)}.${r.int(9)} Safari/605.1.15 ${v(r, 3, 100)} (${v(r, 3, 20)};${v(r, 4, 20)})`);
    }
  }
  return out;
}

const UA_TOKENS = [
  "0", "1", "9", "12", "0.1", "3.4.5", "_", ".", "..", "/", "/v", " ", "(", ")", ";", ":", ",", "-", "x", "A", "Z", "é", "中", "😀", "\t",
  "rv:", "Build/", "Mobile/", "Windows NT ", "Windows Phone ", "Windows Phone OS ", "Android ", "Android/", "CPU OS ", "CPU iPhone OS ",
  "Mac OS X ", "CrOS ", "CrOS x86_64 ", "Chrome/", "Safari/", "Version/", "FBDV/iPhone12,8", "Nokia 6.1 Plus", "_OS ", "xBuild/", "aMobile/",
];

function mutate(r: Rng, input: string): string {
  let s = input;
  const ops = 1 + r.int(4);
  for (let i = 0; i < ops; i++) {
    const at = r.int(s.length + 1);
    const op = r.int(3);
    if (op === 0) s = s.slice(0, at) + r.pick(UA_TOKENS) + s.slice(at);
    else if (op === 1) s = s.slice(0, at) + s.slice(at + 1 + r.int(4));
    else s = s.slice(0, at) + r.pick(UA_TOKENS) + s.slice(at + 1);
  }
  return s;
}

function tokenSoup(r: Rng, tokens: readonly string[], maxTokens: number): string {
  return Array.from({ length: r.int(maxTokens) + 1 }, () => r.pick(tokens)).join("");
}

export function userAgentCorpus(serverDir: string): { source: string; value: string }[] {
  const r = rng(20260917);
  const out: { source: string; value: string }[] = [];
  const seen = new Set<string>();
  const add = (source: string, value: string) => {
    if (seen.has(value) || !value.isWellFormed()) return;
    seen.add(value);
    out.push({ source, value });
  };
  for (const ua of sourceUserAgents(serverDir)) add("node-sources", ua);
  const dataset = datasetUserAgents();
  for (const ua of dataset) add("user-agents-dataset", ua);
  const templates = templateUserAgents(r, 12000);
  for (const ua of templates) add("templates", ua);
  const bases = [...dataset, ...templates];
  for (let i = 0; i < 12000; i++) add("mutations", mutate(r, r.pick(bases)));
  for (let i = 0; i < 6000; i++) add("token-soup", tokenSoup(r, UA_TOKENS, 14));
  add("edge", "");
  add("edge", " ");
  add("edge", "1.2.3");
  add("edge", "(1.2.3)");
  return out;
}

const HEX = "0123456789abcdef";

function hexGroup(r: Rng, maxLen = 4) {
  return Array.from({ length: 1 + r.int(maxLen) }, () => HEX[r.int(16)]).join("");
}

function ipv6Forms(r: Rng): string {
  const groups = Array.from({ length: 8 }, () => (r.next() < 0.3 ? "0" : hexGroup(r)));
  const form = r.int(9);
  if (form === 0) return groups.join(":");
  if (form === 1) return groups.map(g => g.padStart(4, "0")).join(":").toUpperCase();
  if (form === 2 || form === 3) {
    const start = r.int(8);
    const end = start + r.int(8 - start);
    const left = groups.slice(0, start).join(":");
    const right = groups.slice(end + 1).join(":");
    return `${left}::${right}`;
  }
  if (form === 4) return `::ffff:${r.int(256)}.${r.int(256)}.${r.int(256)}.${r.int(256)}`;
  if (form === 5) return `${groups.slice(0, 6).join(":")}:${r.pick(["1.2.3.4", "01.2.3.4", "255.255.255.255", "256.1.1.1", "1.2.3"])}`;
  if (form === 6) return `${groups.slice(0, 4).join(":")}::${hexGroup(r)}${r.pick(["%eth0", "%25", "%", "%\n", "/64", "/64%eth0", "/1234", "/", "/48", "/129", "/0", "%lo/64"])}`;
  if (form === 7) return groups.slice(0, 7 + r.int(3)).join(":");
  return `${hexGroup(r, 6)}:${r.pick([":::", "::", ":"])}${hexGroup(r)}${r.pick(["", ":", "::", ":1:2"])}`;
}

const IP_TOKENS = ["0", "1", "01", "9", "10", "255", "256", "a", "f", "F", "ffff", "g", ":", "::", ".", "/", "/48", "/24", "%", "%eth0", " ", "\n", " ", "x", "é", "12345"];

export function ipBucketCorpus(): string[] {
  const r = rng(4815162342);
  const out = new Set<string>();
  for (let i = 0; i < 3000; i++) out.add(`${r.int(256)}.${r.int(256)}.${r.int(256)}.${r.int(256)}`);
  for (let i = 0; i < 2000; i++) {
    const octet = () => r.pick([String(r.int(256)), String(r.int(1000)), `0${r.int(100)}`, `00${r.int(10)}`, "", " 1", "1 ", "-1", "+1", "0x1"]);
    const count = r.pick([4, 4, 4, 3, 5]);
    out.add(Array.from({ length: count }, octet).join("."));
  }
  for (let i = 0; i < 6000; i++) out.add(ipv6Forms(r));
  for (let i = 0; i < 5000; i++) out.add(tokenSoup(r, IP_TOKENS, 12));
  for (const edge of ["", "::", "::1", "1::", ":", ":::", "1:2:3:4:5:6:7:8", "1:2:3:4:5:6:7::", "::2:3:4:5:6:7:8", "0:0:1::", "2001:0:1::", "1.2.3.4", " 1.2.3.4", "1.2.3.4 ", "2a06:98c0:3600::103", "172.68.34.28"]) out.add(edge);
  return [...out];
}

/** Datacenter-heavy address sampling for real ASN lookups. */
export function userIdIps(r: Rng): { ip: string; kind: string }[] {
  const out: { ip: string; kind: string }[] = [];
  const v4Prefixes = ["3.", "13.", "18.", "34.", "35.", "52.", "54.", "104.16.", "104.28.", "172.64.", "172.68.", "172.71.", "162.158.", "51.", "95.216.", "159.89.", "138.68.", "45.33.", "20.", "40.", "17.", "146.75.", "151.101.", "23.", "73.", "98.", "24.", "71.", "92.", "81.", "2.", "5.", "31.", "37.", "109.", "176.", "185.", "188.", "212.", "217."];
  for (let i = 0; i < 6000; i++) {
    const prefix = r.pick(v4Prefixes);
    const needed = 4 - (prefix.split(".").length - 1);
    const rest = Array.from({ length: needed }, () => String(r.int(256))).join(".");
    out.push({ ip: `${prefix}${rest}`, kind: "v4-prefix" });
  }
  for (let i = 0; i < 3000; i++) out.push({ ip: `${r.int(224)}.${r.int(256)}.${r.int(256)}.${r.int(256)}`, kind: "v4-random" });
  const v6Prefixes = ["2a06:98c0:", "2a06:98c1:", "2606:4700:", "2600:1f00:", "2600:1f18:", "2a01:4f8:", "2a01:4f9:", "2001:4860:", "2604:a880:", "2a03:b0c0:", "2001:41d0:", "2a02:6b8:", "2601:", "2600:1700:", "2a02:c7c:", "2003:", "2a01:cb00:", "2406:da00:", "2402:4e00:", "2c0f:f248:"];
  for (let i = 0; i < 5000; i++) {
    const prefix = r.pick(v6Prefixes);
    const have = prefix.split(":").length - 1;
    const rest = Array.from({ length: 8 - have }, () => hexGroup(r)).join(":");
    const full = `${prefix}${rest}`;
    const form = r.int(4);
    const ip = form === 0 ? full : form === 1 ? full.replace(/(^|:)0(:0)+(:|$)/, "::") : form === 2 ? full.toUpperCase() : `${full.split(":").slice(0, 4).join(":")}::${hexGroup(r)}`;
    out.push({ ip, kind: "v6-prefix" });
  }
  for (let i = 0; i < 1000; i++) out.push({ ip: `2${hexGroup(r, 3)}:${hexGroup(r)}:${hexGroup(r)}::${hexGroup(r)}`, kind: "v6-random" });
  for (let i = 0; i < 300; i++) out.push({ ip: `::ffff:${r.int(224)}.${r.int(256)}.${r.int(256)}.${r.int(256)}`, kind: "v4-mapped" });
  return out;
}

const ZONE_TOKENS = ["eth0", "0", "1", "25", "a", "F", "x", "0x", "0x1f", "-", "-1", ".", ":", "::", "1.2.3.4", "255.255.255.255", "1234.5.6.7", "99999999999999999999.1.1.1", "ffff", "123456789abcdef", "fffffffffffffffffffffffffffffffffff", "20000000000001", "Z", "lo"];

/** IPv6 addresses with zone ids built to exercise mmdb-lib's parser. */
export function zoneIps(r: Rng): string[] {
  const bases = ["2a06:98c0:3600::103", "2600:1f18:1234::1", "fe80::1", "::1", "::", "2a01:4f8::", "::ffff:104.16.1.1", "1:2:3:4:5:6:7:8", "2001:4860:4860::8888", "2604:a880:400:d0::1"];
  const out: string[] = [];
  for (let i = 0; i < 4000; i++) out.push(`${r.pick(bases)}%${tokenSoup(r, ZONE_TOKENS, 6)}`);
  return out;
}

/** Strings a spoofed header could carry that Node's and Rust's IP parsers may treat differently. */
export function weirdUserIdIps(): { ip: string; kind: string }[] {
  const bases = ["104.16.1.1", "172.68.34.28", "2a06:98c0:3600::103", "2600:1f18:1234::1", "73.1.2.3", "95.216.1.2"];
  const out: { ip: string; kind: string }[] = [];
  for (const base of bases) {
    for (const ip of [` ${base}`, `${base} `, `${base}\n`, `${base}%eth0`, `${base}/24`, base.toUpperCase(), base.replace(/\b(\d)\b/, "0$1"), `[${base}]`, `::ffff:${base}`]) {
      out.push({ ip, kind: "weird" });
    }
  }
  return out;
}

export function dayBoundaryInstant(r: Rng): string {
  const day = Date.UTC(2020 + r.int(11), r.int(12), 1 + r.int(28));
  const offsets = [-1, 0, 1, -1000, 999, 86_399_999, 43_200_000, r.int(86_400_000)];
  return new Date(day + r.pick(offsets)).toISOString();
}

export const UNICODE_BITS = ["é", "中", "😀", " ", "\n", ":", "'", "\\", " ", "%", "ß"];
