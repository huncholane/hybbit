// Dumps Node's validateIPPattern / matchesCIDR / matchesRange over generated
// addresses, and getIpAddress / resolveClientIp / collectCandidateClientIps /
// getRequestUserAgent over generated header sets (request.ip computed by the real
// @fastify/proxy-addr with trustProxy: true).
import { writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { createAsnLookup } from "../../../server/src/db/geolocation/asn.ts";
import { matchesCIDR, matchesRange, validateIPPattern } from "../../../server/src/lib/ipUtils.ts";
import { collectCandidateClientIps, resolveClientIp } from "../../../server/src/services/tracker/resolveClientIp.ts";
import { getIpAddress, getRequestUserAgent } from "../../../server/src/utils.ts";

const require = createRequire(new URL("../../../server/package.json", import.meta.url));
const proxyAddr = require("@fastify/proxy-addr");

const OUT = process.argv[2];

let seed = 0x1badb002;
function rand() {
  seed |= 0;
  seed = (seed + 0x6d2b79f5) | 0;
  let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
  t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
  return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
}
const pick = <T>(items: T[]): T => items[Math.floor(rand() * items.length)];
const chance = (p: number) => rand() < p;
const int = (n: number) => Math.floor(rand() * n);

function octet(): string {
  const r = rand();
  if (r < 0.8) return String(int(256));
  if (r < 0.9) return pick(["0", "00", "01", "001", "010", "099", "199", "255"]);
  return pick(["256", "300", "999", "", "-1", "1a", " 1", "0x1"]);
}
function ipv4(): string {
  const parts = [octet(), octet(), octet(), octet()];
  if (chance(0.05)) parts.pop();
  if (chance(0.03)) parts.push(octet());
  return parts.join(".");
}
function hexGroup(): string {
  const r = rand();
  if (r < 0.85) return int(0x10000).toString(16).slice(0, 1 + int(4));
  if (r < 0.92) return int(0x10000).toString(16).toUpperCase();
  return pick(["0", "00000", "g", "", "/1", "ffff", "0000"]);
}
function ipv6(): string {
  const r = rand();
  if (r < 0.3) return Array.from({ length: 8 }, hexGroup).join(":");
  if (r < 0.6) {
    const left = Array.from({ length: int(4) }, hexGroup).join(":");
    const right = Array.from({ length: int(4) }, hexGroup).join(":");
    return `${left}::${right}`;
  }
  if (r < 0.75) return pick(["::ffff:", "::", "64:ff9b::", "1:2:3:4:5:6:"]) + ipv4();
  if (r < 0.85) return pick(["fe80::1%eth0", "fe80::1%", "::1%lo", "fe80::a:b%en0"]);
  return pick([
    "::", "::1", ":::", "1::2::3", "1:2:3:4:5:6:7:8:9", ":1:2:3:4:5:6:7", "1:2:3:4:5:6:7:", "2001:db8::1",
    "2001:DB8::1", "::a/1", "::/5", "1:2:3:4:5:6:7:8", "::ffff:01.2.3.4", "::1.2.3.4", "1.2.3.4::", "2a06:98c0:3600::103",
  ]);
}
function address(): string {
  const r = rand();
  if (r < 0.45) return ipv4();
  if (r < 0.9) return ipv6();
  return pick(["", " ", "localhost", "abc", "1.2.3.4 ", " ::1", "1.2.3.4\t", "0x7f000001", "2130706433", "...", "::ffff:1.2.3.4/120"]);
}
function subnetSuffix(v6: boolean): string {
  const r = rand();
  if (r < 0.8) return `/${int(v6 ? 130 : 34)}`;
  return pick(["/", "/-1", "/abc", "/024", "/0064", "/1/2", "//24", "/24%eth0", "/1234", "/ 24", "/33", "/129"]);
}

// Addresses related to a subnet, so both matches and misses occur
function flipLowBits(ip: string): string {
  const parts = ip.split(".");
  if (parts.length === 4 && parts.every(p => /^\d+$/.test(p) && Number(p) < 256)) {
    parts[3] = String(int(256));
    if (chance(0.3)) parts[2] = String(int(256));
    return parts.join(".");
  }
  const groups = ip.split(":");
  if (groups.length > 2) groups[groups.length - 1] = int(0x10000).toString(16);
  return groups.join(":");
}

const patterns = new Set<string>();
const cidrPairs: Array<[string, string]> = [];
const rangePairs: Array<[string, string]> = [];

for (let i = 0; i < 6000; i++) {
  const base = address();
  const v6 = base.includes(":");
  const r = rand();
  let pattern: string;
  if (r < 0.35) pattern = base;
  else if (r < 0.7) pattern = base + subnetSuffix(v6);
  else if (r < 0.9) pattern = `${pick(["", " "])}${base}${pick(["-", " - ", "-", "--"])}${chance(0.8) ? flipLowBits(base) : address()}${chance(0.1) ? "-1.1.1.1" : ""}`;
  else pattern = pick(["", "   ", "\t\n", "-", " - ", "/24", "1.2.3.4-", "-1.2.3.4", "a-b", "1.2.3.4/24-5.6.7.8", `${base}%zone`, `${base}/24/`]);
  if (chance(0.1)) pattern = ` ${pattern} `;
  patterns.add(pattern);

  const ip = chance(0.6) ? flipLowBits(base) : address();
  cidrPairs.push([ip, chance(0.85) ? base + subnetSuffix(v6) : pick([base, address(), ""])]);
  const parts = base.split(".");
  if (parts.length === 4 && parts.every(p => /^\d+$/.test(p) && Number(p) < 256) && chance(0.5)) {
    const [lo, hi] = [int(256), int(256)].sort((a, b) => a - b);
    const prefix = parts.slice(0, 3).join(".");
    rangePairs.push([ip, `${prefix}.${lo}${pick(["-", " - ", "-"])}${chance(0.2) ? parts[0] + ".255.255" : prefix}.${hi}`]);
  } else {
    rangePairs.push([ip, chance(0.85) ? `${base}-${chance(0.7) ? flipLowBits(base) : address()}` : pick([base, "", "-", `${base}-`, `-${base}`, `${base} - ${base}`])]);
  }
}

const validations = [...patterns].map(pattern => ({ pattern, result: validateIPPattern(pattern) }));
const cidr = cidrPairs.map(([ip, subnet]) => ({ ip, cidr: subnet, result: matchesCIDR(ip, subnet) }));
const range = rangePairs.map(([ip, span]) => ({ ip, range: span, result: matchesRange(ip, span) }));

// Header sets for client IP resolution. Values are what Node's parser hands over:
// latin1, without leading or trailing spaces or tabs.
const DATACENTER = ["13.224.0.1", "3.5.140.2", "34.117.59.81", "20.190.128.1", "159.89.1.1", "5.9.1.1", "51.38.1.1", "104.16.1.1", "2600:1f18::1", "2a06:98c0:3600::103", "2A06:98C0:3600::103"];
const RESIDENTIAL = ["73.1.2.3", "71.114.1.2", "81.2.69.160", "79.192.1.1", "203.0.113.10", "192.0.2.10", "2003:e8::1", "8.8.8.8", "1.1.1.1", "10.0.0.1", "127.0.0.1"];
const GARBAGE = ["", "unknown", "1.2.3.4, 5.6.7.8", " 1.2.3.4 ", "1.2.3.4 ", "::ffff:1.2.3.4", "fe80::1%eth0", "a b", "999.1.1.1", ",", ", ,", ",\t,"];
const anyIp = () => pick([...DATACENTER, ...RESIDENTIAL, ...(chance(0.3) ? GARBAGE : [])]);
function forwardedFor(): string {
  const count = 1 + int(4);
  const entries = Array.from({ length: count }, () => (chance(0.15) ? pick(["", " ", "\t", "unknown", "a b"]) : anyIp()));
  const separators = [",", ", ", " ,", " , ", ",\t", ",,"];
  return entries.reduce((acc, entry, index) => (index === 0 ? entry : acc + pick(separators) + entry), "");
}
const trimOws = (value: string) => value.replace(/^[ \t]+|[ \t]+$/g, "");

const clientCases = [];
for (let i = 0; i < 5000; i++) {
  const headers: Record<string, string> = {};
  if (chance(0.5)) headers["x-real-ip"] = trimOws(anyIp());
  if (chance(0.6)) headers["x-forwarded-for"] = trimOws(forwardedFor());
  if (chance(0.6)) headers["cf-connecting-ip"] = trimOws(anyIp());
  if (chance(0.7)) headers["user-agent"] = pick(["Mozilla/5.0", "", "curl/8.0", "Ünïcödé agent", "a\tb"]);
  const socket = pick(["198.51.100.10", "172.18.0.5", "::1", "::ffff:127.0.0.1", "2001:db8::5"]);
  const firstPartyProxy = chance(0.25);
  const mode = pick(["direct", "proxied", "asn"]);
  const extra = [chance(0.5) ? pick([...RESIDENTIAL, ""]) : undefined, chance(0.3) ? anyIp() : undefined];

  const raw = { headers, socket: { remoteAddress: socket } };
  const addrs = proxyAddr.all(raw, () => true);
  const request = { headers, ip: addrs[addrs.length - 1] } as any;
  const options =
    mode === "direct"
      ? { firstPartyProxy, proxiedEdge: () => false }
      : mode === "proxied"
        ? { firstPartyProxy, proxiedEdge: () => true }
        : { firstPartyProxy, lookupAsn: createAsnLookup() };
  const resolved = resolveClientIp(request, options);
  clientCases.push({
    headers,
    socket,
    firstPartyProxy,
    mode,
    extra: extra.map(value => value ?? ""),
    requestIp: request.ip,
    getIpAddress: getIpAddress(request),
    resolved,
    candidates: collectCandidateClientIps(request, [...extra, resolved]),
    userAgent: getRequestUserAgent(headers),
  });
}

writeFileSync(`${OUT}/ip_corpus.json`, JSON.stringify({ validations, cidr, range, clientCases }));
console.log({
  validations: validations.length,
  valid: validations.filter(v => v.result.valid).length,
  cidr: cidr.length,
  cidrTrue: cidr.filter(c => c.result).length,
  range: range.length,
  rangeTrue: range.filter(c => c.result).length,
  clientCases: clientCases.length,
});
process.exit(0);
