// Dumps decideSiteExclusion over generated rules and requests, using the real
// GeoLite2 lookups (country and ASN) so the Rust side's Geo adapters are covered too.
import { writeFileSync } from "node:fs";
import { createAsnLookup } from "../../../server/src/db/geolocation/asn.ts";
import { decideSiteExclusion } from "../../../server/src/services/sites/siteExclusionDecision.ts";

const OUT = process.argv[2];
let seed = 0x5173;
function rand() {
  seed |= 0;
  seed = (seed + 0x6d2b79f5) | 0;
  let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
  t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
  return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
}
const pick = <T>(items: T[]): T => items[Math.floor(rand() * items.length)];
const chance = (p: number) => rand() < p;
const some = <T>(items: T[], max = 3): T[] => Array.from({ length: Math.floor(rand() * (max + 1)) }, () => pick(items));

const IPS = ["8.8.8.8", "1.1.1.1", "13.224.0.1", "81.2.69.160", "2003:e8::1", "2600:1f18::1", "203.0.113.10", "10.0.0.1", "", " 8.8.8.8", "unknown", "::ffff:8.8.8.8", "fe80::1%eth0", "01.2.3.4"];
const IP_RULES = ["8.8.8.8", " 8.8.8.8 ", "8.8.8.0/24", "8.0.0.0/8", "1.1.1.1-1.1.1.10", "1.1.1.2-1.1.1.10", "2003:e8::/32", "2600:1f18::/32", "::/0", "0.0.0.0/0", "", "garbage", "10.0.0.1-10.0.0.1", "2003:e8::1-2003:e8::2", "::a/1/64", "8.8.8.8/33", "81.2.69.160", "unknown"];
const ASN_RULES = ["AS15169", "as15169", "15169", "AS13335", "13335", " AS16509 ", "AS 16509", "0015169", "AS", "bogus", "99999999999999999999999", "AS3320", "3320", "AS2856"];
const COUNTRIES = ["US", "us", "GB", "gb", "DE", "De", "", "USA", "ı", "İ"];
const GLOBS = ["/admin/*", "/ADMIN*", "*", "**", "", "  ", "/a*b*c", "*.vercel.app", "preview.*", "/İ*", "/i̇*", "/ß", "/SS", "/*é", "/ΑΣ", "/ας", "/ασ", "/😀*", "*😀", "/a?b", "/x**y", "/" + "*a".repeat(10) + "b"];
const PATHS = ["/admin/users", "/Admin", "/", "", "/abc", "/aXbXc", "/İstanbul", "/i̇stanbul", "/ß", "/ss", "/SS", "/café", "/ΑΣ", "/ας", "/😀x", "x😀", "/a?b", "/xANYy", "/" + "a".repeat(40)];
const HOSTS = ["preview.vercel.app", "vercel.app", "PREVIEW.example.com", "", "localhost", "ÉXAMPLE.com"];
const UAS = ["Mozilla/5.0 HeadlessChrome/120", "curl/8.0", "", "İ-agent", "Googlebot"];
const UA_RULES = ["headlesschrome", "  ", "", "CURL", "i̇", "İ", "bot"];
const QUERIES = ["", "?Preview=true&x=1", "utm_source=Internal-QA", "preview", "?a=1&a=2", "?%zz=1", "?ÄB=c", "?äb=C", "?x=%E2%82", "?=v", "?name=", "?NAME=Value*"];
const QUERY_RULES = ["preview", "PREVIEW=TRUE", "utm_source=internal-*", "=x", "", " ", "name=", "äb", "ÄB=c*", "x", "a=2", "name=value\\*", "name=*"];

const cases = [];
for (let i = 0; i < 4000; i++) {
  const configuration = {
    excludedIPs: some(IP_RULES, 2),
    useOrganizationExcludedIPs: chance(0.8),
    organizationExcludedIPs: some(IP_RULES, 2),
    excludedCountries: chance(0.3) ? some(COUNTRIES, 2) : [],
    excludedPaths: chance(0.5) ? some(GLOBS) : [],
    excludedHostnames: chance(0.4) ? some(GLOBS.concat(HOSTS)) : [],
    excludedUserAgents: chance(0.4) ? some(UA_RULES) : [],
    excludedASNs: chance(0.3) ? some(ASN_RULES) : [],
    excludedQueryParams: chance(0.4) ? some(QUERY_RULES) : [],
  };
  const request = {
    ipAddress: pick(IPS),
    candidateIps: some(IPS, 3),
    pathname: chance(0.9) ? pick(PATHS) : undefined,
    querystring: chance(0.8) ? pick(QUERIES) : undefined,
    hostname: chance(0.9) ? pick(HOSTS) : undefined,
    userAgent: chance(0.9) ? pick(UAS) : undefined,
  };
  const decision = await decideSiteExclusion(configuration, { ...request, lookupAsn: createAsnLookup() });
  cases.push({ configuration, request, decision });
}

writeFileSync(`${OUT}/exclusion_corpus.json`, JSON.stringify(cases));
const byReason: Record<string, number> = {};
for (const c of cases) byReason[c.decision.excluded ? (c.decision as any).reason : "accepted"] = (byReason[c.decision.excluded ? (c.decision as any).reason : "accepted"] ?? 0) + 1;
console.log({ cases: cases.length, byReason });
process.exit(0);
