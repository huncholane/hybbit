// Builds the UA corpus for the Rust ua-parser port's differential test: every UA
// in the ua-parser-js test fixtures, UA-looking literals from the server's tests,
// hand-picked modern browsers, in-app browsers, bots and edge cases, then
// deterministic mutations (case changes, Unicode injection, splices, letters that
// Unicode case folding would wrongly match, UA_MAX_LENGTH boundaries) and a token
// soup built from the literals the regexes look for.
//
//   git clone --depth 1 --branch 2.0.3 https://github.com/faisalman/ua-parser-js.git /tmp/uap
//   node server-rs/src/ua/tools/build_corpus.mjs /tmp/uap server/src corpus.json
import fs from "node:fs";
import path from "node:path";
import vm from "node:vm";

const [uapRoot, serverSrc, outPath] = process.argv.slice(2);
if (!outPath) {
  console.error("usage: build_corpus.mjs <ua-parser-js checkout> <server/src> <out.json>");
  process.exit(2);
}

const seen = new Set();
const corpus = [];
const add = (s) => {
  if (typeof s !== "string") return;
  if (seen.has(s)) return;
  seen.add(s);
  corpus.push(s);
};

function walk(dir, pred, out = []) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (entry.name === "node_modules") continue;
      walk(p, pred, out);
    } else if (pred(p)) out.push(p);
  }
  return out;
}

// 1. ua-parser-js fixtures: every "ua" field anywhere in test/data JSON
function collectUa(node) {
  if (Array.isArray(node)) node.forEach(collectUa);
  else if (node && typeof node === "object") {
    for (const [k, v] of Object.entries(node)) {
      if (k === "ua" && typeof v === "string") add(v);
      else if (k === "headers" && v && typeof v["user-agent"] === "string") add(v["user-agent"]);
      else collectUa(v);
    }
  }
}
let fixtureFiles = walk(path.join(uapRoot, "test/data"), (p) => p.endsWith(".json"));
for (const f of fixtureFiles) collectUa(JSON.parse(fs.readFileSync(f, "utf8")));
const fromFixtures = corpus.length;

// 2. string literals from ua-parser-js unit tests and server test files
const literalRe = /'((?:[^'\\\n]|\\.){6,})'|"((?:[^"\\\n]|\\.){6,})"|`((?:[^`\\$]|\\.){6,})`/g;
function unescapeJs(s) {
  try {
    return JSON.parse('"' + s.replace(/\\'/g, "'").replace(/\\`/g, "`").replace(/"/g, '\\"').replace(/\\\\"/g, '\\"') + '"');
  } catch {
    return null;
  }
}
function looksLikeUa(s) {
  return /\//.test(s) && /[A-Za-z]/.test(s) && !/^\.{0,2}\//.test(s) && !/^https?:/.test(s) && s.length < 2000;
}
const literalFiles = [
  ...walk(path.join(uapRoot, "test/unit"), (p) => /\.(m?js)$/.test(p)),
  ...walk(serverSrc, (p) => p.endsWith(".test.ts")),
  path.join(serverSrc, "services/tracker/botBlocking/uaBots/patterns.ts"),
];
for (const f of literalFiles) {
  const text = fs.readFileSync(f, "utf8");
  for (const m of text.matchAll(literalRe)) {
    const raw = m[1] ?? m[2] ?? m[3];
    const s = unescapeJs(raw);
    if (s && looksLikeUa(s)) add(s);
  }
}
const fromLiterals = corpus.length - fromFixtures;

// 3. hand-picked modern browsers, in-app browsers, bots and CLIs
const modern = [
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0",
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 OPR/115.0.0.0",
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 YaBrowser/24.12.0.0 Safari/537.36",
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Vivaldi/7.0.3495.18",
  "Mozilla/5.0 (Windows NT 6.1; Win64; x64; Trident/7.0; rv:11.0) like Gecko",
  "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Safari/605.1.15",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:133.0) Gecko/20100101 Firefox/133.0",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Arc/1.0",
  "Mozilla/5.0 (iPhone; CPU iPhone OS 18_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Mobile/15E148 Safari/604.1",
  "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/131.0.6778.73 Mobile/15E148 Safari/604.1",
  "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/133.0 Mobile/15E148 Safari/605.1.15",
  "Mozilla/5.0 (iPhone; CPU iPhone OS 17_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) EdgiOS/131.2903.68 Version/17.0 Mobile/15E148 Safari/604.1",
  "Mozilla/5.0 (iPad; CPU OS 17_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Mobile/15E148 Safari/604.1",
  "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/22B91 Instagram 360.0.0.30.109 (iPhone15,3; iOS 18_1_1; en_US; en; scale=3.00; 1290x2796; 682071289; IABMV/1)",
  "Mozilla/5.0 (iPhone; CPU iPhone OS 17_6_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 [FBAN/FBIOS;FBAV/490.0.0.51.107;FBBV/654321;FBDV/iPhone14,5;FBMD/iPhone;FBSN/iOS;FBSV/17.6.1;FBSS/3;FBID/phone;FBLC/en_US;FBOP/5;FBRV/0]",
  "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 musical_ly_37.5.0 JsSdk/2.0 NetType/WIFI Channel/App Store ByteLocale/en Region/US",
  "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 LinkedInApp/9.30.1",
  "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) GSA/340.0.689846395 Mobile/15E148 Safari/604.1",
  "Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 Snapchat/12.95.0.40 (like Safari/8615.3.12.10.4, panda)",
  "Mozilla/5.0 (Linux; Android 14; SM-S928B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.6778.81 Mobile Safari/537.36",
  "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36",
  "Mozilla/5.0 (Linux; Android 14; SAMSUNG SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/27.0 Chrome/125.0.0.0 Mobile Safari/537.36",
  "Mozilla/5.0 (Linux; Android 13; Pixel 7 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36",
  "Mozilla/5.0 (Linux; Android 14; Pixel 8 Build/AP2A.240805.005; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/127.0.6533.103 Mobile Safari/537.36 Instagram 343.0.0.33.101 Android (34/14; 420dpi; 1080x2205; Google/google; Pixel 8; shiba; shiba; en_US; 628299143)",
  "Mozilla/5.0 (Linux; Android 13; SM-A536B Build/TP1A.220624.014; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/120.0.6099.230 Mobile Safari/537.36 [FB_IAB/FB4A;FBAV/446.0.0.26.108;]",
  "Mozilla/5.0 (Linux; Android 12; M2101K6G) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36 OPR/86.0.0.0",
  "Mozilla/5.0 (Linux; Android 14; moto g power 5G - 2024) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36",
  "Mozilla/5.0 (Linux; Android 13; SM-X710) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Android 14; Mobile; rv:133.0) Gecko/133.0 Firefox/133.0",
  "Mozilla/5.0 (Linux; Android 11; KFTRWI) AppleWebKit/537.36 (KHTML, like Gecko) Silk/131.3.1 like Chrome/131.0.6778.135 Safari/537.36",
  "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
  "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0",
  "Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0",
  "Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
  "Mozilla/5.0 (SMART-TV; Linux; Tizen 7.0) AppleWebKit/537.36 (KHTML, like Gecko) 76.0.3809.146/7.0 TV Safari/537.36",
  "Mozilla/5.0 (Web0S; Linux/SmartTV) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36 WebAppManager",
  "Mozilla/5.0 (PlayStation; PlayStation 5/6.50) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.4 Safari/605.1.15",
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64; Xbox; Xbox Series X) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/48.0.2564.82 Safari/537.36 Edge/20.02",
  "Mozilla/5.0 (Nintendo Switch; WifiWebAuthApplet) AppleWebKit/606.4 (KHTML, like Gecko) NF/6.0.1.15.4 NintendoBrowser/5.1.0.20393",
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/131.0.6778.85 Safari/537.36",
  "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/120.0.0.0 Safari/537.36",
  "Mozilla/5.0 HeadlessChrome/120",
  "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
  "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; Googlebot/2.1; +http://www.google.com/bot.html) Chrome/131.0.6778.69 Safari/537.36",
  "Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.6778.69 Mobile Safari/537.36 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
  "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
  "Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)",
  "facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)",
  "Twitterbot/1.0",
  "Slackbot-LinkExpanding 1.0 (+https://api.slack.com/robots)",
  "curl/8.5.0",
  "Wget/1.21.4",
  "python-requests/2.32.3",
  "axios/1.7.9",
  "node-fetch/1.0 (+https://github.com/bitinn/node-fetch)",
  "Go-http-client/2.0",
  "okhttp/4.12.0",
  "PostmanRuntime/7.43.0",
  "Dalvik/2.1.0 (Linux; U; Android 14; SM-G991B Build/UP1A.231005.007)",
  "Hygo/1.0 CFNetwork/1568.200.51 Darwin/24.1.0",
  "ServerSDK/1.0",
  "SpoofedBot/1.0",
  "Mozilla/5.0",
  "Mozilla/5.0 (Macintosh) Chrome/120 Safari/537.36",
  "Mozilla/5.0 MyOwnBrowser/1.3",
];
modern.forEach(add);

// 4. edge cases: empty, whitespace, unicode, line terminators, long strings
const chromeWin = modern[0];
const edge = [
  "",
  " ",
  "   \t ",
  "\n",
  "?",
  "undefined",
  "null",
  "Chrome",
  "chrome/",
  "CHROME/120.0",
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/v.1 Safari/537.36",
  "Mozilla/5.0 (Linux; Android 10; 小米 Build/QKQ1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0 Mobile Safari/537.36",
  "Mozilla/5.0 (Linux; Android 10; Redmi Note 8 Pro Build/QKQ1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0 Mobile Safari/537.36",
  "Mozilla/5.0 (Windows NT 10.0; Win64) Chrome/120.0 Safari/537.36",
  "Mozilla/5.0 (Windows NT 10.0;\rWin64) Chrome/120.0 Safari/537.36",
  "Mozilla/5.0 (Windows NT 10.0; Win64) Chrome/120.١ Safari/537.36",
  "Mozilla/5.0 (Windows NT 10.0; Win64) Chrome/１２０.0 Safari/537.36",
  "Mozilla/5.0 (Linux; Android 13; 😀 phone) AppleWebKit/537.36 Chrome/120.0 Mobile Safari/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Konqueror/5.0",
  "Mozilla/5.0 (X11; Linux x86_64) Konſqueror/5.0",
  "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0) élinks (2.1",
  "éChrome/120.0",
  "Mozilla/5.0 (hbbtv/1.2.1 (+PVR; éVendor; Model 中;)",
  "HbbTV/1.5.1 (+DRM;  　Vendor Name; Model X; 1.0; 2.0;)",
  "Roku/DVP-9.10 (519.10E04111A)",
  "Mozilla/5.0 (Linux; U; Android 4.0.4; en-us; itel mobile1 Build/IMM76D)",
  "Mozilla/5.0 (Linux; Android 9; itel P10001L Build/PPR1) AppleWebKit/537.36",
  "Mozilla/5.0 (Linux; Android 9; itel W7001 Build/PPR1) AppleWebKit/537.36",
  "Cobalt/22.lts.4.306044-gold (unlike Gecko) v8/8.8.278.17-jit gles Starboard/13",
  "Mozilla/5.0 (X11; Linux x86_64) Cobalt/abc.def",
  "Mozilla/5.0 (X11; Linux x86_64) Cobalt/9a",
  "Links (2.29; Linux 6.1.0 x86_64; GNU C 12.2; text)",
  "Lynx/2_9_0dev.10 libwww-FM/2.14 SSL-MM/1.4.1 GNUTLS/3.7.1",
  " ".repeat(10) + chromeWin,
  " ".repeat(600) + chromeWin,
  " ﻿  " + "x".repeat(520) + " Chrome/120.0",
  chromeWin + " " + "a".repeat(600),
  "a".repeat(499) + "😀" + " Chrome/1.0",
  "a".repeat(498) + "😀" + " Chrome/1.0",
  "a".repeat(495) + "Chrome/120.0 Safari/1" + "b".repeat(20),
  "Mozilla/5.0 (Linux; Android 14; SM-S928B) ".repeat(20),
  "x".repeat(501),
  "x".repeat(500),
  "Chrome/" + "1".repeat(600),
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36".repeat(8),
];
edge.forEach(add);
const baseCount = corpus.length;

// 5. deterministic mutations: case changes, unicode injection, splices
let seed = 0x9e3779b9;
const rand = () => {
  seed ^= seed << 13; seed >>>= 0;
  seed ^= seed >>> 17;
  seed ^= seed << 5; seed >>>= 0;
  return seed / 0x100000000;
};
const pick = (arr) => arr[Math.floor(rand() * arr.length)];
const injections = ["é", "中", "😀", " ", " ", "\r", "K", "ſ", "İ", "", "﻿", "\t", "　", "_", ";", ")", " "];
const base = corpus.slice(0, baseCount).filter((s) => s.length > 0);
for (const s of base) {
  add(s.toUpperCase());
  add(s.toLowerCase());
  // inject 1 to 3 odd characters at random positions
  for (let v = 0; v < 2; v++) {
    let t = s;
    const n = 1 + Math.floor(rand() * 3);
    for (let i = 0; i < n; i++) {
      const pos = Math.floor(rand() * (t.length + 1));
      t = t.slice(0, pos) + pick(injections) + t.slice(pos);
    }
    add(t);
  }
  // splice with another corpus entry
  const other = pick(base);
  add(s.slice(0, Math.floor(rand() * s.length)) + other.slice(Math.floor(rand() * other.length)));
}

// 6. letters JS /i refuses to fold but Unicode folding would (Kelvin sign, long s,
//    dotted and dotless i) plus fullwidth digits
for (const s of base) {
  add(s.replace(/k/g, "K"));
  add(s.replace(/K/g, "K"));
  add(s.replace(/s/g, "ſ"));
  add(s.replace(/i/g, "ı").replace(/I/g, "İ"));
  add(s.replace(/[0-9]/g, (d) => String.fromCharCode(0xff10 + Number(d))));
}

// 7. UA_MAX_LENGTH boundaries with leading JS whitespace and astral characters
const pads = [" ", " ", "﻿", " ", "\t", "", "　"];
for (const s of base.slice(0, 400)) {
  const pad = pick(pads).repeat(1 + Math.floor(rand() * 4));
  const filler = pick(["a", "é", "中", "😀", " ", ";"]);
  let t = pad + s;
  while (t.length < 480 + Math.floor(rand() * 60)) t += filler;
  add(t + " " + s);
  add(s + filler.repeat(Math.max(0, 500 - s.length - 1)) + "😀 Chrome/1.2");
}

// 8. token soup: random sequences of the literal fragments the regexes look for
const uapSource = fs.readFileSync(path.join(uapRoot, "src/main/ua-parser.js"), "utf8").replace(
  "UAParser.VERSION = LIBVERSION;",
  "UAParser.VERSION = LIBVERSION; UAParser.__defaultRegexes = defaultRegexes;"
);
const sandbox = { module: { exports: {} } };
sandbox.exports = sandbox.module.exports;
vm.runInNewContext(uapSource, sandbox);
const defaultRegexes = sandbox.module.exports.__defaultRegexes;
const tokens = new Set();
for (const table of Object.values(defaultRegexes)) {
  for (let i = 0; i < table.length; i += 2) {
    for (const re of table[i]) {
      for (const tok of re.source.replace(/\\[dwsb]/g, " ").replace(/\\(.)/g, "$1").split(/[^A-Za-z0-9 ;\/._-]+/)) {
        if (tok.trim().length >= 2) tokens.add(tok);
      }
    }
  }
}
const tokenList = [...tokens];
const seps = ["", " ", "/", "; ", "(", ")", "_", "-", ".", " build/", " bui", "; wv)", " mobile safari/", " version/", "é", " "];
for (let n = 0; n < 40000; n++) {
  let t = pick(["", "Mozilla/5.0 (", "Mozilla/5.0 (Linux; Android " + Math.floor(rand() * 15) + "; ", "Mozilla/5.0 (Windows NT 10.0; "]);
  const parts = 2 + Math.floor(rand() * 10);
  for (let p = 0; p < parts; p++) {
    let tok = pick(tokenList);
    if (rand() < 0.3) tok = tok.toUpperCase();
    t += tok + pick(seps);
    if (rand() < 0.4) t += Math.floor(rand() * 200) + (rand() < 0.5 ? "." + Math.floor(rand() * 99) : "");
  }
  add(t);
}

const wellFormed = corpus.filter((s) => s.isWellFormed());
fs.writeFileSync(outPath, JSON.stringify(wellFormed));
console.log(JSON.stringify({ fromFixtures, fromLiterals, base: baseCount, total: wellFormed.length, droppedIllFormed: corpus.length - wellFormed.length }));
