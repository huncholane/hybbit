// Generates src/replay/testdata/page_urls.json: page URLs a recorder might send
// (real ones, hostile ones, and random recombinations of URL parts) with what Node's
// parseReplayPageUrl returns for each, so the Rust port's WHATWG handling of
// hostname, pathname and search is checked against ada rather than the url crate.
//
// Usage: node gen_urls.mjs > ../../src/replay/testdata/page_urls.json
// Deterministic: a fixed-seed PRNG drives the random part.

function parseReplayPageUrl(pageUrl) {
  if (!pageUrl) return {};
  try {
    const url = new URL(pageUrl);
    return { hostname: url.hostname, pathname: url.pathname, querystring: url.search };
  } catch {
    if (pageUrl.startsWith("/")) {
      return { pathname: pageUrl.split(/[?#]/, 1)[0], querystring: pageUrl.split("#", 1)[0].split(/\?(.*)/s)[1] };
    }
    return {};
  }
}

let seed = 0x0badf00d;
function random() {
  seed |= 0;
  seed = (seed + 0x6d2b79f5) | 0;
  let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
  t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
  return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
}
const pick = list => list[Math.floor(random() * list.length)];

const fixed = [
  "https://example.com/admin/users?tab=settings",
  "https://shop.example.com/parity/full?utm_source=newsletter&utm_medium=email",
  "https://例え.jp/パス/ü?q=é&utm_source=ニュース#frag",
  "http://user:pa ss@EXAMPLE.com:8080/a/../b/./c?x=1 2&y='\"<>`#h",
  "https://example.com/%zz/%41?%zz",
  "https://example.com?",
  "https://example.com#only-hash",
  "https://example.com/a?b#c?d",
  "file:///C:/Users/me/index.html?x=1",
  "file://host/share/file.txt",
  "about:blank",
  "blob:https://example.com/uuid-1234",
  "data:text/html,<h1>hi</h1>?x",
  "chrome-extension://abcdefghijklmnop/popup.html?q=1",
  "capacitor://localhost/tabs/home?x=1",
  "android-app://com.example/https/example.com/path",
  "mailto:someone@example.com?subject=hi",
  "javascript:alert(1)",
  "  https://example.com/trim  ",
  "https://example.com/tab\there/new\nline",
  "https://[::1]:3000/ipv6?x",
  "https://127.1/short-ipv4",
  "https://0x7f.0.0.1/hex-ipv4",
  "https://xn--nxasmq6b.com/punycode",
  "https://EXAMPLE.COM./trailing-dot",
  "http://example.com:80/default-port",
  "https://example.com/emoji/😀?e=😀",
  "https://example.com/\\backslash\\path",
  "foo://host/path?query#frag",
  "foo://host",
  "foo:/path/only",
  "foo:opaque?q",
  "/relative/path?x=1#y",
  "/admin/settings?x=1#y",
  "//protocol-relative.com/x",
  "?only=query",
  "#only-hash",
  "relative",
  "",
  "https://",
  "http://[::1",
  "https://exa mple.com/",
  "https://example.com:99999/",
];

const schemes = ["https://", "http://", "HTTPS://", "file://", "ws://", "foo://", "blob:", "", "/", "//"];
const hosts = ["example.com", "EXAMPLE.com", "例え.jp", "127.0.0.1", "[2001:db8::1]", "a.b.c.d.e", "user@host", "u:p@host.com", "host:8080", "", "xn--80ak6aa92e.com", "exa%41mple.com", "host.com."];
const paths = ["", "/", "/a/b", "/a/../b", "/%2e%2e/x", "/ü/😀", "/sp ace", "/a%zz", "/;params", "/\\x", "/a?b", "/'\"<>`{}|^"];
const queries = ["", "?", "?a=1&b=2", "?q=é 😀", "?x='\"<>`", "?%zz", "?utm_source=google&utm_medium=cpc&gclid=1", "?a#b"];
const fragments = ["", "#", "#frag", "#a?b", "#😀 x"];

const inputs = [...fixed];
for (let i = 0; i < 700; i++) {
  inputs.push(pick(schemes) + pick(hosts) + pick(paths) + pick(queries) + pick(fragments));
}

const cases = [];
const seen = new Set();
for (const input of inputs) {
  if (seen.has(input) || !input.isWellFormed()) continue;
  seen.add(input);
  const parsed = parseReplayPageUrl(input);
  cases.push([input, parsed.hostname ?? null, parsed.pathname ?? null, parsed.querystring ?? null]);
}
process.stdout.write(JSON.stringify(cases));
