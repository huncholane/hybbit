// Generates src/replay/testdata/canonical.json: random JSON documents written with
// every spelling JSON allows (escapes, surrogates, number forms, repeated and
// array-index keys, whitespace) paired with what Node makes of them,
// `JSON.stringify(JSON.parse(text))`, or null where JSON.parse throws.
//
// Usage: node gen_canonical.mjs > ../../src/replay/testdata/canonical.json
// Deterministic: a fixed-seed PRNG drives every choice.

let seed = 0x5eed1234;
function random() {
  // mulberry32
  seed |= 0;
  seed = (seed + 0x6d2b79f5) | 0;
  let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
  t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
  return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
}
const pick = list => list[Math.floor(random() * list.length)];
const chance = p => random() < p;

const ws = () => (chance(0.2) ? pick([" ", "\n", "\t", "\r\n  ", ""]) : "");

function hex4(unit) {
  const hex = unit.toString(16).padStart(4, "0");
  return chance(0.5) ? hex : hex.toUpperCase();
}

function stringLiteral() {
  let out = '"';
  const length = Math.floor(random() * 8);
  for (let i = 0; i < length; i++) {
    const r = random();
    if (r < 0.3) out += pick(["a", "Z", "0", " ", "é", "漢", "😀", " ", "", "~", "/", "'"]);
    else if (r < 0.45) out += pick(["\\n", "\\t", "\\r", "\\b", "\\f", '\\"', "\\\\", "\\/"]);
    else if (r < 0.6) out += "\\u" + hex4(Math.floor(random() * 0x80));
    else if (r < 0.72) out += "\\u" + hex4(0xd800 + Math.floor(random() * 0x400));
    else if (r < 0.84) out += "\\u" + hex4(0xdc00 + Math.floor(random() * 0x400));
    else if (r < 0.92) out += "\\u" + hex4(Math.floor(random() * 0x10000));
    else out += "\\ud83d\\ude00";
  }
  return out + '"';
}

function numberLiteral() {
  return pick([
    "0", "-0", "1", "1.0", "1.50", "-12.25e3", "1e21", "1E+21", "1e-7", "5e-324", "2e-324", "1e400", "-1e400",
    "123456789012345678901", "9007199254740993", "0.1", "100", "1e2", "3.14159", "-0.0", "4294967295",
    String(Math.floor(random() * 1e6)), (random() * 1e3).toString(), "1726000000000.5",
  ]);
}

const KEYS = ["a", "b", "type", "data", "0", "1", "2", "10", "01", "-1", "1.5", "4294967294", "4294967295", "\\u0031", "\\u0061", "__proto__", "constructor", "\\ud800", "�"];

function value(depth) {
  const r = random();
  if (depth > 4 || r < 0.35) {
    return pick([() => stringLiteral(), () => numberLiteral(), () => "true", () => "false", () => "null"])();
  }
  if (r < 0.65) {
    const count = Math.floor(random() * 5);
    const members = [];
    for (let i = 0; i < count; i++) members.push(ws() + '"' + pick(KEYS) + '"' + ws() + ":" + ws() + value(depth + 1) + ws());
    return "{" + (members.length ? members.join(",") : ws()) + "}";
  }
  const count = Math.floor(random() * 5);
  const items = [];
  for (let i = 0; i < count; i++) items.push(ws() + value(depth + 1) + ws());
  return "[" + (items.length ? items.join(",") : ws()) + "]";
}

function mutate(text) {
  // Occasionally break the document so rejections are covered too
  const at = Math.floor(random() * (text.length + 1));
  return pick([
    text.slice(0, at) + pick([",", "]", "}", '"', "\\", "", "x"]) + text.slice(at),
    text.slice(0, at),
    text + pick([",", " x", "]"]),
  ]);
}

const cases = [];
for (let i = 0; i < 1500; i++) {
  let text = ws() + value(0) + ws();
  if (chance(0.15)) text = mutate(text);
  let expected;
  try {
    expected = JSON.stringify(JSON.parse(text));
  } catch {
    expected = null;
  }
  // The fixture is read by serde_json, which refuses lone surrogates in its own
  // strings; inputs are escape-only and outputs are well-formed, so this holds
  if (!text.isWellFormed() || (expected !== null && !expected.isWellFormed())) continue;
  cases.push([text, expected ?? null]);
}
process.stdout.write(JSON.stringify(cases));
