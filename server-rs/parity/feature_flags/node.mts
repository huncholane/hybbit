// Node side of the feature flag parity check. Generates deterministic corpora, runs
// them through the real Node code and writes inputs and outputs as JSON for the Rust
// tests in src/feature_flags/parity.rs to replay. Run through run.sh.
//
// Usage: npx tsx node.mts <suite> <out-dir>
//   suites: regex, evaluator, schemas, query, cache-seed, cache-node-read, cleanup, e2e
//
// HYGO_SERVER_DIR points at a server/ directory with node_modules (default: the
// server/ next to this repository's server-rs/).
import { createRequire } from "node:module";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const serverDir = process.env.HYGO_SERVER_DIR ?? join(here, "../../../server");
const requireFromServer = createRequire(join(serverDir, "package.json"));
const [suite, outDir] = process.argv.slice(2);
mkdirSync(outDir, { recursive: true });

export const PARITY_SITE_ID = 65731;
export const PARITY_EMPTY_SITE_ID = 65732;

// ---------------------------------------------------------------------------------
// Deterministic randomness and JSON with raw number spellings
// ---------------------------------------------------------------------------------

function mulberry32(seed: number) {
  return () => {
    seed |= 0;
    seed = (seed + 0x6d2b79f5) | 0;
    let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
let random = mulberry32(20260917);
const chance = (p: number) => random() < p;
const int = (min: number, max: number) => min + Math.floor(random() * (max - min + 1));
const pick = <T,>(items: readonly T[]): T => items[Math.floor(random() * items.length)];

/** A number spelled exactly as given in the JSON text (1.0, -0, 1e21, ...). */
class Raw {
  constructor(readonly text: string) {}
}
const MISSING = Symbol("missing");

function jsonText(value: unknown): string {
  if (value instanceof Raw) return value.text;
  if (Array.isArray(value)) return `[${value.map(item => (item === MISSING ? "null" : jsonText(item))).join(",")}]`;
  if (value !== null && typeof value === "object") {
    const members: string[] = [];
    for (const [key, member] of Object.entries(value)) {
      if (member === MISSING) continue;
      members.push(`${JSON.stringify(key)}:${jsonText(member)}`);
    }
    // Keys generated as "__proto__" are kept as own members through an ordered list
    const extra = (value as { [PROTO_MEMBER]?: unknown })[PROTO_MEMBER];
    if (extra !== undefined) members.push(`"__proto__":${jsonText(extra)}`);
    return `{${members.join(",")}}`;
  }
  return JSON.stringify(value);
}
const PROTO_MEMBER = Symbol("__proto__ member");

function object(entries: [string, unknown][]): Record<string, unknown> {
  const result: Record<string, unknown> = {};
  for (const [key, value] of entries) {
    if (key === "__proto__") (result as any)[PROTO_MEMBER] = value;
    else result[key] = value;
  }
  return result;
}

const write = (name: string, data: unknown) => {
  writeFileSync(join(outDir, name), JSON.stringify(data));
  console.error(`wrote ${name}`);
};

// ---------------------------------------------------------------------------------
// Regex validation and matching
// ---------------------------------------------------------------------------------

const HANDWRITTEN_PATTERNS = [
  // plain and valid
  "^/pricing", "foo|bar", "[a-z]+\\d{2}", " ", "^/pricing(/|$)", "a|b|c", "^$", "x*", "(?:)", "()", "(|)", "a||b",
  // V8 errors
  "", "(", "((a)", "a)", ")", "\\", "a\\", "[\\", "*", "+a", "?", "a**", "a+*", "a???", "^*", "$+", "\\b*", "\\B{2}", "{1}",
  "{1,}", "{1,2}", "a{2}{3}", "a{2,1}", "a{99999999999,1}", "(?<=a)*", "(?<!a)+", "(?<=a){2}", "(?=a)*", "(?!a)?",
  "(?", "(?)", "(?i)", "(?x:a)", "(?i=a)", "(?i!a)", "(?i<a>b)", "(?-)", "(?-:a)", "(?--i:a)", "(?i--m:a)", "(?ii:a)",
  "(?i-i:a)", "(?ims-:a)", "(?i-ms:a)", "(?-ims:a)", "(?m:^a$)", "(?s:.)", "(?<", "(?<a", "(?<a>", "(?<a>b", "(?<1>a)",
  "(?<a-b>c)", "(?<$a_1>b)", "(?<\u00e9>a)", "(?<\u{1d465}>a)", "(?<\\u{1d465}>a)", "(?<\\u0061>b)", "(?<\\u{110000}>a)",
  "(?<\\uD835\\uDC65>a)", "(?<a\\u200cb>c)", "(?<\\u005c>a)", "(?<a\u200d>b)", "(?<a>x)(?<a>y)", "(?<a>x)|(?<a>y)",
  "(?:(?<a>x)|(?<a>y))\\k<a>", "(?<a>(?<a>y))", "(?<a>x|(?<a>y))", "((?<a>x)|(?<a>y))(?<a>z)", "(?<a>x)|((?<a>y)|(?<a>z))",
  "\\k<a>", "\\k<a>(?<a>x)", "\\k<b>(?<a>x)", "\\k(?<a>x)", "\\k", "\\k<", "[\\k](?<a>x)", "[\\k]", "(?<a>\\k<a>)",
  "(?<a>x)\\k", "(?<a>x)\\k<a", "(?<n>a)\\k<n>",
  "[a", "[", "[^", "[]", "[^]", "[]]", "[z-a]", "[a-z-0]", "[\\d-a]", "[a-\\d]", "[\\w-\\s]", "[-]", "[a-]", "[-a]",
  "[\\b]", "[\\B]", "[\\-]", "[\\c]", "[\\c1]", "[\\c_]", "[\\cA]", "[\\x41-\\x5A]", "[\\u0041-\\u005a]", "[\\1]", "[\\8]",
  "[\\0]", "[\\07]", "[\\p{L}]", "[\\k<a>]", "[\\]]", "[[]", "[a-\\]", "[\\\\-a]", "[\u{1f600}-\u{1f601}]", "[\u{1f601}-\u{1f600}]",
  // Annex B escapes and literals
  "\\c", "\\cA", "\\ca", "\\c1", "\\c_", "\\c*", "\\x", "\\x4", "\\x41", "\\xZZ", "\\u", "\\u004", "\\u0041", "\\u{41}",
  "\\u{1F600}", "\\uD83D\\uDE00", "\\uD83D", "\\0", "\\00", "\\000", "\\0000", "\\01", "\\08", "\\1", "\\12", "\\123",
  "\\400", "\\777", "\\8", "\\9", "\\18", "\\81", "\\99", "(a)\\1", "(a)\\2", "\\2(a)(b)", "(a)(b)\\10", "(((((((((((a)))))))))))\\11",
  "\\p{L}", "\\P{L}", "\\p", "\\a", "\\e", "\\g", "\\-", "\\/", "a]", "a}", "}", "]", "{", "a{", "a{,5}", "a{1,", "a{1",
  "x{2,3}{", "{a}", "a{1}b{2,}c{3,4}", "a{2147483647}", "a{2147483648}", "a{0}", "(?:a{0})*", "(){0}", "\\n\\t\\v\\f\\r",
  // lookarounds
  "(?<=\\$)\\d+", "(?<!\\$)\\d+", "(?=a)b", "(?!a)b", "(?<=(?=a)a)b", "a(?=b)*", "(?=(a))*\\1",
  // backreferences inside their own groups
  "(a\\1)", "(a\\1)*", "((a)\\1)", "(a)(b\\1\\2)", "(?<n>a\\k<n>)",
  // unicode text
  "\u00e9", "\u{1f600}", "\u{1f600}+", "^\u{1f600}$", "^.$", "^..$", "[\u{1f600}]", "\u2028", "\ufeff", "a\u0000b",
  // safe-regex2 and ret specifics
  "(a+)+$", "^(x+x+)+y$", "(a{2,3}){2,3}", "(a|a)*$", "(a+|b)*", "(?:a+)+", "(a*)*", "((a)+)", "(a+)+?", "a+?",
  "a*".repeat(25), "a*".repeat(26), "(a*)".repeat(26), "[a]*".repeat(26), "(?:a|b*)*", "(a|(b*))*", "\\u005C(", "\\u005C*",
  "\\x5C(", "\\u0028a\\u0029", "\\u002a", "\\cJ", "\\c?", "\\c[", "[\\b]*", "\\\\u0041", "\\\\\\u0041", "\\99999999999999",
  "\\1111111111111", "(a)\\8", "(a)\\18", "\\1*", "\\81*", "\\108", "[\\s\\S]", "[^\\w]", ".+", "(?<name>a)+", "(?<na-me>a)",
];

const FRAGMENTS = [
  "a", "b", "z", "A", "0", "9", "_", "-", ",", ".", "^", "$", "|", "|", "(", "(", ")", ")", "(?:", "(?=", "(?!", "(?<=", "(?<!",
  "(?<n>", "(?<n2>", "(?<\u00e9>", "(?i:", "(?-i:", "(?m:", "(?s:", "(?i-m:", "(?", "[", "]", "[^", "\\", "\\d", "\\D", "\\w", "\\W",
  "\\s", "\\S", "\\b", "\\B", "\\1", "\\2", "\\10", "\\0", "\\01", "\\8", "\\k<n>", "\\k", "\\x41", "\\x4", "\\u0041", "\\u00e9",
  "\\u{41}", "\\uD83D", "\\cA", "\\c", "\\c1", "\\p{L}", "\\/", "*", "+", "?", "*?", "+?", "??", "{2}", "{2,}", "{2,3}", "{,3}",
  "{3,2}", "{", "}", "{1", "\\n", "\\t", "\\v", "\\f", "\\r", "[\\b]", "\u00e9", "\u{1f600}", "\u2028", " ", "a-z", "\\-", "[a-z]", "(a+)+",
  "(a|b)*", "\\u005C", "\\x5C", "\\c_", "\\cz",
];

// Subjects stay short: V8-valid random patterns can backtrack exponentially
const SUBJECTS = [
  "", "a", "A", "b", "ab", "aB", "abc", "ABC", "aaa", "ba", "z", "_", "-", "0", "7", "9", " ", "\t", "\n", "\r\n", "\u2028",
  "\u00a0", "\ufeff", "\u00e9", "\u00c9", "\u00df", "\u1e9e", "\u017f", "s", "S", "k", "K", "\u212a", "\u00b5", "\u039c", "\u03bc", "\u0131", "\u0130", "i", "I", "\u03a9", "\u03c9",
  "\u2126", "\u{1f600}", "a\u{1f600}b", "/pricing", "/pricing/pro", "\\", "[", "]", "{", "}", "x{2}", "a]", "\\c1", "\u0001", "\u001f",
  "\u0008", "$42", "yy", "8", "\n3", "\u0000", "aaaaaaaaab", "\u00e9\u{1f600}\u00c9",
];

// Matching semantics with subjects chosen per pattern: captures reset per iteration,
// the empty-iteration rule, lazy loops, lookbehind captures, backreferences in all
// directions, duplicate names, modifiers and case folding.
const SEMANTIC: [string, string[]][] = [
  ["^(a|ab)(c|bcd)(d*)$", ["abcd", "acd", "abcdd"]],
  ["(a*)*b", ["aaab", "b", "aaa"]],
  ["(a*)+b", ["aaab", "b", "x"]],
  ["(a|b)*?c", ["abc", "c", "ab"]],
  ["^(?:a|())*$", ["aa", "", "ab"]],
  ["^(?:(a)|b\\1)+$", ["aba", "ab", "abab", "b"]],
  ["(z)((a+)?(b+)?(c))*\\3", ["zaacbbbcac", "zaacbbbcaca", "zc"]],
  ["^(?:(a)|(b))+\\2$", ["abb", "ab", "ba", "aba"]],
  ["(a)|\\1b", ["b", "ab", "x"]],
  ["(?=(a+))a*b\\1", ["baaabac", "baaabaac", "ab"]],
  ["(?<=(\\d+)(\\d+))$", ["1053", "a", ""]],
  ["(?<=\\1(a))b", ["aab", "ab", "b"]],
  ["(?<=(a)\\1)b", ["aab", "ab"]],
  ["(.*?)a(?!(a+)b\\2c)\\2(.*)", ["baaabaac", "abc", "aac"]],
  ["^(?:a{0,2}?){3}$", ["aaaaaa", "aaaaaaa", ""]],
  ["(a{2,3})+?b", ["aaaaab", "aab", "ab"]],
  ["^x*?y$", ["xxy", "y", "xx"]],
  ["^(?:x|)*y$", ["xxy", "y"]],
  ["(a|)*b", ["aab", "b"]],
  ["^(?:a?)*?b$", ["aab", "b", "ac"]],
  ["^(a*?)*b$", ["aab", "b"]],
  ["\\b\\w+\\b", ["hello world", " ", "_"]],
  ["\\Bb\\B", ["abc", "b", "ab"]],
  ["^$", ["", "a", "\n"]],
  ["(?m:^b$)", ["a\nb\nc", "abc", "b"]],
  ["(?m:a$)", ["a\u2028b", "ab", "a\r"]],
  ["^b", ["a\nb"]],
  ["(?s:a.b)", ["a\nb", "a\u2029b", "acb"]],
  ["a.b", ["a\nb", "a\rb", "acb"]],
  ["(?-s:a.b)", ["a\nb", "acb"]],
  ["(?s-m:^a.b$)", ["a\nb"]],
  ["[\\s\\S]*x", ["\n\nx", ""]],
  ["[^\\d\\s]+", ["12 34", "12a"]],
  ["(?i:(a)\\1)", ["aA", "Aa", "ab"]],
  ["(?i:(\u017f)\\1)", ["\u017fs", "\u017f\u017f", "sS"]],
  ["(?i:(k)\\1)", ["k\u212a", "kK"]],
  ["(?:(?<n>a)|(?<n>b))\\k<n>{2}", ["bbb", "aaa", "abb", "bb"]],
  ["(?:(?=(a)))?\\1", ["a", "b"]],
  ["(?:(?=(a))a)*\\1b", ["aab", "b"]],
  ["^(?:(?<a>x)|(?<a>y))+\\k<a>$", ["xyy", "xyx", "yxx"]],
  ["(?<!(?<a>b))\\k<a>c", ["c", "bc", "ac"]],
  ["(?<=(?<a>\\w){3})f", ["abcdef"]],
  ["(?<=\\b)a", ["a", "ba"]],
  ["(?<=^|,)b", ["a,b", "b", "ab"]],
  ["(?<!a{2,})b", ["aab", "ab", "b"]],
  ["(?<=a+?)b", ["aab"]],
  ["(?:(a)b|ac)+", ["abac"]],
  ["(?:(a)|b)*\\1c", ["abc", "aac", "bac"]],
  ["(a)(?:\\1|b)*c", ["aabac", "ac"]],
  ["(?i:[\u00e0-\u00ff])", ["\u00c0", "\u0178", "\u00ff"]],
  ["(?i:\u0130)", ["i", "\u0130", "I"]],
  ["(?i:[\\u0100-\\u017f]+)$", ["\u0100\u0101", "S"]],
  ["\\1(a)", ["a", "aa"]],
  ["(?:\\1(a))+", ["aa", "a"]],
  ["x(?:a|b\\1)?(c)", ["xc", "xbc"]],
  ["^(?:()|a)+$", ["a", "aa", ""]],
  ["^(?:a|()){3,}$", ["a", "aaa", ""]],
  ["(?:a{2})*?$", ["aaa"]],
  ["^.{0,3}?\u{1f600}", ["ab\u{1f600}", "abcd\u{1f600}"]],
  ["[\\uD83D][\\uDE00]", ["\u{1f600}"]],
  ["\\uD83D.", ["\u{1f600}", "\u{1f601}"]],
  ["^[^\\uD83D]", ["\u{1f600}", "a"]],
];

function regexCorpus() {
  const patterns: string[] = [...HANDWRITTEN_PATTERNS];
  for (let i = 0; i < 3000; i++) {
    let pattern = "";
    const count = int(1, 10);
    for (let j = 0; j < count; j++) pattern += pick(FRAGMENTS);
    patterns.push(pattern);
  }
  // Group syntax: names, duplicates across alternatives, modifiers, named references
  const GROUP_FRAGMENTS = ["(?<a>", "(?<b>", "(?<a>", "(", "(?:", ")", ")", ")", "|", "|", "\\k<a>", "\\k<b>", "\\k", "x", "y", "(?i:", "(?-i:", "(?i-", "(?", "i", "m", "s", "-", ":", "<", ">", "=", "!", "\\u{61}", "\\u0061", "[\\k]", "*", "\\1", "\\2"];
  for (let i = 0; i < 1500; i++) {
    let pattern = "";
    const count = int(2, 12);
    for (let j = 0; j < count; j++) pattern += pick(GROUP_FRAGMENTS);
    patterns.push(pattern);
  }
  const characters = "ab()[]{}|*+?.^$\\-,:=!<>0189cdkuxpPsSwWbBnrtfv_\u00e9\u{1f600} ";
  const units = [...characters];
  for (let i = 0; i < 1500; i++) {
    let pattern = [...pick(HANDWRITTEN_PATTERNS)];
    const edits = int(1, 3);
    for (let j = 0; j < edits; j++) {
      const at = int(0, pattern.length);
      const kind = int(0, 2);
      if (kind === 0) pattern.splice(at, 0, pick(units));
      else if (kind === 1) pattern.splice(at, 1);
      else pattern.splice(at, 1, pick(units));
    }
    patterns.push(pattern.join(""));
  }
  // (?i:...) against case-folding subjects
  for (const text of ["a", "k", "s", "\u00df", "\u017f", "\u212a", "\u00b5", "\u0131", "i", "\u0130", "\u03c9", "\u2126", "\u00c9", "\u00e9", "[a-z]", "[^a-z]", "\\w", "\\W", "[k]", "[\u212a]", "[\u00df]", "\\u212A", "[A-Z]+", "[\u00e0-\u00ff]", "(a)\\1", "(?<x>k)\\k<x>"]) {
    patterns.push(`(?i:${text})`, `^(?i:${text})$`, `(?i:^${text}$)`);
  }
  // length limits, counted in UTF-16 code units
  patterns.push("a".repeat(256), "a".repeat(257), "\u{1f600}".repeat(128), "\u{1f600}".repeat(129), "a".repeat(255) + "\u{1f600}", "[" + "a".repeat(300));
  // repetition counts around the limit
  for (let count = 20; count <= 30; count++) {
    patterns.push("a*".repeat(count), "(?:a|b)?".repeat(count), "x{1,2}".repeat(count), "(a*|b)".repeat(count));
  }
  // ret hangs forever on references like \99999999999999999999; keep them out of Node
  const hangs = (pattern: string) => /\\\d{16,}/.test(pattern);
  const unique = [...new Set(patterns)].filter(pattern => !hangs(pattern));

  const { validateFeatureFlagRegexPattern } = requireTs("services/featureFlags/regex.ts");
  const safeRegex = requireFromServer("safe-regex2");
  const ret = requireFromServer("ret");
  const cases = unique.map(pattern => {
    let v8: string | null = null;
    let compiled: RegExp | null = null;
    try {
      compiled = new RegExp(pattern);
    } catch (error) {
      v8 = (error as Error).message;
    }
    let tokens: unknown;
    try {
      tokens = ret(pattern);
    } catch {
      tokens = null;
    }
    return {
      pattern,
      validate: validateFeatureFlagRegexPattern(pattern),
      v8,
      ret: tokens === null ? null : JSON.parse(JSON.stringify(tokens)),
      safe: safeRegex(pattern, { limit: 25 }),
      tests: compiled ? SUBJECTS.map(subject => compiled!.test(subject)) : null,
    };
  });
  const semantic = SEMANTIC.flatMap(([pattern, subjects]) =>
    subjects.map(subject => ({ pattern, subject, result: new RegExp(pattern).test(subject) })),
  );
  write("regex.json", { subjects: SUBJECTS, cases, semantic });
}

// ---------------------------------------------------------------------------------
// Evaluator
// ---------------------------------------------------------------------------------

const TEXT = [
  "", "a", "ab", "abc", "example.com", "www.example.com", "/pricing", "/pricing/pro", "/docs", "en-US", "en", "US", "GB",
  "US-CA", "GB-ENG", "Oakland", "Mobile", "Desktop", "Tablet", "visitor-1", "user-1", "pro", "team", "1", "1.5", "0", "true",
  "false", "null", "undefined", "1e+21", "[object Object]", "\u00e9", "\u{1f600}", "a,b", " ", "function Object() { [native code] }",
  "function toString() { [native code] }", "0,1", "Pro", "PRO", "pr", "ro", "https://ref.example/", "5",
];
const NUMBER_LITERALS = ["0", "1", "1.0", "1.5", "-0", "-1", "1e21", "1E+2", "100", "50", "12.5", "33.3", "0.1", "123456789012345678901", "2e-7", "99.99999999999999"];
const KEYS = ["plan", "utm", "ref", "a", "b", "0", "1", "2", "01", "-1", "4294967294", "4294967295", "constructor", "toString", "__proto__", "length", "hasOwnProperty", "valueOf", "", "\u00e9", "\u{1f600}"];
const FIELDS = ["hostname", "pathname", "query", "referrer", "language", "country", "region", "city", "device_type", "user_id", "trait"];
const OPERATORS = ["equals", "not_equals", "contains", "starts_with", "ends_with", "regex"];
const REGEX_POOL = [
  "^/pricing", "a|b", "^[a-z]+$", "\\d", "^/p(r|x)", "(?i:ABC)", "(?<=/)docs", "\u00e9$", "^.$", "^..$", "(?<a>e)\\k<a>", "[",
  "(", "*", "(a+)+", "a".repeat(257), "", "^US", "Mobile|Desktop", "^$", "\\bpro\\b", "(?i:pro)", "^1$", "^\\u0031",
];

function number() {
  return new Raw(pick(NUMBER_LITERALS));
}

function randomJson(depth: number): unknown {
  const roll = random();
  if (depth <= 0 || roll < 0.55) {
    return pick<() => unknown>([() => pick(TEXT), number, () => chance(0.5), () => null])();
  }
  if (roll < 0.75) return Array.from({ length: int(0, 3) }, () => randomJson(depth - 1));
  return object(Array.from({ length: int(0, 4) }, () => [pick(KEYS), randomJson(depth - 1)] as [string, unknown]));
}

function maybe(value: () => unknown, missing = 0.2): unknown {
  return chance(missing) ? MISSING : value();
}

let uniquePatternCounter = 0;
const uniquePatterns: string[] = [];

function ruleValue(operator: unknown): unknown {
  if (operator === "regex" && chance(0.8)) {
    if (chance(0.3)) {
      uniquePatternCounter += 1;
      const pattern = `^u${uniquePatternCounter}$`;
      uniquePatterns.push(pattern);
      return chance(0.7) ? pattern : [pattern, pick(REGEX_POOL)];
    }
    return chance(0.7) ? pick(REGEX_POOL) : Array.from({ length: int(0, 3) }, () => (chance(0.8) ? pick(REGEX_POOL) : number()));
  }
  const roll = random();
  if (roll < 0.5) return pick(TEXT);
  if (roll < 0.62) return number();
  if (roll < 0.68) return chance(0.5);
  if (roll < 0.88) return Array.from({ length: int(0, 4) }, () => (chance(0.8) ? pick(TEXT) : randomJson(1)));
  if (roll < 0.94) return null;
  if (roll < 0.97) return MISSING;
  return randomJson(2);
}

function rule(): unknown {
  if (chance(0.012)) return pick([5, "rule", [], true, null]);
  const operator = chance(0.94) ? pick(OPERATORS) : pick(["EQUALS", "", null, 1, MISSING]);
  const field = chance(0.95) ? pick(FIELDS) : pick(["", "Hostname", "unknown", null, 5, MISSING]);
  return object([
    ["field", field],
    ["key", maybe(() => (chance(0.9) ? pick(KEYS) : pick([1, 0, true, null, [], {}, ["a", "b"]])), 0.3)],
    ["operator", operator],
    ["value", ruleValue(operator)],
  ]);
}

const ROLLOUTS = () => pick<unknown>([0, 10, 25, 33, 50, 75, 90, 100, new Raw("33.3"), new Raw("50.5"), new Raw("100.0"), 150, -10, "50", "abc", null, true, [30], {}, [], MISSING]);

function variant(): unknown {
  if (chance(0.025)) return pick([5, "x", [], {}, null]);
  return object([
    ["key", chance(0.9) ? pick(["control", "test", "a", "b", "variant-3"]) : pick([1, null, MISSING, true])],
    ["name", maybe(() => pick(["Control", ""]), 0.6)],
    ["rolloutPercentage", chance(0.8) ? pick([0, 10, 25, 33, 34, 50, 100]) : ROLLOUTS()],
    ["payload", maybe(() => randomJson(3), 0.4)],
  ]);
}

function conditionSet(): unknown {
  if (chance(0.025)) return pick([5, "set", [], null]);
  return object([
    ["name", maybe(() => pick<unknown>(["us", "beta", "", 0, 1, null, "all traffic"]), 0.3)],
    ["rules", chance(0.95) ? Array.from({ length: int(0, 3) }, rule) : pick<unknown>([MISSING, {}, "rules", null])],
    ["rolloutPercentage", maybe(ROLLOUTS, 0.5)],
    ["variants", maybe(() => (chance(0.9) ? Array.from({ length: int(0, 3) }, variant) : pick<unknown>([{}, "v", null])), 0.5)],
    ["payload", maybe(() => randomJson(3), 0.5)],
  ]);
}

function flag(index: number): unknown {
  if (chance(0.004)) return null;
  if (chance(0.004)) return pick([5, "flag", []]);
  const flagType = chance(0.93) ? pick(["boolean", "multivariate", "remote_config"]) : pick<unknown>(["other", null, MISSING, 1]);
  return object([
    ["flagId", index + 1],
    ["siteId", chance(0.95) ? 42 : pick<unknown>(["42", MISSING, null, 4.5])],
    ["key", chance(0.9) ? pick(["checkout", "new_ui", "f1", "k", "beta.flag:x-1"]) : pick<unknown>(["1", "0", "2", "__proto__", "constructor", "", 7, null, MISSING])],
    ["description", null],
    ["enabled", chance(0.85) ? true : pick<unknown>([false, 1, 0, "", "yes", null, MISSING])],
    ["runtime", chance(0.9) ? pick(["client", "server", "both"]) : pick<unknown>(["CLIENT", null, MISSING, 1])],
    ["flagType", flagType],
    ["payload", maybe(() => randomJson(3), 0.3)],
    ["variants", chance(0.9) ? Array.from({ length: int(0, 4) }, variant) : pick<unknown>([MISSING, null, {}, "variants"])],
    ["rolloutPercentage", chance(0.8) ? pick([0, 1, 25, 50, 99, 100]) : ROLLOUTS()],
    ["rules", chance(0.9) ? Array.from({ length: int(0, 3) }, rule) : pick<unknown>([MISSING, null, {}, "rules"])],
    ["conditionSets", chance(0.9) ? Array.from({ length: chance(0.5) ? 0 : int(1, 3) }, conditionSet) : pick<unknown>([MISSING, null, {}, "sets"])],
    ["salt", chance(0.95) ? pick(["salt", "c12999c4f0e6a492dc3088e1a4fa8fb0", "\u00e9\u{1f600}"]) : pick<unknown>([MISSING, 5, null])],
    ["version", chance(0.95) ? int(1, 9) : pick<unknown>(["2", MISSING, null, new Raw("1.0")])],
    ["createdAt", "2026-01-02 03:04:05.123456"],
    ["updatedAt", "2026-09-17 08:10:03.430756"],
  ]);
}

/**
 * A flag whose regex rules touch many distinct patterns, to exercise cache eviction.
 * Its first condition set reuses patterns the previous bulk flag inserted; whether
 * they are still cached, re-inserted and kept, or re-inserted and pushed out again by
 * this flag's own fresh patterns depends on how many fresh patterns follow.
 */
let lastOldPattern = "^u0$";
let previousBulkPatterns: string[] = [];
function bulkRegexFlag(index: number): unknown {
  const sets = [];
  const old = previousBulkPatterns.slice(0, 40);
  lastOldPattern = old.length ? pick(old) : "^u0$";
  sets.push({ name: "old", rules: [{ field: "pathname", operator: "regex", value: old.length ? old : ["^u0$"] }] });
  const total = pick([100, 400, 900, 960, 1000, 1100]);
  const fresh = Array.from({ length: total }, () => {
    uniquePatternCounter += 1;
    const pattern = `^u${uniquePatternCounter}$`;
    uniquePatterns.push(pattern);
    return pattern;
  });
  for (let i = 0; i < 4; i++) {
    const chunk = fresh.slice((i * total) / 4, ((i + 1) * total) / 4);
    sets.push({ name: `fresh-${i}`, rules: [{ field: "pathname", operator: "regex", value: chunk }] });
  }
  previousBulkPatterns = fresh;
  return { flagId: index + 1, siteId: 42, key: `bulk${index}`, enabled: true, runtime: "both", flagType: "boolean", rolloutPercentage: 100, rules: [], variants: [], conditionSets: sets, salt: "s", version: 1 };
}

function context(pathnamePattern?: string): unknown {
  const text = () => maybe(() => pick(TEXT), 0.3);
  const recent = pathnamePattern ?? (uniquePatterns.length ? uniquePatterns[int(Math.max(0, uniquePatterns.length - 1200), uniquePatterns.length - 1)] : "^u0$");
  return object([
    ["anonymousId", pick(["visitor-1", "visitor-2", "a", "", "\u00e9\u{1f600}", "0", "anon-" + int(0, 50)])],
    ["identifiedUserId", maybe(() => pick(["user-1", "", "u2"]), 0.5)],
    ["hostname", text()],
    ["pathname", pathnamePattern || chance(0.3) ? recent.slice(1, -1) : text()],
    ["query", maybe(() => object(Array.from({ length: int(0, 4) }, () => [pick(KEYS), pick(TEXT)] as [string, unknown])), 0.2)],
    ["referrer", text()],
    ["language", text()],
    ["country", text()],
    ["region", text()],
    ["city", text()],
    ["deviceType", text()],
    [
      "traits",
      maybe(() => {
        if (chance(0.06)) return pick<unknown>([["pro", 1], "pro", 5, true, []]);
        return object(Array.from({ length: int(0, 5) }, () => [pick(KEYS), randomJson(2)] as [string, unknown]));
      }, 0.2),
    ],
  ]);
}

function evaluatorCorpus() {
  const { evaluateFeatureFlagDefinitions } = requireTs("services/featureFlags/evaluator.ts");
  const cases = [];
  for (let index = 0; index < 6000; index++) {
    const bulk = index % 30 === 29;
    const flags = bulk ? [bulkRegexFlag(index), flag(1)] : Array.from({ length: int(1, 5) }, (_, i) => flag(i));
    const definitions = jsonText(flags);
    const contextText = jsonText(context(bulk ? lastOldPattern : undefined));
    const runtime = pick([null, "client", "server", ""]);
    let result: string | null = null;
    let error: string | null = null;
    try {
      const options = runtime === null ? {} : { runtime };
      result = JSON.stringify(evaluateFeatureFlagDefinitions(JSON.parse(definitions), JSON.parse(contextText), options));
    } catch (thrown) {
      error = String(thrown);
    }
    cases.push({ definitions, context: contextText, runtime, result, error });
  }
  write("evaluator.json", { cases });
}

// ---------------------------------------------------------------------------------
// Evaluate body validation
// ---------------------------------------------------------------------------------

const WHITESPACE = [" ", "\t", "\n", "\u000b", "\u000c", "\r", "\u00a0", "\u1680", "\u2000", "\u200a", "\u2028", "\u2029", "\u202f", "\u205f", "\u3000", "\ufeff", "\u0085", "\u180e", "\u200b"];

function stringOfLength(units: number): string {
  // Mix one- and two-unit characters while hitting the exact UTF-16 length
  let text = "";
  while (text.length < units) text += units - text.length >= 2 && chance(0.3) ? "\u{1f600}" : pick(["a", "\u00e9", "z"]);
  return text;
}

function bodyValue(kind: "id" | "string" | "number" | "record", limit: number): unknown {
  const roll = random();
  if (roll < 0.12) return pick<unknown>([null, 5, new Raw("1.5"), true, [], {}, ["a"], MISSING]);
  if (kind === "number") {
    return new Raw(pick(["0", "-0", "1", "1024", "1920", "1.5", "-1", "-1.5", "1e21", "1e-7", "2147483648", "0.0", "1E3", "12345678901234567890"]));
  }
  if (kind === "record") {
    return object(Array.from({ length: int(0, 4) }, () => [pick(KEYS), chance(0.8) ? stringOfLength(pick([0, 5, 2048, 2049, 2047])) : pick<unknown>([1, null, true, [], {}])] as [string, unknown]));
  }
  const length = pick([0, 1, 2, limit - 1, limit, limit + 1, limit + 2]);
  let text = stringOfLength(Math.max(0, length));
  if (chance(0.4)) {
    const pad = () => Array.from({ length: int(0, 2) }, () => pick(WHITESPACE)).join("");
    text = pad() + text + pad();
  }
  if (chance(0.05)) text = Array.from({ length: int(1, 3) }, () => pick(WHITESPACE)).join("");
  return text;
}

function schemasCorpus() {
  const { evaluateFeatureFlagsSchema } = requireTs("api/featureFlags/schemas.ts");
  const bodies: (string | null)[] = [null, "null", "5", '"body"', "[]", "{}", "true"];
  for (let i = 0; i < 2500; i++) {
    bodies.push(
      jsonText(
        object([
          ["anonymousId", chance(0.1) ? MISSING : bodyValue("id", 128)],
          ["identifiedUserId", maybe(() => bodyValue("id", 255), 0.5)],
          ["hostname", maybe(() => bodyValue("string", 253), 0.6)],
          ["pathname", maybe(() => bodyValue("string", 2048), 0.6)],
          ["querystring", maybe(() => bodyValue("string", 2048), 0.7)],
          ["query", maybe(() => bodyValue("record", 0), 0.7)],
          ["referrer", maybe(() => bodyValue("string", 2048), 0.7)],
          ["language", maybe(() => bodyValue("string", 35), 0.6)],
          ["screenWidth", maybe(() => bodyValue("number", 0), 0.5)],
          ["screenHeight", maybe(() => bodyValue("number", 0), 0.5)],
          ["extra", maybe(() => "ignored", 0.9)],
        ]),
      ),
    );
  }
  const cases = bodies.map(body => {
    const result = evaluateFeatureFlagsSchema.safeParse(body === null ? undefined : JSON.parse(body));
    return result.success
      ? { body, data: JSON.stringify(result.data), details: null }
      : { body, data: null, details: JSON.stringify(result.error.errors) };
  });
  write("schemas.json", { cases });

  const { featureFlagBodySchema, featureFlagUpdateSchema } = requireTs("api/featureFlags/schemas.ts");
  const flagBodies: (string | null)[] = [null, "null", "[]", "{}", '"flag"', '{"extra":1}'];
  for (let i = 0; i < 3000; i++) flagBodies.push(jsonText(flagBody(i % 2 === 1)));
  for (let i = 0; i < 4000; i++) flagBodies.push(jsonText(plausibleFlagBody()));
  const outcome = (schema: any, body: string | null) => {
    const result = schema.safeParse(body === null ? undefined : JSON.parse(body));
    return result.success ? { data: JSON.stringify(result.data), details: null } : { data: null, details: JSON.stringify(result.error.errors) };
  };
  const flagCases = flagBodies.map(body => ({ body, create: outcome(featureFlagBodySchema, body), update: outcome(featureFlagUpdateSchema, body) }));
  write("flag-schemas.json", { cases: flagCases });
}

// Flag create/update bodies around every limit of featureFlagBodySchema
const REGEX_VALUES = ["^/pricing(/|$)", "(a+)+$", "[", "", "a".repeat(257), "(?<=a)b", "^u1$", 5, true, null];

function sized(length: number): string {
  return "a".repeat(length);
}

function payloadBody(): unknown {
  const roll = random();
  if (roll < 0.1) return sized(pick([4095, 4096, 4097]));
  if (roll < 0.18) return Array.from({ length: pick([99, 100, 101]) }, () => pick<unknown>([1, "x", null]));
  if (roll < 0.24) return object([["__proto__", 1], ["a", [sized(4097)]], ["2", { b: Array.from({ length: 101 }, () => 0) }]]);
  if (roll < 0.3) return pick<unknown>([null, new Raw("1.0"), new Raw("-0"), true]);
  return randomJson(3);
}

function variantBody(): unknown {
  if (chance(0.04)) return pick<unknown>([null, 5, "x", []]);
  return object([
    ["key", maybe(() => pick<unknown>(["control", "test", "a", " b ", "", "1st", "a b", sized(100), sized(101), "x.y:z-1", 5, null]), 0.1)],
    ["name", maybe(() => pick<unknown>(["Control", " n ", sized(120), sized(121), 5]), 0.6)],
    ["rolloutPercentage", maybe(() => pick<unknown>([0, 10, 33, 34, 50, 60, 100, 101, -1, new Raw("50.5"), "50", null]), 0.1)],
    ["payload", maybe(payloadBody, 0.6)],
  ]);
}

function ruleBody(): unknown {
  if (chance(0.04)) return pick<unknown>([null, 5, "rule", []]);
  const operator = chance(0.85) ? pick(OPERATORS) : pick<unknown>(["EQUALS", "", 5, MISSING]);
  let value: unknown;
  if (operator === "regex") {
    value = chance(0.7) ? pick(REGEX_VALUES) : Array.from({ length: int(0, 3) }, () => pick(REGEX_VALUES));
  } else {
    const roll = random();
    if (roll < 0.35) value = pick(TEXT);
    else if (roll < 0.45) value = sized(pick([511, 512, 513]));
    else if (roll < 0.55) value = number();
    else if (roll < 0.6) value = chance(0.5);
    else if (roll < 0.8) value = Array.from({ length: int(0, 4) }, () => pick<unknown>([pick(TEXT), 1, false, null, {}, sized(513)]));
    else if (roll < 0.86) value = Array.from({ length: pick([49, 50, 51]) }, () => "v");
    else value = pick<unknown>([null, MISSING, {}, [[]]]);
  }
  return object([
    ["field", chance(0.9) ? pick(FIELDS) : pick<unknown>(["", "Hostname", 5, MISSING])],
    ["key", maybe(() => pick<unknown>(["plan", " utm ", "", "  ", sized(128), sized(129), 5, null]), 0.4)],
    ["operator", operator],
    ["value", value],
  ]);
}

function listOf(make: () => unknown, limit: number): unknown {
  if (chance(0.06)) return Array.from({ length: pick([limit, limit + 1]) }, make);
  if (chance(0.04)) return pick<unknown>([null, {}, "list", 5]);
  return Array.from({ length: int(0, 3) }, make);
}

function conditionSetBody(): unknown {
  if (chance(0.04)) return pick<unknown>([null, 5, []]);
  return object([
    ["name", maybe(() => pick<unknown>(["us", " beta ", sized(120), sized(121), 0]), 0.5)],
    ["rules", maybe(() => listOf(ruleBody, 25), 0.3)],
    ["rolloutPercentage", maybe(() => pick<unknown>([0, 50, 100, 101, new Raw("12.5"), "50"]), 0.6)],
    ["variants", maybe(() => listOf(variantBody, 20), 0.5)],
    ["payload", maybe(payloadBody, 0.6)],
  ]);
}

/** Mostly valid bodies, so defaults, outputs and the shape refinement get exercised. */
function plausibleFlagBody(): unknown {
  const flagType = pick(["boolean", "multivariate", "multivariate", "remote_config"]);
  const plausibleVariant = () =>
    object([
      ["key", chance(0.93) ? pick(["control", "test", "variant-b", " c "]) : pick<unknown>(["", "1x", sized(101)])],
      ["name", maybe(() => pick(["Control", " spaced "]), 0.6)],
      ["rolloutPercentage", chance(0.9) ? pick([0, 10, 25, 33, 34, 50, 60, 100]) : pick<unknown>([101, new Raw("50.5"), -1])],
      ["payload", maybe(() => randomJson(2), 0.6)],
    ]);
  const plausibleRule = () => {
    const operator = pick(OPERATORS);
    const field = pick(FIELDS);
    return object([
      ["field", field],
      ["key", field === "query" || field === "trait" ? (chance(0.9) ? pick(["plan", " utm "]) : MISSING) : maybe(() => "k", 0.8)],
      ["operator", operator],
      ["value", operator === "regex" ? (chance(0.85) ? pick(["^/pricing", "a|b", "^u1$"]) : pick(REGEX_VALUES)) : chance(0.8) ? pick(TEXT) : pick<unknown>([1, true, ["a", 2], sized(513)])],
    ]);
  };
  const variants = () => Array.from({ length: pick([0, 0, 1, 2, 2, 3]) }, plausibleVariant);
  return object([
    ["key", chance(0.95) ? pick(["checkout", " new_ui ", "beta.flag:x-1"]) : pick<unknown>(["", "1abc", sized(101)])],
    ["description", maybe(() => pick<unknown>(["", "About", null, sized(1001)]), 0.5)],
    ["enabled", maybe(() => chance(0.5), 0.3)],
    ["runtime", maybe(() => pick(["client", "server", "both"]), 0.3)],
    ["flagType", maybe(() => flagType, 0.1)],
    ["payload", maybe(() => randomJson(3), 0.5)],
    ["variants", maybe(variants, 0.3)],
    ["rolloutPercentage", maybe(() => (chance(0.9) ? pick([0, 25, 100]) : pick<unknown>([101, new Raw("12.5")])), 0.4)],
    ["rules", maybe(() => Array.from({ length: int(0, 3) }, plausibleRule), 0.4)],
    [
      "conditionSets",
      maybe(
        () =>
          Array.from({ length: int(0, 3) }, () =>
            object([
              ["name", maybe(() => pick(["us", " all "]), 0.4)],
              ["rules", maybe(() => Array.from({ length: int(0, 2) }, plausibleRule), 0.3)],
              ["rolloutPercentage", maybe(() => pick([0, 50, 100]), 0.6)],
              ["variants", maybe(variants, 0.5)],
              ["payload", maybe(() => pick<unknown>([null, { a: 1 }, "x"]), 0.6)],
            ]),
          ),
        0.4,
      ),
    ],
  ]);
}

function flagBody(update: boolean): unknown {
  return object([
    ["key", maybe(() => pick<unknown>(["checkout", " spaced ", "", "1abc", "a b", sized(100), sized(101), "\u00e9", 5, null, true]), update ? 0.6 : 0.1)],
    ["description", maybe(() => pick<unknown>(["", "desc", " x ", sized(1000), sized(1001), null, 5]), 0.6)],
    ["enabled", maybe(() => pick<unknown>([true, false, "true", 1, null]), 0.5)],
    ["runtime", maybe(() => pick<unknown>(["client", "server", "both", "CLIENT", "", 5, null]), 0.5)],
    ["flagType", maybe(() => pick<unknown>(["boolean", "multivariate", "multivariate", "remote_config", "other", 5, null]), 0.4)],
    ["payload", maybe(payloadBody, 0.6)],
    ["variants", maybe(() => listOf(variantBody, 20), 0.5)],
    ["rolloutPercentage", maybe(() => pick<unknown>([0, 50, 100, 101, -1, new Raw("50.5"), "50", null, new Raw("1e2")]), 0.5)],
    ["rules", maybe(() => listOf(ruleBody, 25), 0.4)],
    ["conditionSets", maybe(() => listOf(conditionSetBody, 20), 0.5)],
    ["extra", maybe(() => 1, 0.9)],
  ]);
}

// ---------------------------------------------------------------------------------
// parseQuery (copied verbatim from server/src/api/featureFlags/index.ts, which is not
// exported and whose module loads GeoIP databases on import)
// ---------------------------------------------------------------------------------

function parseQuery(querystring?: string) {
  if (!querystring) return {};
  const params = new URLSearchParams(querystring.startsWith("?") ? querystring.slice(1) : querystring);
  return Object.fromEntries(params.entries());
}

function queryCorpus() {
  const pieces = ["a", "b", "=", "&", "&", "+", "%", "%2", "%20", "%zz", "%E2%82%AC", "%E2%82", "%C3", "%FF", "%ED%A0%80", "?", "\u00e9", "\u{1f600}", " ", "#", "__proto__", "1", "0", "01", "constructor", ";", "%3D", "%26", "\u0000"];
  const inputs = ["", "?", "??a=1", "a", "a=", "=a", "&&", "a=1&a=2", "b=1&2=x&1=y", "__proto__=x", "%", "+%2B+"];
  for (let i = 0; i < 2000; i++) inputs.push(Array.from({ length: int(1, 12) }, () => pick(pieces)).join(""));
  const cases = [...new Set(inputs)].map(querystring => ({ querystring, result: JSON.stringify(parseQuery(querystring)) }));
  write("query.json", { cases });
}

// ---------------------------------------------------------------------------------
// Definitions cache bytes and the evaluate route against the parity stores
// ---------------------------------------------------------------------------------

function requireTs(path: string) {
  return loaded[path];
}
const loaded: Record<string, any> = {};
async function load(...paths: string[]) {
  for (const path of paths) loaded[path] = await import(join(serverDir, "src", path));
}

const SEED_FLAGS = `INSERT INTO feature_flags (site_id, key, description, enabled, runtime, flag_type, payload, variants, rollout_percentage, rules, condition_sets, salt, version, created_at, updated_at) VALUES
  (${PARITY_SITE_ID}, 'b_flag', 'second', true, 'client', 'boolean', '"123"'::jsonb, '[{"b":1,"1":2,"a":[1.0,1e21,-0,0.1,123456789012345678901]}]', 50, '[]', '[]', 'salt-b', 2, '2026-01-02 03:04:05.1', '2026-01-02 03:04:05'),
  (${PARITY_SITE_ID}, 'a_flag', NULL, true, 'both', 'boolean', '"hello"'::jsonb, '[]', 100, '[{"field":"pathname","operator":"equals","value":"/pricing"}]', '[]', 'salt-a', 1, '2026-01-02 03:04:05.123456', '2026-09-17 08:10:03.430756'),
  (${PARITY_SITE_ID}, 'C_flag', 'unicode \u00e9 \u{1f600} "quoted" \\ back', true, 'server', 'remote_config', '"{\\"z\\":1,\\"2\\":3}"'::jsonb, '[]', 100, '[]', '[{"name":"fallback","rules":[],"payload":{"checkoutColor":"green","10":[true,null]}}]', 'salt-c', 3, '0044-03-15 00:00:00 BC', 'infinity'),
  (${PARITY_SITE_ID}, 'd_flag', NULL, false, 'client', 'boolean', NULL, '[]', 0, '[]', '[]', 'salt-d', 1, '12345-01-01 00:00:00', '-infinity'),
  (${PARITY_SITE_ID}, 'e_flag', '', true, 'both', 'boolean', 'null'::jsonb, '"[1,2]"', 100, '"null"', '{"x": 1}', 'salt-e', 1, '2026-09-17 08:10:03', '2026-09-17 08:10:03.000001'),
  (${PARITY_SITE_ID}, 'mv_flag', NULL, true, 'client', 'multivariate', '{"a": "\\u0001\\u001f\\u2028"}'::jsonb, '[{"key":"control","rolloutPercentage":50,"payload":{"color":"blue"}},{"key":"test","rolloutPercentage":50,"payload":{"color":"green","n":1.50}}]', 100, '[{"field":"trait","key":"plan","operator":"equals","value":["pro","team"]}]', '[]', 'salt-mv', 4, '2026-03-01 00:00:00', '2026-03-01 00:00:00'),
  (${PARITY_SITE_ID}, 'q_flag', NULL, true, 'client', 'boolean', '{"q": true}'::jsonb, '[]', 100, '[{"field":"query","key":"utm","operator":"equals","value":"a b"},{"field":"device_type","operator":"equals","value":"Desktop"}]', '[]', 'salt-q', 1, '2026-03-01 00:00:00', '2026-03-01 00:00:00'),
  (${PARITY_SITE_ID}, 'r_flag', NULL, true, 'both', 'boolean', NULL, '[]', 100, '[{"field":"hostname","operator":"regex","value":"^(www\\\\.)?example\\\\.com$"},{"field":"user_id","operator":"starts_with","value":"user"}]', '[]', 'salt-r', 1, '2026-03-01 00:00:00', '2026-03-01 00:00:00')`;

async function seed() {
  const { sql } = requireTs("db/postgres/postgres.ts");
  await cleanup();
  for (const site of [PARITY_SITE_ID, PARITY_EMPTY_SITE_ID]) {
    await sql.unsafe(`INSERT INTO sites (site_id, id, name, domain) VALUES (${site}, 'parityff${site}', 'feature flag parity', 'ff.example')`);
  }
  await sql.unsafe(SEED_FLAGS);
  await sql.unsafe(`INSERT INTO user_profiles (site_id, user_id, traits) VALUES
    (${PARITY_SITE_ID}, 'user-1', '{"plan":"pro","1":"x","constructor":"own"}'),
    (${PARITY_SITE_ID}, 'user-2', '"{\\"plan\\":\\"team\\"}"'::jsonb),
    (${PARITY_SITE_ID}, 'user-3', NULL),
    (${PARITY_SITE_ID}, 'user-4', '["pro"]')`);
}

async function cleanup() {
  const { sql } = requireTs("db/postgres/postgres.ts");
  const { redis } = requireTs("db/redis/redis.ts");
  for (const site of [PARITY_SITE_ID, PARITY_EMPTY_SITE_ID]) {
    await sql.unsafe(`DELETE FROM user_profiles WHERE site_id = ${site}`);
    await sql.unsafe(`DELETE FROM feature_flags WHERE site_id = ${site}`);
    await sql.unsafe(`DELETE FROM sites WHERE site_id = ${site}`);
    await redis.del(`feature-flags:definitions:${site}`);
  }
}

async function cacheSeed() {
  const { redis } = requireTs("db/redis/redis.ts");
  const { getFeatureFlagDefinitions } = requireTs("services/featureFlags/definitions.ts");
  await seed();
  const key = `feature-flags:definitions:${PARITY_SITE_ID}`;
  await redis.del(key);
  const rows = await getFeatureFlagDefinitions(PARITY_SITE_ID);
  const cached = await redis.get(key);
  const ttl = await redis.ttl(key);
  await redis.del(key);
  write("cache-node.json", { cached, ttl, rows: JSON.stringify(rows) });
}

/** Node reading what Rust wrote: the value must parse to the same rows. */
async function cacheNodeRead() {
  const { redis } = requireTs("db/redis/redis.ts");
  const { getFeatureFlagDefinitions } = requireTs("services/featureFlags/definitions.ts");
  const key = `feature-flags:definitions:${PARITY_SITE_ID}`;
  const rust = JSON.parse(readFileSync(join(outDir, "cache-rust.json"), "utf8"));
  await redis.set(key, rust.cached, "EX", 300);
  const rows = await getFeatureFlagDefinitions(PARITY_SITE_ID);
  await redis.del(key);
  write("cache-node-read.json", { rows: JSON.stringify(rows) });
}

function e2eBodies() {
  const bodies: { site: string; runtime: "client" | "server"; body: string | null }[] = [];
  const sites = [String(PARITY_SITE_ID), `parityff${PARITY_SITE_ID}`, String(PARITY_EMPTY_SITE_ID), "99999999", "abc", "0065731"];
  const add = (body: unknown, site = String(PARITY_SITE_ID), runtime: "client" | "server" = "client") =>
    bodies.push({ site, runtime, body: body === undefined ? null : jsonText(body) });
  add(undefined);
  add({});
  add({ anonymousId: "" });
  for (const site of sites) for (const runtime of ["client", "server"] as const) add({ anonymousId: "visitor-1" }, site, runtime);
  for (let i = 0; i < 400; i++) {
    add(
      object([
        ["anonymousId", chance(0.95) ? pick(["visitor-1", "visitor-2", " spaced ", "\u00e9\u{1f600}", "anon-" + int(0, 30)]) : pick<unknown>([null, "", 5])],
        ["identifiedUserId", maybe(() => pick(["user-1", "user-2", "user-3", "user-4", "nobody", "", " user-1 "]), 0.3)],
        ["hostname", maybe(() => pick(["example.com", "www.example.com", "example.org", ""]), 0.3)],
        ["pathname", maybe(() => pick(["/pricing", "/docs", ""]), 0.3)],
        ["querystring", maybe(() => pick(["?utm=a+b", "utm=a%20b", "utm=x&utm=a+b", "", "?", "utm"]), 0.5)],
        ["query", maybe(() => pick<unknown>([{ utm: "a b" }, { utm: "x" }, {}, { utm: 5 }]), 0.7)],
        ["screenWidth", maybe(() => new Raw(pick(["0", "-0", "1920", "800", "1025", "1.5", "-1"])), 0.4)],
        ["screenHeight", maybe(() => new Raw(pick(["0", "1080", "1300", "600"])), 0.4)],
      ]),
      chance(0.9) ? String(PARITY_SITE_ID) : pick(sites),
      chance(0.7) ? "client" : "server",
    );
  }
  return bodies;
}

async function e2e() {
  const { evaluateFeatureFlags, evaluateServerFeatureFlags } = await import(join(serverDir, "src/api/featureFlags/index.ts"));
  await seed();
  const cases = [];
  for (const entry of e2eBodies()) {
    const reply: any = {
      statusCode: 200,
      status(code: number) {
        this.statusCode = code;
        return this;
      },
      send(payload: unknown) {
        this.payload = payload;
        return this;
      },
    };
    const request = {
      params: { siteId: entry.site },
      body: entry.body === null ? undefined : JSON.parse(entry.body),
      headers: { "x-real-ip": "127.0.0.1" },
      ip: "127.0.0.1",
    };
    await (entry.runtime === "client" ? evaluateFeatureFlags : evaluateServerFeatureFlags)(request, reply);
    const payload = { ...reply.payload };
    if (typeof payload.generatedAt === "string") payload.generatedAt = "<generatedAt>";
    cases.push({ ...entry, status: reply.statusCode, response: JSON.stringify(payload) });
  }
  write("e2e.json", { cases });
}

// ---------------------------------------------------------------------------------

switch (suite) {
  case "regex":
    await load("services/featureFlags/regex.ts");
    regexCorpus();
    break;
  case "evaluator":
    await load("services/featureFlags/evaluator.ts");
    evaluatorCorpus();
    break;
  case "schemas":
    await load("api/featureFlags/schemas.ts");
    schemasCorpus();
    break;
  case "query":
    queryCorpus();
    break;
  case "cache-seed":
    await load("db/postgres/postgres.ts", "db/redis/redis.ts", "services/featureFlags/definitions.ts");
    await cacheSeed();
    break;
  case "cache-node-read":
    await load("db/postgres/postgres.ts", "db/redis/redis.ts", "services/featureFlags/definitions.ts");
    await cacheNodeRead();
    break;
  case "e2e":
    await load("db/postgres/postgres.ts", "db/redis/redis.ts");
    random = mulberry32(917);
    await e2e();
    break;
  case "cleanup":
    await load("db/postgres/postgres.ts", "db/redis/redis.ts");
    await cleanup();
    break;
  default:
    throw new Error(`unknown suite ${suite}`);
}
process.exit(0);
