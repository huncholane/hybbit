// Differential corpus for the Rust port of server/src/api/analytics/utils and
// the segment helpers. Generates deterministic inputs, runs them through the real
// Node modules and writes gzipped JSON fixtures that
// server-rs/src/analytics/parity_tests.rs replays.
//
// Run from the server directory (for node_modules), with production's Node major
// (24) and TZ=UTC:
//   cd server && TZ=UTC npx tsx ../server-rs/parity/analytics/dump.mts
// Node 26 (V8 14) differs from Node 24 (V8 13.6) on a handful of duplicate named
// capture groups in the regex corpus; the committed fixtures come from Node 24.21.
// PARITY_SERVER and PARITY_OUT override the server checkout and output directory.
// The Rust side: `cargo test parity_` in server-rs.
import { mkdirSync, writeFileSync } from "node:fs";
import { register } from "node:module";
import { fileURLToPath } from "node:url";
import { gzipSync } from "node:zlib";

// Defaults assume this file sits in server-rs/parity/analytics of a checkout whose
// server/ has node_modules installed; PARITY_SERVER and PARITY_OUT override them.
const SERVER = process.env.PARITY_SERVER ?? fileURLToPath(new URL("../../../server", import.meta.url));
const OUT = process.env.PARITY_OUT ?? fileURLToPath(new URL("./fixtures", import.meta.url));
const FIXED_NOW = Date.parse("2024-03-10T07:34:56.789Z");

register(new URL("./hooks.mjs", import.meta.url));

// First, so no other import loads it (and the real segmentAccess) before the hook applies
const esp = await import(`${SERVER}/src/api/analytics/segments/expandSegmentParam.ts`);
const gfs = await import(`${SERVER}/src/api/analytics/utils/getFilterStatement.ts`);
const qv = await import(`${SERVER}/src/api/analytics/utils/query-validation.ts`);
const sf = await import(`${SERVER}/src/api/analytics/utils/sessionFilters.ts`);
const tw = await import(`${SERVER}/src/api/analytics/utils/timeWindow.ts`);
const cqv = await import(`${SERVER}/src/api/analytics/utils/customQueryValidation.ts`);
const ec = await import(`${SERVER}/src/api/analytics/utils/eventConditions.ts`);
const utils = await import(`${SERVER}/src/api/analytics/utils/utils.ts`);
const aq = await import(`${SERVER}/src/api/analytics/utils/analyticsQuery.ts`);
const seg = await import(`${SERVER}/src/api/analytics/segments/segmentSchema.ts`);
const scopes = await import(`${SERVER}/src/lib/scopes.ts`);
const SqlString = (await import(`${SERVER}/node_modules/sqlstring/index.js`)).default;
const chCommon = await import(`${SERVER}/node_modules/@clickhouse/client-common/dist/index.js`);

// ---------------------------------------------------------------------------
// Deterministic randomness
// ---------------------------------------------------------------------------
let seed = 0x5eed1234;
const rand = () => {
  seed = (seed + 0x6d2b79f5) | 0;
  let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
  t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
  return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
};
const int = (n: number) => Math.floor(rand() * n);
const pick = <T,>(items: readonly T[]): T => items[int(items.length)];
const chance = (p: number) => rand() < p;
const repeat = <T,>(count: number, make: () => T): T[] => Array.from({ length: count }, make);

// ---------------------------------------------------------------------------
// Encoding JS values that JSON cannot carry
// ---------------------------------------------------------------------------
const enc = (value: unknown): unknown => {
  if (value === undefined) return { $js: "undefined" };
  if (typeof value === "number") {
    if (Number.isNaN(value)) return { $js: "NaN" };
    if (value === Infinity) return { $js: "Infinity" };
    if (value === -Infinity) return { $js: "-Infinity" };
    if (Object.is(value, -0)) return { $js: "-0" };
    return value;
  }
  if (value instanceof Set) return { $set: [...value].map(enc) };
  if (value instanceof Date) return { $date: enc(value.getTime()) };
  if (Array.isArray(value)) return value.map(enc);
  if (value && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [key, item] of Object.entries(value)) out[key] = enc(item);
    return out;
  }
  return value;
};

const run = (fn: () => unknown) => {
  try {
    return { ok: enc(fn()) };
  } catch (error) {
    return { error: error instanceof Error ? error.message : String(error), name: (error as Error)?.name ?? null };
  }
};

const counts: Record<string, number> = {};
const write = (name: string, cases: unknown[]) => {
  mkdirSync(OUT, { recursive: true });
  const text = JSON.stringify({ node: process.version, generatedWithNow: FIXED_NOW, cases });
  writeFileSync(`${OUT}/${name}.json.gz`, gzipSync(text, { level: 9 }));
  counts[name] = cases.length;
  console.log(`${name}: ${cases.length} cases, ${text.length} bytes`);
};

// ---------------------------------------------------------------------------
// Shared pools
// ---------------------------------------------------------------------------
const BASE_PARAMS = [
  "browser", "operating_system", "language", "country", "region", "city", "device_type", "referrer", "hostname",
  "pathname", "page_title", "querystring", "event_name", "channel", "utm_source", "utm_medium", "utm_campaign",
  "utm_term", "utm_content", "entry_page", "exit_page", "dimensions", "browser_version", "operating_system_version",
  "user_id", "lat", "lon", "timezone", "tag",
];
const FILTER_TYPES = [
  "equals", "not_equals", "contains", "not_contains", "starts_with", "ends_with", "regex", "not_regex", "is_null",
  "is_not_null", "greater_than", "less_than", "greater_than_or_equal", "less_than_or_equal",
];
const REGEXES = [
  "^/blog/.*", "[invalid", "(unclosed", "^(?!.*test).*$", "(a)\\1", "(?<=a)b", "(?<!a)b", "a{2,1}", "\\", "(?<name>x)\\k<name>",
  "^/docs/[a-z-]+$", ".*", "a".repeat(501), "(?i:abc)", "[z-a]", "x**", "(?<a>x)|(?<a>y)", "(?<a>x)(?<a>y)", "\\k<nope>",
  "^https://(www\\.)?producthunt\\.com", "\\d{4}-\\d{2}", "(?=x)", "\\8", "[\\b]", "\\cJ", "{1}", "a{1", "é+", "😀{2}", "",
];
const VALUE_STRINGS = [
  "Chrome", "Firefox", "", " ", "/blog", "/", "50%", "a_b", "C:\\temp", "it's", '"quoted"', "back\\slash", "new\nline",
  "tab\tstop", "cr\rhere", "nul\0byte", "sub\x1aend", "\b", "é", "日本語", "😀", "\u2028", "\ufeff", "Windows 10",
  "CA-San Francisco", "1920x1080", "US", "DE", "Organic Search", "Direct", "40.7128", "-74.006", "0", "-0", "1e3", "abc",
  " 12 ", "0x1f", "Infinity", "-Infinity", "NaN", "1_000", ".5", "5.", "x".repeat(500), "y".repeat(501),
  "😀".repeat(251), "url_parameters['utm_source']", "pathname", "'; DROP TABLE events;--", "%_\\%", "{{DOUBLE_STAR}}",
  "fp1", "user123", "Paid Search", "/docs/", "Mobile", "1e999", "00012",
];
const NUMBERS = [0, -0, 1, -1, 40.7128, -74.006, 1e21, 1e-7, 123456789012345680000, 1.5, 9007199254740993, 1e308, -1e308, 5e-324, 48.1, 3];

const genValue = (): unknown => {
  const roll = rand();
  if (roll < 0.62) return pick(VALUE_STRINGS);
  if (roll < 0.77) return pick(REGEXES);
  if (roll < 0.95) return pick(NUMBERS);
  return pick([true, false, null, {}, [], { name: "x" }]);
};

const FEATURE_FLAGS = ["feature_flag:beta", "feature_flag:new_checkout", "feature_flag:A", "feature_flag:my.flag:v2-x_1", `feature_flag:a${"b".repeat(99)}`];
const BAD_PARAMS = ["password", "BROWSER", "url_param:campaign", "utm_foo", "", "feature_flag:", "feature_flag:1abc", `feature_flag:a${"b".repeat(100)}`, "feature_flag:x'y", "session_id", "feature_flag:flag\n", "brówser"];

const genFilter = (): unknown => {
  const filter: Record<string, unknown> = {};
  const parameter = (() => {
    const roll = rand();
    if (roll < 0.8) return pick(BASE_PARAMS);
    if (roll < 0.87) return pick(FEATURE_FLAGS);
    if (roll < 0.96) return pick(BAD_PARAMS);
    return pick([5, null, ["browser"], { a: 1 }, true]);
  })();
  const type = chance(0.92) ? pick(FILTER_TYPES) : pick(["like", "", "EQUALS", 5, null]);
  const value = chance(0.93) ? repeat(pick([0, 1, 1, 1, 1, 2, 2, 3, 4]), genValue) : pick(["Chrome", 5, null, { 0: "x" }]);
  const keys = chance(0.85) ? ["parameter", "type", "value"] : ["value", "type", "parameter"];
  for (const key of keys) {
    if (chance(0.03)) continue;
    filter[key] = key === "parameter" ? parameter : key === "type" ? type : value;
  }
  if (chance(0.05)) filter[pick(["extra", "0", "10", "__proto__x"])] = pick(["x", 1, null]);
  return filter;
};

// ---------------------------------------------------------------------------
// 1. Filters
// ---------------------------------------------------------------------------
{
  const SPECIAL_FILTER_TEXTS = [
    '[{"parameter":"lat","type":"greater_than","value":[1e999]}]',
    '[{"parameter":"lat","type":"equals","value":[-0]}]',
    '[{"parameter":"browser","type":"equals","value":["\\ud800x"]}]',
    '[{"parameter":"browser","type":"equals","parameter":"country","value":["x"]}]',
    " [ ] ",
    '{"parameter":"browser","type":"equals","value":["x"]}',
    "42",
    '"x"',
    "null",
    "[null]",
    "[[]]",
    '[{"parameter":"browser","type":"equals","value":["a"],"__proto__":{"x":1}}]',
    '[{"0":1,"parameter":"browser","type":"equals","value":["a"]}]',
    '[{"parameter":"lat","type":"greater_than","value":[1e999]},{"parameter":"browser","type":"equals","value":["x"]}]',
    '[{"parameter":"country","type":"equals","value":[1e999]},{"parameter":"pathname","type":"equals","value":["/x"]}]',
    "not json",
    "[{",
    "{",
    "[1,]",
    "\ufeff[]",
    "[]",
    "",
    '[{"parameter":"browser","type":"equals","value":["\\u0000"]}]',
    '[{"parameter":"lon","type":"not_equals","value":[]}]',
    '[{"parameter":"user_id","type":"equals","value":[]}]',
    '[{"parameter":"user_id","type":"equals","value":[123, "u"]}]',
    '[{"parameter":"lat","type":"greater_than","value":[]}]',
  ];
  const texts: unknown[] = [...SPECIAL_FILTER_TEXTS];
  for (let i = 0; i < 3500; i++) {
    const roll = rand();
    if (roll < 0.9) texts.push(JSON.stringify(repeat(pick([0, 1, 1, 1, 2, 2, 3, 4]), genFilter)));
    else if (roll < 0.95) texts.push(pick(SPECIAL_FILTER_TEXTS));
    else {
      const text = JSON.stringify(repeat(pick([1, 2]), genFilter));
      texts.push(pick([[text], [text, text], ["", ""], [text, "[]"], [""]]));
    }
  }

  // Mostly valid filters, so more cases reach SQL generation
  const VALID_STRINGS = VALUE_STRINGS.filter(value => value.length <= 500);
  const genValidFilter = () => {
    const type = pick(FILTER_TYPES);
    const parameter = chance(0.9) ? pick(BASE_PARAMS) : pick(FEATURE_FLAGS);
    const numeric = ["greater_than", "less_than", "greater_than_or_equal", "less_than_or_equal"].includes(type) || ((parameter === "lat" || parameter === "lon") && chance(0.7));
    const regex = type === "regex" || type === "not_regex";
    const count = type === "is_null" || type === "is_not_null" ? pick([0, 0, 1]) : regex ? 1 : pick([1, 1, 1, 2, 3]);
    const value = repeat(count, () =>
      regex ? pick(REGEXES.filter(pattern => gfs.validateRegexPattern(pattern) === null)) : numeric ? (chance(0.5) ? pick(NUMBERS) : pick(["40.5", "-70.25", "10", "0", " 12 ", "0x1f", "1e3", "-0"])) : chance(0.85) ? pick(VALID_STRINGS) : pick(NUMBERS)
    );
    return { parameter, type, value };
  };
  for (let i = 0; i < 2500; i++) {
    const text = JSON.stringify(repeat(1 + int(4), genValidFilter));
    texts.push(chance(0.03) ? [text] : text);
  }

  const TIME = "AND timestamp >= toDateTime('2024-01-01 00:00:00', 'UTC')";
  const TIME2 = "and\n\t timestamp > now() - INTERVAL 1 DAY  ";
  const allowlist = new Set(["browser", "country", "pathname", "user_id", "channel", "event_name", "lat", "feature_flag:beta"]);
  const mappings = { "url_parameters['utm_source']": "utm_source", pathname: "page_path", lat: "latitude", "feature_flags['beta']": "beta_flag" };
  const cases = texts.map(filters => ({
    filters: enc(filters),
    results: [
      run(() => gfs.getFilterStatement(filters)),
      run(() => gfs.getFilterStatement(filters, 42, TIME)),
      run(() => gfs.getFilterStatement(filters, 7, TIME2, { sessionLevelParams: ["channel"] })),
      run(() =>
        gfs.getFilterStatement(filters, 0, TIME, { sessionLevelParams: [], parameterAllowlist: allowlist, dualUserIdColumns: false })
      ),
      run(() =>
        gfs.getFilterStatement(filters, 9, "", { fieldMappings: mappings, sessionLevelParams: ["pathname", "hostname", "city", "feature_flag:beta"] })
      ),
      run(() => sf.getSessionFilterStatement(filters, 3, TIME)),
      run(() => sf.buildFilteredSessionsCTE(filters, 3, TIME)),
      run(() => sf.buildSessionAndRowFilterFragments(filters, 3, TIME, sf.TARGET_EVENT_ROW_LEVEL_PARAMS)),
      run(() => sf.buildSessionAndRowFilterFragments(filters, 3, TIME, ["event_name"], "Custom")),
      run(() => qv.validateFilters(filters)),
    ],
  }));
  write("filters", cases);

  const sqlParams = [...BASE_PARAMS, ...FEATURE_FLAGS, ...BAD_PARAMS, "utm_", "utm_x'y", "url_param:", "url_param:a'b\\c", "feature_flag:x'y", "Referrer", "entry_page ", "😀"];
  write(
    "sql_params",
    sqlParams.map(parameter => ({ parameter, result: run(() => gfs.getSqlParam(parameter)) }))
  );

  const conditionCases = [];
  for (let i = 0; i < 1500; i++) {
    const expression = pick(["browser", "session_channel", "url_parameters['x']", "concat(a, b)"]);
    const type = pick(FILTER_TYPES);
    const values = repeat(pick([0, 1, 1, 2, 3]), () => (chance(0.8) ? pick([...VALUE_STRINGS, ...REGEXES]) : pick(NUMBERS)));
    conditionCases.push({
      expression,
      type,
      values: enc(values),
      condition: run(() => gfs.buildStringFilterCondition(expression, type, values)),
      wrapped: values.map(value => gfs.wrapLikeValue(type, value)),
      regex: values.map(value => gfs.validateRegexPattern(String(value))),
    });
  }
  write("conditions", conditionCases);
}

// ---------------------------------------------------------------------------
// 2. Time windows and time param validation
// ---------------------------------------------------------------------------
{
  const DATES = [
    "2024-01-01", "2024-01-31", "2024-03-10", "2024-03-31", "2024-11-03", "2024-10-27", "2024-02-29", "2023-02-29", "2024-02-31",
    "2024-13-01", "2024-00-10", "0001-01-00", "0012-13-05", "0000-01-01", "9999-12-31", "01/01/2024", "2024-1-1", "bogus",
    " 2024-01-01", "2024-01-01'; DROP TABLE events;--", "2024-01-01T00:00:00Z", "Jan 1 2024", "2026-09-17", "2024-06-15",
  ];
  const DATETIMES = [
    "2024-01-01 00:00:00", "2024-01-02 12:30:00", "2024-03-10 02:30:00", "2024-03-10T02:30:00Z", "2024-03-10T07:34:00+05:30",
    "2024-03-10T07:34:00-0800", "2024-11-03 01:30:00", "2024-01-01 24:00:00", "2024-01-01 25:00:00", "2024-01-01T10:00:00+24:00",
    "2024-02-30 10:00:00", "0000-01-01 00:00:00+01:00", "9999-12-31T23:59:59-10:00", "2024-01-01", "Jan 1 2024 10:00",
    "01/02/2024 10:00:00", "2024-01-01 10:00:00.123", "2024-01-01 00:00:00' OR '1'='1", "2024-03-10T07:34:56Z",
    "2024-03-10 07:00:00", "2024-03-10 07:34:56", "2024-03-10T08:00:00+00:30", "2024-03-10T06:15:00",
  ];
  const ZONES = [
    "UTC", "utc", "America/New_York", "america/new_york", "Asia/Kolkata", "Australia/Lord_Howe", "Pacific/Chatham", "Asia/Kathmandu",
    "Europe/London", "America/Sao_Paulo", "Etc/GMT+12", "+05:30", "-0800", "\u221205:00", "+24:00", "Not/AZone",
    "UTC'; DROP TABLE events;--", "Factory", "EST", "US/Pacific-New", "Europe/Kiev", "GMT0",
  ];
  const MINUTES: unknown[] = ["60", "0", "30", 60, 0, 1440, "-5", "abc", "1e20", 1e20, "Infinity", " 30 ", "0x10", "30.5", 0.5, "1e-9", 90, "120", 5];
  const field = (pool: readonly unknown[]) => {
    if (chance(0.08)) return chance(0.5) ? [pick(pool)] : [pick(pool), pick(pool)];
    if (chance(0.06)) return "";
    return pick(pool);
  };
  const cases: unknown[] = [];
  const addCase = (params: unknown) => {
    Date.now = () => FIXED_NOW;
    const buckets = ["minute", "five_minutes", "ten_minutes", "fifteen_minutes", "hour", "day", "week", "month", "year"];
    cases.push({
      params: enc(params),
      validate: run(() => qv.validateHttpTimeParams(params)),
      window: run(() => {
        const window = tw.resolveTimeWindow(params as any);
        return {
          isAllTime: window.isAllTime,
          where: window.where(),
          whereStart: window.where("start_time"),
          bucketed: ["minute", "hour", "week"].map(bucket => window.bucketed("timestamp", bucket as any)),
          fill: buckets.map(bucket => window.fill(bucket as any)),
        };
      }),
      statement: run(() => tw.getTimeStatement(params as any, "event_hour")),
    });
  };
  for (const params of [undefined, null, "start_date=2025-01-01", ["2024-01-01"], {}]) addCase(params);
  for (const zone of ZONES) {
    addCase({ start_date: "2024-03-01", end_date: "2024-03-31", time_zone: zone });
    addCase({ start_datetime: "2024-03-10 01:00:00", end_datetime: "2024-03-10T09:45:00Z", time_zone: zone });
    addCase({ past_minutes_start: 90, past_minutes_end: 0, time_zone: zone });
    addCase({ time_zone: zone });
  }
  const VALID_DATES = ["2024-01-01", "2024-01-31", "2024-03-10", "2024-03-31", "2024-11-03", "2024-10-27", "2024-02-29", "2023-02-29", "2024-02-31", "0001-01-00", "2026-09-17", "2024-06-15", "2025-12-31", "2024-04-07"];
  const VALID_DATETIMES = DATETIMES.filter(value => !Number.isNaN(tw.parseDateTimeMs(value)) && /^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(Z|[+-]\d{2}:?\d{2})?$/.test(value));
  const DST_ZONES = [...ZONES, "Europe/Berlin", "America/Los_Angeles", "Australia/Sydney", "America/Santiago", "Asia/Tehran", "Pacific/Apia", "America/St_Johns", "Africa/Casablanca", "Asia/Gaza", "Europe/Dublin", "America/Havana", "Antarctica/Troll", "+14:00", "-12:00", "\u221200:30"];
  for (let i = 0; i < 2400; i++) {
    const params: Record<string, unknown> = {};
    const mode = int(3);
    if (mode === 0) {
      params.start_date = pick(VALID_DATES);
      params.end_date = pick(VALID_DATES);
    } else if (mode === 1) {
      params.start_datetime = pick(VALID_DATETIMES);
      params.end_datetime = pick(VALID_DATETIMES);
    } else {
      params.past_minutes_start = pick([90, "60", 1440, "30.5", 0.5, 10080, "5"]);
      params.past_minutes_end = pick([0, "0", 5, "1", 0.25]);
    }
    if (chance(0.85)) params.time_zone = pick(DST_ZONES);
    addCase(params);
  }
  for (let i = 0; i < 3000; i++) {
    const params: Record<string, unknown> = {};
    const mode = int(4);
    if (mode === 0 || chance(0.25)) {
      if (chance(0.9)) params.start_date = field(DATES);
      if (chance(0.9)) params.end_date = field(DATES);
    }
    if (mode === 1 || chance(0.25)) {
      if (chance(0.9)) params.start_datetime = field(DATETIMES);
      if (chance(0.9)) params.end_datetime = field(DATETIMES);
    }
    if (mode === 2 || chance(0.25)) {
      if (chance(0.9)) params.past_minutes_start = field(MINUTES);
      if (chance(0.9)) params.past_minutes_end = field(MINUTES);
    }
    if (chance(0.7)) params.time_zone = field(ZONES);
    if (chance(0.1)) params.filters = "[]";
    addCase(params);
  }
  write("time_windows", cases);
}

// ---------------------------------------------------------------------------
// 3. Date.parse and datetime normalization
// ---------------------------------------------------------------------------
{
  const two = () => String(chance(0.8) ? int(32) : int(100)).padStart(2, "0");
  const four = () => String(chance(0.7) ? 1900 + int(200) : int(10000)).padStart(4, "0");
  const zone = () =>
    pick(["", "", "Z", `+${two()}:${two()}`, `-${two()}${two()}`, "+05:30", "-08:00", `+${two()}`, "z", "+5:30", " UTC", "Z "]);
  const TOKENS = [
    "2024", "01", "1", "31", "-", "/", ":", ".", " ", "T", "Z", "UTC", "GMT", "PST", "am", "pm", "Jan", "january", "(", ")",
    "+", "0530", "05:30", "Mon", "x", "\t", "\u00a0", "\u2028", "12", "123", "1234567890123", "000", ",", "\0", "t", "Sept",
    "24", "::", "999999", "-000000", "+275760", "(comment)", "ut", "cst",
  ];
  const strings = new Set<string>();
  const MONTHS = ["Jan", "feb", "MAR", "April", "may", "Jun", "jul", "Aug", "Sept", "oct", "Nov", "December", "Febr", "ju"];
  const legacy = () => {
    const day = String(int(40));
    const year = pick(["2024", "24", "99", "0", "1970", "275760", "-1"]);
    const time = pick(["", " 10:00", " 10:00:00", " 1:2:3", " 12:00 AM", " 12:00 pm", " 13:00 PM", " 10:00:00.123", " 10::", " 24:00", " 10:61"]);
    const zone = pick(["", " GMT", " UTC", " Z", " GMT+0200", " +0530", " -08", " PST", " EDT", " (Pacific Standard Time)", " GMT+2", " UT", "Z", " +05:30"]);
    return pick([
      `${pick(MONTHS)} ${day} ${year}${time}${zone}`,
      `${day} ${pick(MONTHS)} ${year}${time}${zone}`,
      `${pick(["Mon, ", "Tuesday ", ""])}${day} ${pick(MONTHS)} ${year}${time}${zone}`,
      `${int(14)}/${day}/${year}${time}${zone}`,
      `${year}/${int(14)}/${day}${time}${zone}`,
      `${year}-${int(14)}-${day}${time}${zone}`,
      `${pick(MONTHS)}-${day}-${year}${time}`,
    ]);
  };
  while (strings.size < 12000) strings.add(legacy());
  while (strings.size < 42000) {
    const roll = rand();
    if (roll < 0.35) strings.add(`${four()}-${two()}-${two()}${pick([" ", "T"])}${two()}:${two()}:${two()}${zone()}`);
    else if (roll < 0.5) strings.add(`${four()}-${two()}-${two()}`);
    else strings.add(repeat(1 + int(8), () => pick(TOKENS)).join(""));
  }
  const cases = [...strings].map(text => ({
    text,
    parse: enc(Date.parse(text)),
    parseDateTimeMs: enc(tw.parseDateTimeMs(text)),
    normalized: run(() => tw.normalizeDatetimeForClickhouse(text)),
  }));
  write("dates", cases);
}

// ---------------------------------------------------------------------------
// 4. Number(), parseInt()
// ---------------------------------------------------------------------------
{
  const TOKENS = [
    "0", "1", "9", "12", ".", "-", "+", "e", "E", "x", "X", "o", "O", "b", "B", "a", "f", "F", "g", "Infinity", " ", "\t",
    "\u00a0", "\ufeff", "\u2028", "\u0085", "_", "0x", "0b", "0o", "1e308", "5e-324", "9007199254740993", "123456789012345678901234567890",
    "0x" + "f".repeat(20), "0b" + "1".repeat(60), "0o" + "7".repeat(25), "00", "1.5", "e5", "NaN", "infinity", "٣",
  ];
  const strings = new Set<string>(["", " ", "0", "-0", "+0", "0x", "1e", ".", "5.", ".5", "-.5", "+.5e-3"]);
  while (strings.size < 20000) strings.add(repeat(1 + int(5), () => pick(TOKENS)).join(""));
  const show = (value: number) => (Object.is(value, -0) ? "-0" : String(value));
  write(
    "numbers",
    [...strings].map(text => ({ text, number: show(Number(text)), parseInt: show(parseInt(text, 10)) }))
  );
}

// ---------------------------------------------------------------------------
// 5. Time zones
// ---------------------------------------------------------------------------
{
  const { readFileSync } = await import("node:fs");
  const names: string[] = JSON.parse(readFileSync(new URL("./icu_names_2026c.json", import.meta.url), "utf8"));
  const recase = (text: string) =>
    [...text].map(c => (chance(0.5) ? c.toUpperCase() : c.toLowerCase())).join("");
  const ALPHABET = [..."/_-+0123456789aZ :\u2212é"];
  const mutate = (text: string) => {
    const chars = [...text];
    const at = int(chars.length + 1);
    const roll = rand();
    if (roll < 0.33) chars.splice(at, 0, pick(ALPHABET));
    else if (roll < 0.66) chars.splice(at, 1);
    else chars.splice(at, 1, pick(ALPHABET));
    return chars.join("");
  };
  const zones = new Set<string>(names);
  for (const name of names) {
    zones.add(recase(name));
    zones.add(mutate(name));
    zones.add(mutate(recase(name)));
  }
  while (zones.size < 12000) {
    zones.add(repeat(1 + int(7), () => pick([..."+-\u22120123456789:"])).join(""));
  }
  const tz = (value: string) => {
    try {
      Intl.DateTimeFormat(undefined, { timeZone: value });
      return true;
    } catch {
      return false;
    }
  };
  write("time_zones", [...zones].map(zone => ({ zone, valid: tz(zone), isValidTimeZone: tw.isValidTimeZone(zone) })));
}

// ---------------------------------------------------------------------------
// 6. Regex patterns
// ---------------------------------------------------------------------------
{
  const TOKENS = [
    "(", ")", "(?:", "(?=", "(?!", "(?<=", "(?<!", "(?<a>", "(?<b>", "(?<1>", "(?<$_é>", "(?i:", "(?-i:", "(?m-s:", "(?ii:", "(?-:",
    "(?i-", "[", "]", "[^", "\\", "\\1", "\\2", "\\10", "\\k<a>", "\\k<b>", "\\k", "\\k<", "\\u0041", "\\u{41}", "\\x4", "\\x41",
    "\\c", "\\cA", "\\c1", "\\p{L}", "{", "}", "{1}", "{2,1}", "{1,}", "{,1}", "{99999999999}", "*", "+", "?", "??", "|", "^",
    "$", ".", "a", "b", "-", "z", "0", "9", "\\d", "\\w", "\\b", "\\B", "\\0", "\\8", "\\00", "/", "😀", "é", "\\ud83d\\ude00",
    "(?<\\u0061>", "(?<\\u{61}>", ">", "<", "\\-", "\\]",
  ];
  const patterns = new Set<string>(REGEXES);
  const NAMED = [
    "(?<a>", "(?<b>", "(?<a>x)", "(?<b>y)", "\\k<a>", "\\k<b>", "\\k<c>", "|", "(", ")", "(?:", "(?<=a)", "(?<!b)", "*", "+", "?", "{2}",
    "[\\k]", "[\\c1]", "[\\c]", "\\k", "(?<\\u{1d4d0}>", "(?<\\ud835\\udcd0>", "(?<𝓐>", "(?<a\\u0062>", "(?<$>", "(?<_1>", "\\1", "\\2", "\\3",
    "\\01", "\\377", "\\400", "[\\1-\\2]", "[a-\\d]", "[\\w-z]", "\\cz", "\\c_", "(?i-ms:", "(?-i:", "(?smi:", "(?ms-:",
  ];
  while (patterns.size < 55000) patterns.add(repeat(1 + int(8), () => pick(NAMED)).join(""));
  while (patterns.size < 75000) patterns.add(repeat(1 + int(9), () => pick(TOKENS)).join(""));
  const raw = (pattern: string) => {
    try {
      new RegExp(pattern);
      return null;
    } catch (error) {
      return (error as Error).message;
    }
  };
  // The SyntaxError message repeats the pattern; only the part after it is stored
  const suffix = (pattern: string, message: string | null) => {
    const prefix = `Invalid regular expression: /${pattern}/: `;
    return message === null ? null : message.startsWith(prefix) ? message.slice(prefix.length) : `UNEXPECTED ${message}`;
  };
  write(
    "regexes",
    [...patterns].map(pattern => {
      const validate = gfs.validateRegexPattern(pattern);
      const rawError = suffix(pattern, raw(pattern));
      // validateRegexPattern's message embeds the SyntaxError in full; store it only when it says something else
      const derived = rawError === null ? null : `Invalid regex pattern: Invalid regular expression: /${pattern}/: ${rawError}`;
      return validate === derived && rawError !== null ? { pattern, rawError } : { pattern, rawError, validate };
    })
  );
}

// ---------------------------------------------------------------------------
// 7. Custom query validation and ClickHouse errors
// ---------------------------------------------------------------------------
{
  const STARTS = ["SELECT", "select", "WITH t AS (SELECT user_id FROM scoped_events) SELECT", " WITH x as(select 1)", "INSERT", "", "  SELECT", "SHOW", "WITH scoped_events AS (SELECT 1) SELECT", "SeLeCt"];
  const PIECES = [
    " count(*)", " *", " a.user_id", " 'FROM events'", ' "events"', " `events`", " -- comment\n", " /* FROM events */", " # hash\n",
    " // slash\n", " $$x$$", " 'it''s'", " 'a\\'b'", " FROM scoped_events", " FROM events", " FROM scoped_events, sessions_mv_target",
    " FROM (SELECT * FROM scoped_events) x", " JOIN events ON 1=1", " ARRAY JOIN mapKeys(url_parameters) AS k", " WHERE user_id IN events",
    " WHERE user_id GLOBAL NOT IN scoped_events", " WHERE country IN tuple('US')", " WHERE x IN t", " GROUP BY k, x", " ORDER BY 1, 2",
    " LIMIT 10", ";", " ; SELECT 1", " SETTINGS max_threads=1", " FORMAT JSON", " INTO OUTFILE 'x'", " hostName()", " HOSTNAME ()",
    " s3Cluster('x')", " icebergS3('x')", " dictGet('a','b',1)", " system.tables", " INFORMATION_SCHEMA .x", " AS scoped_events",
    " numbers(10)", " url('http://x')", " file('x')", "\u00a0FROM\u3000scoped_events", " sleep(1)", " toStartOfDay(timestamp)",
    " 'unterminated", " /* unterminated", " FROM system.parts", " UNION ALL SELECT * FROM events", " fromUnixTimestamp(1)",
    " FROMscoped_events", " join\tevents", " IN(1,2)", " NOT IN x", ", other", " Exception", " t AS (SELECT 1)", ", u AS(", " FROM t",
    " FROM u", " 'x\\", " \"\\\"\"", " zeros(3)", " generateSeries(1, 3)", " ossX()", " hive ()", " ARRAY\u3000JOIN arr", " FROM\u2028scoped_events",
    " WHERE 1=1", " LEFT JOIN scoped_events b USING (session_id)", " PREWHERE x", "\n", " 😀", " 'é'", " /*", "*/", " --", " -",
  ];
  const queries = new Set<string>([
    "SELECT count(*) FROM scoped_events",
    "WITH t AS (SELECT user_id, count() c FROM scoped_events GROUP BY user_id) SELECT * FROM t",
    "SELECT * FROM scoped_events WHERE 1=1 # '\nUNION ALL SELECT * FROM events WHERE site_id = 2 -- '",
    "SELECT $x$'$x$ AS a FROM scoped_events UNION ALL SELECT * FROM events -- '",
    "  SELECT 1 ;;  ",
    ";;;",
    "",
  ]);
  while (queries.size < 4000) queries.add(pick(STARTS) + repeat(1 + int(8), () => pick(PIECES)).join(""));
  const cases = [...queries].map(query => {
    const normalized = cqv.normalizeCustomQuery(query);
    const stripped = cqv.stripSqlLiteralsAndComments(query);
    const compact = stripped.trim();
    return {
      query,
      validate: cqv.validateScopedQuery(query),
      normalized,
      unsupported: cqv.hasUnsupportedSyntax(query),
      stripped,
      cteNames: [...cqv.getCteNames(compact)],
      tables: cqv.collectTableReferences(compact),
      inTables: cqv.collectInTableReferences(compact),
    };
  });
  write("custom_queries", cases);

  const CODES = ["1", "47", "62", "497", "159", "0", "0062", "99999999999999999999", "241", "999", "6", ""];
  const MESSAGES = [
    "Unknown expression identifier 'foo' (table default.events (072583d3-1467-4d46-89ff-3f6981180a16)). (UNKNOWN_IDENTIFIER)",
    "hygo_query: Not enough privileges. (ACCESS_DENIED)",
    "hygo_query: not ENOUGH privileges.",
    "Syntax error: failed at position 5 (from 10.0.0.1:1234) (SYNTAX_ERROR)",
    "Timeout exceeded: elapsed 10.2 seconds (TIMEOUT_EXCEEDED)",
    "Memory limit (for query) exceeded (MEMORY_LIMIT_EXCEEDED)\nStack trace:\n0. DB::Exception\n1. x",
    "user hygo_query failed reading /var/lib/clickhouse/store/x.bin on host ch-1",
    "weird (version 1 (a) (b)) tail (version 26.7.4.58 (official build))",
    "UUID (0725 83D3-1467-4D46-89FF-3F6981180A16) (072583D3-1467-4D46-89FF-3F6981180A16)",
    "\u00a0 (from [::1]:9000)\u3000",
    "no parens",
  ];
  const errorCases = [];
  for (let i = 0; i < 800; i++) {
    const code = pick(CODES);
    const roll = rand();
    const message =
      roll < 0.7
        ? `Code: ${code}. DB::Exception: ${pick(MESSAGES)}${pick(["", " (version 26.3.17.4 (official build))", "\n"])}`
        : roll < 0.8
          ? pick(MESSAGES)
          : roll < 0.9
            ? pick(["", "socket hang up", "Timeout error.", `code: ${code}. x`, `Code: ${code} DB`])
            : `Error: ${code}. Exception: ${pick(MESSAGES)}`;
    const parsed = chCommon.parseError(message);
    errorCases.push({
      message,
      sanitized: cqv.sanitizeClickhouseError(new Error(message)),
      parsed: { message: parsed.message, code: parsed.code ?? null, type: parsed.type ?? null },
    });
  }
  errorCases.push({ message: null, sanitized: cqv.sanitizeClickhouseError("boom"), parsed: null });
  write("clickhouse_errors", errorCases);
}

// ---------------------------------------------------------------------------
// 8. Segment schemas
// ---------------------------------------------------------------------------
{
  const NAMES: unknown[] = ["", "   ", "x", "  Mobile DE  ", "n".repeat(80), "n".repeat(81), 5, null, ["x"], "😀".repeat(41), "😀".repeat(40), " \ufeffok\u3000"];
  const DESCRIPTIONS: unknown[] = [null, "d", "d".repeat(500), `  ${"d".repeat(500)}  `, "d".repeat(501), 3, {}];
  const cases = [];
  const genSegmentFilter = () => {
    const type = pick(FILTER_TYPES);
    const parameter = chance(0.9) ? pick(BASE_PARAMS) : pick(FEATURE_FLAGS);
    const regex = type === "regex" || type === "not_regex";
    const numeric = ["greater_than", "less_than", "greater_than_or_equal", "less_than_or_equal"].includes(type) || parameter === "lat" || parameter === "lon";
    const count = type === "is_null" || type === "is_not_null" ? int(2) : regex ? pick([1, 1, 1, 2]) : pick([1, 1, 2, 3, 0, 51]);
    const value = repeat(count, () =>
      regex ? pick(REGEXES) : numeric ? pick([48.1, "12", "north", 1e308, "Infinity", "-0", ""]) : pick(["Mobile", "DE", "/docs", "x".repeat(500), "x".repeat(501), 5, "😀".repeat(251)])
    );
    return { parameter, type, value };
  };
  for (let i = 0; i < 1500; i++) {
    const body: Record<string, unknown> = { name: pick(["Mobile DE", "  x ", "n".repeat(80), "😀".repeat(40)]), filters: repeat(1 + int(3), genSegmentFilter) };
    if (chance(0.4)) body.description = pick([null, "desc", "  padded  ", "d".repeat(500)]);
    if (chance(0.4)) body.isPublic = chance(0.5);
    if (chance(0.4)) body.scope = pick(["site", "organization"]);
    if (chance(0.3)) delete body.name;
    const outcome = (result: any) => (result.success ? { data: result.data } : { issues: result.error.errors });
    cases.push({
      body: enc(body),
      create: enc(outcome(seg.createSegmentSchema.safeParse(body))),
      update: enc(outcome(seg.updateSegmentSchema.safeParse(body))),
      filters: enc(outcome(seg.segmentFiltersSchema.safeParse(body.filters))),
    });
  }
  for (let i = 0; i < 2500; i++) {
    let body: unknown;
    if (chance(0.04)) body = pick([null, [], "x", 5, undefined, true]);
    else {
      const object: Record<string, unknown> = {};
      if (chance(0.85)) object.name = pick(NAMES);
      if (chance(0.4)) object.description = pick(DESCRIPTIONS);
      if (chance(0.9)) {
        const roll = rand();
        object.filters =
          roll < 0.75
            ? repeat(pick([0, 1, 1, 2, 3]), genFilter)
            : roll < 0.85
              ? repeat(21, genFilter)
              : pick(["x", 5, null, {}, [null], [[]]]);
      }
      if (chance(0.3)) object.isPublic = pick([true, false, "true", 1, null]);
      if (chance(0.3)) object.scope = pick(["site", "organization", "team", 5, null, ""]);
      if (chance(0.1)) object[pick(["siteId", "0", "__x", "10", "b", "type"])] = pick([4, "x", null]);
      body = object;
    }
    const outcome = (result: any) => (result.success ? { data: result.data } : { issues: result.error.errors });
    cases.push({
      body: enc(body),
      create: enc(outcome(seg.createSegmentSchema.safeParse(body))),
      update: enc(outcome(seg.updateSegmentSchema.safeParse(body))),
      filters: enc(outcome(seg.segmentFiltersSchema.safeParse((body as any)?.filters))),
    });
  }
  write("segment_schemas", cases);
}

// ---------------------------------------------------------------------------
// 9. expandSegmentParam
// ---------------------------------------------------------------------------
{
  const SEGMENT_IDS: unknown[] = ["7", 7, "", "seven", "0", "-1", "1.5", "7.0", " 7 ", ["7"], ["7", "8"], null, "1e3", "0x10", "Infinity"];
  const SITE_IDS: unknown[] = ["1", "abc", "0", undefined, "2.5", " 3 ", "1e2"];
  const STATEMENTS: unknown[] = [null, { analytics: ["read"] }, { segments: ["read"] }, { segments: ["write"] }, {}];
  const validFilters = () => JSON.stringify(repeat(1 + int(2), () => ({ parameter: pick(BASE_PARAMS), type: pick(["equals", "contains", "not_equals"]), value: [pick(["Mobile", "DE", "/x", "Chrome"])] })));
  const cases = [];
  for (let i = 0; i < 1500; i++) {
    const query: Record<string, unknown> = {};
    if (chance(0.9)) query.segment_id = pick(SEGMENT_IDS);
    if (chance(0.6))
      query.filters = pick([validFilters(), validFilters(), "not json", "", ["x"], '[{"parameter":"nope","type":"equals","value":["x"]}]', '[{"parameter":"device_type","type":"equals","value":["Mobile"]}]']);
    const params: Record<string, unknown> = {};
    const siteId = pick(SITE_IDS);
    if (siteId !== undefined) params.siteId = siteId;
    const bearer = chance(0.3) ? { statements: pick(STATEMENTS) } : null;
    const segmentFilters = chance(0.1)
      ? JSON.parse('[{"type":"equals","value":["Mobile"],"parameter":"device_type"}]')
      : JSON.parse(validFilters());
    const loaded = chance(0.15) ? null : { segment: { isPublic: chance(0.3), filters: segmentFilters }, organizationId: "org" };
    const actor = { userId: null, hasSiteAccess: chance(0.6), isAdmin: false };
    (globalThis as any).__segmentStub = { loaded, actor };
    const request: any = { query: structuredClone(query), params, headers: {} };
    if (bearer) {
      request.bearerAuth = true;
      request.bearerStatements = bearer.statements;
    }
    const reply: any = { statusCode: null, payload: null };
    reply.status = (code: number) => ((reply.statusCode = code), reply);
    reply.send = (payload: unknown) => ((reply.payload = payload), reply);
    await esp.expandSegmentParam(request, reply);
    cases.push({
      query: enc(query),
      siteId: enc(siteId),
      bearerCanRead: bearer ? scopes.hasScope(bearer.statements as any, { resource: "segments", action: "read" }) : null,
      loaded: loaded ? enc({ filters: loaded.segment.filters, isPublic: loaded.segment.isPublic }) : null,
      hasSiteAccess: actor.hasSiteAccess,
      status: reply.statusCode,
      payload: enc(reply.payload),
      filtersAfter: enc(request.query.filters),
    });
  }
  write("expand_segment", cases);
}

// ---------------------------------------------------------------------------
// 10. Pagination, event conditions, SqlString, formatQueryParams, processResults
// ---------------------------------------------------------------------------
{
  const LIMITS: unknown[] = [undefined, "25", 25, "abc", -5, 0, "0", "1e5", " 7", "3.9", ["2"], ["2", "3"], "99999999999999999999", 1.5, "-1", "", "1".repeat(400), "0x10", "  +12abc"];
  const cases = [];
  for (const limit of LIMITS)
    for (const page of LIMITS)
      for (const defaultLimit of [10, 100])
        cases.push({ limit: enc(limit), page: enc(page), defaultLimit, result: aq.getPaginationStatements({ limit: limit as any, page: page as any }, defaultLimit) });
  cases.push({ limit: 25, page: 3, defaultLimit: 100, isCount: true, result: aq.getPaginationStatements({ limit: 25, page: 3 }, 100, true) });
  write("pagination", cases);

  const PATTERN_CHARS = [..."/.*+?^${}()|[]\\ab-_ '\"\n😀é"];
  const pattern = () => (chance(0.1) ? "{{DOUBLE_STAR}}" : repeat(int(10), () => pick(PATTERN_CHARS)).join(""));
  const propertyFilters = () =>
    repeat(int(3), () => ({ key: pick(["plan", "k'ey", "a\\b", "", "😀"]), value: pick(["pro", "v') OR 1=1--", "", 42, 9.5, -0, 1e21, true, false, "c\\d"]) }));
  const eventCases = [];
  for (let i = 0; i < 1500; i++) {
    const p = pattern();
    const filters = propertyFilters();
    const type = pick(["outbound", "button_click", "form_submit", "copy"]);
    const autocapturePattern = chance(0.2) ? undefined : chance(0.2) ? pick(["", "   ", "  hello  "]) : pattern();
    eventCases.push({
      pattern: p,
      filters: enc(filters),
      type,
      autocapturePattern: enc(autocapturePattern),
      patternToRegex: utils.patternToRegex(p),
      page: ec.buildPageCondition(p, filters),
      event: ec.buildEventCondition(p, filters),
      autocapture: ec.buildAutocaptureCondition(type, autocapturePattern, filters),
    });
  }
  write("event_conditions", eventCases);

  const ESCAPE_CHARS = [..."a'\"\\\0\b\t\n\r\x1a%_😀é\u2028 "];
  const escapeValues: unknown[] = [null, undefined, true, false, 0, -0, 1.5, 1e21, NaN, Infinity, ["a", 1, null, ["b", true]], [{ a: 1 }], { a: "x", b: [1, 2] }];
  for (let i = 0; i < 1500; i++) escapeValues.push(repeat(int(12), () => pick(ESCAPE_CHARS)).join(""));
  write("sql_string", escapeValues.map(value => ({ value: enc(value), escaped: SqlString.escape(value) })));

  const paramValues: unknown[] = [
    null, undefined, 0, -0, 1.5, 1e21, NaN, Infinity, -Infinity, true, false, "", "a'b\\c\td\ne\rf", "😀", [1, "x", null, undefined, [2, "y"]],
    new Date(1700000000123), new Date(1700000000000), new Date(-1500), new Date(NaN), { a: 1, "b'": "c" }, [],
  ];
  for (let i = 0; i < 300; i++) paramValues.push(repeat(int(8), () => pick(ESCAPE_CHARS)).join(""));
  write("query_params", paramValues.map(value => ({ value: enc(value), formatted: chCommon.formatQueryParams({ value }) })));

  const NUMERIC_STRINGS = ["51", "81.4", "-3", "0", "120248430174340693", "007", "1.50", "1e5", "0.0000001", "-0", " 1", "NaN", "Infinity", "", "1e21", "123456789012345680000", "0.1", "5e-7", "9007199254740993", "4.35", "-0.0"];
  const rows = [];
  for (let i = 0; i < 400; i++) {
    const row: Record<string, unknown> = {};
    for (let j = 0; j < 1 + int(5); j++) {
      row[pick(["count", "value", "session_id", "user_id", "identified_user_id", "effective_user_id", "ratio", "10", "2"])] =
        chance(0.8) ? pick(NUMERIC_STRINGS) : pick([1, null, true, 2.5]);
    }
    rows.push(row);
  }
  const processed = await utils.processResults({ json: async () => structuredClone(rows) } as any);
  write("process_results", rows.map((row, index) => ({ row: enc(row), processed: enc(processed[index]) })));
}

console.log(JSON.stringify(counts));
process.exit(0);
