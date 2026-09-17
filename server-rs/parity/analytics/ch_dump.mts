// Runs complete analytics queries built from the shared utils against the parity
// ClickHouse through the real Node executor (runAnalyticsQuery / runPaginatedQuery)
// and records SQL, params and processed rows for the Rust side to replay.
//
//   source server-rs/parity/env.sh && cd server && npx tsx ../server-rs/parity/analytics/ch_dump.mts
// The Rust side (needs the same stores): `cargo test parity_clickhouse -- --ignored`.
import { mkdirSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { gzipSync } from "node:zlib";

// Defaults assume this file sits in server-rs/parity/analytics of a checkout whose
// server/ has node_modules installed; PARITY_SERVER and PARITY_OUT override them.
const SERVER = process.env.PARITY_SERVER ?? fileURLToPath(new URL("../../../server", import.meta.url));
const OUT = process.env.PARITY_OUT ?? fileURLToPath(new URL("./fixtures", import.meta.url));
const FIXED_NOW = Date.parse("2026-09-10T12:34:56.789Z");
Date.now = () => FIXED_NOW;

const gfs = await import(`${SERVER}/src/api/analytics/utils/getFilterStatement.ts`);
const sf = await import(`${SERVER}/src/api/analytics/utils/sessionFilters.ts`);
const tw = await import(`${SERVER}/src/api/analytics/utils/timeWindow.ts`);
const aq = await import(`${SERVER}/src/api/analytics/utils/analyticsQuery.ts`);

let seed = 0xc11c4;
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

const enc = (value: unknown): unknown => {
  if (value === undefined) return { $js: "undefined" };
  if (typeof value === "number") {
    if (Number.isNaN(value)) return { $js: "NaN" };
    if (value === Infinity) return { $js: "Infinity" };
    if (value === -Infinity) return { $js: "-Infinity" };
    if (Object.is(value, -0)) return { $js: "-0" };
    return value;
  }
  if (Array.isArray(value)) return value.map(enc);
  if (value && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [key, item] of Object.entries(value)) out[key] = enc(item);
    return out;
  }
  return value;
};

const SITES = [1, 2, 3, 4, 37, 45];
const FILTERS = [
  { parameter: "browser", type: "equals", values: ["Chrome", "Safari", "Firefox", "Edge"] },
  { parameter: "country", type: "not_equals", values: ["US", "DE", "GB"] },
  { parameter: "pathname", type: "contains", values: ["/", "blog", "a", "_", "%"] },
  { parameter: "pathname", type: "starts_with", values: ["/", "/docs", "/p"] },
  { parameter: "pathname", type: "regex", values: ["^/$", "^/[a-z]+", ".*"] },
  { parameter: "referrer", type: "is_not_null", values: [] },
  { parameter: "channel", type: "equals", values: ["Direct", "Organic Search", "Referral"] },
  { parameter: "event_name", type: "is_null", values: [] },
  { parameter: "entry_page", type: "equals", values: ["/", "/pricing"] },
  { parameter: "exit_page", type: "not_contains", values: ["/", "x"] },
  { parameter: "device_type", type: "equals", values: ["Desktop", "Mobile"] },
  { parameter: "operating_system_version", type: "contains", values: ["Windows", "10"] },
  { parameter: "browser_version", type: "starts_with", values: ["Chrome 1", "Safari"] },
  { parameter: "city", type: "is_not_null", values: [] },
  { parameter: "dimensions", type: "ends_with", values: ["x1080", "0"] },
  { parameter: "lat", type: "greater_than", values: ["0", "30.5"] },
  { parameter: "lon", type: "equals", values: ["-122.4", "0"] },
  { parameter: "user_id", type: "is_not_null", values: [] },
  { parameter: "utm_source", type: "is_null", values: [] },
  { parameter: "hostname", type: "not_regex", values: ["^www\\.", "localhost"] },
  { parameter: "querystring", type: "contains", values: ["utm", "?"] },
  { parameter: "page_title", type: "not_equals", values: ["", "Home"] },
  { parameter: "timezone", type: "starts_with", values: ["America", "Europe"] },
  { parameter: "feature_flag:beta", type: "is_null", values: [] },
  { parameter: "tag", type: "equals", values: [""] },
  { parameter: "language", type: "contains", values: ["en", "'"] },
];
const genFilters = () =>
  JSON.stringify(
    repeat(int(3), () => {
      const template = pick(FILTERS);
      const value = template.values.length === 0 ? [] : repeat(1 + int(Math.min(2, template.values.length)), () => pick(template.values));
      return { parameter: template.parameter, type: template.type, value };
    })
  );
const WINDOWS: Record<string, unknown>[] = [
  {},
  { start_date: "2026-06-01", end_date: "2026-09-09", time_zone: "UTC" },
  { start_date: "2026-08-01", end_date: "2026-08-31", time_zone: "America/New_York" },
  { start_date: "2026-07-15", end_date: "2026-09-01", time_zone: "Asia/Kolkata" },
  { start_datetime: "2026-08-10 00:00:00", end_datetime: "2026-09-12T06:30:00Z", time_zone: "Europe/Berlin" },
  { start_datetime: "2026-09-01T10:15:00+02:00", end_datetime: "2026-09-16 23:59:59", time_zone: "Australia/Lord_Howe" },
  { past_minutes_start: 60 * 24 * 30, past_minutes_end: 0, time_zone: "UTC" },
  { past_minutes_start: "20160", past_minutes_end: "1440", time_zone: "America/Los_Angeles" },
];
const BUCKETS = ["hour", "day", "week", "month", "fifteen_minutes"];

type Case = Record<string, unknown>;
const cases: Case[] = [];
const execute = async (name: string, spec: { query: string; params?: Record<string, unknown> }, inputs: Record<string, unknown>) => {
  try {
    const rows = await aq.runAnalyticsQuery(spec);
    cases.push({ name, inputs: enc(inputs), query: spec.query, params: enc(spec.params ?? {}), rows: enc(rows) });
  } catch (error) {
    const original = (error as any).original;
    cases.push({ name, inputs: enc(inputs), query: spec.query, params: enc(spec.params ?? {}), error: original?.message ?? String(error) });
  }
};

for (let i = 0; i < 260; i++) {
  const siteId = pick(SITES);
  const filters = genFilters();
  const params = pick(WINDOWS);
  const bucket = pick(BUCKETS);
  const inputs = { siteId, filters, params, bucket };
  const window = tw.resolveTimeWindow(params as any);
  const timeStatement = window.where();
  let filterStatement: string;
  try {
    filterStatement = gfs.getFilterStatement(filters, siteId, timeStatement);
  } catch (error) {
    cases.push({ name: "filter-error", inputs: enc(inputs), error: (error as Error).message });
    continue;
  }
  const kind = i % 5;
  if (kind === 0) {
    await execute(
      "totals",
      {
        query: `SELECT count() AS events, uniqExact(session_id) AS sessions, round(avg(lat), 6) AS avg_lat FROM events WHERE site_id = {siteId:Int32} ${timeStatement} ${filterStatement}`,
        params: { siteId },
      },
      inputs
    );
  } else if (kind === 1) {
    const cte = sf.buildFilteredSessionsCTE(filters, siteId, timeStatement);
    await execute(
      "filtered-sessions",
      {
        query: cte
          ? `WITH ${cte} SELECT count() AS sessions, toString(min(session_id)) AS first_session FROM FilteredSessions`
          : `SELECT uniqExact(session_id) AS sessions FROM events WHERE site_id = {siteId:Int32} ${timeStatement}`,
        params: { siteId },
      },
      inputs
    );
  } else if (kind === 2) {
    await execute(
      "bucketed",
      {
        query: `SELECT ${window.bucketed("timestamp", bucket as any)} AS time, count() AS pageviews, uniqExact(session_id) AS sessions
          FROM events
          WHERE site_id = {siteId:Int32} AND type = 'pageview' ${timeStatement} ${filterStatement}
          GROUP BY time ORDER BY time ${window.fill(bucket as any)}`,
        params: { siteId },
      },
      inputs
    );
  } else if (kind === 3) {
    const { filteredSessionsCTE, rowFilterStatement } = sf.buildSessionAndRowFilterFragments(filters, siteId, timeStatement, sf.TARGET_EVENT_ROW_LEVEL_PARAMS);
    await execute(
      "row-fragments",
      {
        query: `${filteredSessionsCTE ? `WITH ${filteredSessionsCTE}` : ""}
          SELECT pathname, count() AS count, round(count() * 100 / sum(count()) OVER (), 2) AS percentage
          FROM events ${filteredSessionsCTE ? "INNER JOIN FilteredSessions USING (session_id)" : ""}
          WHERE site_id = {siteId:Int32} ${timeStatement} ${rowFilterStatement}
          GROUP BY pathname ORDER BY count DESC, pathname ASC LIMIT {limit:Int32};`,
        params: { siteId, limit: 7 },
      },
      inputs
    );
  } else {
    const limit = pick([undefined, "5", 3, "abc", ["2"]]);
    const page = pick([undefined, "2", 1, "0", 3]);
    const { limitStatement, offsetStatement } = aq.getPaginationStatements({ limit, page } as any, 4);
    const pagination = { limit, page };
    const data = {
      query: `SELECT session_id, count() AS events, max(timestamp) AS last_seen FROM events WHERE site_id = {siteId:Int32} ${timeStatement} ${filterStatement} GROUP BY session_id ORDER BY events DESC, session_id ASC ${limitStatement} ${offsetStatement}`,
      params: { siteId },
    };
    const count = {
      query: `SELECT COUNT(DISTINCT session_id) AS totalCount FROM events WHERE site_id = {siteId:Int32} ${timeStatement} ${filterStatement}`,
      params: { siteId },
    };
    try {
      const result = await aq.runPaginatedQuery(data, count);
      cases.push({ name: "paginated", inputs: enc({ ...inputs, pagination }), query: data.query, countQuery: count.query, params: enc(data.params), rows: enc(result.data), totalCount: enc(result.totalCount) });
    } catch (error) {
      cases.push({ name: "paginated", inputs: enc({ ...inputs, pagination }), query: data.query, countQuery: count.query, params: enc(data.params), error: (error as any).original?.message ?? String(error) });
    }
  }
}

// Parameter formatting end to end
const PARAM_VALUES: Record<string, unknown>[] = [
  { s: "plain", n: 1.5, arr: ["a", "b'c", "d\\e", "tab\there"], u: undefined, b: true },
  { s: "quote ' and backslash \\ and newline \n", n: -0, arr: [], u: "x", b: false },
  { s: "😀 é 日本", n: 1e21, arr: ["😀"], u: null, b: true },
];
for (const params of PARAM_VALUES) {
  await execute(
    "params",
    { query: "SELECT {s:String} AS s, {n:Float64} AS n, {arr:Array(String)} AS arr, {u:Nullable(String)} AS u, {b:Bool} AS b, toUInt64(18446744073709551615) AS big, 0.1 + 0.2 AS float", params },
    { params }
  );
}

// Failures: the executor's error path (message as the Node client parses it)
await execute("error", { query: "SELECT nope FROM events WHERE site_id = {siteId:Int32}", params: { siteId: 1 } }, {});
await execute("error", { query: "SELEC 1", params: {} }, {});
await execute("error", { query: "SELECT {missing:String}", params: {} }, {});

// enrichWithTraits against the parity Postgres; the profiles seen are recorded so
// the Rust side can tell a changed database from a divergence
{
  const utils = await import(`${SERVER}/src/api/analytics/utils/utils.ts`);
  const { db } = await import(`${SERVER}/src/db/postgres/postgres.ts`);
  const { userProfiles } = await import(`${SERVER}/src/db/postgres/schema.ts`);
  const profiles = (await db.select({ siteId: userProfiles.siteId, userId: userProfiles.userId, traits: userProfiles.traits }).from(userProfiles))
    .map(profile => [profile.siteId, profile.userId, profile.traits])
    .sort((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b)));
  const known = profiles.map(profile => profile[1] as string);
  for (const siteId of [3, 4]) {
    const rows = [
      { identified_user_id: known[0] ?? "none", x: 1 },
      { identified_user_id: "", x: 2 },
      { identified_user_id: "missing", count: 5 },
      { x: 3 },
      { traits: "old", identified_user_id: known[1] ?? "none" },
      { identified_user_id: known[0] ?? "none", x: 4 },
    ];
    const enriched = await utils.enrichWithTraits(structuredClone(rows) as any, siteId);
    cases.push({ name: "enrich", inputs: enc({ siteId, rows }), profiles: enc(profiles), rows: enc(enriched) });
  }
}

mkdirSync(OUT, { recursive: true });
const text = JSON.stringify({ node: process.version, generatedWithNow: FIXED_NOW, cases });
writeFileSync(`${OUT}/clickhouse.json.gz`, gzipSync(text, { level: 9 }));
const errors = cases.filter(item => "error" in item).length;
console.log(`clickhouse: ${cases.length} cases (${errors} errors), ${text.length} bytes`);
process.exit(0);
