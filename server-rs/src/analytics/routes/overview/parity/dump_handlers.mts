// Differential corpus for the Rust port of the overview route group
// (server-rs/src/analytics/routes/overview). Runs generated requests through the
// real Node handlers with ClickHouse, Site Configuration and site access stubbed
// (see hooks.mjs), and records, per case: every I/O call the handler made (SQL
// text, the formatted query params and settings, the rows the stub answered or
// the failure it raised) and the final status and JSON body.
//
// server-rs/src/analytics/routes/overview/parity.rs replays each case through the
// Rust handler with a backend that checks every call against the recording and
// answers the same rows, then compares the response byte for byte.
//
// Run from a server checkout with node_modules, under TZ=UTC:
//   cd <repo>/server && TZ=UTC npx tsx <worktree>/server-rs/src/analytics/routes/overview/parity/dump_handlers.mts
// PARITY_SERVER overrides the server directory whose handlers are loaded.
import { mkdirSync, writeFileSync } from "node:fs";
import { registerHooks } from "node:module";
import { fileURLToPath } from "node:url";
import { gzipSync } from "node:zlib";

const SERVER = process.env.PARITY_SERVER ?? fileURLToPath(new URL("../../../../../../server", import.meta.url));
const OUT = fileURLToPath(new URL("./fixtures", import.meta.url));
const FIXED_NOW = Date.parse("2026-09-10T12:34:56.789Z");
Date.now = () => FIXED_NOW;

registerHooks(await import(new URL("./hooks.mjs", import.meta.url).href));

const handlers = {
  live: (await import(`${SERVER}/src/api/analytics/getLiveUsercount.ts`)).getLiveUsercount,
  overview: (await import(`${SERVER}/src/api/analytics/getOverview.ts`)).getOverview,
  overviewBucketed: (await import(`${SERVER}/src/api/analytics/getOverviewBucketed.ts`)).getOverviewBucketed,
  overviewLite: (await import(`${SERVER}/src/api/analytics/lite/getOverviewLite.ts`)).getOverviewLite,
  overviewBucketedLite: (await import(`${SERVER}/src/api/analytics/lite/getOverviewBucketedLite.ts`)).getOverviewBucketedLite,
  metricLite: (await import(`${SERVER}/src/api/analytics/lite/getMetricLite.ts`)).getMetricLite,
  metric: (await import(`${SERVER}/src/api/analytics/getMetric.ts`)).getMetric,
  pageTitles: (await import(`${SERVER}/src/api/analytics/getPageTitles.ts`)).getPageTitles,
  retention: (await import(`${SERVER}/src/api/analytics/getRetention.ts`)).getRetention,
  journeys: (await import(`${SERVER}/src/api/analytics/getJourneys.ts`)).getJourneys,
  hasData: (await import(`${SERVER}/src/api/sites/getSiteHasData.ts`)).getSiteHasData,
  isPublic: (await import(`${SERVER}/src/api/sites/getSiteIsPublic.ts`)).getSiteIsPublic,
  siteEventCount: (await import(`${SERVER}/src/api/analytics/events/getSiteEventCount.ts`)).getSiteEventCount,
  orgEventCount: (await import(`${SERVER}/src/api/analytics/getOrgEventCount.ts`)).getOrgEventCount,
} as const;
type HandlerName = keyof typeof handlers;
const chCommon = await import(`${SERVER}/node_modules/@clickhouse/client-common/dist/index.js`);
const requestLogger = (await import(`${SERVER}/src/lib/logger/logger.ts`)).logger.child({ parity: "overview" });

// ---------------------------------------------------------------------------
// Deterministic randomness
// ---------------------------------------------------------------------------
let seed = 0x0f3e7a11;
const rand = () => {
  seed = (seed + 0x6d2b79f5) | 0;
  let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
  t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
  return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
};
const int = (n: number) => Math.floor(rand() * n);
const pick = <T,>(items: readonly T[]): T => items[int(items.length)];
const chance = (p: number) => rand() < p;

// ---------------------------------------------------------------------------
// Recording stubs
// ---------------------------------------------------------------------------
const sqlTexts: string[] = [];
const sqlIds = new Map<string, number>();
const sqlId = (text: string) => {
  let id = sqlIds.get(text);
  if (id === undefined) {
    id = sqlTexts.length;
    sqlTexts.push(text);
    sqlIds.set(text, id);
  }
  return id;
};

type Call = Record<string, unknown>;
let calls: Call[] = [];
let currentKind: HandlerName = "overview";
let failureRate = 0;
let bounce = 10;
let configValue: unknown = undefined;
let sitesValue: unknown[] = [];

// SQL Node renders from an unknown bucket (`undefined(`, a prototype member's
// source, `[object Object]`) never runs; ClickHouse rejects it
const clickhouseWouldReject = (sql: string) =>
  /undefined\(|\[native code\]|\[object Object\]|INTERVAL undefined/.test(sql);

const num = (max: number) => String(int(max));
const float = () => (chance(0.1) ? null : Math.round(rand() * 100000) / 1000);
const TIMES = ["2026-09-08 00:00:00", "2026-09-09 00:00:00", "2026-09-10 00:00:00", "2026-09-10 12:00:00"];
const VALUES = ["Chrome", "/", "/blog/post", "120248430174340693", "007", "", "1.50", "42", "United States", "it's", "日本"];

const makeRows = (sql: string): Record<string, unknown>[] => {
  const count = int(4);
  const many = <T,>(make: (index: number) => T) => Array.from({ length: count }, (_, index) => make(index));
  switch (currentKind) {
    case "live":
      return pick([[{ count: num(50) }], [{ count: num(50) }], [], [{}]]);
    case "hasData":
      return chance(0.5) ? [] : [{ has_data: 1 }];
    case "overview":
    case "overviewLite":
      if (sql.includes("totalCount")) return [{ totalCount: num(90) }];
      if (!sql.includes("AS session_duration") && !sql.includes("pages_per_session")) break;
      if (sql.includes("GROUP BY time") || sql.includes("ORDER BY time")) break;
      return chance(0.05)
        ? []
        : [{ sessions: num(900), pages_per_session: float(), bounce_rate: float(), session_duration: float(), pageviews: num(3000), users: num(700) }];
    default:
      break;
  }
  if (sql.includes("totalCount")) {
    return pick([[{ totalCount: num(300) }], [{ totalCount: num(300) }], [], [{ totalCount: null }]]);
  }
  if (sql.includes("cohort_period")) {
    const periods = ["2026-09-07", "2026-08-31", "2026-08-24"];
    return many(() => ({
      cohort_period: pick(periods),
      period_difference: num(5),
      cohort_size: num(40),
      retained_users: num(40),
      retention_percentage: pick([100, 25.5, 0, 33.33, 12.5]),
    }));
  }
  if (sql.includes("journey_segments")) {
    return many(() => {
      const row: Record<string, unknown> = {
        journey: pick([["/", "/pricing"], ["/a", "/b", "/a"], ["/it's", "/日本"]]),
        sessions_count: num(20),
        percentage: pick([12.5, 100, 33.333333333333336, null, 0.1]),
      };
      if (chance(0.1)) delete row.journey;
      return row;
    });
  }
  if (sql.includes("total_count")) {
    return many(index => {
      const row: Record<string, unknown> = { value: pick(VALUES) };
      if (sql.includes("hostname")) row.hostname = pick(["hygo.ai", "www.hygo.ai"]);
      row.pageviews = num(500);
      row.count = num(200);
      row.percentage = float();
      row.pageviews_percentage = float();
      if (!chance(0.15)) row.total_count = index === 0 && chance(0.1) ? null : num(999);
      return row;
    });
  }
  if (sql.includes("event_count")) {
    return many(index => ({
      [sql.includes("event_date") ? "event_date" : "time"]: TIMES[index],
      pageview_count: num(100),
      custom_event_count: num(10),
      performance_count: "0",
      outbound_count: num(3),
      error_count: "0",
      button_click_count: num(5),
      copy_count: "0",
      form_submit_count: "0",
      input_change_count: "1",
      event_count: num(200),
    }));
  }
  if (sql.includes("GROUP BY time") || sql.includes("USING time") || sql.includes("ORDER BY time")) {
    return many(index => ({
      time: TIMES[index],
      sessions: num(90),
      pages_per_session: float(),
      bounce_rate: float(),
      session_duration: float(),
      pageviews: num(200),
      users: num(80),
    }));
  }
  return many(() => {
    const row: Record<string, unknown> = { value: pick(VALUES), count: num(100), percentage: float() };
    if (chance(0.5)) row.pathname = pick(["/", "/a"]);
    row.pageviews = num(300);
    row.bounce_rate = float();
    if (chance(0.5)) row.time_on_page_seconds = float();
    return row;
  });
};

const formatParams = (params: Record<string, unknown> | undefined) =>
  params === undefined
    ? null
    : Object.entries(params).map(([name, value]) => [name, chCommon.formatQueryParams({ value })]);

(globalThis as any).__overviewParity = {
  query: async ({ query, query_params, clickhouse_settings }: any) => {
    const call: Call = {
      io: "query",
      sql: sqlId(query),
      params: formatParams(query_params),
      settings: clickhouse_settings ?? null,
    };
    calls.push(call);
    if (clickhouseWouldReject(query)) {
      call.rejected = true;
      throw new Error("Unknown function undefined");
    }
    if (chance(failureRate)) {
      call.error = "simulated ClickHouse failure";
      throw new Error("simulated ClickHouse failure");
    }
    const rows = makeRows(query);
    call.rows = rows;
    return { json: async () => structuredClone(rows) };
  },
  bounceThreshold: async (siteId: unknown) => {
    calls.push({ io: "bounce", site: String(siteId), type: typeof siteId, value: bounce });
    return bounce;
  },
  config: async (siteId: unknown) => {
    calls.push({ io: "config", site: String(siteId), type: typeof siteId, value: configValue ?? null });
    return configValue;
  },
  sites: async () => {
    calls.push({ io: "sites", value: sitesValue });
    return sitesValue;
  },
};

// ---------------------------------------------------------------------------
// Request generators (query-string shaped: strings, or arrays for repeats)
// ---------------------------------------------------------------------------
const TIME_ZONES = ["UTC", "America/New_York", "Asia/Kolkata", "Europe/London", "Australia/Lord_Howe", "Pacific/Chatham", "Etc/GMT+12", "America/Los_Angeles"];
const DATES = ["2026-06-01", "2026-08-31", "2026-09-01", "2026-09-09", "2026-09-10", "2026-09-11", "2024-02-29"];
const DATETIMES = [
  "2026-09-01 00:00:00",
  "2026-09-10T12:00:00Z",
  "2026-09-10 11:30:00+05:30",
  "2026-09-09T23:15:07-0700",
  "2026-09-10 12:34:00",
  "2026-08-31T00:00:00",
];
const MINUTES = [["60", "0"], ["1440", "0"], ["30", "15"], ["1e300", "0"], ["0", "0"], ["5.5", "0.5"], ["10080", "60"], ["90", ""]];

const genTime = (query: Record<string, unknown>) => {
  const roll = rand();
  if (roll < 0.15) return;
  if (roll < 0.25) {
    query.start_date = "";
    query.end_date = "";
    if (chance(0.5)) query.time_zone = pick(TIME_ZONES);
    return;
  }
  if (roll < 0.6) {
    const [a, b] = [pick(DATES), pick(DATES)].sort();
    query.start_date = a;
    query.end_date = b;
  } else if (roll < 0.8) {
    query.start_datetime = pick(DATETIMES);
    query.end_datetime = pick(DATETIMES);
  } else {
    const [start, end] = pick(MINUTES);
    query.past_minutes_start = start;
    query.past_minutes_end = end;
  }
  if (chance(0.75)) query.time_zone = pick(TIME_ZONES);
  if (chance(0.05)) query.start_date = pick(DATES);
};

const filter = (parameter: string, type: string, value: unknown[]) => ({ parameter, type, value });
const FILTER_SETS: unknown[][] = [
  [filter("country", "equals", ["US"])],
  [filter("country", "equals", ["US", "DE"])],
  [filter("browser", "contains", ["Chr"])],
  [filter("device_type", "not_equals", ["Mobile"])],
  [filter("hostname", "starts_with", ["www."])],
  [filter("operating_system", "ends_with", ["OS"])],
  [filter("region", "is_null", [])],
  [filter("region", "is_not_null", [])],
  [filter("country", "equals", [])],
  [filter("country", "regex", ["^U"])],
  [filter("country", "not_regex", ["[invalid"])],
  [filter("browser", "equals", [42])],
  [filter("pathname", "equals", ["/"])],
  [filter("pathname", "contains", ["blog"])],
  [filter("referrer", "equals", ["google.com"])],
  [filter("channel", "equals", ["Direct"])],
  [filter("channel", "not_equals", ["Organic Search"])],
  [filter("utm_campaign", "equals", ["launch"])],
  [filter("event_name", "equals", ["signup"])],
  [filter("page_title", "contains", ["Hygo"])],
  [filter("entry_page", "equals", ["/"])],
  [filter("exit_page", "not_equals", ["/pricing"])],
  [filter("user_id", "equals", ["user123"])],
  [filter("feature_flag:beta", "equals", ["on"])],
  [filter("dimensions", "equals", ["1920x1080"])],
  [filter("lat", "greater_than", [40])],
  [filter("querystring", "contains", ["ref"])],
  [filter("city", "equals", ["CA-San Francisco"])],
  [filter("browser_version", "starts_with", ["Chrome 1"])],
  [filter("country", "equals", ["US"]), filter("device_type", "equals", ["Desktop"])],
  [filter("country", "equals", ["US"]), filter("pathname", "equals", ["/"])],
  [filter("utm_campaign", "equals", ["launch"]), filter("event_name", "equals", ["signup"])],
  [filter("hostname", "equals", ["it's"]), filter("browser", "not_contains", ["bot", "spider"])],
];
const RAW_FILTERS: unknown[] = [
  "",
  "[]",
  "not json",
  "{}",
  '[{"parameter":"nope","type":"equals","value":["x"]}]',
  '[{"parameter":"country","type":"eq","value":["x"]}]',
  ['[{"parameter":"country","type":"equals","value":["US"]}]', "[]"],
];
const genFilters = (query: Record<string, unknown>) => {
  const roll = rand();
  if (roll < 0.3) return;
  if (roll < 0.85) {
    query.filters = JSON.stringify(pick(FILTER_SETS));
  } else {
    query.filters = pick(RAW_FILTERS);
  }
};

const BUCKETS: unknown[] = [
  undefined, undefined, undefined, "minute", "five_minutes", "ten_minutes", "fifteen_minutes", "hour", "day", "week",
  "month", "year", "", "fortnight", "constructor", "__proto__", "toString", ["day", "hour"],
];
const BASE_PARAMS = [
  "browser", "operating_system", "language", "country", "region", "city", "device_type", "referrer", "hostname",
  "pathname", "page_title", "querystring", "event_name", "channel", "utm_source", "utm_medium", "utm_campaign",
  "utm_term", "utm_content", "entry_page", "exit_page", "dimensions", "browser_version", "operating_system_version",
  "user_id", "lat", "lon", "timezone", "tag",
];
const PARAMETERS: unknown[] = [
  ...BASE_PARAMS, "pathname", "country", "device_type", "event_name", "page_title", "entry_page", "exit_page",
  "feature_flag:beta", "url_param:gclid", "utm_foo", "nope", undefined, ["country", "browser"], "", "BROWSER",
  "url_param:it's",
];
const LIMITS: unknown[] = [undefined, undefined, "10", "1", "0", "-3", "abc", "2.5", "1e3", "Infinity", "250", "600", ["5", "6"], " 7 ", "0x10", "-Infinity"];
const PAGES: unknown[] = [undefined, undefined, "1", "2", "3", "0", "-1", "abc", "2.5", "Infinity", ["2", "3"], ""];

const set = (query: Record<string, unknown>, key: string, value: unknown) => {
  if (value !== undefined) query[key] = value;
};

const SITES = ["1", "3", "37"];
const ORGS = ["kb0biUnGlr3qcPEnKUTeqjv0TyGK2eHE", "uYq2uOfGurt0dSp3fffpkYYFlUTyVxLh"];

type Case = { handler: HandlerName; params: Record<string, string>; query: Record<string, unknown> };

const genCase = (handler: HandlerName): Case => {
  const query: Record<string, unknown> = {};
  const params: Record<string, string> = { siteId: pick(SITES) };
  switch (handler) {
    case "live":
      set(query, "minutes", pick([undefined, "", "5", "30", "abc", "1.5", "-1", "0", ["5", "10"]]));
      break;
    case "overview":
    case "overviewLite":
      genTime(query);
      genFilters(query);
      break;
    case "overviewBucketed":
    case "overviewBucketedLite":
      genTime(query);
      genFilters(query);
      set(query, "bucket", pick(BUCKETS));
      break;
    case "metric":
    case "metricLite":
      genTime(query);
      genFilters(query);
      set(query, "parameter", pick(PARAMETERS));
      set(query, "limit", pick(LIMITS));
      set(query, "page", pick(PAGES));
      break;
    case "pageTitles":
      genTime(query);
      genFilters(query);
      set(query, "limit", pick(LIMITS));
      set(query, "page", pick(PAGES));
      break;
    case "retention":
      set(query, "mode", pick([undefined, "day", "week", "DAY", "", ["day", "day"]]));
      set(query, "range", pick([undefined, "7", "30", "90", "365", "1000", "3", "0", "abc", "0x20", "-5", "", "12.7", ["30", "60"]]));
      break;
    case "journeys":
      genTime(query);
      genFilters(query);
      set(query, "steps", chance(0.7) ? pick([undefined, "2", "3", "4", "5", "10", "3.9", " 4"]) : pick(["11", "1", "abc", "", ["3", "4"], "-2"]));
      set(query, "limit", chance(0.8) ? pick([undefined, "1", "50", "500", "20.5", "07"]) : pick(["501", "0", "abc", ""]));
      set(query, "stepFilters", pick([
        undefined, undefined, "", '{"0":"/"}', '{"1":"/blog/*"}', '{"0":"/","2":"/pricing/**"}', '{"a":"/"}', "[]",
        "null", '{"0":5}', "not json", '{"01":"/x","1":"/y"}', `{"0":"${"x".repeat(2049)}"}`,
        '{"99999999999999999999":"/a"}', `{"0":"/it's"}`, '{"2":"/b","0":"/a"}', ['{"0":"/"}', "{}"],
        '{"1":"/docs/**/intro.html"}', '{"0":"/a","0":"/b"}',
      ]));
      break;
    case "hasData":
    case "isPublic":
      break;
    case "siteEventCount":
      genTime(query);
      genFilters(query);
      set(query, "bucket", pick(BUCKETS));
      break;
    case "orgEventCount":
      delete params.siteId;
      params.organizationId = pick(ORGS);
      genTime(query);
      break;
  }
  return { handler, params, query };
};

// ---------------------------------------------------------------------------
// Run
// ---------------------------------------------------------------------------
const invoke = async (handler: HandlerName, params: Record<string, string>, query: Record<string, unknown>) => {
  const reply = {
    statusCode: 200,
    body: undefined as unknown,
    sent: false,
    status(code: number) {
      this.statusCode = code;
      return this;
    },
    send(payload: unknown) {
      this.body = payload;
      this.sent = true;
      return this;
    },
  };
  // The real request logger: its argument sanitizer throws on a ZodError, which
  // changes what the handlers' catch blocks answer (run with LOG_LEVEL=info, as
  // in production, and stdout redirected)
  const request = { params, query, log: requestLogger };
  let returned: unknown;
  try {
    returned = await (handlers[handler] as any)(request, reply);
  } catch (error) {
    // Fastify's default error handler for an exception escaping the handler
    return {
      status: 500,
      body: JSON.stringify({ statusCode: 500, error: "Internal Server Error", message: (error as Error).message }),
    };
  }
  const body = reply.sent ? reply.body : returned;
  return { status: reply.statusCode, body: JSON.stringify(body) };
};

const PER_HANDLER: Record<HandlerName, number> = {
  live: 120,
  overview: 350,
  overviewBucketed: 450,
  overviewLite: 350,
  overviewBucketedLite: 450,
  metricLite: 450,
  metric: 700,
  pageTitles: 350,
  retention: 150,
  journeys: 450,
  hasData: 40,
  isPublic: 40,
  siteEventCount: 400,
  orgEventCount: 150,
};

const cases: unknown[] = [];
for (const handler of Object.keys(PER_HANDLER) as HandlerName[]) {
  for (let index = 0; index < PER_HANDLER[handler]; index++) {
    const generated = genCase(handler);
    currentKind = handler;
    calls = [];
    failureRate = chance(0.1) ? 1 : 0;
    bounce = pick([10, 10, 30, 0]);
    configValue = handler === "isPublic" ? pick([undefined, { public: true }, { public: false }, { public: null }]) : undefined;
    sitesValue = pick([
      [],
      [{ siteId: 1, organizationId: ORGS[0] }, { siteId: 2, organizationId: ORGS[0] }, { siteId: 5, organizationId: ORGS[1] }],
      [{ siteId: 5, organizationId: ORGS[1] }],
      [{ siteId: 37, organizationId: ORGS[0] }],
    ]);
    const response = await invoke(handler, generated.params, generated.query);
    cases.push({ ...generated, failureRate, bounce, config: configValue ?? null, sites: sitesValue, calls, response });
  }
}

mkdirSync(OUT, { recursive: true });
const text = JSON.stringify({ node: process.version, now: FIXED_NOW, sql: sqlTexts, cases });
writeFileSync(`${OUT}/handlers.json.gz`, gzipSync(text, { level: 9 }));
const statuses: Record<string, number> = {};
for (const item of cases as any[]) statuses[`${item.handler} ${item.response.status}`] = (statuses[`${item.handler} ${item.response.status}`] ?? 0) + 1;
console.log(`${cases.length} cases, ${sqlTexts.length} distinct SQL texts, ${text.length} bytes`);
console.log(statuses);
