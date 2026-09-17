// Differential corpus for the reports routes (funnels, goals, performance, bots).
// Generates deterministic inputs, runs them through the real Node query builders
// and goal schema, and writes fixtures.json.gz next to this file, which
// src/analytics/routes/reports/parity_tests.rs replays against the Rust port.
//
// Run with production's Node major (24) and TZ=UTC from a checkout whose server/
// has node_modules installed:
//   cd server && TZ=UTC PARITY_SERVER=$PWD npx tsx ../server-rs/src/analytics/routes/reports/parity/dump.mts
// Past-minutes windows read the clock, so the corpus leaves them out; the HTTP
// harness covers them.
import { writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { gzipSync } from "node:zlib";

const SERVER = process.env.PARITY_SERVER ?? fileURLToPath(new URL("../../../../../../server", import.meta.url));
const OUT = process.env.PARITY_OUT ?? fileURLToPath(new URL("./fixtures.json.gz", import.meta.url));

const getFunnel = await import(`${SERVER}/src/api/analytics/funnels/getFunnel.ts`);
const getFunnelStepSessions = await import(`${SERVER}/src/api/analytics/funnels/getFunnelStepSessions.ts`);
const getGoals = await import(`${SERVER}/src/api/analytics/goals/getGoals.ts`);
const getGoalTimeSeries = await import(`${SERVER}/src/api/analytics/goals/getGoalTimeSeries.ts`);
const getGoalSessions = await import(`${SERVER}/src/api/analytics/goals/getGoalSessions.ts`);
const goalConditions = await import(`${SERVER}/src/api/analytics/goals/goalConditions.ts`);
const goalSchema = await import(`${SERVER}/src/api/analytics/goals/goalSchema.ts`);
const perfOverview = await import(`${SERVER}/src/api/analytics/performance/getPerformanceOverview.ts`);
const perfTimeSeries = await import(`${SERVER}/src/api/analytics/performance/getPerformanceTimeSeries.ts`);
const perfByDimension = await import(`${SERVER}/src/api/analytics/performance/getPerformanceByDimension.ts`);
const botOverview = await import(`${SERVER}/src/api/analytics/bots/getBotOverview.ts`);
const botTimeSeries = await import(`${SERVER}/src/api/analytics/bots/getBotTimeSeries.ts`);
const botDimension = await import(`${SERVER}/src/api/analytics/bots/getBotDimension.ts`);
const botAiSummary = await import(`${SERVER}/src/api/analytics/bots/getBotAiSummary.ts`);

let seed = 0x7e9057a1;
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

const run = (fn: () => unknown) => {
  try {
    const value = fn();
    return { ok: value === undefined ? { $js: "undefined" } : value };
  } catch (error) {
    return { error: error instanceof Error ? error.message : String(error) };
  }
};

// ---------------------------------------------------------------------------
// Query strings
// ---------------------------------------------------------------------------
const FILTERS = [
  "",
  "[]",
  "not json",
  '[{"parameter":"browser","type":"equals","value":["Chrome"]}]',
  '[{"parameter":"utm_campaign","type":"equals","value":["launch"]}]',
  '[{"parameter":"pathname","type":"contains","value":["/blog"]}]',
  '[{"parameter":"event_name","type":"equals","value":["signup"]}]',
  '[{"parameter":"channel","type":"not_equals","value":["Direct","Organic Search"]}]',
  '[{"parameter":"country","type":"equals","value":["US"]},{"parameter":"device_type","type":"equals","value":["Mobile"]}]',
  '[{"parameter":"entry_page","type":"equals","value":["/"]}]',
  '[{"parameter":"user_id","type":"is_not_null","value":[]}]',
  '[{"parameter":"lat","type":"greater_than","value":["40.5"]}]',
  '[{"parameter":"lat","type":"greater_than","value":["north"]}]',
  '[{"parameter":"referrer","type":"regex","value":["^https://(www\\\\.)?google\\\\.com"]}]',
  '[{"parameter":"pathname","type":"regex","value":["(unclosed"]}]',
  '[{"parameter":"feature_flag:beta","type":"equals","value":["true"]}]',
  '[{"parameter":"hostname","type":"equals","value":["a.com"]},{"parameter":"utm_source","type":"equals","value":["x"]},{"parameter":"exit_page","type":"starts_with","value":["/buy"]}]',
  '[{"parameter":"city","type":"equals","value":["CA-San Francisco"]},{"parameter":"querystring","type":"is_null","value":[]}]',
  '[{"parameter":"asn_org","type":"equals","value":["x"]}]',
  '[{"parameter":"browser_version","type":"equals","value":["Chrome 140"]},{"parameter":"operating_system_version","type":"equals","value":["Windows 10/11"]}]',
  '[{"parameter":"lon","type":"not_equals","value":["-74.006"]},{"parameter":"dimensions","type":"equals","value":["1920x1080"]}]',
  '[{"parameter":"tag","type":"equals","value":["v1"]},{"parameter":"timezone","type":"equals","value":["UTC"]}]',
  '{"parameter":"browser"}',
];
const DATES = ["2024-01-01", "2024-01-31", "2026-09-17", "2024-02-30", "2024-13-01", "01/02/2024", ""];
const DATETIMES = ["2024-01-01 00:00:00", "2024-01-01T12:30:00Z", "2024-01-02 00:00:00+02:00", "2024-01-01 12:00", "2024-01-03T00:00:00-0530"];
const ZONES = ["UTC", "America/New_York", "Asia/Kolkata", "Not/AZone", "", "utc", "Europe/London"];
const BUCKETS = ["minute", "five_minutes", "ten_minutes", "fifteen_minutes", "hour", "day", "week", "month", "year", "", "hourly", "toString", "constructor", "__proto__", "valueOf"];

const genQuery = (extra: () => Record<string, unknown> = () => ({})) => {
  const query: Record<string, unknown> = {};
  if (chance(0.7)) query.filters = chance(0.95) ? pick(FILTERS) : [pick(FILTERS), pick(FILTERS)];
  const roll = rand();
  if (roll < 0.45) {
    query.start_date = pick(DATES);
    query.end_date = pick(DATES);
  } else if (roll < 0.65) {
    query.start_datetime = pick(DATETIMES);
    query.end_datetime = pick(DATETIMES);
  }
  if (chance(0.8)) query.time_zone = chance(0.97) ? pick(ZONES) : ["UTC", "UTC"];
  return { ...query, ...extra() };
};

// ---------------------------------------------------------------------------
// Funnel steps and goals
// ---------------------------------------------------------------------------
const STEP_TYPES = ["page", "event", "outbound", "button_click", "form_submit", "copy", "path", "", "Page", 5, null];
const STRINGS = ["/pricing", "/blog/*", "/docs/**", "**", "/a.b+c?", "signup", "domain_search", "Buy now", "https://partner.com/*", "  coupon-*  ", "", "   ", "it's", 'q"uote', "back\\slash", "{{DOUBLE_STAR}}", "日本語", "😀", "nul\0x", "a$b^c|d", "/x/{1}"];
const WEIRD = [null, 5, 0, true, false, ["a", "b"], [], { a: 1 }, 1.5, -0];
const genString = () => pick(STRINGS);
const genLoose = () => (chance(0.75) ? genString() : pick(WEIRD));

const genFilters = (): unknown => {
  const roll = rand();
  if (roll < 0.7)
    return repeat(int(3), () => {
      if (chance(0.05)) return pick([null, "ab", 5, []]);
      const filter: Record<string, unknown> = {};
      if (chance(0.95)) filter.key = chance(0.9) ? pick(["utm_source", "plan", "amount", "k'ey", ""]) : pick(WEIRD);
      if (chance(0.95)) filter.value = pick(["google", "pro", 10, 99.5, true, false, "", null, [1, { x: 2 }], 1e21, { a: 1 }]);
      return filter;
    });
  if (roll < 0.85) return pick(["", 0, null, false]);
  return pick(["ab", 5, { a: 1 }, true]);
};

const genStepLike = (config: boolean) => {
  if (chance(0.03)) return pick([null, 5, "step", []]);
  const step: Record<string, unknown> = {};
  if (!config && chance(0.97)) step.type = pick(STEP_TYPES);
  if (chance(0.92)) step[config ? pick(["pathPattern", "eventName", "valuePattern"]) : "value"] = genLoose();
  if (config && chance(0.3)) step[pick(["pathPattern", "eventName", "valuePattern"])] = genLoose();
  if (!config && chance(0.4)) step.name = genLoose();
  if (!config && chance(0.3)) step.hostname = chance(0.7) ? pick(["app.example.com", "", "a'b"]) : pick(WEIRD);
  if (chance(0.35)) step.propertyFilters = genFilters();
  if (chance(0.2)) {
    step.eventPropertyKey = chance(0.8) ? pick(["plan", "", "k"]) : pick(WEIRD);
    if (chance(0.8)) step.eventPropertyValue = pick(["pro", 7, true, false, "", null]);
  }
  return step;
};

const genSteps = (): unknown => {
  if (chance(0.05)) return pick(["abcd", { length: 3 }, 5, null]);
  return repeat(1 + int(5), () => genStepLike(false));
};

const GOAL_TYPES = ["path", "event", "outbound", "button_click", "form_submit", "copy", "pageview", "", "Path"];
let nextGoalId = 1;
const genGoals = () =>
  repeat(1 + int(4), () => ({
    goalId: nextGoalId++,
    siteId: 4,
    name: chance(0.8) ? "goal" : null,
    goalType: pick(GOAL_TYPES),
    config: chance(0.03) ? null : genStepLike(true),
    createdAt: "2026-09-17 09:21:12.456999",
  }));

// ---------------------------------------------------------------------------
// Cases
// ---------------------------------------------------------------------------
const cases: unknown[] = [];
const add = (fn: string, args: unknown[], result: unknown) => cases.push({ fn, args, result });

for (let i = 0; i < 700; i++) {
  const query = genQuery();
  const steps = genSteps();
  const site = pick([1, 4, 37]);
  add("buildFunnelQuery", [query, site, steps], run(() => getFunnel.buildFunnelQuery(query, site, steps)));
}

for (let i = 0; i < 700; i++) {
  const query = genQuery(() => ({ mode: pick(["reached", "dropped"]) }));
  const steps = genSteps();
  const length = Array.isArray(steps) ? steps.length : 2;
  const step = 1 + int(Math.max(1, length - (query.mode === "dropped" ? 1 : 0)));
  add(
    "buildFunnelStepSessionsQuery",
    [query, 4, steps, step],
    run(() => getFunnelStepSessions.buildFunnelStepSessionsQuery(query, 4, steps, step))
  );
}

for (let i = 0; i < 500; i++) {
  const query = genQuery();
  const goals = genGoals();
  add("buildGoalsTotalSessionsQuery", [query, 4], run(() => getGoals.buildGoalsTotalSessionsQuery(query, 4)));
  add("buildGoalsConversionsQuery", [query, 4, goals], run(() => getGoals.buildGoalsConversionsQuery(query, 4, goals)));
  const bucketed = { ...query, ...(chance(0.9) ? { bucket: pick(BUCKETS) } : {}) };
  add("buildGoalTimeSeriesQuery", [bucketed, 4, goals], run(() => getGoalTimeSeries.buildGoalTimeSeriesQuery(bucketed, 4, goals)));
  for (const goal of goals) {
    add("buildGoalCondition", [goal], run(() => goalConditions.buildGoalCondition(goal)));
  }
  const condition = pick(["type = 'pageview'", "type = 'custom_event' AND event_name = 'x'"]);
  add("buildGoalSessionsQuery", [query, 37, condition], run(() => getGoalSessions.buildGoalSessionsQuery(query, 37, condition)));
}

const DIMENSIONS = ["pathname", "country", "device_type", "browser", "operating_system", "region", "city", "", "referrer"];
const SORTS = ["event_count", "lcp_p75", "cls_avg", "ttfb_p99", "pathname", "country", "nope", ""];
for (let i = 0; i < 500; i++) {
  const query = genQuery(() => ({
    ...(chance(0.8) ? { bucket: pick(BUCKETS) } : {}),
    ...(chance(0.9) ? { dimension: chance(0.95) ? pick(DIMENSIONS) : ["pathname", "country"] } : {}),
    ...(chance(0.5) ? { sort_by: pick(SORTS) } : {}),
    ...(chance(0.5) ? { sort_order: pick(["asc", "desc", "ASC", ""]) } : {}),
    ...(chance(0.5) ? { limit: pick(["10", "0", "-1", "abc", "25", ""]) } : {}),
    ...(chance(0.5) ? { page: pick(["1", "2", "0", "x", "3"]) } : {}),
  }));
  const site = pick([1, 39]);
  add("buildPerformanceOverviewQuery", [query, site], run(() => perfOverview.buildPerformanceOverviewQuery(query, site)));
  add("buildPerformanceTimeSeriesQuery", [query, site], run(() => perfTimeSeries.buildPerformanceTimeSeriesQuery(query, site)));
  const count = chance(0.5);
  add(
    "buildPerformanceByDimensionQuery",
    [query, site, count],
    run(() => perfByDimension.buildPerformanceByDimensionQuery(query, site, count))
  );
}

const BOT_DIMENSIONS = ["browser", "browser_version", "operating_system", "operating_system_version", "country", "region", "city", "device_type", "referrer", "hostname", "pathname", "dimensions", "asn_org", "asn_provider", "bot_category", "bot_name", "bot_operator", "bot_purpose", "matched_ua_pattern", "event_name", "", "channel"];
const LAYERS = ["ua_pattern", "header_heuristics", "client_signals", "bot_asn", "rate_anomaly", "", "nope", "toString", "__proto__", "hasOwnProperty"];
const PURPOSES = ["ai", "ai_crawler", "ai_agent", "seo", "search", "social_preview", "monitoring", "security", "scripted", "headless", "ai_training", "ai_search", "", "nonsense", "toString"];
for (let i = 0; i < 700; i++) {
  const query = genQuery(() => ({
    ...(chance(0.7) ? { bucket: pick(BUCKETS) } : {}),
    ...(chance(0.9) ? { dimension: pick(BOT_DIMENSIONS) } : {}),
    ...(chance(0.5) ? { layer: chance(0.95) ? pick(LAYERS) : ["ua_pattern", "bot_asn"] } : {}),
    ...(chance(0.5) ? { purpose: chance(0.95) ? pick(PURPOSES) : ["ai", "seo"] } : {}),
    ...(chance(0.5) ? { limit: pick(["10", "0", "abc", "25"]) } : {}),
    ...(chance(0.5) ? { page: pick(["1", "2", "0", "x"]) } : {}),
  }));
  add("buildBotOverviewQuery", [query], run(() => botOverview.buildBotOverviewQuery(query)));
  add("buildBotTimeSeriesQuery", [query], run(() => botTimeSeries.buildBotTimeSeriesQuery(query)));
  const count = chance(0.5);
  add("buildBotDimensionQuery", [query, count], run(() => botDimension.buildBotDimensionQuery(query, count)));
  add("buildBotAiSummaryQuery", [query], run(() => botAiSummary.buildBotAiSummaryQuery(query)));
}

// goalBodySchema
const genGoalBody = (): unknown => {
  if (chance(0.04)) return pick([null, "text", 5, [], true]);
  const body: Record<string, unknown> = {};
  if (chance(0.5)) body.name = chance(0.85) ? pick(["Signup", "", "x".repeat(600)]) : pick(WEIRD);
  if (chance(0.93)) body.goalType = chance(0.85) ? pick(GOAL_TYPES.slice(0, 6)) : pick(["pageview", "", 5, null, ["path"]]);
  if (chance(0.93)) {
    if (chance(0.05)) body.config = pick([null, "x", [], 5]);
    else {
      const config: Record<string, unknown> = {};
      for (const key of ["pathPattern", "eventName", "valuePattern", "eventPropertyKey"]) {
        if (chance(0.35)) config[key] = chance(0.85) ? pick(["/buy/**", "signup", "", "  ", "k", "v".repeat(513), "é".repeat(512)]) : pick(WEIRD);
      }
      if (chance(0.3)) config.eventPropertyValue = pick(["pro", 7, true, false, "", null, [], { a: 1 }]);
      if (chance(0.35)) {
        config.propertyFilters = chance(0.85)
          ? repeat(int(3), () =>
              chance(0.9)
                ? Object.fromEntries(
                    [
                      ["key", chance(0.9) ? pick(["plan", "", "a"]) : pick(WEIRD)],
                      ["value", pick(["pro", 1, true, null, [], { x: 1 }, 1e21])],
                      ...(chance(0.1) ? [["extra", 1]] : []),
                    ].filter(() => chance(0.95))
                  )
                : pick([null, "x", 5])
            )
          : pick(["x", {}, null, 5]);
      }
      if (chance(0.1)) config.unknownKey = "x";
      body.config = config;
    }
  }
  if (chance(0.1)) body.extra = 1;
  return body;
};
for (let i = 0; i < 2500; i++) {
  const body = genGoalBody();
  const parsed = goalSchema.goalBodySchema.safeParse(body);
  add("goalBodySchema", [body], parsed.success ? { ok: parsed.data } : { issues: parsed.error.errors });
}

const text = JSON.stringify({ node: process.version, cases });
writeFileSync(OUT, gzipSync(text, { level: 9 }));
const counts: Record<string, number> = {};
for (const item of cases as { fn: string }[]) counts[item.fn] = (counts[item.fn] ?? 0) + 1;
console.log(JSON.stringify({ node: process.version, bytes: text.length, counts }, null, 1));
process.exit(0);
