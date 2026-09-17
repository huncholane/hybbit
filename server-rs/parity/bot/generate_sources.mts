// Regenerates the parts of server-rs/src/bot that are copied from the Node code
// rather than ported by hand, so no pattern or script byte is retyped:
//
// - the pattern tables at the bottom of src/bot/ua_bots/patterns.rs, from
//   server/src/services/tracker/botBlocking/uaBots/patterns.ts;
// - src/bot/anomaly_observe.lua, the `anomalyObserve` script body from
//   server/src/db/redis/redis.ts (update ANOMALY_OBSERVE_SHA1 when it changes).
//
//   cd server && npx tsx ../server-rs/parity/bot/generate_sources.mts <out dir>
import { createHash } from "crypto";
import { readFileSync, writeFileSync } from "fs";
import { BOT_PATTERNS, EXTRA_BOT_PATTERNS, type BotPattern } from "../../../server/src/services/tracker/botBlocking/uaBots/patterns.ts";

const OUT = process.argv[2];
if (!OUT) throw new Error("usage: generate_sources.mts <out dir>");

function rustStr(value: string): string {
  if (value.includes('"')) throw new Error(`cannot quote ${value}`);
  return value.includes("\\") ? `r"${value}"` : `"${value}"`;
}

const categoryVariant: Record<string, string> = {
  search: "Search",
  ai: "Ai",
  social: "Social",
  monitoring: "Monitoring",
  seo: "Seo",
  security: "Security",
  framework: "Framework",
  headless: "Headless",
  generic: "Generic",
};
const purposeVariant: Record<string, string> = {
  ai_training: "AiTraining",
  ai_search: "AiSearch",
  ai_agent: "AiAgent",
  search: "Search",
  social_preview: "SocialPreview",
  seo: "Seo",
  monitoring: "Monitoring",
  security: "Security",
  scripted: "Scripted",
  headless: "Headless",
  unknown: "Unknown",
};

function entry(p: BotPattern): string {
  const category = `BotCategory::${categoryVariant[p.category]}`;
  if (p.name === undefined && p.operator === undefined && p.purpose === undefined) {
    return `    upstream(${rustStr(p.pattern)}, ${category}),`;
  }
  const optional = (value: string | undefined) => (value === undefined ? "None" : `Some(${rustStr(value)})`);
  const purpose = p.purpose === undefined ? "None" : `Some(BotPurpose::${purposeVariant[p.purpose]})`;
  return `    named(${rustStr(p.pattern)}, ${category}, ${optional(p.name)}, ${optional(p.operator)}, ${purpose}),`;
}

let tables = "";
tables += `pub static EXTRA_BOT_PATTERNS: [BotPattern; ${EXTRA_BOT_PATTERNS.length}] = [\n`;
tables += EXTRA_BOT_PATTERNS.map(entry).join("\n") + "\n];\n\n";
tables += `pub static BOT_PATTERNS: [BotPattern; ${BOT_PATTERNS.length}] = [\n`;
tables += BOT_PATTERNS.map(entry).join("\n") + "\n];\n";
writeFileSync(`${OUT}/patterns.rs.txt`, tables);

const redisTs = readFileSync(new URL("../../../server/src/db/redis/redis.ts", import.meta.url), "utf8");
const start = redisTs.indexOf('redis.defineCommand("anomalyObserve", {');
const luaStart = redisTs.indexOf("lua: `", start) + "lua: `".length;
const lua = redisTs.slice(luaStart, redisTs.indexOf("`,", luaStart));
writeFileSync(`${OUT}/anomaly_observe.lua`, lua);

console.log("patterns", EXTRA_BOT_PATTERNS.length, BOT_PATTERNS.length);
console.log("anomalyObserve sha1", createHash("sha1").update(lua).digest("hex"), "bytes", lua.length);
