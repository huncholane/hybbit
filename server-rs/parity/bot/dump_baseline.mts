// Node's computeSiteBaselines against the parity ClickHouse, with each value in
// the encoded form written to the shared Redis hash. See run.sh.
import { writeFileSync } from "fs";
import { redis } from "../../../server/src/db/redis/redis.ts";
import { computeSiteBaselines } from "../../../server/src/services/tracker/botBlocking/siteBaseline.ts";

const OUT = process.env.BOT_DIFF_DUMPS!;
if (!OUT) throw new Error("set BOT_DIFF_DUMPS");

const baselines = await computeSiteBaselines();
const out: Record<string, { events10m: number; eligible: boolean; encoded: string }> = {};
for (const [siteId, baseline] of baselines) {
  out[String(siteId)] = { ...baseline, encoded: `${baseline.events10m}:${baseline.eligible ? 1 : 0}` };
}
writeFileSync(`${OUT}/baseline.json`, JSON.stringify({ computedAt: Date.now(), baselines: out }));
const values = Object.values(out);
console.log("sites", values.length, "eligible", values.filter(v => v.eligible).length);
await redis.quit();
process.exit(0);
