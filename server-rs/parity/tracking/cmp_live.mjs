// Compares http_cases.json (recorded from harness_server.ts) with
// http_cases_live.json (the rejection cases recorded from a real Node backend), to
// show the harness answers exactly like the full application.
// Usage: node cmp_live.mjs <out dir>
import { readFileSync } from "node:fs";
const dir = process.argv[2];
const harness = JSON.parse(readFileSync(`${dir}/http_cases.json`, "utf8"));
const live = JSON.parse(readFileSync(`${dir}/http_cases_live.json`, "utf8"));
let same = 0;
for (const l of live) {
  const h = harness.find(x => x.name === l.name);
  const fields = ["status", "contentType", "connection", "response"];
  const diff = fields.filter(f => h[f] !== l[f]);
  if (diff.length) console.log("DIFF", l.name, diff.map(f => `${f}: harness=${h[f]} live=${l[f]}`).join(" | "));
  else same++;
}
console.log(`${same}/${live.length} identical`);
