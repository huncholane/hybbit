// Node side of the cookie-session parity check: every case through the real
// getSessionFromReq (auth.api.getSession). Run through run.sh, from server/.
import { readFileSync } from "node:fs";
import { getSessionFromReq } from "../../../server/src/lib/auth-utils.js";
import { sql } from "../../../server/src/db/postgres/postgres.js";

const plan = JSON.parse(readFileSync(process.argv[2], "utf8"));
const results = [];
for (const testCase of plan.cases) {
  for (const statement of testCase.setup) await sql.unsafe(statement);
  const headers: Record<string, string> = {};
  if (testCase.cookie !== null) headers.cookie = testCase.cookie;
  let userId: string | null = null;
  let error = false;
  try {
    const session = await getSessionFromReq({ headers } as any);
    userId = session?.user?.id ?? null;
  } catch (e) {
    error = true;
  }
  const [{ coalesce: rows }] = await sql.unsafe(plan.state);
  results.push({ name: testCase.name, userId, error, rows: JSON.parse(rows) });
}
for (const statement of plan.cleanup) await sql.unsafe(statement);
console.log(JSON.stringify(results));
process.exit(0);
