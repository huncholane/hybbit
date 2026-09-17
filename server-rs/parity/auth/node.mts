// Node side of the bearer parity check: runs every case in the plan through the real
// checkApiKey and prints the results as JSON. Run through run.sh, from server/.
import { readFileSync } from "node:fs";
import { checkApiKey } from "../../../server/src/lib/auth-utils.js";
import { sql } from "../../../server/src/db/postgres/postgres.js";

const plan = JSON.parse(readFileSync(process.argv[2], "utf8"));
const results = [];
for (const testCase of plan.cases) {
  for (const statement of testCase.setup) await sql.unsafe(statement);
  const headers: Record<string, string> = {};
  if (testCase.token !== null) headers.authorization = `Bearer ${testCase.token}`;
  const query = testCase.queryApiKey !== null ? { api_key: testCase.queryApiKey } : {};
  const request = { headers, query } as any;
  const result = await checkApiKey(request, testCase.target);
  const [{ coalesce: rows }] = await sql.unsafe(plan.state);
  results.push({
    name: testCase.name,
    result: {
      valid: result.valid,
      role: result.role ?? null,
      userId: result.userId ?? null,
      organizationId: result.organizationId ?? null,
      rateLimited: result.rateLimited ?? false,
      statements: result.statements ?? null,
    },
    rows: JSON.parse(rows),
  });
}
for (const statement of plan.cleanup) await sql.unsafe(statement);
console.log(JSON.stringify(results));
process.exit(0);
