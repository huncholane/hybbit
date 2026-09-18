// Node's startup database init, run on its own: the two calls
// `server/src/index.ts` makes as `Promise.all([initializeClickhouse(), initPostgres()])`.
// The drizzle migrations are not here because Node does not run them from the
// application either; `server/docker-entrypoint.sh` runs `drizzle-kit migrate` first,
// and run.sh does the same before calling this.
//
//   source server-rs/parity/env.sh && POSTGRES_DB=… CLICKHOUSE_DB=… \
//     cd server && npx tsx ../server-rs/parity/db-init/node_init.mts
import { fileURLToPath } from "node:url";

const SERVER = process.env.PARITY_SERVER ?? fileURLToPath(new URL("../../../server", import.meta.url));

const { initializeClickhouse } = await import(`${SERVER}/src/db/clickhouse/clickhouse.ts`);
const { initPostgres } = await import(`${SERVER}/src/db/postgres/initPostgres.ts`);

await Promise.all([initializeClickhouse(), initPostgres()]);

// The ClickHouse client keeps its HTTP agent alive, so ask for the exit explicitly
process.exit(0);
