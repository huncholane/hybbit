// Stands in for server/src/db/clickhouse/clickhouse.ts: every query is handed to
// the dump script, which records it and decides the rows (or the failure).
export const clickhouse = {
  query: async args => globalThis.__overviewParity.query(args),
};
export const clickhouseQuery = clickhouse.query;
