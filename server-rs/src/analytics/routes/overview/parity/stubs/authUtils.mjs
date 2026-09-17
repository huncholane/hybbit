// Stands in for server/src/lib/auth-utils.ts: the Sites the request may read come
// from the case being dumped.
export async function getSitesUserHasAccessTo() {
  return globalThis.__overviewParity.sites();
}
