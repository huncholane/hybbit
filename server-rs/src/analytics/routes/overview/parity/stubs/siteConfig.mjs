// Stands in for server/src/lib/siteConfig.ts: the bounce threshold and the Site
// row come from the case being dumped.
export const DEFAULT_BOUNCE_THRESHOLD_SECONDS = 10;
export const siteConfig = {
  getBounceThreshold: async siteId => globalThis.__overviewParity.bounceThreshold(siteId),
  getConfig: async siteId => globalThis.__overviewParity.config(siteId),
};
