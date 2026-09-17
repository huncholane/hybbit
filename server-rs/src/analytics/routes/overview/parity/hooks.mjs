// Module resolve hook for dump_handlers.mts: the handlers' database and auth
// dependencies are replaced by stubs that read and record through
// globalThis.__overviewParity, so the real handler code runs without stores.
// Installed with module.registerHooks (in-thread, ahead of tsx's own hooks).
const stub = name => new URL(`./stubs/${name}.mjs`, import.meta.url).href;

const REPLACEMENTS = [
  ["/db/clickhouse/clickhouse.js", "clickhouse"],
  ["/db/postgres/postgres.js", "postgres"],
  ["/lib/siteConfig.js", "siteConfig"],
  ["/lib/auth-utils.js", "authUtils"],
];

export function resolve(specifier, context, nextResolve) {
  for (const [suffix, name] of REPLACEMENTS) {
    if (specifier.endsWith(suffix)) {
      return { url: stub(name), shortCircuit: true, format: "module" };
    }
  }
  return nextResolve(specifier, context);
}
