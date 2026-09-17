// Module resolve hook: route expandSegmentParam's import of segmentAccess.js to the stub.
const stub = new URL("./segment_access_stub.mjs", import.meta.url).href;

export async function resolve(specifier, context, nextResolve) {
  if (
    (specifier.endsWith("/segmentAccess.js") || specifier.endsWith("/segmentAccess.ts")) &&
    context.parentURL &&
    context.parentURL.includes("expandSegmentParam")
  ) {
    return { url: stub, shortCircuit: true, format: "module" };
  }
  if (process.env.HOOK_DEBUG && specifier.includes("segmentAccess")) {
    console.error("hook saw", specifier, context.parentURL);
  }
  return nextResolve(specifier, context);
}
