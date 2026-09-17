// Preload for a second Node backend used only by the generate-route parity run:
// listens on NODE_ALT_PORT instead of the hard-coded 3001 and sends OpenRouter
// calls to OPENROUTER_MOCK_URL. Node's own code is untouched.
import net from "node:net";

const altPort = Number(process.env.NODE_ALT_PORT);
const originalListen = net.Server.prototype.listen;
net.Server.prototype.listen = function (...args) {
  if (args[0] && typeof args[0] === "object" && args[0].port === 3001) {
    args[0] = { ...args[0], port: altPort };
  } else if (args[0] === 3001) {
    args[0] = altPort;
  }
  return originalListen.apply(this, args);
};

const originalFetch = globalThis.fetch;
globalThis.fetch = (input, init) => {
  const url = typeof input === "string" ? input : input?.url;
  if (url && url.startsWith("https://openrouter.ai/")) {
    return originalFetch(process.env.OPENROUTER_MOCK_URL, init);
  }
  return originalFetch(input, init);
};
