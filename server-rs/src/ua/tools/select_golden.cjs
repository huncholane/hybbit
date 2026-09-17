// Picks the committed golden subset of a Node dump: the shortest UA showing each
// distinct browser, OS, vendor, engine, CPU and device-type value, truncation and
// non-ASCII cases, plus an even spread of the rest.
//
//   node server-rs/src/ua/tools/select_golden.cjs node-dump.json server-rs/src/ua/testdata/node_golden.json
const fs = require("fs");
const [dumpPath, outPath] = process.argv.slice(2);
const dump = JSON.parse(fs.readFileSync(dumpPath, "utf8"));
// the repository style bans the em dash, and a few test-file literals carry one
dump.cases = dump.cases.filter((c) => !c.input.includes("\u2014"));

const keyOf = {
  browserName: (c) => c.browser.name,
  browserType: (c) => c.browser.type,
  browserMajorEmpty: (c) => (c.browser.major === "" ? "empty" : null),
  osName: (c) => c.os.name,
  deviceType: (c) => c.device.type,
  deviceVendor: (c) => c.device.vendor,
  engineName: (c) => c.engine.name,
  cpu: (c) => c.cpu.architecture,
  deviceTypes: (c) => c.deviceTypes.join(","),
  truncated: (c) => (c.ua !== c.input ? "cut" + (c.input.length % 12) + (c.input.isWellFormed() && c.ua.length < 500 ? "s" : "") : null),
  nonAscii: (c) => (/[^\x00-\x7f]/.test(c.input) ? [...c.input].filter((ch) => ch.charCodeAt(0) > 127).map((ch) => "U+" + ch.codePointAt(0).toString(16)).slice(0, 1)[0] : null),
};

const chosen = new Map();
for (const [dimension, key] of Object.entries(keyOf)) {
  const best = new Map();
  for (const c of dump.cases) {
    const k = key(c);
    if (k === null || k === undefined) continue;
    const prev = best.get(k);
    if (!prev || c.input.length < prev.input.length) best.set(k, c);
  }
  for (const c of best.values()) chosen.set(c.input, c);
  console.error(dimension, best.size);
}
// plus a deterministic spread of ordinary cases
for (let i = 0; i < dump.cases.length; i += 587) chosen.set(dump.cases[i].input, dump.cases[i]);

const rows = [...chosen.values()].map((c) => [
  c.input,
  c.ua === c.input ? null : c.ua,
  c.browser.name, c.browser.version, c.browser.major, c.browser.type,
  c.cpu.architecture,
  c.device.type, c.device.model, c.device.vendor,
  c.engine.name, c.engine.version,
  c.os.name, c.os.version,
  c.deviceTypes.join(","),
]);
const text = `{"screens":${JSON.stringify(dump.screens)},"rows":[\n` + rows.map((r) => JSON.stringify(r)).join(",\n") + "\n]}\n";
fs.writeFileSync(outPath, text);
console.error("cases", rows.length, "bytes", text.length);
