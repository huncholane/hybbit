#!/usr/bin/env node
// Regenerates regexes.rs from the ua-parser-js build the Node server runs, so the
// Rust tables are the JS tables and never a hand transcription of them.
//
//   node server-rs/src/ua/tools/generate.cjs server/node_modules/ua-parser-js/src/main/ua-parser.js \
//     > server-rs/src/ua/regexes.rs
//
// ua-parser-js keeps its tables private, so the source is evaluated with one extra
// statement that exposes them. Every regex source is copied verbatim; mod.rs
// translates the JS syntax when it compiles them.
"use strict";

const fs = require("fs");
const vm = require("vm");

const sourcePath = process.argv[2];
if (!sourcePath) {
  console.error("usage: generate.cjs <path to ua-parser.js>");
  process.exit(2);
}

const src = fs.readFileSync(sourcePath, "utf8");
const anchor = "UAParser.VERSION = LIBVERSION;";
if (!src.includes(anchor)) throw new Error("patch anchor not found; ua-parser-js layout changed");
const patched = src.replace(
  anchor,
  anchor + " UAParser.__internals = { LIBVERSION, defaultRegexes, windowsVersionMap, lowerize, trim, strMapper };"
);
const sandbox = { module: { exports: {} } };
sandbox.exports = sandbox.module.exports;
vm.runInNewContext(patched, sandbox);
const { LIBVERSION, defaultRegexes, windowsVersionMap, lowerize, trim, strMapper } = sandbox.module.exports.__internals;

const FIELDS = { name: "Name", version: "Version", type: "Type", model: "Model", vendor: "Vendor", architecture: "Architecture" };
const field = (f) => {
  if (!FIELDS[f]) throw new Error(`unknown field ${f}`);
  return FIELDS[f];
};
const rustStr = (s) => {
  if (typeof s !== "string") throw new Error(`expected string, got ${String(s)}`);
  return JSON.stringify(s); // the constants are plain ASCII, where JSON and Rust escapes agree
};
const rawStr = (s) => {
  let hashes = "#";
  while (s.includes('"' + hashes)) hashes += "#";
  return `r${hashes}"${s}"${hashes}`;
};

// String maps, emitted once each, entries in JS for-in order (integer-like keys
// first, ascending, then insertion order), which is the order strMapper tries them.
const maps = new Map();
const mapName = (map) => {
  if (maps.has(map)) return maps.get(map).name;
  const name = map === windowsVersionMap ? "WINDOWS_VERSION_MAP" : `STR_MAP_${maps.size}`;
  const entries = [];
  for (const key in map) {
    const value = map[key];
    const needles = Array.isArray(value) ? value : typeof value === "string" ? [value] : [];
    entries.push(`(${rustStr(key)}, &[${needles.map(rustStr).join(", ")}])`);
  }
  const fallback = Object.prototype.hasOwnProperty.call(map, "*")
    ? `Some(${map["*"] === undefined ? "None" : `Some(${rustStr(map["*"])})`})`
    : "None";
  maps.set(map, {
    name,
    code: `pub(super) static ${name}: StrMap = StrMap {\n    entries: &[${entries.join(", ")}],\n    fallback: ${fallback},\n};\n`,
  });
  return name;
};

const rep = (regex, replacement) => {
  const key = `${regex.source}\u0000${regex.flags}`;
  if (typeof replacement !== "string") throw new Error(`replacement for /${regex.source}/ is not a string`);
  switch (key) {
    case "(.+)\u0000":
    case "(.+)\u0000g": {
      const at = replacement.indexOf("$1");
      if (at < 0 || replacement.indexOf("$", at + 2) >= 0 || replacement.slice(0, at).includes("$")) {
        throw new Error(`unsupported replacement ${replacement}`);
      }
      const prefix = replacement.slice(0, at);
      const suffix = replacement.slice(at + 2);
      return `Rep::WrapLines { prefix: ${rustStr(prefix)}, suffix: ${rustStr(suffix)}, global: ${regex.global} }`;
    }
    case "_\u0000g":
      return `Rep::ReplaceAll { from: '_', to: ${rustStr(replacement)} }`;
    case "\\.\u0000g":
      return `Rep::ReplaceAll { from: '.', to: ${rustStr(replacement)} }`;
    case "^\u0000":
      if (replacement.includes("$")) throw new Error(`unsupported replacement ${replacement}`);
      return `Rep::Prepend(${rustStr(replacement)})`;
    case "[^\\d\\.]+.\u0000":
      if (replacement !== "") throw new Error(`unsupported replacement ${replacement}`);
      return "Rep::StripFirstNonVersionRun";
    case "ower\u0000":
      if (replacement !== "") throw new Error(`unsupported replacement ${replacement}`);
      return `Rep::RemoveFirst(${rustStr(regex.source)})`;
    default:
      throw new Error(`no Rust equivalent for replace(/${regex.source}/${regex.flags}, ${JSON.stringify(replacement)})`);
  }
};

const prop = (q) => {
  if (typeof q === "string") return `Capture(${field(q)})`;
  if (!Array.isArray(q)) throw new Error(`unexpected prop ${String(q)}`);
  if (q.length === 2) {
    if (q[1] === lowerize) return `Lower(${field(q[0])})`;
    if (q[1] === trim) return `Trim(${field(q[0])})`;
    if (typeof q[1] === "function") throw new Error(`unknown function prop ${q[1].name}`);
    return `Const(${field(q[0])}, ${rustStr(q[1])})`;
  }
  if (q.length === 3) {
    if (q[1] === strMapper) return `Map(${field(q[0])}, &${mapName(q[2])})`;
    if (q[1] instanceof sandboxRegExp()) return `Replace(${field(q[0])}, ${rep(q[1], q[2])})`;
    throw new Error(`unsupported 3-tuple prop ${String(q[1])}`);
  }
  if (q.length === 4) {
    if (q[3] !== lowerize) throw new Error("4-tuple prop with a function other than lowerize");
    return `ReplaceLower(${field(q[0])}, ${rep(q[1], q[2])})`;
  }
  throw new Error(`unsupported prop arity ${q.length}`);
};

// RegExp objects come from the sandbox realm, so instanceof needs its constructor.
let sandboxRegExpCtor;
const sandboxRegExp = () => sandboxRegExpCtor;

const tables = [];
let total = 0;
for (const item of ["browser", "cpu", "device", "engine", "os"]) {
  const arr = defaultRegexes[item];
  let out = `pub(super) static ${item.toUpperCase()}: &[RuleSrc] = &[\n`;
  for (let i = 0; i < arr.length; i += 2) {
    const regexes = arr[i];
    const props = arr[i + 1];
    sandboxRegExpCtor = regexes[0].constructor;
    out += "    RuleSrc {\n        patterns: &[\n";
    for (const re of regexes) {
      if (re.flags !== "i") throw new Error(`/${re.source}/${re.flags}: every table regex is expected to be case-insensitive only`);
      out += `            ${rawStr(re.source)},\n`;
      total++;
    }
    out += `        ],\n        props: &[${props.map(prop).join(", ")}],\n    },\n`;
  }
  out += "];\n";
  tables.push(out);
}

process.stdout.write(
  `//! Regex tables of ua-parser-js ${LIBVERSION} (\`defaultRegexes\`), ${total} patterns.
//!
//! GENERATED by tools/generate.cjs from the ua-parser.js the Node server runs; do not
//! edit by hand. Patterns are the JS sources verbatim (all compiled with the \`i\`
//! flag); mod.rs translates them. Rules are in the order rgxMapper tries them.
#![cfg_attr(rustfmt, rustfmt_skip)]

use super::table::{Field::*, Prop::*, Rep, RuleSrc, StrMap};

${tables.join("\n")}
${[...maps.values()].map((m) => m.code).join("\n")}`
);
