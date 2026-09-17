// Generates server-rs/src/tracking/channel_lists.rs from server/src/services/tracker/const.ts
// and shared/src/aiOperators.ts, then checks every extracted entry against Node's own
// classification functions so a transcription slip cannot go unnoticed.
import { readFileSync, writeFileSync } from "node:fs";
import { AI_CHAT_DOMAINS } from "../../../shared/src/aiOperators.ts";
import * as constMod from "../../../server/src/services/tracker/const.ts";

const source = readFileSync(new URL("../../../server/src/services/tracker/const.ts", import.meta.url), "utf8");
const listRe = /^(?:export )?const (\w+)(?:: [^=]+)? = \[([\s\S]*?)\];/gm;
const lists: Record<string, string[]> = {};
for (const match of source.matchAll(listRe)) {
  const [, name, body] = match;
  const withoutComments = body
    .split("\n")
    .map(line => line.replace(/^\s*\/\/.*$/, ""))
    .join("\n");
  const items = [...withoutComments.matchAll(/"((?:[^"\\]|\\.)*)"/g)].map(m => JSON.parse(`"${m[1]}"`));
  lists[name] = items;
}
lists.aiChatDomains = AI_CHAT_DOMAINS;

// Cross-check exported lists against the module's own values
for (const name of ["aiChatAppIds", "socialAppIds", "videoAppIds", "searchAppIds", "emailAppIds", "shoppingAppIds", "newsAppIds", "productivityAppIds"]) {
  const actual = (constMod as any)[name] as string[];
  if (JSON.stringify(actual) !== JSON.stringify(lists[name])) {
    throw new Error(`extracted ${name} differs from the module export`);
  }
}

const order = [
  "searchDomains",
  "socialDomains",
  "videoDomains",
  "shoppingDomains",
  "aiChatDomains",
  "aiChatSources",
  "aiChatMediums",
  "aiChatAppIds",
  "searchSources",
  "socialSources",
  "videoSources",
  "shoppingSources",
  "emailSources",
  "smsSources",
  "socialMediums",
  "videoMediums",
  "displayMediums",
  "affiliateMediums",
  "referralMediums",
  "emailMediums",
  "pushMediums",
  "audioMediums",
  "influencerMediums",
  "cpcMediums",
  "cpmMediums",
  "contentMediums",
  "eventMediums",
  "socialAppIds",
  "videoAppIds",
  "searchAppIds",
  "emailAppIds",
  "shoppingAppIds",
  "newsAppIds",
  "productivityAppIds",
];
for (const name of Object.keys(lists)) {
  if (!order.includes(name)) throw new Error(`unexpected list ${name}`);
}

const snake = (name: string) => name.replace(/([A-Z])/g, "_$1").toUpperCase();
let out = `//! Channel classification lists, generated from server/src/services/tracker/const.ts
//! (and AI_CHAT_DOMAINS from shared/src/aiOperators.ts). Entry order matters: the
//! classifiers test the lists in order and the first match wins. Regenerate with the
//! parity script rather than editing by hand, so the two sides cannot drift.

`;
for (const name of order) {
  const items = lists[name];
  if (!items) throw new Error(`missing list ${name}`);
  out += `pub(super) const ${snake(name)}: &[&str] = &[\n`;
  for (const item of items) out += `    ${JSON.stringify(item)},\n`;
  out += `];\n\n`;
}
writeFileSync(process.argv[2], out.trimEnd() + "\n");
console.log(Object.fromEntries(order.map(name => [name, lists[name].length])));
