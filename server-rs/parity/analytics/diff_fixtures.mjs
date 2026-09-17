// Compares two fixture directories case by case (Node 24 vs Node 26 outputs).
import { readdirSync, readFileSync } from "node:fs";
import { gunzipSync } from "node:zlib";

const [a, b] = process.argv.slice(2);
for (const name of readdirSync(a).filter(file => file.endsWith(".json.gz")).sort()) {
  const left = JSON.parse(gunzipSync(readFileSync(`${a}/${name}`)).toString());
  const right = JSON.parse(gunzipSync(readFileSync(`${b}/${name}`)).toString());
  let differing = 0;
  const examples = [];
  for (let i = 0; i < Math.max(left.cases.length, right.cases.length); i++) {
    const l = JSON.stringify(left.cases[i]);
    const r = JSON.stringify(right.cases[i]);
    if (l !== r) {
      differing++;
      if (examples.length < 3) examples.push({ index: i, left: l.slice(0, 600), right: r.slice(0, 600) });
    }
  }
  console.log(name, left.node, right.node, "cases", left.cases.length, "differing", differing);
  for (const example of examples) console.log(JSON.stringify(example, null, 1));
}
