// Sends raw HTTP/1.1 requests to a Fastify target and records exactly what comes back.
// Usage: node http_cases.mjs <port> <out.json> [rejections-only]
import { writeFileSync } from "node:fs";
import net from "node:net";

const [port, outFile, mode] = process.argv.slice(2);
const rejectionsOnly = mode === "rejections-only";

const bytes = text => Buffer.from(text, "utf8");
const pageview = '{"type":"pageview","site_id":"site_abc","pathname":"/pricing"}';

const cases = [
  { name: "no content-type, no body", headers: [], body: bytes("") },
  { name: "no content-type, content-length 0", headers: [["Content-Length", "0"]], body: bytes("") },
  { name: "no content-type with a body", headers: [["Content-Length", "2"]], body: bytes("{}") },
  { name: "no content-type, chunked empty", headers: [["Transfer-Encoding", "chunked"]], body: bytes(""), chunked: true },
  { name: "json empty", headers: [["Content-Type", "application/json"], ["Content-Length", "0"]], body: bytes("") },
  { name: "json empty chunked", headers: [["Content-Type", "application/json"], ["Transfer-Encoding", "chunked"]], body: bytes(""), chunked: true },
  { name: "json truncated", headers: [["Content-Type", "application/json"]], body: bytes("{") },
  { name: "json whitespace", headers: [["Content-Type", "application/json"]], body: bytes("  \n") },
  { name: "json trailing garbage", headers: [["Content-Type", "application/json"]], body: bytes("{} x") },
  { name: "json valid pageview", valid: true, headers: [["Content-Type", "application/json"]], body: bytes(pageview) },
  { name: "json with bom", valid: true, headers: [["Content-Type", "application/json"]], body: Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), bytes(pageview)]) },
  { name: "json double bom", headers: [["Content-Type", "application/json"]], body: Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf, 0xef, 0xbb, 0xbf]), bytes(pageview)]) },
  { name: "json null", headers: [["Content-Type", "application/json"]], body: bytes("null") },
  { name: "json string", headers: [["Content-Type", "application/json"]], body: bytes('"x"') },
  { name: "json array", headers: [["Content-Type", "application/json"]], body: bytes("[1]") },
  { name: "json empty object", headers: [["Content-Type", "application/json"]], body: bytes("{}") },
  { name: "text/plain json", headers: [["Content-Type", "text/plain"]], body: bytes(pageview) },
  { name: "text/plain empty", headers: [["Content-Type", "text/plain"], ["Content-Length", "0"]], body: bytes("") },
  { name: "json charset param", valid: true, headers: [["Content-Type", "application/json; charset=utf-8"]], body: bytes(pageview) },
  { name: "json latin1 charset param", valid: true, headers: [["Content-Type", "application/json; charset=latin1"]], body: bytes(pageview) },
  { name: "json uppercase", valid: true, headers: [["Content-Type", "APPLICATION/JSON"]], body: bytes(pageview) },
  { name: "json spaced params", valid: true, headers: [["Content-Type", "application/json ; x=\"y\""]], body: bytes(pageview) },
  { name: "text/plain params", headers: [["Content-Type", "text/plain;charset=UTF-8"]], body: bytes(pageview) },
  { name: "xml", headers: [["Content-Type", "application/xml"]], body: bytes("<a/>") },
  { name: "form urlencoded", headers: [["Content-Type", "application/x-www-form-urlencoded"]], body: bytes("a=1") },
  { name: "space before slash", headers: [["Content-Type", "application /json"]], body: bytes(pageview) },
  { name: "extra slash", headers: [["Content-Type", "application/json/x"]], body: bytes(pageview) },
  { name: "empty content-type", headers: [["Content-Type", ""]], body: bytes(pageview) },
  { name: "undefined content-type", headers: [["Content-Type", "undefined"]], body: bytes(pageview) },
  { name: "wildcard subtype", headers: [["Content-Type", "application/*"]], body: bytes(pageview) },
  { name: "no subtype", headers: [["Content-Type", "json"]], body: bytes(pageview) },
  { name: "semicolon only", headers: [["Content-Type", ";"]], body: bytes(pageview) },
  { name: "json then text content-type", valid: true, headers: [["Content-Type", "application/json"], ["Content-Type", "text/plain"]], body: bytes(pageview) },
  { name: "text then json content-type", headers: [["Content-Type", "text/plain"], ["Content-Type", "application/json"]], body: bytes(pageview) },
  { name: "proto key", headers: [["Content-Type", "application/json"]], body: bytes('{"type":"pageview","site_id":"a","__proto__":{"x":1}}') },
  { name: "escaped proto key", headers: [["Content-Type", "application/json"]], body: bytes('{"type":"pageview","site_id":"a","feature_flags":{"\\u005f_proto__":"x"}}') },
  { name: "constructor prototype", headers: [["Content-Type", "application/json"]], body: bytes('{"type":"pageview","site_id":"a","x":[{"constructor":{"prototype":{}}}]}') },
  { name: "constructor string", headers: [["Content-Type", "application/json"]], body: bytes('{"type":"pageview","site_id":"a","constructor":"x"}') },
  { name: "deep nesting", headers: [["Content-Type", "application/json"]], parts: [['{"type":"pageview","site_id":"a","deep":', 1], ["[", 200000], ["]", 200000], ["}", 1]] },
  { name: "infinite lcp", valid: true, headers: [["Content-Type", "application/json"]], body: bytes('{"type":"performance","site_id":"a","lcp":1e400,"cls":-0}') },
  { name: "lone surrogate", valid: true, headers: [["Content-Type", "application/json"]], body: bytes('{"type":"pageview","site_id":"a","hostname":"x\\ud800y"}') },
  { name: "invalid utf8 with length", headers: [["Content-Type", "application/json"]], body: Buffer.concat([bytes('{"type":"pageview","site_id":"'), Buffer.from([0xff]), bytes('"}')]) },
  { name: "truncated sequence same length", valid: true, headers: [["Content-Type", "application/json"]], body: Buffer.concat([bytes('{"type":"pageview","site_id":"'), Buffer.from([0xf0, 0x9f, 0x98]), bytes('"}')]) },
  { name: "invalid utf8 chunked", valid: true, headers: [["Content-Type", "application/json"], ["Transfer-Encoding", "chunked"]], chunked: true, body: Buffer.concat([bytes('{"type":"pageview","site_id":"'), Buffer.from([0xff, 0xed, 0xa0, 0x80, 0xc3]), bytes('"}')]) },
  { name: "declared length over limit", headers: [["Content-Type", "application/json"], ["Content-Length", "10485761"]], body: bytes("{}"), partial: true },
  { name: "declared length over limit for xml", headers: [["Content-Type", "application/xml"], ["Content-Length", "10485761"]], body: bytes("{}"), partial: true },
  { name: "chunked over limit", headers: [["Content-Type", "application/json"], ["Transfer-Encoding", "chunked"]], chunked: true, parts: [['{"a":"', 1], ["a", 10485760], ['"}', 1]] },
  { name: "exactly the limit", headers: [["Content-Type", "application/json"]], parts: [['{"type":"pageview","site_id":"a","pad":"', 1], ["a", 10485760 - 42], ['"}', 1]] },
  { name: "one over the limit", headers: [["Content-Type", "application/json"]], parts: [['{"type":"pageview","site_id":"a","pad":"', 1], ["a", 10485760 - 41], ['"}', 1]] },
  { name: "invalid payload", headers: [["Content-Type", "application/json"]], body: bytes('{"type":"custom_event","site_id":"","screenWidth":-1.5,"x":1}') },
  { name: "unknown type", headers: [["Content-Type", "application/json"]], body: bytes('{"type":"nope"}') },
];

const ipCases = [
  { name: "duplicate forwarded headers", path: "/api/ipecho", headers: [["X-Forwarded-For", "203.0.113.10"], ["X-Forwarded-For", "198.51.100.7, 10.0.0.1"], ["User-Agent", "first"], ["User-Agent", "second"]] },
  { name: "duplicate real ip", path: "/api/ipecho", headers: [["X-Real-IP", "192.0.2.10"], ["X-Real-IP", "192.0.2.11"], ["CF-Connecting-IP", "13.224.0.1"]] },
  { name: "duplicate empty real ip", path: "/api/ipecho", headers: [["X-Real-IP", ""], ["X-Real-IP", ""], ["X-Forwarded-For", "203.0.113.10"]] },
  { name: "empty headers", path: "/api/ipecho", headers: [["X-Real-IP", ""], ["X-Forwarded-For", ""], ["CF-Connecting-IP", ""], ["User-Agent", ""]] },
  { name: "latin1 bytes", path: "/api/ipecho", rawHeaders: [Buffer.from("X-Real-IP: \xa0\r\n", "latin1"), Buffer.from("User-Agent: caf\xe9\r\n", "latin1"), Buffer.from("X-Forwarded-For: 1.2.3.4\xa0, 5.6.7.8\r\n", "latin1")] },
  { name: "tabs and commas", path: "/api/ipecho", headers: [["X-Forwarded-For", ",\t,"], ["CF-Connecting-IP", "2A06:98C0:3600::103"]] },
  { name: "spaces inside tokens", path: "/api/ipecho", headers: [["X-Forwarded-For", "a b ,  c d  ,e"]] },
  { name: "duplicate cf with forwarded", path: "/api/ipecho", headers: [["CF-Connecting-IP", "70.132.5.9"], ["CF-Connecting-IP", "70.132.5.10"], ["X-Forwarded-For", "203.0.113.10, 70.132.5.9"], ["X-Real-IP", "192.0.2.10"]] },
  { name: "nothing", path: "/api/ipecho", headers: [] },
];

function requestBuffer(testCase) {
  const path = testCase.path ?? "/api/track";
  let body = testCase.body ?? Buffer.alloc(0);
  if (testCase.parts) {
    body = Buffer.concat(testCase.parts.map(([text, count]) => bytes(text.repeat(count))));
  }
  const sent = [["Host", "127.0.0.1"], ["Connection", "keep-alive"], ...(testCase.headers ?? [])];
  const hasLength = (testCase.headers ?? []).some(([name]) => name.toLowerCase() === "content-length");
  if (!hasLength && !testCase.chunked && body.length > 0) sent.push(["Content-Length", String(body.length)]);
  if (!hasLength && !testCase.chunked && body.length === 0 && testCase.headers?.some(([n]) => n.toLowerCase() === "content-type")) sent.push(["Content-Length", "0"]);
  const lines = [`POST ${path} HTTP/1.1`, ...sent.map(([name, value]) => `${name}: ${value}`)];
  const head = Buffer.concat([bytes(lines.join("\r\n") + "\r\n"), ...(testCase.rawHeaders ?? []), bytes("\r\n")]);
  testCase.sentHeaders = [
    ...sent,
    ...(testCase.rawHeaders ?? []).map(buffer => {
      const line = buffer.toString("latin1").replace(/\r\n$/, "");
      return [line.slice(0, line.indexOf(":")), line.slice(line.indexOf(":") + 1).replace(/^[ \t]+|[ \t]+$/g, "")];
    }),
  ];
  let payload = body;
  if (testCase.chunked) {
    const chunks = [];
    const size = 65536;
    for (let offset = 0; offset < body.length; offset += size) {
      const piece = body.subarray(offset, offset + size);
      chunks.push(bytes(piece.length.toString(16) + "\r\n"), piece, bytes("\r\n"));
    }
    chunks.push(bytes("0\r\n\r\n"));
    payload = Buffer.concat(chunks);
  }
  if (testCase.partial) payload = body;
  return { head, payload, body };
}

function send(testCase) {
  return new Promise(resolve => {
    const { head, payload, body } = requestBuffer(testCase);
    const socket = net.connect(Number(port), "127.0.0.1");
    const received = [];
    let done = false;
    const finish = () => {
      if (done) return;
      done = true;
      socket.destroy();
      const raw = Buffer.concat(received);
      const split = raw.indexOf("\r\n\r\n");
      const headText = raw.subarray(0, split).toString("latin1");
      const [statusLine, ...headerLines] = headText.split("\r\n");
      const headers = Object.fromEntries(headerLines.map(line => [line.slice(0, line.indexOf(":")).toLowerCase(), line.slice(line.indexOf(":") + 1).trim()]));
      resolve({
        name: testCase.name,
        path: testCase.path ?? "/api/track",
        requestHeaders: testCase.sentHeaders,
        chunked: Boolean(testCase.chunked),
        bodyHex: testCase.parts ? null : body.toString("hex"),
        parts: testCase.parts ?? null,
        status: Number(statusLine.split(" ")[1]),
        contentType: headers["content-type"] ?? null,
        connection: headers["connection"] ?? null,
        response: raw.subarray(split + 4).toString("utf8"),
      });
    };
    socket.on("data", chunk => {
      received.push(chunk);
      const raw = Buffer.concat(received);
      const split = raw.indexOf("\r\n\r\n");
      if (split === -1) return;
      const match = /content-length: (\d+)/i.exec(raw.subarray(0, split).toString("latin1"));
      if (match && raw.length - split - 4 >= Number(match[1])) finish();
    });
    socket.on("end", finish);
    socket.on("close", finish);
    socket.on("error", () => {});
    socket.write(head);
    socket.write(payload);
    setTimeout(finish, 20000);
  });
}

const selected = rejectionsOnly ? cases.filter(c => !c.valid && !(c.parts && c.name.includes("limit")) && !c.partial) : [...cases, ...ipCases];
const results = [];
for (const testCase of selected) {
  const result = await send(testCase);
  results.push(result);
  console.log(`${result.status} ${result.connection ?? "-"} ${testCase.name}: ${result.response.slice(0, 160)}`);
}
writeFileSync(outFile, JSON.stringify(results));
