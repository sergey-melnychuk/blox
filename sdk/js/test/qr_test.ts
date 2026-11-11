// The TypeScript QR encoder against the Rust qrcode crate, module for module.
//
// Any of the 8 mask patterns gives a valid QR code; the two encoders' penalty rules can pick
// different ones. So: with the mask the Rust encoder chose, the matrices must be identical.
import { assert, assertEquals } from "jsr:@std/assert@1";
import { qrMatrix, qrSvg } from "../src/qr.ts";

const V = JSON.parse(await Deno.readTextFile(new URL("../../../test-vectors/qr-v1.json", import.meta.url)));
const rowsOf = (m: boolean[][]) => m.map((r) => r.map((d) => (d ? "1" : "0")).join(""));

for (const c of V.cases) {
  Deno.test(`qr: ${c.data.slice(0, 24)}`, () => {
    assertEquals(qrMatrix(c.data).length, c.rows.length, "same version");
    const same = [0, 1, 2, 3, 4, 5, 6, 7].filter((mask) => JSON.stringify(rowsOf(qrMatrix(c.data, mask))) === JSON.stringify(c.rows));
    assertEquals(same.length, 1, "identical under exactly one mask");
  });
}

Deno.test("svg", () => {
  const svg = qrSvg("BLOX:HELLO");
  assert(svg.startsWith("<svg") && svg.includes("<path"));
});
