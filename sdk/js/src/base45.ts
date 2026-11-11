/** Base45 (RFC 9285): QR's alphanumeric alphabet, so QR codes use alphanumeric mode. */

const ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:";

export function base45(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.length; i += 2) {
    if (i + 1 < bytes.length) {
      let n = bytes[i] * 256 + bytes[i + 1];
      for (let k = 0; k < 3; k++) {
        out += ALPHABET[n % 45];
        n = Math.floor(n / 45);
      }
    } else {
      let n = bytes[i];
      for (let k = 0; k < 2; k++) {
        out += ALPHABET[n % 45];
        n = Math.floor(n / 45);
      }
    }
  }
  return out;
}

export function unbase45(s: string): Uint8Array {
  const d = Array.from(s, (c) => {
    const i = ALPHABET.indexOf(c);
    if (i < 0) throw new Error("bad base45");
    return i;
  });
  const out: number[] = [];
  for (let i = 0; i < d.length; i += 3) {
    const chunk = d.slice(i, i + 3);
    if (chunk.length === 3) {
      const n = chunk[0] + chunk[1] * 45 + chunk[2] * 2025;
      if (n > 0xffff) throw new Error("bad base45");
      out.push(n >> 8, n & 0xff);
    } else if (chunk.length === 2) {
      const n = chunk[0] + chunk[1] * 45;
      if (n > 0xff) throw new Error("bad base45");
      out.push(n);
    } else throw new Error("bad base45");
  }
  return new Uint8Array(out);
}
