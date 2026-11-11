/** Size bucketing (BLOX.md §4.7): append 0x80, then zeros up to the next bucket. */

export const BUCKETS = [1 << 10, 4 << 10, 16 << 10, 64 << 10, 256 << 10];

export function pad(plaintext: Uint8Array): Uint8Array {
  const bucket = BUCKETS.find((b) => plaintext.length < b);
  if (bucket === undefined) throw new Error("message too large");
  const out = new Uint8Array(bucket);
  out.set(plaintext);
  out[plaintext.length] = 0x80;
  return out;
}

export function unpad(padded: Uint8Array): Uint8Array {
  let end = padded.length - 1;
  while (end >= 0 && padded[end] === 0) end--;
  if (end < 0 || padded[end] !== 0x80) throw new Error("bad padding");
  return padded.slice(0, end);
}
