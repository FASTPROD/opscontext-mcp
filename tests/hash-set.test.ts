// [LOCK] [VERIFY-STREAMS-THE-HISTORY]: the verifier keeps every hash of the history in a HashSet
// (32 bytes an entry) instead of a Set<string>; its answers must be the ones a Set would give.
import { describe, it, expect } from "vitest";
import { createHash } from "crypto";
import { HashSet } from "../src/hash-set.js";

const h = (s: string) => createHash("sha256").update(s).digest("hex");

describe("HashSet", () => {
  it("answers has() like a Set<string>, across several table growths", () => {
    const set = new HashSet(4); // starts at the minimum size, so it grows many times
    const ref = new Set<string>();
    for (let i = 0; i < 20000; i++) {
      const v = h("v" + i);
      set.add(v);
      ref.add(v);
    }
    expect(set.size).toBe(ref.size);
    for (let i = 0; i < 20000; i += 97) expect(set.has(h("v" + i))).toBe(true);
    for (let i = 0; i < 500; i++) expect(set.has(h("absent" + i))).toBe(false);
    set.add(h("v1"));
    expect(set.size).toBe(ref.size);
  });

  it("compares all 32 bytes, not only the bytes the slot is chosen from", () => {
    const set = new HashSet(16);
    const a = h("a");
    const b = a.slice(0, 24) + h("b").slice(24); // same first 12 bytes, different tail
    set.add(a);
    expect(set.has(a)).toBe(true);
    expect(set.has(b)).toBe(false);
    set.add(b);
    expect(set.has(b)).toBe(true);
    expect(set.size).toBe(2);
  });

  it("keeps a value that is not a 64-character hex string exactly as given", () => {
    const set = new HashSet(16);
    set.add("not-a-hash");
    set.add(undefined);
    set.add(h("x").toUpperCase());
    expect(set.has("not-a-hash")).toBe(true);
    expect(set.has(undefined)).toBe(true);
    expect(set.has(h("x").toUpperCase())).toBe(true);
    expect(set.has(h("x"))).toBe(false);
    expect(set.size).toBe(3);
  });

  it("costs well under 120 bytes a hash at scale", () => {
    const n = 100000;
    const set = new HashSet(n);
    for (let i = 0; i < n; i++) set.add(h("s" + i));
    expect(set.size).toBe(n);
    expect(set.bytes / n).toBeLessThan(120);
  });
});
