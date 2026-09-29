/**
 * A set of SHA-256 hashes at 32 bytes an entry plus an index, instead of one JS string an entry.
 * verifyChain() keeps every hash of the history in one of these (5 million on the author's Mac,
 * 2026-09-29), so the whole check fits in a few hundred MB. [LOCK] [VERIFY-STREAMS-THE-HISTORY]
 * (src/audit.ts)
 *
 * Open addressing keyed on 8 bytes of the hash, full 32-byte compare on a hit, the table doubled
 * at half load. A value that is not a 64-character lowercase hex string (the hash field of a
 * malformed record) is kept as it is in a plain Set, so every membership answer is the one a
 * Set<string> would give.
 */
export class HashSet {
  private n = 0;
  private cap: number;
  private table: Int32Array;
  private store: Buffer;
  private readonly odd = new Set<unknown>();

  constructor(expected = 1024) {
    let cap = 1024;
    while (cap < expected * 2) cap *= 2;
    this.cap = cap;
    this.table = new Int32Array(cap).fill(-1);
    this.store = Buffer.allocUnsafe(Math.max(expected, 1024) * 32);
  }

  /** Distinct values held. */
  get size(): number {
    return this.n + this.odd.size;
  }

  /** Bytes held by the index and the hash store (the plain Set for odd values is not counted). */
  get bytes(): number {
    return this.table.byteLength + this.store.length;
  }

  has(value: unknown): boolean {
    if (!isHex64(value)) return this.odd.has(value);
    return this.find(Buffer.from(value, "hex")).found;
  }

  add(value: unknown): void {
    if (!isHex64(value)) {
      this.odd.add(value);
      return;
    }
    const buf = Buffer.from(value, "hex");
    const r = this.find(buf);
    if (r.found) return;
    if ((this.n + 1) * 32 > this.store.length) {
      const bigger = Buffer.allocUnsafe(this.store.length * 2);
      this.store.copy(bigger);
      this.store = bigger;
    }
    buf.copy(this.store, this.n * 32);
    this.table[r.slot] = this.n;
    this.n++;
    if (this.n * 2 > this.cap) this.grow();
  }

  private slotOf(buf: Buffer, offset = 0): number {
    return (buf.readUInt32LE(offset) ^ buf.readUInt32LE(offset + 8)) & (this.cap - 1);
  }

  private find(buf: Buffer): { slot: number; found: boolean } {
    let i = this.slotOf(buf);
    for (;;) {
      const k = this.table[i];
      if (k === -1) return { slot: i, found: false };
      if (this.store.compare(buf, 0, 32, k * 32, k * 32 + 32) === 0) return { slot: i, found: true };
      i = (i + 1) & (this.cap - 1);
    }
  }

  private grow(): void {
    const old = this.table;
    this.cap *= 2;
    this.table = new Int32Array(this.cap).fill(-1);
    for (const k of old) {
      if (k === -1) continue;
      let i = this.slotOf(this.store, k * 32);
      while (this.table[i] !== -1) i = (i + 1) & (this.cap - 1);
      this.table[i] = k;
    }
  }
}

function isHex64(v: unknown): v is string {
  return typeof v === "string" && v.length === 64 && /^[0-9a-f]{64}$/.test(v);
}
