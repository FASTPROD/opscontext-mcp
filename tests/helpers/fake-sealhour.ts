// A throwaway SealHour service on 127.0.0.1, for tests: the three addresses of protocol version 1 as the
// client uses them (POST /v1/checkpoints, GET /v1/proofs/<digest>), a receipt key made for the test, hours
// sealed on demand and stamped by the fake time stamp server (tests/helpers/fake-tsa.ts). It records every
// request it receives, so a test can check what left the machine, and it can be told to answer wrongly.
import http from "http";
import type { AddressInfo } from "net";
import { generateKeyPairSync, randomBytes, sign, type KeyObject } from "crypto";
import { readFileSync, writeFileSync } from "fs";
import { join } from "path";
import { auditPath, canonBytes, checkpointProblems, customerOf, digestOf, hourOf, isoSecond, leafHash, mth, TREE_RULE } from "../../src/anchor-protocol.js";
import { buildTsq, parseTsr } from "../../src/anchor-tsa.js";
import type { FakeTsa } from "./fake-tsa.js";

type Scripted = { status: number; body?: unknown; headers?: Record<string, string> };
/** A scripted POST answer, or a receipt that is wrong in one way. */
export type PostScript = Scripted | "wrong-key" | "other-digest" | "other-customer" | "wrong-hour" | "cut";

interface Stored { cp: unknown; customer: string; receipt: Record<string, unknown>; hour: string }
interface Hour { root: Buffer; leaves: unknown[]; tsr: Buffer | null; time: string | null; ots: "pending" | "complete" | "none" }

export interface FakeSealHour {
  url: string;
  keyId: string;
  /** The receipt key's public half, PEM. */
  keyFile: string;
  /** The value for CONTEXTENGINE_SEALHOUR_TEST. `anchors: false` leaves the stamp's certificate unknown to the client. */
  env(o?: { anchors?: boolean }): string;
  clock: () => Date;
  /** Used once each, oldest first, before the normal behaviour. */
  nextPost: PostScript[];
  nextProof: Scripted[];
  /** Change the files of every bundle served from now on (a tampered or hostile bundle). */
  mangle: ((files: Record<string, Buffer>) => void) | null;
  pilotOver: boolean;
  requests: Array<{ method: string; path: string; headers: http.IncomingHttpHeaders; body: Buffer }>;
  stored: Map<string, Stored>;
  hours: Map<string, Hour>;
  missed: Set<string>;
  /** Seal an hour: one tree over its checkpoints, stamped by the fake time stamp server unless told not to. */
  seal(hour: string, o?: { stamp?: boolean; ots?: "pending" | "complete" | "none" }): Promise<void>;
  posts(): Array<{ digest: string; authorization: string }>;
  close(): Promise<void>;
}

const LICENCE = /^CE-[0-9A-F]{4}(-[0-9A-F]{4}){3}$/;
const PILOT = /^pilot-[0-9a-f]{64}$/;

export async function startFakeSealHour(dir: string, tsa: FakeTsa | null): Promise<FakeSealHour> {
  const keyId = "test-receipts-1";
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const other = generateKeyPairSync("ed25519");
  const keyFile = join(dir, `${keyId}.pub`);
  writeFileSync(keyFile, publicKey.export({ type: "spki", format: "pem" }));

  const signed = (body: Record<string, unknown>, key: KeyObject = privateKey): Record<string, unknown> =>
    ({ ...body, signature: sign(null, canonBytes(body), key).toString("base64") });
  const receiptFor = (digest: string, customer: string, at: Date, how?: PostScript): Record<string, unknown> => {
    const received_at = isoSecond(at);
    const body: Record<string, unknown> = { version: 1, kind: "receipt", checkpoint_digest: digest, customer, received_at, hour: hourOf(received_at), key_id: keyId };
    if (how === "other-digest") body.checkpoint_digest = "ab".repeat(32);
    if (how === "other-customer") body.customer = "cd".repeat(32);
    if (how === "wrong-hour") body.hour = hourOf(isoSecond(new Date(at.getTime() + 2 * 3_600_000)));
    return signed(body, how === "wrong-key" ? other.privateKey : privateKey);
  };

  const s: FakeSealHour = {
    url: "",
    keyId,
    keyFile,
    env: (o = {}) => JSON.stringify({ url: s.url, keys: [{ id: keyId, file: keyFile }], anchors: o.anchors === false || !tsa ? [] : [tsa.caFile] }),
    clock: () => new Date(),
    nextPost: [],
    nextProof: [],
    mangle: null,
    pilotOver: false,
    requests: [],
    stored: new Map(),
    hours: new Map(),
    missed: new Set(),
    posts: () => s.requests.filter((r) => r.method === "POST").map((r) => {
      let digest = "";
      try { digest = digestOf(JSON.parse(r.body.toString("utf8"))); } catch { digest = "(not JSON)"; }
      return { digest, authorization: String(r.headers.authorization ?? "") };
    }),
    async seal(hour, o = {}) {
      const mine = [...s.stored.entries()].filter(([, v]) => v.hour === hour)
        .map(([digest, v]) => ({ kind: "checkpoint", customer: v.customer, digest }))
        .sort((a, b) => (a.customer + a.digest < b.customer + b.digest ? -1 : 1));
      const before = [...s.hours.entries()].pop();
      const leaves: unknown[] = [...(before ? [{ kind: "previous", hour: before[0], root: before[1].root.toString("hex") }] : []), ...mine];
      if (leaves.length === 0) leaves.push({ kind: "journal", note: "an hour with no checkpoint" });
      const root = mth(leaves.map(leafHash));
      let tsr: Buffer | null = null;
      let time: string | null = null;
      if (o.stamp !== false && tsa) {
        const r = await fetch(tsa.url, { method: "POST", headers: { "Content-Type": "application/timestamp-query" }, body: buildTsq(root.toString("hex"), randomBytes(8)) });
        tsr = Buffer.from(await r.arrayBuffer());
        time = parseTsr(tsr).time;
      }
      s.hours.set(hour, { root, leaves, tsr, time, ots: o.ots ?? "pending" });
    },
    close: () => new Promise((resolve) => { server.closeAllConnections(); server.close(() => resolve()); }),
  };

  const bundle = (digest: string, st: Stored, h: Hour): Record<string, unknown> => {
    const hashes = h.leaves.map(leafHash);
    const i = h.leaves.findIndex((l) => (l as { digest?: string }).digest === digest);
    const as = (o: unknown) => Buffer.from(JSON.stringify(o, null, 2) + "\n");
    const files: Record<string, Buffer> = {
      "leaf.json": as(h.leaves[i]),
      "path.json": as({ hour: st.hour, tree: TREE_RULE, index: i, size: hashes.length, leaf_hash: hashes[i].toString("hex"), siblings: auditPath(i, hashes).map((b) => b.toString("hex")), root: h.root.toString("hex") }),
      "checkpoint.json": as(st.cp),
      "receipt.json": as(st.receipt),
      "root.bin": h.root,
      "stamps.json": as({
        tsa: tsa ? { test: { name: "Test stamp service (not a real time stamp)", profile: "test", partial_chain: false, ok: !!h.tsr, time: h.time, ca_file: h.tsr ? "certs/test-ca.pem" : null, untrusted: null } } : {},
        ots: h.ots === "complete" ? { ok: true, bitcoin_block: 900001 } : h.ots === "pending" ? { ok: false } : { ok: false, skipped: "test: no Bitcoin" },
      }),
      [`keys/${keyId}.pub`]: readFileSync(keyFile),
      "README.txt": Buffer.from("test proof\n"),
      "LISEZMOI.txt": Buffer.from("preuve de test\n"),
    };
    if (h.tsr && tsa) {
      files["root.test.tsr"] = h.tsr;
      files["certs/test-ca.pem"] = readFileSync(tsa.caFile);
    }
    if (h.ots !== "none") files["root.bin.ots"] = Buffer.from(`fake attestation, ${h.ots}`);
    s.mangle?.(files);
    return { version: 1, kind: "bundle", checkpoint_digest: digest, files: Object.fromEntries(Object.entries(files).map(([n, d]) => [n, d.toString("base64")])) };
  };

  const server = http.createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      const body = Buffer.concat(chunks);
      const path = req.url ?? "";
      s.requests.push({ method: req.method ?? "", path, headers: req.headers, body });
      const answer = (status: number, obj: unknown, headers: Record<string, string> = {}) => {
        const out = Buffer.from(JSON.stringify(obj));
        res.writeHead(status, { "Content-Type": "application/json", "Content-Length": out.length, ...headers });
        res.end(out);
      };
      if (req.method === "POST" && path === "/v1/checkpoints") {
        const script = s.nextPost.shift();
        if (script === "cut") { req.socket.destroy(); return; }
        if (script && typeof script === "object") { answer(script.status, script.body ?? { error: `scripted ${script.status}` }, script.headers); return; }
        const m = /^Bearer (.+)$/.exec(String(req.headers.authorization ?? ""));
        const credential = m?.[1] ?? "";
        if (!LICENCE.test(credential) && !PILOT.test(credential)) { answer(401, { error: "no OpsContext licence key or SealHour pilot token was sent" }); return; }
        if (PILOT.test(credential) && s.pilotOver) { answer(403, { error: "the SealHour pilot has ended; SealHour is included in OpsContext Team and Enterprise" }); return; }
        let cp: unknown;
        try { cp = JSON.parse(body.toString("utf8")); } catch { answer(400, { error: "the body is not JSON in UTF-8 with each key written once" }); return; }
        const problems = checkpointProblems(cp, body.length);
        if (problems.length > 0) { answer(400, { error: `not a checkpoint of protocol version 1: ${problems.join("; ")}` }); return; }
        const digest = digestOf(cp);
        const customer = customerOf(credential);
        const known = s.stored.get(digest);
        if (known) {
          if (known.customer !== customer) answer(409, { error: "this checkpoint was already received from another customer" });
          else answer(200, known.receipt);
          return;
        }
        const receipt = receiptFor(digest, customer, s.clock(), script);
        // A wrong receipt is what the service "sent"; what it keeps is the right one, as a real retry would find it.
        const kept = script ? receiptFor(digest, customer, s.clock()) : receipt;
        s.stored.set(digest, { cp, customer, receipt: kept, hour: String(kept.hour) });
        answer(201, receipt);
        return;
      }
      const proof = /^\/v1\/proofs\/([0-9a-f]{64})$/.exec(path);
      if (req.method === "GET" && proof) {
        const script = s.nextProof.shift();
        if (script) { answer(script.status, script.body ?? { error: `scripted ${script.status}` }, script.headers); return; }
        const st = s.stored.get(proof[1]);
        if (!st) { answer(404, { error: "unknown checkpoint" }); return; }
        if (s.missed.has(st.hour)) { answer(410, { error: `hour ${st.hour} was not sealed and never will be: SealHour missed it; the next checkpoint of the same log names this one and dates it` }); return; }
        const h = s.hours.get(st.hour);
        if (!h) { answer(202, { status: "pending", hour: st.hour, why: "hour not sealed yet" }); return; }
        answer(200, bundle(proof[1], st, h));
        return;
      }
      answer(404, { error: "not found" });
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
  s.url = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  server.on("connection", (c) => c.unref());
  return s;
}
