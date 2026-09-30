// A throwaway RFC 3161 time stamp server on 127.0.0.1, for tests: its own test CA and TSA certificate
// (made with OpenSSL in a temp folder), replies made by `openssl ts -reply`, as the SealHour protocol
// fixture's build does. It records every request it receives, so a test can check what left.
import { execFileSync } from "child_process";
import { mkdirSync, readFileSync, writeFileSync } from "fs";
import { join } from "path";
import http from "http";
import type { AddressInfo } from "net";
import { findOpenssl } from "../../src/anchor-tsa.js";

export type TsaMode = "ok" | "http503" | "cut" | "garbage" | "other-request" | "hang";

export interface FakeTsa {
  id: string;
  url: string;
  caFile: string;
  mode: TsaMode;
  /** Answer HTTP 503 to this many requests, then follow `mode` again. */
  failNext: number;
  requests: Array<{ body: Buffer; headers: http.IncomingHttpHeaders; path: string }>;
  /** Stop listening: from then on the port refuses connections. */
  close(): Promise<void>;
  /** The provider entry for CONTEXTENGINE_ANCHOR_TEST_PROVIDERS. */
  entry(): { id: string; name: string; url: string; caFile: string };
}

const REQ_CNF = `[req]
distinguished_name = dn
prompt = no
[dn]
CN = unused
[v3_ca]
basicConstraints = critical, CA:TRUE
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
[v3_tsa]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = critical, timeStamping
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
`;

const TSA_CNF = (k: string) => `[tsa]
default_tsa = t
[t]
serial = ${k}/serial
signer_cert = ${k}/tsa.crt
certs = ${k}/ca.pem
signer_key = ${k}/tsa.key
signer_digest = sha256
default_policy = 1.2.3.4.1
digests = sha256
accuracy = secs:1
ordering = yes
tsa_name = yes
ess_cert_id_chain = no
ess_cert_id_alg = sha256
`;

export async function startFakeTsa(dir: string, id = "test-a"): Promise<FakeTsa> {
  const ssl = findOpenssl();
  if (!ssl || ssl.libressl) throw new Error("the fake time stamp server needs OpenSSL (not LibreSSL)");
  const k = join(dir, `fake-tsa-${id}`);
  mkdirSync(k, { recursive: true });
  const run = (...args: string[]) => execFileSync(ssl.path, args, { stdio: "pipe" });
  writeFileSync(join(k, "req.cnf"), REQ_CNF);
  writeFileSync(join(k, "tsa.cnf"), TSA_CNF(k));
  writeFileSync(join(k, "serial"), "01\n");
  for (const n of ["ca", "tsa"]) run("genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", join(k, `${n}.key`));
  run("req", "-new", "-x509", "-key", join(k, "ca.key"), "-out", join(k, "ca.pem"), "-days", "3650", "-config", join(k, "req.cnf"), "-extensions", "v3_ca", "-subj", `/O=OpsContext tests/CN=Test CA ${id}`);
  run("req", "-new", "-key", join(k, "tsa.key"), "-out", join(k, "tsa.csr"), "-config", join(k, "req.cnf"), "-subj", `/O=OpsContext tests/CN=Test TSA ${id}`);
  run("x509", "-req", "-in", join(k, "tsa.csr"), "-CA", join(k, "ca.pem"), "-CAkey", join(k, "ca.key"), "-CAcreateserial", "-out", join(k, "tsa.crt"), "-days", "3650", "-extfile", join(k, "req.cnf"), "-extensions", "v3_tsa");

  let n = 0;
  const reply = (query: Buffer): Buffer => {
    const q = join(k, `q${++n}.tsq`);
    const r = join(k, `r${n}.tsr`);
    writeFileSync(q, query);
    run("ts", "-reply", "-config", join(k, "tsa.cnf"), "-queryfile", q, "-out", r);
    return readFileSync(r);
  };
  const other = (): Buffer => {
    const q = join(k, `other${++n}.tsq`);
    run("ts", "-query", "-digest", "ab".repeat(32), "-sha256", "-cert", "-out", q);
    return reply(readFileSync(q));
  };

  const t: FakeTsa = {
    id,
    url: "",
    caFile: join(k, "ca.pem"),
    mode: "ok",
    failNext: 0,
    requests: [],
    close: () => new Promise((resolve) => server.close(() => resolve())),
    entry: () => ({ id, name: `Test TSA ${id}`, url: t.url, caFile: t.caFile }),
  };
  const server = http.createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      const body = Buffer.concat(chunks);
      t.requests.push({ body, headers: req.headers, path: req.url ?? "" });
      if (t.failNext > 0) { t.failNext--; res.writeHead(503); res.end("busy"); return; }
      if (t.mode === "cut") { req.socket.destroy(); return; }
      if (t.mode === "hang") return; // never answers
      if (t.mode === "http503") { res.writeHead(503); res.end("busy"); return; }
      let out: Buffer;
      if (t.mode === "garbage") out = Buffer.from("<html>not a time stamp</html>");
      else if (t.mode === "other-request") out = other();
      else out = reply(body);
      res.writeHead(200, { "Content-Type": "application/timestamp-reply", "Content-Length": out.length });
      res.end(out);
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
  t.url = `http://127.0.0.1:${(server.address() as AddressInfo).port}/tsr`;
  // A hanging request must not keep the test process alive.
  server.on("connection", (s) => s.unref());
  return t;
}
