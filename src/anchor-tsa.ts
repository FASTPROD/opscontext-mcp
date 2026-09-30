// The interim backend's time stamp client (COMPR-TSA docs/SEALHOUR_PROTOCOL.md section 7.3): a direct
// RFC 3161 stamp of the 32-byte checkpoint digest from free public providers, until the SealHour service
// exists. The only module of the SealHour client that opens a network connection.
//
// [LOCKED] [ONLY-THE-DIGEST-LEAVES] - 2026-09-30
// [NEVER] send a time stamp provider anything but a TimeStampReq over the checkpoint digest (version,
//         SHA-256 message imprint, a random nonce, certReq), never the checkpoint, a record, a name, a
//         path or a licence key, and never let a test hook point the client at a host that is not this
//         machine.
// WHY: the enable screen promises the owner that one 32-byte fingerprint leaves, to the two services it
//      names, and nothing else (plan section 8; workplan 2, "seul un condensé sort"). A request built by
//      an outside tool, a header added "for debugging" or an override pointing at another server would
//      break that promise silently: the stamp would still verify.
// FIX: the request is built here, byte for byte (buildTsq), and a test captures what a provider receives
//      and compares it with the expected DER. The providers are pinned below; the test override accepts
//      loopback URLs only.
//
// [LOCKED] [A-STAMP-IS-CHECKED-BEFORE-IT-COUNTS] - 2026-09-30
// [NEVER] store a reply as a stamp before its status is granted, its message imprint is this checkpoint's
//         digest and its nonce is this request's, and never call a stamp checked unless OpenSSL verified
//         its signature and chain against the provider's pinned root.
// WHY: a reply is only bytes from the network: an error page, another request's answer or a replayed old
//      stamp all parse. LibreSSL 3.3 (macOS's /usr/bin/openssl) fails a genuine DigiCert chain (measured
//      2026-09-30), so its "FAILED" is not evidence either way.
// FIX: status, imprint and nonce are read from the DER here; OpenSSL (preferred over LibreSSL) checks the
//      signature and chain with -queryfile, at the stamp's own time (-attime), so a stamp stays checkable
//      after the provider's certificate expires. What cannot be checked is said as not checked.
import { execFileSync, spawnSync } from "child_process";
import { existsSync, mkdirSync, readFileSync, renameSync, unlinkSync, writeFileSync } from "fs";
import { join } from "path";
import { randomBytes } from "crypto";
import http from "http";
import https from "https";

/** FreeTSA's root CA, from https://freetsa.org/files/cacert.pem (SHA-256 fingerprint
 *  A6:37:9E:7C:EC:C0:5F:AA:3C:BF:07:60:13:D7:45:E3:27:BB:BA:A3:8C:0B:9A:F2:24:69:D4:70:1D:18:AA:BC). */
const FREETSA_ROOT = `-----BEGIN CERTIFICATE-----
MIIH/zCCBeegAwIBAgIJAMHphhYNqOmAMA0GCSqGSIb3DQEBDQUAMIGVMREwDwYD
VQQKEwhGcmVlIFRTQTEQMA4GA1UECxMHUm9vdCBDQTEYMBYGA1UEAxMPd3d3LmZy
ZWV0c2Eub3JnMSIwIAYJKoZIhvcNAQkBFhNidXNpbGV6YXNAZ21haWwuY29tMRIw
EAYDVQQHEwlXdWVyemJ1cmcxDzANBgNVBAgTBkJheWVybjELMAkGA1UEBhMCREUw
HhcNMTYwMzEzMDE1MjEzWhcNNDEwMzA3MDE1MjEzWjCBlTERMA8GA1UEChMIRnJl
ZSBUU0ExEDAOBgNVBAsTB1Jvb3QgQ0ExGDAWBgNVBAMTD3d3dy5mcmVldHNhLm9y
ZzEiMCAGCSqGSIb3DQEJARYTYnVzaWxlemFzQGdtYWlsLmNvbTESMBAGA1UEBxMJ
V3VlcnpidXJnMQ8wDQYDVQQIEwZCYXllcm4xCzAJBgNVBAYTAkRFMIICIjANBgkq
hkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAtgKODjAy8REQ2WTNqUudAnjhlCrpE6ql
mQfNppeTmVvZrH4zutn+NwTaHAGpjSGv4/WRpZ1wZ3BRZ5mPUBZyLgq0YrIfQ5Fx
0s/MRZPzc1r3lKWrMR9sAQx4mN4z11xFEO529L0dFJjPF9MD8Gpd2feWzGyptlel
b+PqT+++fOa2oY0+NaMM7l/xcNHPOaMz0/2olk0i22hbKeVhvokPCqhFhzsuhKsm
q4Of/o+t6dI7sx5h0nPMm4gGSRhfq+z6BTRgCrqQG2FOLoVFgt6iIm/BnNffUr7V
DYd3zZmIwFOj/H3DKHoGik/xK3E82YA2ZulVOFRW/zj4ApjPa5OFbpIkd0pmzxzd
EcL479hSA9dFiyVmSxPtY5ze1P+BE9bMU1PScpRzw8MHFXxyKqW13Qv7LWw4sbk3
SciB7GACbQiVGzgkvXG6y85HOuvWNvC5GLSiyP9GlPB0V68tbxz4JVTRdw/Xn/XT
FNzRBM3cq8lBOAVt/PAX5+uFcv1S9wFE8YjaBfWCP1jdBil+c4e+0tdywT2oJmYB
BF/kEt1wmGwMmHunNEuQNzh1FtJY54hbUfiWi38mASE7xMtMhfj/C4SvapiDN837
gYaPfs8x3KZxbX7C3YAsFnJinlwAUss1fdKar8Q/YVs7H/nU4c4Ixxxz4f67fcVq
M2ITKentbCMCAwEAAaOCAk4wggJKMAwGA1UdEwQFMAMBAf8wDgYDVR0PAQH/BAQD
AgHGMB0GA1UdDgQWBBT6VQ2MNGZRQ0z357OnbJWveuaklzCBygYDVR0jBIHCMIG/
gBT6VQ2MNGZRQ0z357OnbJWveuakl6GBm6SBmDCBlTERMA8GA1UEChMIRnJlZSBU
U0ExEDAOBgNVBAsTB1Jvb3QgQ0ExGDAWBgNVBAMTD3d3dy5mcmVldHNhLm9yZzEi
MCAGCSqGSIb3DQEJARYTYnVzaWxlemFzQGdtYWlsLmNvbTESMBAGA1UEBxMJV3Vl
cnpidXJnMQ8wDQYDVQQIEwZCYXllcm4xCzAJBgNVBAYTAkRFggkAwemGFg2o6YAw
MwYDVR0fBCwwKjAooCagJIYiaHR0cDovL3d3dy5mcmVldHNhLm9yZy9yb290X2Nh
LmNybDCBzwYDVR0gBIHHMIHEMIHBBgorBgEEAYHyJAEBMIGyMDMGCCsGAQUFBwIB
FidodHRwOi8vd3d3LmZyZWV0c2Eub3JnL2ZyZWV0c2FfY3BzLmh0bWwwMgYIKwYB
BQUHAgEWJmh0dHA6Ly93d3cuZnJlZXRzYS5vcmcvZnJlZXRzYV9jcHMucGRmMEcG
CCsGAQUFBwICMDsaOUZyZWVUU0EgdHJ1c3RlZCB0aW1lc3RhbXBpbmcgU29mdHdh
cmUgYXMgYSBTZXJ2aWNlIChTYWFTKTA3BggrBgEFBQcBAQQrMCkwJwYIKwYBBQUH
MAGGG2h0dHA6Ly93d3cuZnJlZXRzYS5vcmc6MjU2MDANBgkqhkiG9w0BAQ0FAAOC
AgEAaK9+v5OFYu9M6ztYC+L69sw1omdyli89lZAfpWMMh9CRmJhM6KBqM/ipwoLt
nxyxGsbCPhcQjuTvzm+ylN6VwTMmIlVyVSLKYZcdSjt/eCUN+41K7sD7GVmxZBAF
ILnBDmTGJmLkrU0KuuIpj8lI/E6Z6NnmuP2+RAQSHsfBQi6sssnXMo4HOW5gtPO7
gDrUpVXID++1P4XndkoKn7Svw5n0zS9fv1hxBcYIHPPQUze2u30bAQt0n0iIyRLz
aWuhtpAtd7ffwEbASgzB7E+NGF4tpV37e8KiA2xiGSRqT5ndu28fgpOY87gD3ArZ
DctZvvTCfHdAS5kEO3gnGGeZEVLDmfEsv8TGJa3AljVa5E40IQDsUXpQLi8G+UC4
1DWZu8EVT4rnYaCw1VX7ShOR1PNCCvjb8S8tfdudd9zhU3gEB0rxdeTy1tVbNLXW
99y90xcwr1ZIDUwM/xQ/noO8FRhm0LoPC73Ef+J4ZBdrvWwauF3zJe33d4ibxEcb
8/pz5WzFkeixYM2nsHhqHsBKw7JPouKNXRnl5IAE1eFmqDyC7G/VT7OF669xM6hb
Ut5G21JE4cNK6NNucS+fzg1JPX0+3VhsYZjj7D5uljRvQXrJ8iHgr/M6j2oLHvTA
I2MLdq2qjZFDOCXsxBxJpbmLGBx9ow6ZerlUxzws2AWv2pk=
-----END CERTIFICATE-----
`;

/** DigiCert Trusted Root G4, from the macOS system root store (SHA-256 fingerprint
 *  55:2F:7B:DC:F1:A7:AF:9E:6C:E6:72:01:7F:4F:12:AB:F7:72:40:C7:8E:76:1A:C2:03:D1:D9:D2:0A:C8:99:88). */
const DIGICERT_G4_ROOT = `-----BEGIN CERTIFICATE-----
MIIFkDCCA3igAwIBAgIQBZsbV56OITLiOQe9p3d1XDANBgkqhkiG9w0BAQwFADBi
MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3
d3cuZGlnaWNlcnQuY29tMSEwHwYDVQQDExhEaWdpQ2VydCBUcnVzdGVkIFJvb3Qg
RzQwHhcNMTMwODAxMTIwMDAwWhcNMzgwMTE1MTIwMDAwWjBiMQswCQYDVQQGEwJV
UzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQu
Y29tMSEwHwYDVQQDExhEaWdpQ2VydCBUcnVzdGVkIFJvb3QgRzQwggIiMA0GCSqG
SIb3DQEBAQUAA4ICDwAwggIKAoICAQC/5pBzaN675F1KPDAiMGkz7MKnJS7JIT3y
ithZwuEppz1Yq3aaza57G4QNxDAf8xukOBbrVsaXbR2rsnnyyhHS5F/WBTxSD1If
xp4VpX6+n6lXFllVcq9ok3DCsrp1mWpzMpTREEQQLt+C8weE5nQ7bXHiLQwb7iDV
ySAdYyktzuxeTsiT+CFhmzTrBcZe7FsavOvJz82sNEBfsXpm7nfISKhmV1efVFiO
DCu3T6cw2Vbuyntd463JT17lNecxy9qTXtyOj4DatpGYQJB5w3jHtrHEtWoYOAMQ
jdjUN6QuBX2I9YI+EJFwq1WCQTLX2wRzKm6RAXwhTNS8rhsDdV14Ztk6MUSaM0C/
CNdaSaTC5qmgZ92kJ7yhTzm1EVgX9yRcRo9k98FpiHaYdj1ZXUJ2h4mXaXpI8OCi
EhtmmnTK3kse5w5jrubU75KSOp493ADkRSWJtppEGSt+wJS00mFt6zPZxd9LBADM
fRyVw4/3IbKyEbe7f/LVjHAsQWCqsWMYRJUadmJ+9oCw++hkpjPRiQfhvbfmQ6QY
uKZ3AeEPlAwhHbJUKSWJbOUOUlFHdL4mrLZBdd56rF+NP8m800ERElvlEFDrMcXK
chYiCd98THU/Y+whX8QgUWtvsauGi0/C1kVfnSD8oR7FwI+isX4KJpn15GkvmB0t
9dmpsh3lGwIDAQABo0IwQDAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIB
hjAdBgNVHQ4EFgQU7NfjgtJxXWRM3y5nP+e6mK4cD08wDQYJKoZIhvcNAQEMBQAD
ggIBALth2X2pbL4XxJEbw6GiAI3jZGgPVs93rnD5/ZpKmbnJeFwMDF/k5hQpVgs2
SV1EY+CtnJYYZhsjDT156W1r1lT40jzBQ0CuHVD1UvyQO7uYmWlrx8GnqGikJ9yd
+SeuMIW59mdNOj6PWTkiU0TryF0Dyu1Qen1iIQqAyHNm0aAFYF/opbSnr6j3bTWc
fFqK1qI4mfN4i/RN0iAL3gTujJtHgXINwBQy7zBZLq7gcfJW5GqXb5JQbZaNaHqa
sjYUegbyJLkJEVDXCLG4iXqEI2FCKeWjzaIgQdfRnGTZ6iahixTXTBmyUEFxPT9N
cCOGDErcgdLMMpSEDQgJlxxPwO5rIHQw0uA5NBCFIRUBCOhVMt5xSdkoF1BN5r5N
0XWs0Mr7QbhDparTwwVETyw2m+L64kW4I1NsBm9nVX9GtUw/bihaeSbSpKhil9Ie
4u1Ki7wb/UdKDd9nZn6yW0HQO+T0O/QEY+nvwlQAUaCKKsnOeMzV6ocEGLPOr0mI
r/OSmbaz5mEP0oUA51Aa5BuVnRmhuZyxm7EAHu/QD09CbMkKvO5D+jpxpchNJqU1
/YldvIViHTLSoCtU7ZpXwdv6EM8Zt4tKG48BtieVU+i2iW1bvGjUI+iLUaJW+fCm
gKDWHrO8Dw9TdSmq6hN35N6MgSGtBxBHEa2HPQfRdbzP82Z+
-----END CERTIFICATE-----
`;

export interface Provider {
  /** File-name safe: the stamp is checkpoint.<id>.tsr. */
  id: string;
  /** Shown to the owner on the enable screen and in every report. */
  name: string;
  url: string;
  /** The pinned trust anchor: the root the stamp's chain must reach. */
  caPem: string;
}

/**
 * The two free providers of the interim backend. Both answered and verified against these roots on
 * 2026-09-30 (one real stamp each, of a public test string). Never remove a root that signed stamps
 * people keep: an old stamp is checked against the root pinned when it was made.
 */
export const PROVIDERS: readonly Provider[] = [
  { id: "freetsa", name: "FreeTSA (freetsa.org)", url: "https://freetsa.org/tsr", caPem: FREETSA_ROOT },
  { id: "digicert", name: "DigiCert (timestamp.digicert.com)", url: "http://timestamp.digicert.com", caPem: DIGICERT_G4_ROOT },
];

/**
 * The providers in use: the pinned ones, or, for tests only, stand-ins on this machine given as JSON in
 * CONTEXTENGINE_ANCHOR_TEST_PROVIDERS ([{id, name, url, caFile}]). A stand-in whose URL is not on the
 * loopback is refused: the override can never send a digest to another machine. [LOCK] [ONLY-THE-DIGEST-LEAVES]
 */
export function activeProviders(): Provider[] {
  const raw = process.env.CONTEXTENGINE_ANCHOR_TEST_PROVIDERS;
  if (!raw) return [...PROVIDERS];
  let list: Array<{ id?: unknown; name?: unknown; url?: unknown; caFile?: unknown }>;
  try {
    list = JSON.parse(raw);
  } catch {
    throw new Error("CONTEXTENGINE_ANCHOR_TEST_PROVIDERS is not JSON");
  }
  return list.map((p) => {
    const url = new URL(String(p.url));
    if (url.protocol !== "http:" || !["127.0.0.1", "localhost", "[::1]"].includes(url.hostname)) {
      throw new Error(`test provider refused: ${url.origin} is not this machine`);
    }
    const id = String(p.id);
    if (!/^[a-z0-9-]{1,32}$/.test(id)) throw new Error(`test provider id refused: ${id}`);
    return { id, name: String(p.name ?? id), url: url.href, caPem: readFileSync(String(p.caFile), "utf8") };
  });
}

// ---------- the request, built here byte for byte ----------

const SHA256_ALG = Buffer.from("300d06096086480165030402010500", "hex"); // AlgorithmIdentifier { sha256, NULL }

function derLength(n: number): Buffer {
  if (n < 0x80) return Buffer.from([n]);
  const bytes: number[] = [];
  for (let v = n; v > 0; v = Math.floor(v / 256)) bytes.unshift(v & 0xff);
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

function der(tag: number, ...content: Buffer[]): Buffer {
  const body = Buffer.concat(content);
  return Buffer.concat([Buffer.from([tag]), derLength(body.length), body]);
}

/** A positive INTEGER's minimal content bytes. */
function derUint(bytes: Buffer): Buffer {
  let i = 0;
  while (i < bytes.length - 1 && bytes[i] === 0) i++;
  const v = bytes.subarray(i);
  return v[0] & 0x80 ? Buffer.concat([Buffer.from([0]), v]) : Buffer.from(v);
}

/**
 * TimeStampReq (RFC 3161 section 2.4.1): version 1, the SHA-256 message imprint of the 32-byte digest,
 * a nonce, certReq true. No policy, no extension, nothing else. [LOCK] [ONLY-THE-DIGEST-LEAVES]
 */
export function buildTsq(digestHex: string, nonce: Buffer): Buffer {
  if (!/^[0-9a-f]{64}$/.test(digestHex)) throw new Error("the message imprint is a 64-hex SHA-256 digest");
  const imprint = der(0x30, SHA256_ALG, der(0x04, Buffer.from(digestHex, "hex")));
  return der(0x30, der(0x02, Buffer.from([1])), imprint, der(0x02, derUint(nonce)), Buffer.from([0x01, 0x01, 0xff]));
}

// ---------- the reply, read here ----------

interface Tlv {
  tag: number;
  vstart: number;
  end: number;
}

function tlv(buf: Buffer, pos: number): Tlv {
  if (pos + 2 > buf.length) throw new Error("truncated");
  const tag = buf[pos];
  if ((tag & 0x1f) === 0x1f) throw new Error("unexpected tag");
  let len = buf[pos + 1];
  let p = pos + 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n === 0 || n > 4) throw new Error("unsupported length");
    if (p + n > buf.length) throw new Error("truncated");
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + buf[p + i];
    p += n;
  }
  if (p + len > buf.length) throw new Error("truncated");
  return { tag, vstart: p, end: p + len };
}

function kids(buf: Buffer, t: Tlv): Tlv[] {
  const out: Tlv[] = [];
  for (let p = t.vstart; p < t.end; ) {
    const c = tlv(buf, p);
    out.push(c);
    p = c.end;
  }
  return out;
}

const val = (buf: Buffer, t: Tlv) => buf.subarray(t.vstart, t.end);
const OID_SIGNED_DATA = "2a864886f70d010702";
const OID_TST_INFO = "2a864886f70d0109100104";
const OID_SHA256 = "608648016503040201";

export interface TsrInfo {
  /** PKIStatus: 0 granted, 1 granted with modifications, 2 rejection, 3 waiting, 4 and 5 revocation. */
  status: number;
  statusText: string | null;
  /** From the token's TSTInfo, when the reply carries one. */
  imprintSha256: string | null;
  nonce: string | null;
  /** genTime, as an ISO UTC time (fraction kept when the provider gives one). */
  time: string | null;
}

/** Read a TimeStampResp (RFC 3161 section 2.4.2): status, message imprint, nonce, time. Throws on
 *  anything that is not DER of that shape. The signature is OpenSSL's to check. */
export function parseTsr(buf: Buffer): TsrInfo {
  const top = tlv(buf, 0);
  if (top.tag !== 0x30) throw new Error("not a time stamp reply");
  const [statusInfo, token] = kids(buf, top);
  const si = kids(buf, statusInfo);
  if (!si[0] || si[0].tag !== 0x02) throw new Error("no status in the reply");
  const status = val(buf, si[0]).reduce((a, b) => a * 256 + b, 0);
  let statusText: string | null = null;
  if (si[1]?.tag === 0x30) {
    const t = kids(buf, si[1])[0];
    if (t) statusText = val(buf, t).toString("utf8");
  }
  const out: TsrInfo = { status, statusText, imprintSha256: null, nonce: null, time: null };
  if (!token) return out;
  const ci = kids(buf, token);
  if (val(buf, ci[0]).toString("hex") !== OID_SIGNED_DATA || ci[1]?.tag !== 0xa0) throw new Error("the token is not CMS signed data");
  const sd = kids(buf, kids(buf, ci[1])[0]);
  const eci = kids(buf, sd[2]);
  if (val(buf, eci[0]).toString("hex") !== OID_TST_INFO || eci[1]?.tag !== 0xa0) throw new Error("the token does not hold a TSTInfo");
  const oct = kids(buf, eci[1])[0];
  if (oct.tag !== 0x04) throw new Error("unsupported TSTInfo encoding");
  const tst = val(buf, oct);
  const f = kids(tst, tlv(tst, 0));
  const mi = kids(tst, f[2]);
  const alg = kids(tst, mi[0]);
  if (val(tst, alg[0]).toString("hex") === OID_SHA256) out.imprintSha256 = val(tst, mi[1]).toString("hex");
  if (f[4]?.tag === 0x18) {
    const g = /^(\d{4})(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)(\.\d+)?Z$/.exec(val(tst, f[4]).toString("latin1"));
    if (g) out.time = `${g[1]}-${g[2]}-${g[3]}T${g[4]}:${g[5]}:${g[6]}${g[7] ?? ""}Z`;
  }
  const nonce = f.slice(5).find((x) => x.tag === 0x02);
  if (nonce) out.nonce = derUint(val(tst, nonce)).toString("hex").replace(/^(00)+(?=..)/, "");
  return out;
}

// ---------- OpenSSL ----------

let sslCache: { key: string; found: { path: string; libressl: boolean; version: string } | null } | null = null;

/**
 * The openssl to check stamps with: OpenSSL preferred over LibreSSL (which fails genuine chains). An
 * explicit CONTEXTENGINE_OPENSSL is used as given, with no fallback: a binary the owner named that does
 * not run means "no openssl", said as such, never another binary chosen in silence.
 */
export function findOpenssl(): { path: string; libressl: boolean; version: string } | null {
  const pinned = process.env.CONTEXTENGINE_OPENSSL ?? "";
  if (sslCache && sslCache.key === pinned) return sslCache.found;
  const candidates = pinned ? [pinned] : ["/opt/homebrew/bin/openssl", "/usr/local/opt/openssl@3/bin/openssl", "/usr/local/bin/openssl", "openssl", "/usr/bin/openssl"];
  let found: { path: string; libressl: boolean; version: string } | null = null;
  for (const c of candidates) {
    let version: string;
    try {
      version = execFileSync(c, ["version"], { encoding: "utf8", timeout: 5000, stdio: ["ignore", "pipe", "ignore"] }).trim();
    } catch {
      continue;
    }
    if (/^OpenSSL /.test(version)) { found = { path: c, libressl: false, version }; break; }
    if (!found && /LibreSSL/.test(version)) found = { path: c, libressl: true, version };
  }
  sslCache = { key: pinned, found };
  return found;
}

export interface StampCheck {
  /** true: OpenSSL verified it; false: it does not verify; null: it could not be checked here. */
  ok: boolean | null;
  detail: string;
}

/**
 * Check a stored stamp against its pinned root, at the stamp's own time. With `queryFile`, the reply
 * must also answer that request (imprint and nonce); otherwise its imprint must be `digestHex`.
 * [LOCK] [A-STAMP-IS-CHECKED-BEFORE-IT-COUNTS]
 */
export function checkStamp(o: { tsr: string; caFile: string; digestHex?: string; queryFile?: string; time?: string | null }): StampCheck {
  const ssl = findOpenssl();
  if (!ssl) return { ok: null, detail: "openssl was not found on this machine: the stamp could not be checked" };
  const args = ["ts", "-verify", ...(o.queryFile ? ["-queryfile", o.queryFile] : ["-digest", o.digestHex ?? ""]), "-in", o.tsr, "-CAfile", o.caFile];
  const at = o.time ? Math.floor(Date.parse(o.time) / 1000) : NaN;
  if (!ssl.libressl && Number.isFinite(at)) args.push("-attime", String(at));
  const p = spawnSync(ssl.path, args, { encoding: "utf8", timeout: 15_000 });
  const text = `${p.stdout ?? ""}${p.stderr ?? ""}`.trim();
  if (p.status === 0 && /Verification: OK/.test(p.stdout ?? "")) return { ok: true, detail: "signature and chain verified by OpenSSL against the pinned root" };
  if (ssl.libressl) return { ok: null, detail: `LibreSSL (${ssl.path}) could not check this stamp; OpenSSL 3 can (set CONTEXTENGINE_OPENSSL)` };
  return { ok: false, detail: text.split("\n").filter((l) => /error|Verif/i.test(l)).slice(-2).join(" ").slice(0, 300) || "verification failed" };
}

// ---------- the network ----------

/** POST a TimeStampReq; the answer's body, or a plain-words error. Never follows a redirect. */
function post(url: string, body: Buffer, timeoutMs: number): Promise<Buffer> {
  const u = new URL(url);
  const mod = u.protocol === "https:" ? https : http;
  return new Promise((resolve, reject) => {
    // Node's default agent, so an owner behind a proxy can route through it with NODE_USE_ENV_PROXY=1
    // (Node 22.21 and 24.5 onwards); "Connection: close" so no socket outlives the job.
    const req = mod.request(u, {
      method: "POST",
      headers: { "Content-Type": "application/timestamp-query", "Content-Length": body.length, "User-Agent": "opscontext-anchor", Connection: "close" },
    }, (res) => {
      if (res.statusCode !== 200) {
        res.resume();
        reject(new Error(`the service answered HTTP ${res.statusCode}`));
        return;
      }
      const chunks: Buffer[] = [];
      let size = 0;
      res.on("data", (c: Buffer) => {
        size += c.length;
        if (size > 1 << 20) req.destroy(new Error("the answer is larger than 1 MB"));
        else chunks.push(c);
      });
      res.on("end", () => resolve(Buffer.concat(chunks)));
      res.on("error", reject);
    });
    const timer = setTimeout(() => req.destroy(new Error(`no answer within ${Math.round(timeoutMs / 1000)} s`)), timeoutMs);
    req.on("close", () => clearTimeout(timer));
    req.on("error", (e: NodeJS.ErrnoException) => {
      clearTimeout(timer);
      if (e.code === "ECONNREFUSED") reject(new Error("connection refused"));
      else if (e.code === "ENOTFOUND" || e.code === "EAI_AGAIN") reject(new Error("its address could not be found (no network?)"));
      else if (e.code === "ECONNRESET") reject(new Error("the connection was cut"));
      else reject(e);
    });
    req.end(body);
  });
}

export interface StampResult {
  provider: string;
  name: string;
  /** A reply granted for this digest and this request's nonce, stored as checkpoint.<id>.tsr. */
  ok: boolean;
  /** OpenSSL verified it against the pinned root (null: could not be checked here). */
  checked: boolean | null;
  time: string | null;
  tried_at: string;
  error: string | null;
}

function writeAtomic(path: string, data: Buffer | string): void {
  const tmp = `${path}.tmp-${process.pid}`;
  writeFileSync(tmp, data);
  renameSync(tmp, path);
}

/** The pinned root of a provider, as a file OpenSSL can read (written once, rewritten if it changed). */
export function caFileFor(p: Provider, certsDir: string): string {
  mkdirSync(certsDir, { recursive: true });
  const f = join(certsDir, `${p.id}-ca.pem`);
  if (!existsSync(f) || readFileSync(f, "utf8") !== p.caPem) writeAtomic(f, p.caPem);
  return f;
}

/**
 * Ask one provider to stamp `digestHex`, keep the request and the reply in `dir` as
 * checkpoint.<id>.tsq and .tsr, and say what happened. Never throws.
 * [LOCK] [ONLY-THE-DIGEST-LEAVES] [LOCK] [A-STAMP-IS-CHECKED-BEFORE-IT-COUNTS]
 */
export async function stampDigest(digestHex: string, p: Provider, dir: string, o: { certsDir: string; timeoutMs?: number; now?: () => Date }): Promise<StampResult> {
  const triedAt = (o.now ?? (() => new Date()))().toISOString();
  const base = { provider: p.id, name: p.name, tried_at: triedAt };
  const tsqPath = join(dir, `checkpoint.${p.id}.tsq`);
  const tsrPath = join(dir, `checkpoint.${p.id}.tsr`);
  try {
    const nonce = randomBytes(8);
    const tsq = buildTsq(digestHex, nonce);
    const reply = await post(p.url, tsq, o.timeoutMs ?? 15_000);
    let info: TsrInfo;
    try {
      info = parseTsr(reply);
    } catch (e) {
      return { ...base, ok: false, checked: null, time: null, error: `the answer is not a time stamp (${(e as Error).message})` };
    }
    if (info.status !== 0 && info.status !== 1) {
      return { ...base, ok: false, checked: null, time: null, error: `the service refused to stamp (status ${info.status}${info.statusText ? `: ${info.statusText.slice(0, 80)}` : ""})` };
    }
    const wantNonce = derUint(nonce).toString("hex").replace(/^(00)+(?=..)/, "");
    if (info.imprintSha256 !== digestHex || info.nonce !== wantNonce) {
      return { ...base, ok: false, checked: null, time: null, error: "the answer is not for this request (another digest or nonce)" };
    }
    writeAtomic(tsqPath, tsq);
    writeAtomic(tsrPath, reply);
    const check = checkStamp({ tsr: tsrPath, queryFile: tsqPath, caFile: caFileFor(p, o.certsDir), time: info.time });
    if (check.ok === false) {
      for (const f of [tsrPath, tsqPath]) try { unlinkSync(f); } catch { /* already gone */ }
      return { ...base, ok: false, checked: false, time: info.time, error: `the stamp does not verify against the pinned root: ${check.detail}` };
    }
    return { ...base, ok: true, checked: check.ok, time: info.time, error: check.ok === null ? check.detail : null };
  } catch (e) {
    return { ...base, ok: false, checked: null, time: null, error: (e as Error).message.slice(0, 200) };
  }
}
