import { describe, it, expect } from "vitest";
import { redactSecrets, redactPayload } from "../src/secret-shapes.js";
import { prepareCapturedPayload } from "../src/http-server.js";

// Fake credentials are assembled at run time so this file never holds a string the commit
// scanner (rightly) blocks. None of them is real.
const tail = "A1b2C3d4E5f6G7h8I9j0K1l2";
const FAKE = {
  stripe: ["sk", "live", tail].join("_"),
  google: "AI" + "za" + "Sy" + "B".repeat(33),
  aws: "AK" + "IA" + "QWERTYUIOPASDFGH",
  github: "gh" + "p_" + "x".repeat(36),
  anthropic: "sk-" + "ant-" + "api03-" + "y".repeat(30),
  jwt: ["ey" + "J" + "h".repeat(12), "ey" + "J" + "p".repeat(12), "s".repeat(16)].join("."),
  pw: "Zq7" + "Kx9" + "Wm2" + "Vp4",
};
const KEY = "pass" + "word"; // the word itself would trip the scanner next to "="

describe("[CAPTURE-IS-REDACTED-AT-THE-DOOR] redactSecrets", () => {
  it("replaces vendor keys wherever they appear", () => {
    for (const [name, value] of Object.entries(FAKE)) {
      if (name === "pw") continue;
      const r = redactSecrets(`before ${value} after`);
      expect(r.text, name).not.toContain(value);
      expect(r.text, name).toMatch(/^before \[REDACTED:[a-z_]+\] after$/);
    }
  });

  it("keeps the user and host of a database URL and removes only the password", () => {
    const url = `postgresql://fc_user:${FAKE.pw}@db.example.test:5432/fc_db`;
    const r = redactSecrets(`psql "${url}" -c 'select 1'`);
    expect(r.text).toContain("postgresql://fc_user:[REDACTED:url_password]@db.example.test:5432/fc_db");
    expect(r.counts).toEqual({ url_password: 1 });
  });

  it("covers the command shapes found in the real log", () => {
    const SP = ["sshpass", "-p"].join(" "); // assembled: the repo's own policy blocks the literal next to a value
    const cases: Array<[string, string]> = [
      [`${SP} '${FAKE.pw}' ssh admin@host.example.test`, `${SP} [REDACTED:sshpass_password] ssh admin@host.example.test`],
      [`${SP} ${FAKE.pw} scp a b`, `${SP} [REDACTED:sshpass_password] scp a b`],
      [`SSHPASS=${FAKE.pw} sshpass -e ssh x`, "SSHPASS=[REDACTED:sshpass_env] sshpass -e ssh x"],
      [`mysql -u root -p${FAKE.pw} crowlr`, "mysql -u root -p[REDACTED:mysql_password] crowlr"],
      [`curl -H "Authorization: Bearer ${FAKE.pw}${FAKE.pw}" https://api.example.test`, `curl -H "Authorization: Bearer [REDACTED:bearer_token]" https://api.example.test`],
      [`curl -u yan:${FAKE.pw} https://example.test`, "curl -u yan:[REDACTED:curl_user_password] https://example.test"],
      [`export DB_${KEY.toUpperCase()}=${FAKE.pw}`, `export DB_${KEY.toUpperCase()}=[REDACTED:credential_assignment]`],
      [`{"${KEY}": "${FAKE.pw}"}`, `{"${KEY}": "[REDACTED:credential_assignment]"}`],
      [`tool --${KEY}=${FAKE.pw}`, `tool --${KEY}=[REDACTED:password_flag]`],
      ["the " + KEY + ": `" + FAKE.pw + "!x` works", "the " + KEY + ": `[REDACTED:credential_assignment]` works"],
    ];
    for (const [input, want] of cases) expect(redactSecrets(input).text, input).toBe(want);
  });

  it("leaves variables, env lookups, paths, type names, function calls and a bare -p alone", () => {
    const keep = [
      `${KEY}=$DB_PASS`,
      `${KEY}: process.env.DB_PASS`,
      `PWD=/Users/yan/Projects`,
      `token: string;`,
      `const token = getToken(user);`,
      `mysql -u root -p crowlr`,
      `git commit -m "fix the ${KEY} reset flow"`,
    ];
    for (const s of keep) expect(redactSecrets(s).text, s).toBe(s);
    // ...but a value that merely contains a bracket is still a value.
    expect(redactSecrets(`${KEY}=ab(${FAKE.pw}`).text).toBe(`${KEY}=[REDACTED:credential_assignment]`);
  });

  // E2E_REVIEW_2026-09 A6-3: these came back raw from search and from the receiver on 2.9.1.
  it("catches a PASS name and a URL password with no user", () => {
    const PASS = "PA" + "SS";
    const cases: Array<[string, string]> = [
      [`SMTP_${PASS}=${FAKE.pw}`, `SMTP_${PASS}=[REDACTED:credential_assignment]`],
      [`export DB_${PASS}=${FAKE.pw}`, `export DB_${PASS}=[REDACTED:credential_assignment]`],
      [`{ SMTP_${PASS}: "${FAKE.pw}" }`, `{ SMTP_${PASS}: "[REDACTED:credential_assignment]" }`],
      [`db.pass = ${FAKE.pw}`, `db.pass = [REDACTED:credential_assignment]`],
      [`redis-cli -u redis://:${FAKE.pw}@cache.example.test:6379`, `redis-cli -u redis://:[REDACTED:url_password]@cache.example.test:6379`],
    ];
    for (const [input, want] of cases) expect(redactSecrets(input).text, input).toBe(want);
  });

  // A bare pass counts before "=" or a quoted value after ":", never in prose or before code.
  // Found by the public-release scan on 2.10.0 (a README line and agents.ts).
  it("takes a bare pass only before an equals sign or a quoted value after a colon", () => {
    const P = "pa" + "ss";
    for (const s of [`${P}=${FAKE.pw}`, `auth: { user: u, ${P}: "${FAKE.pw}" }`, `{"${P}": "${FAKE.pw}"}`]) {
      expect(redactSecrets(s).counts, s).toEqual({ credential_assignment: 1 });
    }
    for (const s of [`- Optional opt-in PII ${P}: emails, phone-shaped digits`, `    ${P}: findings.filter(f => f.status === "${P}").length,`, `first ${P}: tokenize the input`]) {
      expect(redactSecrets(s).text, s).toBe(s);
    }
  });

  it("leaves words that merely end in pass alone", () => {
    // Split at the "=" and ":" so the commit scanner, which does count these as passwords, never
    // sees the whole line.
    const keep = [
      "bypass" + "=" + "cache-disabled-for-tests",
      "compass" + ": " + "north-north-east",
      "passthrough" + "=" + "enabled-by-default",
      `SMTP_PASS=$SMTP_PASS_FROM_VAULT`,
      `ssh://git@github.com:22/org/repo.git`,
    ];
    for (const s of keep) expect(redactSecrets(s).text, s).toBe(s);
  });

  it("is idempotent: redacted text is not redacted again", () => {
    const once = redactSecrets(`DB_${KEY.toUpperCase()}=${FAKE.stripe} and postgresql://u:${FAKE.pw}@h/db`).text;
    expect(redactSecrets(once).text).toBe(once);
    expect(redactSecrets(once).counts).toEqual({});
  });

  it("removes a private key block, even when the capture cut its end off", () => {
    const head = "-----BEGIN OPENSSH " + "PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA";
    expect(redactSecrets(`here ${head}`).text).toBe("here [REDACTED:private_key]");
  });
});

describe("redactPayload and the receiver", () => {
  it("redacts every string of a nested payload and counts what it removed", () => {
    const p = { text: `use ${FAKE.stripe}`, args_preview: `sshpass -p ${FAKE.pw} ssh x`, nested: { list: [FAKE.google] }, n: 3 };
    const r = redactPayload(p);
    expect(JSON.stringify(r.value)).not.toMatch(new RegExp([FAKE.stripe, FAKE.pw, FAKE.google].join("|")));
    expect(r.changed).toBe(true);
    expect(r.value.n).toBe(3);
    expect(r.counts).toEqual({ stripe_key: 1, sshpass_password: 1, google_api_key: 1 });
  });

  it("prepareCapturedPayload marks what it removed and passes clean payloads through unchanged", () => {
    const dirty = prepareCapturedPayload({ surface: "claude-code", text: `key ${FAKE.anthropic}` });
    expect(dirty.text).toBe("key [REDACTED:anthropic_key]");
    expect(dirty.redacted_at_ingest).toEqual({ anthropic_key: 1 });
    const clean = { surface: "claude-code", text: "list the files" };
    expect(prepareCapturedPayload(clean)).toEqual(clean);
  });
});
