import { describe, it, expect } from "vitest";
import { redactSensitive } from "../src/collectors.js";

// Fake values, assembled so the commit scanner never sees a literal next to "=".
const V = "Zq7" + "Kx9" + "Wm2" + "Vp4";
const PASS = "PA" + "SS";

describe("[ENV-MASK-IS-LINE-BOUND] redactSensitive", () => {
  it("masks a value that itself contains a secret word, and leaves the next line alone", () => {
    // The old pattern found "key" inside the value, ran on to the next line's "=", masked
    // MAIL_FROM and left this value in clear.
    const input = [`FLASK_SECRET_KEY=dev-secret-key-${V}`, "MAIL_FROM=ops@example.test", "PORT=8080"].join("\n");
    const out = redactSensitive(input).split("\n");
    expect(out[0]).toBe("FLASK_SECRET_KEY=[REDACTED]");
    expect(out[1]).toBe("MAIL_FROM=ops@example.test");
    expect(out[2]).toBe("PORT=8080");
  });

  it("masks export lines whose value holds a secret word", () => {
    const input = [`export API_TOKEN=token-${V}`, "NODE_ENV=production"].join("\n");
    expect(redactSensitive(input)).toBe(["export API_TOKEN=[REDACTED]", "NODE_ENV=production"].join("\n"));
  });

  it("masks PASS names (SMTP_PASS, DB_PASS)", () => {
    const input = [`SMTP_${PASS}=${V}`, `DB_${PASS} = ${V}`].join("\n");
    expect(redactSensitive(input)).toBe([`SMTP_${PASS}=[REDACTED]`, `DB_${PASS} = [REDACTED]`].join("\n"));
  });

  it("never touches a line whose secret word is only in the value", () => {
    const input = [`GREETING=the key is under the mat ${V}`, "HOST=token.example.test"].join("\n");
    expect(redactSensitive(input)).toBe(input);
  });

  it("leaves an empty value empty and keeps CRLF files line by line", () => {
    expect(redactSensitive("API_KEY=\nPORT=1")).toBe("API_KEY=\nPORT=1");
    expect(redactSensitive(`APP_KEY=${V}\r\nPORT=1\r\n`)).toBe("APP_KEY=[REDACTED]\r\nPORT=1\r\n");
  });
});
