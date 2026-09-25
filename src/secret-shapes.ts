// [LOCKED] [CAPTURE-IS-REDACTED-AT-THE-DOOR] - 2026-09-25
// [NEVER] write captured text (prompts, commands, tool input, errors) to the audit log without
//         passing it through redactPayload(), and never narrow these shapes without replaying
//         them against a real log first.
// WHY: until 2.8.4 the Claude Code hook sent the first 4,000 characters of every prompt and
//      the first 200 of every command straight into audit.log; only the browser extension
//      filtered. A scan on 2026-09-24 found credentials that had sat there for three months:
//      a Stripe live key, production database passwords inside connection URLs, SSH passwords
//      after `sshpass -p`, API tokens after `Bearer`. The log is hash-chained and archived for
//      good, so a secret written once stays forever unless a redaction is acknowledged.
// FIX: every capture event goes through one door, POST /events in src/http-server.ts, and that
//      door redacts every string of the payload with the shapes below before the append. The
//      same shapes drive `contextengine audit-scrub`, which cleans records written before this.
//      The hook's cut at 200 characters can split a secret; a fragment under a shape's minimum
//      length is not caught. A password written in plain words is not caught either.
//
import { createHmac, randomBytes } from "crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "fs";
import { join } from "path";
import { homedir } from "os";

// Credential shapes for redaction. Each shape either replaces the whole match, or keeps a
// leading context group (the key name, the flag, the user part of a URL) and replaces what
// follows. Order matters: vendor formats first, then command and URL shapes, then the generic
// "name = value" shape, which skips anything already redacted.

export interface SecretShape {
  id: string;
  re: RegExp;
  /** Group 1 is context to keep (a flag, a key name, `scheme://user:`); the rest is replaced. */
  keepPrefix?: boolean;
  /** Return true to leave a match alone (a function call, a type name). */
  skip?: (value: string, after: string) => boolean;
}

const QUOTED_OR_BARE = String.raw`(?:'[^']*'|"[^"]*"|[^\s'"]+)`;

export const SECRET_SHAPES: SecretShape[] = [
  { id: "private_key", re: /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)/g },
  { id: "aws_access_key", re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g },
  { id: "aws_secret_key", re: /(aws_secret_access_key["']?\s*[:=]\s*["']?)[A-Za-z0-9/+=]{40}/gi, keepPrefix: true },
  { id: "stripe_key", re: /\b(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{16,}/g },
  { id: "stripe_webhook_secret", re: /\bwhsec_[0-9A-Za-z]{16,}/g },
  { id: "github_token", re: /\b(?:ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z]{30,}|\bgithub_pat_[0-9A-Za-z_]{40,}/g },
  { id: "anthropic_key", re: /\bsk-ant-[0-9A-Za-z_-]{20,}/g },
  { id: "openai_key", re: /\bsk-(?!ant-)(?:proj-|svcacct-|admin-)?[0-9A-Za-z_-]{32,}/g },
  { id: "slack_token", re: /\bxox[abposr]-[0-9A-Za-z-]{10,}/g },
  { id: "slack_webhook", re: /https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9/_-]+/g },
  { id: "google_api_key", re: /\bAIza[0-9A-Za-z_-]{35}/g },
  { id: "npm_token", re: /\bnpm_[0-9A-Za-z]{36}\b/g },
  { id: "sendgrid_key", re: /\bSG\.[0-9A-Za-z_-]{16,}\.[0-9A-Za-z_-]{16,}/g },
  { id: "telegram_bot_token", re: /\b\d{8,10}:AA[0-9A-Za-z_-]{33}\b/g },
  { id: "jwt", re: /\beyJ[0-9A-Za-z_-]{10,}\.eyJ[0-9A-Za-z_-]{10,}\.[0-9A-Za-z_-]{10,}/g },
  // scheme://user:SECRET@host, the shape of every database URL found on 2026-09-24.
  { id: "url_password", re: /(\b[a-z][a-z0-9+.-]*:\/\/[^\s:/@'"`]+:)[^\s@/'"`]+(?=@)/gi, keepPrefix: true },
  { id: "sshpass_password", re: new RegExp(String.raw`(\bsshpass\s+-p\s*)${QUOTED_OR_BARE}`, "g"), keepPrefix: true },
  { id: "sshpass_env", re: new RegExp(String.raw`(\bSSHPASS=)${QUOTED_OR_BARE}`, "g"), keepPrefix: true },
  // mysql -pSECRET (the value is glued to the flag; a bare -p prompts and is left alone).
  { id: "mysql_password", re: new RegExp(String.raw`(\bmysql(?:dump|admin)?\b[^\n]*?\s-p)(?=[^\s-])${QUOTED_OR_BARE}`, "g"), keepPrefix: true },
  { id: "password_flag", re: new RegExp(String.raw`(--password[=\s]\s*)${QUOTED_OR_BARE}`, "gi"), keepPrefix: true },
  { id: "bearer_token", re: /(\bbearer\s+)(?=[0-9A-Za-z._~+/-]{20,})[0-9A-Za-z._~+/-]+=*/gi, keepPrefix: true },
  { id: "basic_auth", re: /(\bauthorization:\s*basic\s+)[A-Za-z0-9+/]{8,}=*/gi, keepPrefix: true },
  { id: "curl_user_password", re: /(\bcurl\b[^\n]*?\s(?:-u|--user)\s*['"]?[^\s:'"]+:)[^\s'"]+/g, keepPrefix: true },
  { id: "api_key_header", re: /(\bx-api-key:\s*)[^\s'"]{8,}/gi, keepPrefix: true },
  // name = value, the long tail. Skips variables, env lookups, paths, placeholders already
  // redacted, type names and function calls.
  {
    id: "credential_assignment",
    // A backtick opens a value too: "password: `...`" in Markdown, found in the real log.
    re: /(\b[\w.-]*(?:password|passwd|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|private[_-]?key|client[_-]?secret)["'`]?\s*[:=]\s*["'`]?)(?![$<{*/~.[]|process\.env|os\.environ|getenv)[^\s'"`,;)}\]]{6,}/gi,
    keepPrefix: true,
    skip: (value, after) =>
      after.startsWith("(") ||
      (/^[A-Za-z_$][\w$.]*\(/.test(value) && after.startsWith(")")) || // getToken(user), not a value
      /^(?:string|number|boolean|null|undefined|true|false|none|str|int|bool|any|object|required|optional)$/i.test(value),
  },
];

/**
 * Keyed fingerprint of a text: HMAC-SHA-256 with a key that never leaves this machine, first 16
 * hex characters. Two identical prompts get the same fingerprint, so exact repeats stay
 * detectable; without the key a short prompt ("yes", "go on") cannot be guessed back from it.
 */
export function textFingerprint(text: string): string {
  return createHmac("sha256", fingerprintKey()).update(text).digest("hex").slice(0, 16);
}

let cachedKey: { path: string; key: Buffer } | null = null;
function fingerprintKey(): Buffer {
  const dir = join(process.env.CONTEXTENGINE_HOME || join(homedir(), ".contextengine"), "keys");
  const path = join(dir, "fingerprint.key");
  if (cachedKey?.path === path) return cachedKey.key;
  if (!existsSync(path)) {
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    try {
      writeFileSync(path, randomBytes(32).toString("hex"), { mode: 0o600, flag: "wx" });
    } catch {
      /* another process created it first: read theirs */
    }
  }
  cachedKey = { path, key: Buffer.from(readFileSync(path, "utf-8").trim(), "hex") };
  return cachedKey.key;
}

export interface RedactionResult {
  text: string;
  counts: Record<string, number>;
}

/** Replace every credential shape in `input`. Returns the new text and the count per shape. */
export function redactSecrets(input: string): RedactionResult {
  const counts: Record<string, number> = {};
  let text = input;
  for (const shape of SECRET_SHAPES) {
    shape.re.lastIndex = 0;
    text = text.replace(shape.re, (...args: unknown[]) => {
      const match = args[0] as string;
      const offset = args[args.length - 2] as number;
      const whole = args[args.length - 1] as string;
      const prefix = shape.keepPrefix ? String(args[1] ?? "") : "";
      const value = match.slice(prefix.length);
      if (value.startsWith("[REDACTED:")) return match; // already done: keeps a second pass a no-op
      if (shape.skip?.(value, whole.slice(offset + match.length))) return match;
      counts[shape.id] = (counts[shape.id] ?? 0) + 1;
      return `${prefix}[REDACTED:${shape.id}]`;
    });
  }
  return { text, counts };
}

/** Redact every string inside a JSON-like value, returning a copy and the merged counts. */
export function redactPayload<T>(value: T): { value: T; counts: Record<string, number>; changed: boolean } {
  const counts: Record<string, number> = {};
  const walk = (v: unknown): unknown => {
    if (typeof v === "string") {
      const r = redactSecrets(v);
      for (const [k, n] of Object.entries(r.counts)) counts[k] = (counts[k] ?? 0) + n;
      return r.text;
    }
    if (Array.isArray(v)) return v.map(walk);
    if (v && typeof v === "object") {
      const out: Record<string, unknown> = {};
      for (const [k, x] of Object.entries(v as Record<string, unknown>)) out[k] = walk(x);
      return out;
    }
    return v;
  };
  const out = walk(value) as T;
  return { value: out, counts, changed: Object.keys(counts).length > 0 };
}
