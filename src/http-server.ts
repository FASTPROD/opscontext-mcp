// 🔒 LOCKED [HTTP-EVENT-INGEST] — 2026-06-23
// ⛔ NEVER bind to 0.0.0.0 — only 127.0.0.1. The threat model is "browser
//    extension running on the same machine"; a network-reachable port would
//    let any device on the LAN inject audit events.
// ⛔ NEVER compare the secret with `===` — use timingSafeEqual. String compare
//    leaks timing info that lets a remote attacker brute-force the secret
//    one byte at a time.
// ⛔ NEVER auto-generate the secret on first request. The CLI must create it
//    explicitly (so a stray client can't bootstrap itself into the audit log).
//    Refuse with 401 if ~/.contextengine/extension-secret is missing.
// ⛔ NEVER write events before validating shape — a malformed event in the
//    audit log corrupts the chain verifier and ruins compliance evidence.
// WHY: This is the only network surface OpsContext exposes locally. Every
//    decision here is about keeping it auth-required, scope-bound, and shape-
//    validated, because the audit log is the foundation everything else
//    builds on.
// FIX: To add more endpoints, follow the same auth + validation pattern. Do
//    not add a /raw-write or /admin route without a separate secret + a
//    separate LOCK comment explaining why.

import * as http from "http";
import { existsSync, readFileSync } from "fs";
import { join } from "path";
import { homedir } from "os";
import { timingSafeEqual } from "crypto";
import { safeAppend, type AuditEvent } from "./audit.js";
import { redactPayload, textFingerprint } from "./secret-shapes.js";

const PORT = parseInt(process.env.OPSCONTEXT_EVENT_PORT || "7842", 10);
const HOST = "127.0.0.1";
const SECRET_FILE = join(homedir(), ".contextengine", "extension-secret");
const MAX_BODY = 64 * 1024; // 64 KB per batch
const MAX_BATCH = 50;

// [LOCKED] [RECEIVER-ACCEPTS-ONLY-KNOWN-SENDERS] - 2026-09-25
// [NEVER] widen the accepted kinds back to a prefix, accept a reserved actor, answer a web page's
//         origin, or drop the rate cap.
// WHY: E2E_REVIEW_2026-09 A2-2 to A2-4, measured on a sandbox receiver: any web page could read
//      /health (Access-Control-Allow-Origin: *, and any Host header answered, the DNS-rebinding
//      shape), so a site could tell OpsContext was installed; a sender holding the secret could
//      write `cli.anything`, a bare `vscode.`, and actor "system"; and one local sender wrote
//      10,000 valid records in 1.36 s (+12.8 MB) with nothing to slow it, noise that verifies as
//      a valid chain and would bury real events past rotation in seconds.
// FIX: exactly the capture kinds the hook and the extensions send (CAPTURE_EVENT_KINDS); an actor
//      is a short slug and never "system" or "cli" (the server's and the CLI's own names); CORS
//      headers only for browser-extension origins (the extension posts from its service worker,
//      which needs none); Host must name this machine; a token bucket of BURST records refilled
//      at RATE per second, the excess refused with 429 (the extension keeps and retries a refused
//      batch) and counted in one ingest.rate_limited record per minute.
export const CAPTURE_EVENT_KINDS: readonly AuditEvent[] = [
  "browser.prompt",
  "browser.response",
  "browser.tool_call",
  "browser.session_start",
  "browser.session_end",
  "browser.capture_miss",
  "vscode.prompt_submit",
  "vscode.tool_call",
  "vscode.session_start",
];
const RESERVED_ACTORS = new Set(["system", "cli"]);
const ACTOR_RE = /^[a-z][a-z0-9-]{1,31}$/;
const RATE_PER_SEC = 200;
const BURST = 1000;

/** An event kind and actor the door accepts, or why not. Shared with `contextengine emit-event`. */
export function checkCaptureEvent(kind: unknown, actor: unknown, opts: { allowCliActor?: boolean } = {}): string | null {
  if (typeof kind !== "string" || !(CAPTURE_EVENT_KINDS as readonly string[]).includes(kind)) {
    return `event kind '${String(kind)}' not accepted (one of: ${CAPTURE_EVENT_KINDS.join(", ")})`;
  }
  if (actor === undefined) return null;
  if (typeof actor !== "string" || !ACTOR_RE.test(actor)) return `actor must be a short lowercase name`;
  if (RESERVED_ACTORS.has(actor) && !(opts.allowCliActor && actor === "cli")) return `actor '${actor}' is reserved`;
  return null;
}

/** Origins that may read responses: browser extensions only, never a web page. */
function corsHeaders(req: http.IncomingMessage): Record<string, string> {
  const origin = req.headers.origin;
  if (typeof origin !== "string" || !/^(?:chrome|moz|safari-web)-extension:\/\/[\w.-]+$/.test(origin)) return {};
  return {
    "Access-Control-Allow-Origin": origin,
    Vary: "Origin",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, X-OpsContext-Secret",
  };
}

/** A Host header that names this machine, or none (not a browser). */
function hostIsLocal(req: http.IncomingMessage, port: number): boolean {
  const host = req.headers.host;
  if (host === undefined) return true;
  return [`127.0.0.1:${port}`, `localhost:${port}`].includes(host.toLowerCase());
}

const bucket = { tokens: BURST, at: Date.now(), dropped: 0, droppedSince: "" };
/** Takes `n` tokens if there are enough; refills at RATE_PER_SEC up to BURST. */
function takeTokens(n: number): boolean {
  const now = Date.now();
  bucket.tokens = Math.min(BURST, bucket.tokens + ((now - bucket.at) / 1000) * RATE_PER_SEC);
  bucket.at = now;
  if (bucket.tokens < n) {
    if (bucket.dropped === 0) bucket.droppedSince = new Date(now).toISOString();
    bucket.dropped += n;
    return false;
  }
  bucket.tokens -= n;
  return true;
}
function flushDroppedCount(): void {
  if (bucket.dropped === 0) return;
  safeAppend("ingest.rate_limited", { dropped: bucket.dropped, since: bucket.droppedSince, rate_per_sec: RATE_PER_SEC, burst: BURST });
  bucket.dropped = 0;
}

let serverInstance: http.Server | null = null;

interface IncomingEvent {
  v?: number;
  ts?: string;
  event?: string;
  actor?: string;
  payload?: Record<string, unknown>;
}

interface IncomingBatch {
  events: IncomingEvent[];
}

/** Hot-reload the secret from disk so the CLI can rotate without restarting MCP. */
function loadSecret(): string | null {
  try {
    if (!existsSync(SECRET_FILE)) return null;
    return readFileSync(SECRET_FILE, "utf-8").trim();
  } catch {
    return null;
  }
}

function constantTimeEqual(a: string, b: string): boolean {
  // timingSafeEqual requires equal-length buffers — short-circuit on mismatch
  // length but only via Buffer.byteLength so we don't leak via string-length
  // comparison early-exit. Acceptable because length isn't a secret.
  if (a.length !== b.length) return false;
  try {
    return timingSafeEqual(Buffer.from(a), Buffer.from(b));
  } catch {
    return false;
  }
}

/** Validate an event has the minimum shape we'll write to audit. */
function validateEvent(e: IncomingEvent, idx: number): string | null {
  if (typeof e !== "object" || e === null) return `events[${idx}]: not an object`;
  if (e.v !== 1) return `events[${idx}]: missing or unsupported version field (v=${e.v})`;
  if (typeof e.event !== "string" || !e.event) return `events[${idx}]: missing event kind`;
  if (typeof e.ts !== "string" || !e.ts) return `events[${idx}]: missing ts`;
  if (typeof e.payload !== "object" || e.payload === null) return `events[${idx}]: missing payload object`;
  // Only the capture kinds, never the audit module's own (learning.save, audit.redact, ...), which
  // come from the LOCAL server. [LOCK] [RECEIVER-ACCEPTS-ONLY-KNOWN-SENDERS]
  const err = checkCaptureEvent(e.event, e.actor);
  return err ? `events[${idx}]: ${err}` : null;
}

/**
 * The payload as it will be written: every string redacted, and the per-shape counts recorded
 * under `redacted_at_ingest` when anything was removed. The only path from the network to the
 * log. [LOCK] [CAPTURE-IS-REDACTED-AT-THE-DOOR] (src/secret-shapes.ts)
 */
export function prepareCapturedPayload(payload: Record<string, unknown>, event?: string): Record<string, unknown> {
  const { value, counts, changed } = redactPayload(dropPromptText(payload, event));
  return changed ? { ...value, redacted_at_ingest: counts } : value;
}

/**
 * [LOCKED] [PROMPT-TEXT-IS-NOT-KEPT] - 2026-09-25
 * [NEVER] write the text of a prompt or an AI response to the audit log by default.
 * WHY: the owner's decision, 2026-09-25. The text fed one feature, the loop and drift alarm, which
 *      fired 0 times in three months of real use; meanwhile it held the owner's typed passwords
 *      and logins. A record of "prompt sent at 10:02, 340 characters" keeps the evidence of
 *      activity without keeping what was said.
 * FIX: prompts (vscode.prompt_submit, browser.prompt) and responses (browser.response) keep their
 *      length and a keyed fingerprint (textFingerprint), so an exact repeat is still detectable.
 *      Commands and tool input stay, redacted: they are the record of what an agent did.
 *      OPSCONTEXT_KEEP_PROMPT_TEXT=1 keeps the (redacted) text, for someone who wants it.
 */
const PROMPT_TEXT_EVENTS = new Set(["vscode.prompt_submit", "browser.prompt", "browser.response"]);

function dropPromptText(payload: Record<string, unknown>, event?: string): Record<string, unknown> {
  if (!event || !PROMPT_TEXT_EVENTS.has(event) || process.env.OPSCONTEXT_KEEP_PROMPT_TEXT === "1") return payload;
  if (typeof payload.text !== "string") return payload;
  const { text, ...rest } = payload;
  return {
    ...rest,
    char_count: typeof rest.char_count === "number" ? rest.char_count : text.length,
    text_fingerprint: textFingerprint(text),
  };
}

function sendJson(req: http.IncomingMessage, res: http.ServerResponse, status: number, body: unknown, extra: Record<string, string> = {}) {
  const json = JSON.stringify(body);
  res.writeHead(status, {
    "Content-Type": "application/json",
    "Content-Length": Buffer.byteLength(json),
    // Only a browser extension's origin gets CORS headers; the service worker needs none (its
    // host_permissions cover the endpoint). [LOCK] [RECEIVER-ACCEPTS-ONLY-KNOWN-SENDERS]
    ...corsHeaders(req),
    ...extra,
  });
  res.end(json);
}

function handleEvents(req: http.IncomingMessage, res: http.ServerResponse) {
  const secret = loadSecret();
  if (!secret) {
    sendJson(req, res, 401, {
      ok: false,
      error: "no_secret_configured",
      hint: "Run: contextengine init-extension-secret",
    });
    return;
  }
  const provided = req.headers["x-opscontext-secret"];
  if (typeof provided !== "string" || !constantTimeEqual(provided, secret)) {
    sendJson(req, res, 401, { ok: false, error: "bad_secret" });
    return;
  }

  let bytes = 0;
  let tooLarge = false;
  const chunks: Buffer[] = [];
  req.on("data", (chunk: Buffer) => {
    if (tooLarge) return;
    bytes += chunk.length;
    if (bytes > MAX_BODY) {
      // Answer first, then drop the connection: destroying before the reply sent the client a
      // bare reset instead of the 413 (E2E_REVIEW_2026-09 A2-5).
      tooLarge = true;
      chunks.length = 0;
      res.on("finish", () => req.destroy());
      sendJson(req, res, 413, { ok: false, error: "payload_too_large", limit: MAX_BODY }, { Connection: "close" });
      return;
    }
    chunks.push(chunk);
  });
  req.on("end", () => {
    if (tooLarge) return;
    let batch: IncomingBatch;
    try {
      batch = JSON.parse(Buffer.concat(chunks).toString("utf-8"));
    } catch {
      sendJson(req, res, 400, { ok: false, error: "bad_json" });
      return;
    }
    if (!batch || !Array.isArray(batch.events)) {
      sendJson(req, res, 400, { ok: false, error: "missing_events_array" });
      return;
    }
    if (batch.events.length > MAX_BATCH) {
      sendJson(req, res, 400, { ok: false, error: "batch_too_large", limit: MAX_BATCH });
      return;
    }
    // Validate every event BEFORE writing any of them.
    for (let i = 0; i < batch.events.length; i++) {
      const err = validateEvent(batch.events[i], i);
      if (err) {
        sendJson(req, res, 400, { ok: false, error: "invalid_event", detail: err });
        return;
      }
    }
    // [LOCK] [RECEIVER-ACCEPTS-ONLY-KNOWN-SENDERS]: a brake on any one flood, a runaway hook included.
    if (!takeTokens(batch.events.length)) {
      sendJson(req, res, 429, { ok: false, error: "rate_limited", retry_after_ms: 1000 }, { "Retry-After": "1" });
      return;
    }
    // All valid — write them to audit log via safeAppend.
    let written = 0;
    for (const ev of batch.events) {
      const actor = typeof ev.actor === "string" ? ev.actor : "browser-ext";
      // event/payload were validated above — cast is safe.
      // [LOCK] [CAPTURE-IS-REDACTED-AT-THE-DOOR]: redact before the append, never after.
      safeAppend(ev.event as AuditEvent, prepareCapturedPayload(ev.payload!, ev.event), actor);
      written++;
    }
    sendJson(req, res, 200, { ok: true, written });
  });
}

function handleHealth(req: http.IncomingMessage, res: http.ServerResponse) {
  sendJson(req, res, 200, {
    ok: true,
    service: "opscontext-event-ingest",
    port: PORT,
    secretConfigured: loadSecret() !== null,
  });
}

function handleOptions(req: http.IncomingMessage, res: http.ServerResponse) {
  // CORS preflight: answered for a browser extension's origin only.
  res.writeHead(204, { ...corsHeaders(req), ...(req.headers.origin ? { "Access-Control-Max-Age": "600" } : {}) });
  res.end();
}

export interface IngestOptions {
  /** This process is the launchd agent (OPSCONTEXT_DAEMON=1): it keeps trying until it holds the port. */
  daemon?: boolean;
  /** Told the port when this server starts holding it, null when it lets it go (the registry). */
  onPortChange?: (port: number | null) => void;
  /** The pid of a live launchd agent other than this process, or null. */
  liveDaemon?: () => number | null;
  /** Tests only: how often to retry the bind, and how often a holder checks for the agent. */
  retryMs?: number;
  handoverMs?: number;
}

let retryTimer: NodeJS.Timeout | null = null;
let handoverTimer: NodeJS.Timeout | null = null;
let rateTimer: NodeJS.Timeout | null = null;
let warnedInUse = false;

/** One bind attempt. Resolves the port, or null when the port is taken or the bind failed. */
function listenOnce(): Promise<number | null> {
  return new Promise((resolve) => {
    const srv = http.createServer((req, res) => {
      try {
        if (!hostIsLocal(req, PORT)) return sendJson(req, res, 403, { ok: false, error: "bad_host" });
        if (req.method === "OPTIONS") return handleOptions(req, res);
        const url = req.url || "/";
        if (req.method === "POST" && url.startsWith("/events")) return handleEvents(req, res);
        if (req.method === "GET" && url.startsWith("/health")) return handleHealth(req, res);
        sendJson(req, res, 404, { ok: false, error: "not_found" });
      } catch (err) {
        console.error("[ContextEngine] event-ingest error:", err);
        try {
          sendJson(req, res, 500, { ok: false, error: "internal" });
        } catch {
          /* ignore — response may already be closed */
        }
      }
    });
    srv.on("error", (err: NodeJS.ErrnoException) => {
      if (err.code === "EADDRINUSE") {
        if (!warnedInUse) {
          warnedInUse = true;
          console.error(
            `[ContextEngine] ⚠ port ${PORT} already in use — browser-event ingest waits for it (retrying).\n` +
              `  Set OPSCONTEXT_EVENT_PORT=<n> to use a different port (must also update extension options).`,
          );
        }
        resolve(null);
        return;
      }
      console.error("[ContextEngine] event-ingest server error:", err);
      resolve(null);
    });
    srv.listen(PORT, HOST, () => {
      serverInstance = srv;
      warnedInUse = false;
      console.error(
        `[ContextEngine] 🌐 event-ingest on http://${HOST}:${PORT} ` +
          (loadSecret() ? "(secret loaded)" : "(NO SECRET — run `contextengine init-extension-secret`)"),
      );
      resolve(PORT);
    });
  });
}

function closeListener(): Promise<void> {
  return new Promise((resolve) => {
    if (!serverInstance) return resolve();
    const srv = serverInstance;
    serverInstance = null;
    srv.close(() => resolve());
    srv.closeAllConnections?.();
  });
}

/**
 * Boot the local event-ingest HTTP server. Resolves the listening port, or null when the port is
 * taken; in that case it keeps retrying in the background (see below).
 *
 * [LOCKED] [EVENT-PORT-BELONGS-TO-THE-DAEMON] - 2026-09-25
 * [NEVER] give up on the port after one failed bind, or keep it in a chat server while the
 *         launchd agent is alive.
 * WHY: [AUTOSTART-IS-THE-STANDING-INDEXER] meant the agent to own the port from boot, but it bound
 *      once and gave up. On 2026-09-25 the agent (v2.9.1) held nothing while a chat server on a
 *      stale 2.9.0 build held :7842: the redaction guarding the audit log ran whichever build had
 *      grabbed the port first, for as long as that chat stayed open, and events were dropped
 *      silently once it closed. Nothing recorded who held it (E2E_REVIEW_2026-09 A2-1).
 * FIX: the agent retries every few seconds until it binds; any other server retries only while
 *      no agent is alive; a chat server that holds the port hands it over as soon as an agent is
 *      registered; the holder is written into its registry record, and `contextengine servers`
 *      shows it and warns about a stale or non-agent holder.
 *
 * Safe to call multiple times — a second call returns the existing server.
 */
export function startEventIngestServer(opts: IngestOptions = {}): Promise<number | null> {
  if (serverInstance) {
    const addr = serverInstance.address();
    return Promise.resolve(typeof addr === "object" && addr ? addr.port : PORT);
  }
  const liveDaemon = opts.liveDaemon ?? (() => null);
  const retryMs = opts.retryMs ?? (opts.daemon ? 5_000 : 15_000);
  const handoverMs = opts.handoverMs ?? 10_000;
  let attempting = false;

  const held = (port: number) => {
    opts.onPortChange?.(port);
    if (!rateTimer) {
      rateTimer = setInterval(flushDroppedCount, 60_000);
      rateTimer.unref();
    }
    if (!opts.daemon && !handoverTimer) {
      handoverTimer = setInterval(() => {
        const agent = liveDaemon();
        if (agent === null || !serverInstance) return;
        if (handoverTimer) clearInterval(handoverTimer);
        handoverTimer = null;
        console.error(`[ContextEngine] 🌐 handing the event port :${PORT} to the launchd agent (pid ${agent})`);
        void closeListener().then(() => {
          opts.onPortChange?.(null);
          retry();
        });
      }, handoverMs);
      handoverTimer.unref();
    }
  };
  const retry = () => {
    if (retryTimer) return;
    retryTimer = setInterval(() => {
      if (serverInstance || attempting) return;
      if (!opts.daemon && liveDaemon() !== null) return; // the agent's port: leave it to it
      attempting = true;
      void listenOnce().then((port) => {
        attempting = false;
        if (port === null) return;
        if (retryTimer) clearInterval(retryTimer);
        retryTimer = null;
        held(port);
      });
    }, retryMs);
    retryTimer.unref();
  };

  // A chat server does not take the port from under a live agent, not even at start.
  if (!opts.daemon && liveDaemon() !== null) {
    retry();
    return Promise.resolve(null);
  }
  return listenOnce().then((port) => {
    if (port === null) retry();
    else held(port);
    return port;
  });
}

export function stopEventIngestServer(): Promise<void> {
  for (const t of [retryTimer, handoverTimer, rateTimer]) if (t) clearInterval(t);
  retryTimer = handoverTimer = rateTimer = null;
  flushDroppedCount();
  return closeListener();
}

// Test helpers (not exported in dist surface in production use — but the
// module is small enough that tests can import them directly).
export const _internal = {
  prepareCapturedPayload,
  loadSecret,
  constantTimeEqual,
  validateEvent,
  SECRET_FILE,
  PORT,
};
