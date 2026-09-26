// LOCKED — verified March 3 2026 — activation + machine fingerprint + heartbeat
// DO NOT RE-AUDIT — E2E tested Feb 23 2026, all 4 Pro tools verified
//
// [LOCKED] [DELTA-RETIRED] — 2026-08-21
// [NEVER] reintroduce a client-side "delta bundle" (download, decrypt, cache, import premium code).
// WHY: from 0f12967 (2026-02-20) to 2.5.3 the client fetched an AES-encrypted bundle on activation,
//      wrote it to ~/.contextengine/delta/, and never imported it: loadDeltaModule() had no caller,
//      index.ts and cli.ts import agents.js / search.js / firewall.js from the package. Yet gateCheck
//      refused premium tools when the unused cache was missing, and a stale cache needed its own
//      guard (the former [DELTA-VERSION-PIN], 2026-08-14). Dead weight with live failure modes.
// FIX: the gate is the signed licence alone (Ed25519, machine-bound, expiry, daily heartbeat).
//      The moat is the gate plus BSL-1.1, as CLAUDE.md rule 3 states. Retired on Yan's decision,
//      SESSION_23. deactivate() still empties a legacy ~/.contextengine/delta/ so old caches go away.

/**
 * Activation System
 *
 * The npm package ships with core functionality (search, sessions, learnings,
 * operational collectors). PRO unlocks the four high-value tools that consume
 * collector + multi-project data.
 *
 * Free (no activation required):
 *   - search_context, list_sources, read_source, reindex
 *   - save/load/list/delete/end_session
 *   - save/list/delete/import_learning
 *   - Operational collectors run during reindex (PM2, nginx, Docker, git,
 *     cron, .env redacted, composer, systemd) — collected data is searchable
 *     via search_context
 *
 * Activation unlocks the four PRO tools that consume collected/multi-project
 * data and the HTML report generators:
 *   - list_projects (cross-project tech-stack analysis)
 *   - check_ports   (cross-project port conflict scan)
 *   - run_audit     (compliance audit with HTML report)
 *   - score_project (AI-readiness score + SCORE.md + score-report.html)
 *
 * On activation:
 *   1. License key is validated against the ContextEngine API
 *   2. Server returns a signed licence (Ed25519), saved to ~/.contextengine/license.json
 *   3. Premium tools become available
 * The server may still include a `delta` field in its response; it is ignored. [LOCK] [DELTA-RETIRED]
 */

import { existsSync, readFileSync, writeFileSync, mkdirSync, readdirSync, unlinkSync } from "fs";
import { join } from "path";
import { homedir } from "os";
import { createHash } from "crypto";
import { safeAppend } from "./audit.js";
import { verifyLicenseSignature } from "./license-sig.js";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

// Legacy cache location, only ever cleaned now. [LOCK] [DELTA-RETIRED]
const LEGACY_DELTA_DIR = join(homedir(), ".contextengine", "delta");
const LICENSE_FILE = join(homedir(), ".contextengine", "license.json");
const ACTIVATION_API_BASE = process.env.CONTEXTENGINE_API || "https://api.compr.ch/contextengine";
const ACTIVATION_API = `${ACTIVATION_API_BASE}/activate`;
const HEARTBEAT_INTERVAL_MS = 24 * 60 * 60 * 1000; // daily check

// NOTE: collectors.ts runs unconditionally during reindex for all users
// (operational data feeds search_context for everyone). The PRO tools in
// PREMIUM_TOOLS are what consume that data for scoring/audit/cross-project
// reports. Keep the gate at the tool layer, not the data-collection layer.

// Tools that require activation. Re-exported from the central manifest so
// the count and the name list have a SINGLE source of truth. Adding a new
// PRO tool requires editing src/tools-manifest.ts (which also feeds the
// VS Code extension's info panel via ~/.contextengine/server-meta.json).
import { PREMIUM_TOOL_NAMES } from "./tools-manifest.js";
export const PREMIUM_TOOLS = PREMIUM_TOOL_NAMES;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface LicenseInfo {
  key: string;
  email: string;
  plan: "community" | "pro" | "team" | "enterprise";
  activatedAt: string;
  expiresAt: string;
  machineId: string;
  lastHeartbeat: string;
  deltaVersion: string;
  signature: string;
  /** Since 2.10.0: the first failed licence check since the last good one. [LOCK] [LICENSE-IS-CHECKED-DAILY] */
  offlineSince?: string;
  /** Since 2.10.0: the first of consecutive refusals by the licence server (grace before revoked). */
  refusedSince?: { at: string; reason: string };
  /** Since 2.10.0: refused for longer than the grace (refund, expiry, revoked machine). */
  revoked?: { at: string; reason: string };
  /** Since 2.10.0: when the next licence check is due. */
  nextCheck?: string;
}

interface ActivationResponse {
  success: boolean;
  license: LicenseInfo;
  error?: string;
}

// ---------------------------------------------------------------------------
// Machine fingerprint (non-PII)
// ---------------------------------------------------------------------------

function getMachineId(): string {
  const components = [
    process.platform,
    process.arch,
    homedir().split("/").slice(0, 3).join("/"), // just /Users/xxx level
    process.env.USER || process.env.USERNAME || "unknown",
  ];
  return createHash("sha256")
    .update(components.join("|"))
    .digest("hex")
    .slice(0, 16);
}

// ---------------------------------------------------------------------------
// License management
// ---------------------------------------------------------------------------

export function loadLicense(): LicenseInfo | null {
  try {
    if (!existsSync(LICENSE_FILE)) return null;
    const data = JSON.parse(readFileSync(LICENSE_FILE, "utf-8"));

    // Check expiry
    if (new Date(data.expiresAt) < new Date()) {
      console.error("[ContextEngine] ⚠ License expired — premium features disabled");
      return null;
    }

    // Refused by the licence server at the last check. [LOCK] [LICENSE-IS-CHECKED-DAILY]
    if (data.revoked) {
      console.error(`[ContextEngine] ⛔ License refused by the licence server on ${data.revoked.at} (${data.revoked.reason}) — premium features disabled. Run activate again after renewing.`);
      return null;
    }

    // Verify machine binding
    if (data.machineId !== getMachineId()) {
      console.error("[ContextEngine] ⚠ License bound to different machine");
      return null;
    }

    // Verify Ed25519 signature. Three outcomes:
    //   ed25519              → cryptographically verified, full trust
    //   legacy-grandfathered → pre-Ed25519 SHA-256 hash, allowed until flag day
    //   reject               → tampered / wrong keypair / missing signature
    const verify = verifyLicenseSignature(data);
    if (!verify.ok) {
      console.error(
        `[ContextEngine] ⛔ License signature rejected — ${verify.reason}. Premium features disabled. ` +
        `Reactivate at https://api.compr.ch/contextengine/pricing if this surprises you.`,
      );
      safeAppend("activation.signature_reject", {
        plan: data.plan,
        machine_id: data.machineId,
        reason: verify.reason,
      });
      return null;
    }
    // The legacy-grandfathered branch is no longer reachable since the
    // 2026-06-11 flag day — legacy SHA-256 signatures now return ok:false
    // and are rejected above. Branch kept defensively in case the type
    // union ever changes (zero cost; dead in 2.0.1+).
    if (verify.mode === "legacy-grandfathered") {
      console.error(`[ContextEngine] ⚠ ${verify.warning}`);
      safeAppend("activation.legacy_signature", {
        plan: data.plan,
        machine_id: data.machineId,
      });
    }

    return data as LicenseInfo;
  } catch {
    return null;
  }
}

function saveLicense(license: LicenseInfo): void {
  const dir = join(homedir(), ".contextengine");
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
  writeFileSync(LICENSE_FILE, JSON.stringify(license, null, 2));
}

// ---------------------------------------------------------------------------
// Activation flow
// ---------------------------------------------------------------------------

// 🔒 LOCKED [ACTIVATION-PAYLOAD-NO-USAGE-DATA] — 2026-06-24
// ⛔ NEVER add fields to the activation POST body that reflect user
//    USAGE — no project paths, no prompt text, no response text, no
//    tool-call inventory, no file lists, no learning IDs, no audit-log
//    sample, no anything that describes what the customer is doing with
//    OpsContext. The activation server's job is license validation,
//    nothing else.
// ⛔ NEVER share this list with marketing tools (Stripe customer record
//    is the ONLY place email lands; never join it to usage data).
// WHY: This is the LOAD-BEARING commitment of docs/about.md §
//    "Marketing-data isolation". Customers using OpsContext are NOT and
//    WILL NOT be associated with any marketing audience operated by
//    PROD LLC or any sibling brand (CROWLR, KONIVE, INVOC, FASTPROD,
//    compR). Adding a single usage field here breaks that contract
//    silently and starts a slow drift toward telemetry — exactly the
//    posture this product was designed to NOT have.
// FIX: If a future feature legitimately needs server-side telemetry
//    (e.g. a "drift alerts emailed daily" subscription), it requires
//    EXPLICIT per-user opt-in via a separate endpoint with its own
//    payload schema — NOT bundling fields into the license-activation
//    path that every PRO customer hits unconditionally.
export async function activate(licenseKey: string, email: string): Promise<{
  success: boolean;
  message: string;
  plan?: string;
}> {
  try {
    const machineId = getMachineId();

    const response = await fetch(ACTIVATION_API, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        // The 6 fields below are the COMPLETE set the activation server
        // ever sees. Read the LOCK above before adding a 7th.
        key: licenseKey,
        email,
        machineId,
        version: getPackageVersion(),
        platform: process.platform,
        arch: process.arch,
      }),
    });

    if (!response.ok) {
      const text = await response.text();
      return { success: false, message: `Activation failed: ${response.status} ${text}` };
    }

    const data = (await response.json()) as ActivationResponse;

    if (!data.success) {
      return { success: false, message: data.error || "Activation rejected" };
    }

    // Save license
    saveLicense(data.license);

    safeAppend("activation.activate", {
      plan: data.license.plan,
      email: data.license.email,
      machine_id: data.license.machineId,
      expires_at: data.license.expiresAt,
      delta_version: data.license.deltaVersion,
    });

    return {
      success: true,
      message: `✅ Activated! Plan: ${data.license.plan}, expires: ${data.license.expiresAt}`,
      plan: data.license.plan,
    };
  } catch (err) {
    return { success: false, message: `Activation error: ${(err as Error).message}` };
  }
}

// ---------------------------------------------------------------------------
// Heartbeat — periodic license validation
// ---------------------------------------------------------------------------

// [LOCKED] [LICENSE-IS-CHECKED-DAILY] - 2026-09-25
// [NEVER] let a non-refusal (network error, 429, 5xx, 404, a proxy page) cancel a licence, cancel on
//         a single refusal, or let the gate run without the scheduled check being attempted.
// WHY: heartbeat() existed and was never called: 0 callers. A refunded or revoked licence kept
//      every Pro tool until its expiry date, and a licence last checked in 2000 still scored in a
//      sandbox (E2E_REVIEW_2026-09 A4-2). The owner chose to switch it on, with 7 days of grace.
//      A first version cancelled on the first refusal; since no licence had ever been checked, a
//      licence missing from the server's database by mistake (a restore, a hand-made test key)
//      would have lost Pro at the first check after the upgrade, with no warning.
// FIX: gateCheckFresh() runs the check before the gate when it is due: 24 h after a success, 1 h
//      after a failure (so an offline user is not delayed 5 s on every call), at once when never
//      checked or when the date is in the future (an edited file). Only the server's explicit
//      refusal (403 with valid:false, server/src/server.ts) counts as one; the licence is revoked
//      once refusals have lasted REFUSAL_GRACE_DAYS, and a success in between clears them.
//      Anything else starts offlineSince, and the gate refuses once the server has been
//      unreachable for more than OFFLINE_GRACE_DAYS since the first failed check. Both states show
//      in activation_status. The payload is unchanged: [ACTIVATION-PAYLOAD-NO-USAGE-DATA].
const OFFLINE_GRACE_DAYS = 7;
const REFUSAL_GRACE_DAYS = 3;
const RETRY_AFTER_FAILURE_MS = 60 * 60 * 1000;
export type HeartbeatOutcome = "fresh" | "valid" | "refused" | "revoked" | "unreachable" | "no_license";

function scheduleNext(license: LicenseInfo, afterMs: number): void {
  license.nextCheck = new Date(Date.now() + afterMs).toISOString();
}

export async function heartbeat(opts: { force?: boolean; timeoutMs?: number } = {}): Promise<HeartbeatOutcome> {
  const license = loadLicense();
  if (!license) return "no_license";

  const now = Date.now();
  const next = license.nextCheck ? Date.parse(license.nextCheck) : NaN;
  // Due when never scheduled, past its time, or scheduled further out than a day (an edited file).
  if (!opts.force && Number.isFinite(next) && now < next && next - now <= HEARTBEAT_INTERVAL_MS + 60_000) return "fresh";

  let response: Response;
  try {
    response = await fetch(`${ACTIVATION_API_BASE}/heartbeat`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        key: license.key,
        machineId: getMachineId(),
        deltaVersion: license.deltaVersion,
      }),
      signal: AbortSignal.timeout(opts.timeoutMs ?? 5_000),
    });
  } catch {
    return markUnreachable(license);
  }

  if (response.ok) {
    license.lastHeartbeat = new Date().toISOString();
    delete license.offlineSince;
    delete license.refusedSince;
    scheduleNext(license, HEARTBEAT_INTERVAL_MS);
    saveLicense(license);
    safeAppend("activation.heartbeat", { plan: license.plan, machine_id: license.machineId, outcome: "valid" });
    return "valid";
  }
  if (response.status === 403) {
    let body: { valid?: boolean; error?: string } | null = null;
    try {
      body = (await response.json()) as { valid?: boolean; error?: string };
    } catch {
      /* not the server's answer */
    }
    if (body && body.valid === false) {
      const reason = String(body.error ?? "refused");
      delete license.offlineSince; // the server answered
      if (!license.refusedSince) license.refusedSince = { at: new Date().toISOString(), reason };
      const refusedDays = (Date.now() - Date.parse(license.refusedSince.at)) / 86_400_000;
      if (refusedDays > REFUSAL_GRACE_DAYS) {
        license.revoked = { at: new Date().toISOString(), reason };
        saveLicense(license);
        safeAppend("activation.heartbeat", { plan: license.plan, machine_id: license.machineId, outcome: "revoked", reason });
        console.error(`[ContextEngine] ⛔ The licence server has refused this licence since ${license.refusedSince.at} (${reason}) — premium features disabled.`);
        return "revoked";
      }
      scheduleNext(license, RETRY_AFTER_FAILURE_MS);
      saveLicense(license);
      safeAppend("activation.heartbeat", { plan: license.plan, machine_id: license.machineId, outcome: "refused", reason });
      console.error(`[ContextEngine] ⚠ The licence server refused this licence (${reason}). Premium features stop after ${REFUSAL_GRACE_DAYS} days of refusals unless it is renewed or re-activated.`);
      return "refused";
    }
  }
  return markUnreachable(license);
}

function markUnreachable(license: LicenseInfo): HeartbeatOutcome {
  if (!license.offlineSince) license.offlineSince = new Date().toISOString();
  scheduleNext(license, RETRY_AFTER_FAILURE_MS);
  saveLicense(license);
  return "unreachable";
}

/** Days the licence server has been unreachable since the first failed check; 0 when it was reached. */
function offlineDays(license: LicenseInfo): number {
  if (!license.offlineSince) return 0;
  const since = Date.parse(license.offlineSince);
  return Number.isFinite(since) ? (Date.now() - since) / 86_400_000 : 0;
}

/** Where the licence check stands, for activation_status. */
export function licenceCheckState(): string {
  const license = loadLicense();
  if (!license) return "no licence";
  if (license.refusedSince) return `refused by the licence server since ${license.refusedSince.at} (${license.refusedSince.reason}); Pro stops after ${REFUSAL_GRACE_DAYS} days of refusals`;
  if (license.offlineSince) return `licence server unreachable since ${license.offlineSince}; Pro stops after ${OFFLINE_GRACE_DAYS} days`;
  return `last confirmed ${license.lastHeartbeat}${license.nextCheck ? `, next check after ${license.nextCheck}` : ", checked at the next Pro tool call"}`;
}

// ---------------------------------------------------------------------------
// Deactivation
// ---------------------------------------------------------------------------

export function deactivate(): void {
  const prior = loadLicense();

  // Remove license
  if (existsSync(LICENSE_FILE)) unlinkSync(LICENSE_FILE);

  // Remove a legacy delta cache if one is still around. [LOCK] [DELTA-RETIRED]
  if (existsSync(LEGACY_DELTA_DIR)) {
    for (const file of readdirSync(LEGACY_DELTA_DIR)) {
      unlinkSync(join(LEGACY_DELTA_DIR, file));
    }
  }

  safeAppend("activation.deactivate", {
    prior_plan: prior?.plan ?? null,
    prior_email: prior?.email ?? null,
    machine_id: prior?.machineId ?? null,
  });

  console.error("[ContextEngine] 🔒 Deactivated — premium features removed");
}

// ---------------------------------------------------------------------------
// Status
// ---------------------------------------------------------------------------

export function getActivationStatus(): {
  activated: boolean;
  plan: string;
  expiresAt: string;
  deltaVersion: string;
  premiumTools: string[];
  machineId: string;
} {
  const license = loadLicense();

  if (!license) {
    return {
      activated: false,
      plan: "community",
      expiresAt: "n/a",
      deltaVersion: "n/a",
      premiumTools: [],
      machineId: getMachineId(),
    };
  }
  
  return {
    activated: true,
    plan: license.plan,
    expiresAt: license.expiresAt,
    deltaVersion: license.deltaVersion,
    premiumTools: [...PREMIUM_TOOLS],
    machineId: getMachineId(),
  };
}

/**
 * Check if a specific tool requires activation.
 */
export function requiresActivation(toolName: string): boolean {
  return (PREMIUM_TOOLS as readonly string[]).includes(toolName);
}

/**
 * Gate check — returns error message if tool requires activation but isn't activated.
 * Returns null if tool is available.
 */
export function gateCheck(toolName: string): string | null {
  if (!requiresActivation(toolName)) return null;
  
  const license = loadLicense();
  if (!license) {
    return `🔒 "${toolName}" requires a ContextEngine Pro license.\n\n` +
      `Activate with: npx contextengine activate <license-key> <email>\n` +
      `Get a license: https://api.compr.ch/contextengine/pricing\n\n` +
      `Free tools available: search_context, list_sources, read_source, reindex, ` +
      `save_session, load_session, list_sessions, end_session, save_learning, ` +
      `list_learnings, import_learnings`;
  }

  // [LOCK] [LICENSE-IS-CHECKED-DAILY]: past the grace, an unreachable licence server means no Pro.
  const days = offlineDays(license);
  if (days > OFFLINE_GRACE_DAYS) {
    return `🔒 "${toolName}" needs a licence check, and the licence server has not been reachable for ${Math.floor(days)} days ` +
      `(since ${license.offlineSince}). Connect to the internet and run it again.`;
  }

  return null;
}

/** The gate, after the daily licence check when one is due. Use this, not gateCheck, before a Pro tool. */
export async function gateCheckFresh(toolName: string): Promise<string | null> {
  if (requiresActivation(toolName) && loadLicense()) await heartbeat();
  return gateCheck(toolName);
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function getPackageVersion(): string {
  try {
    const pkgPath = join(import.meta.url.replace("file://", ""), "..", "..", "package.json");
    const pkg = JSON.parse(readFileSync(pkgPath, "utf-8"));
    return pkg.version || "unknown";
  } catch {
    return "unknown";
  }
}
