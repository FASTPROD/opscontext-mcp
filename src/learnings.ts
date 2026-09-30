// LOCKED — verified March 3 2026 — learning store: quality gates, auto-categorize, dedup, project-scoped filtering
// DO NOT RE-AUDIT — min 15 chars, inferCategory(), autoImportFromSources() all verified v1.19.1

import { existsSync, readFileSync, writeFileSync, mkdirSync, renameSync, copyFileSync, rmSync, statSync, readdirSync, unlinkSync } from "fs";
import { join, dirname } from "path";
import { homedir } from "os";
import { fileURLToPath } from "url";
import { Chunk } from "./ingest.js";
import { safeAppend } from "./audit.js";
import { trustedProjects, looksLikeMarkedLearnings } from "./trusted-projects.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

/**
 * Learning Store — permanent operational rules that persist forever.
 *
 * Unlike sessions (ephemeral per-conversation context), learnings are
 * **permanent rules** discovered during coding sessions. They get
 * auto-indexed and surfaced via search_context so AI agents don't
 * repeat the same mistakes.
 *
 * Storage: ~/.contextengine/learnings.json
 *
 * Examples:
 * - "Always restart Flask backend after model changes — stale to_dict()"
 * - "Expo --port flag only controls Metro, NOT webpack dev server"
 * - "macOS sandbox blocks ~/Downloads access from VS Code terminal"
 * - "Unicode NFC vs NFD causes false mismatches on Google Drive vs APFS"
 */

const LEARNINGS_PATH = join(process.env.CONTEXTENGINE_HOME || join(homedir(), ".contextengine"), "learnings.json");

export interface Learning {
  id: string;
  category: string;
  rule: string;
  context: string;
  project?: string;
  tags: string[];
  created: string;
  updated: string;
  /** Where an imported record came from (absolute file path). Absent on agent-saved records. */
  source?: string;
}

export interface LearningsStore {
  version: number;
  count: number;
  learnings: Learning[];
  /** Bundled default rules (lowercased, trimmed) the owner deleted: never merged back.
   *  [LOCK] [A-READ-NEVER-WRITES-THE-STORE] */
  dismissed_defaults?: string[];
}

/** Valid categories for learnings */
export const LEARNING_CATEGORIES = [
  "deployment",
  "api",
  "database",
  "frontend",
  "backend",
  "devops",
  "security",
  "performance",
  "testing",
  "debugging",
  "tooling",
  "git",
  "dependencies",
  "architecture",
  "data",
  "infrastructure",
  "mobile",
  "other",
] as const;

export type LearningCategory = (typeof LEARNING_CATEGORIES)[number];

function ensureDir(): void {
  const dir = join(homedir(), ".contextengine");
  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true });
  }
}

/**
 * Load bundled starter learnings from the npm package's defaults/ directory.
 * These are curated, universal best practices shipped with every install.
 */
export function loadBundledDefaults(
  // defaults/ sits next to dist/ in the package root
  defaultsPath: string = join(__dirname, "..", "defaults", "learnings.json"),
): Array<{ category: string; rule: string; context: string; tags: string[] }> {
  if (existsSync(defaultsPath)) {
    try {
      return JSON.parse(readFileSync(defaultsPath, "utf-8"));
    } catch (err) {
      // [LOCK] [EXEC-FAILURE-IS-NOT-EMPTY]: malformed defaults were skipped in silence; say it once (2026-09-29, C6-5).
      console.error(`[ContextEngine] bundled defaults could not be read or parsed (${defaultsPath}): ${err instanceof Error ? err.message : String(err)}; none merged`);
    }
  }
  return [];
}

/**
 * Merge bundled defaults into user store if they don't already exist.
 * Uses rule text (lowercased) for dedup — user learnings always win.
 */
function mergeDefaults(store: LearningsStore): number {
  const bundled = loadBundledDefaults();
  if (bundled.length === 0) return 0;

  const existingRules = new Set(
    store.learnings
      .filter((l) => typeof l.rule === "string")
      .map((l) => l.rule.toLowerCase().trim())
  );
  // A default the owner deleted stays deleted. [LOCK] [A-READ-NEVER-WRITES-THE-STORE]
  for (const r of store.dismissed_defaults ?? []) existingRules.add(r);

  let added = 0;
  const now = new Date().toISOString();

  for (const def of bundled) {
    if (existingRules.has(def.rule.toLowerCase().trim())) continue;

    store.learnings.push({
      id: generateId(),
      category: def.category as LearningCategory,
      rule: def.rule,
      context: def.context,
      tags: def.tags || [],
      created: now,
      updated: now,
    });
    existingRules.add(def.rule.toLowerCase().trim());
    added++;
  }

  return added;
}

/** Is this rule text one of the bundled defaults? */
function isBundledDefault(rule: string): boolean {
  const key = rule.toLowerCase().trim();
  return loadBundledDefaults().some((d) => d.rule.toLowerCase().trim() === key);
}

// [LOCKED] [STORE-NEVER-STARTS-FRESH-OVER-DATA] 2026-09-05
// [NEVER] turn an unreadable learnings.json into an empty store, write the store with a
//         bare writeFileSync, or let two processes write it without the lock below.
// WHY: on 2026-09-05 (16:34Z) the whole store was rebuilt from scratch: every id
//      replaced, every `created` reset, the save_learning-only records gone. Cause, read
//      from the code and the audit log: every MCP server (launchd, VS Code, Claude Code)
//      watches ~880 doc files and re-imports all of them on any change, one full-file
//      rewrite PER RULE; with two or three servers doing that at once, one read a
//      half-written file, `catch { start fresh }` turned it into an empty store, and the
//      next save overwrote 2,808 records with the rebuilt set. The audit log shows 54
//      such bursts since 2026-06-23 and 143,352 ids created for a store of ~2,800: the
//      same race, repeatedly, and the likeliest source of the 66 audit-chain forks.
// FIX: (1) atomic writes, temp file + rename, so a reader never sees a torn file;
//      (2) an unreadable existing file is copied to learnings.json.corrupt-<ts> and the
//          load THROWS, it never becomes an empty store; (3) a saved store that is less
//          than half the on-disk one (and the disk one has >= 100 records) is refused
//          unless CONTEXTENGINE_ALLOW_SHRINK=1; (4) a cross-process lock directory
//          around every load-modify-save; (5) imports run as ONE batch: one load, one
//          save, instead of one rewrite per rule; (6) a daily learnings.json.bak-YYYYMMDD
//          before the first write of the day, last 7 kept.
const STORE_LOCK_DIR = LEARNINGS_PATH + ".lock";
const LOCK_STALE_MS = 30_000;
let lockDepth = 0;
let batchStore: LearningsStore | null = null;
let batchDirty = false;

function sleepMs(ms: number): void {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

// [LOCKED] [A-DEAD-STORE-HOLDER-LOSES-THE-LOCK-AT-ONCE] 2026-09-27
// [NEVER] make a save wait out LOCK_STALE_MS for a holder that is provably gone, or leave a dead
//         writer's full copy of the store on disk.
// WHY: a saver killed inside the lock made every other save in the next ~20 s wait 10 s and fail
//      with "locked by another process" (6 per run, 3 of 3, E2E_REVIEW_2026-09 B4-2), and left its
//      temp copy of the whole store behind for good. The lock directory names its holder's pid;
//      nothing read it.
// FIX: a lock whose pid no longer exists, or a lock directory older than a second with no pid in
//      it, is taken over at once; a live pid keeps the 30 s rule. Inside the lock, temp copies
//      written by a pid that no longer exists are removed.
function storeHolderIsGone(age: number): boolean {
  let pid = NaN;
  try { pid = parseInt(readFileSync(join(STORE_LOCK_DIR, "pid"), "utf-8"), 10); } catch { /* no pid yet */ }
  if (!Number.isInteger(pid) || pid <= 0) return age > 1000;
  if (pid === process.pid) return false;
  try { process.kill(pid, 0); return false; } catch (e) { return (e as NodeJS.ErrnoException).code === "ESRCH"; }
}

function removeDeadWritersTemps(): void {
  try {
    const dir = dirname(LEARNINGS_PATH);
    for (const f of readdirSync(dir)) {
      const m = /^learnings\.json\.tmp-(\d+)-\d+$/.exec(f);
      if (!m) continue;
      const pid = Number(m[1]);
      if (pid === process.pid) continue;
      try { process.kill(pid, 0); } catch (e) { if ((e as NodeJS.ErrnoException).code === "ESRCH") unlinkSync(join(dir, f)); }
    }
  } catch { /* cleanup is a courtesy; the store is untouched either way */ }
}

/** Cross-process, re-entrant (within this process) lock around the store file. */
export function withStoreLock<T>(fn: () => T): T {
  if (lockDepth > 0) { lockDepth++; try { return fn(); } finally { lockDepth--; } }
  ensureDir();
  const timeoutMs = parseInt(process.env.CONTEXTENGINE_LOCK_TIMEOUT_MS || "10000", 10);
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    try {
      mkdirSync(STORE_LOCK_DIR);
      try { writeFileSync(join(STORE_LOCK_DIR, "pid"), String(process.pid)); } catch { /* diagnostics only */ }
      break;
    } catch (e) {
      if ((e as NodeJS.ErrnoException)?.code !== "EEXIST") throw e;
      let age = 0;
      try { age = Date.now() - statSync(STORE_LOCK_DIR).mtimeMs; } catch { age = 0; }
      // [LOCK] [A-DEAD-STORE-HOLDER-LOSES-THE-LOCK-AT-ONCE]
      if (age > LOCK_STALE_MS || storeHolderIsGone(age)) {
        // Holder died (or hung) without releasing: take it over.
        try { rmSync(STORE_LOCK_DIR, { recursive: true, force: true }); } catch { /* retry below */ }
        continue;
      }
      if (Date.now() > deadline) {
        throw new Error(`learnings store is locked by another process (${STORE_LOCK_DIR}, ${Math.round(age / 1000)}s old); refusing to write over it`);
      }
      sleepMs(25);
    }
  }
  lockDepth = 1;
  try {
    removeDeadWritersTemps();
    return fn();
  } finally {
    lockDepth = 0;
    try { rmSync(STORE_LOCK_DIR, { recursive: true, force: true }); } catch { /* best effort */ }
  }
}

/**
 * Run `fn` with ONE load and at most ONE save of the store, under the lock. Inside, every
 * loadStore() returns the same in-memory store and every saveStore() only marks it dirty.
 */
export function withStoreBatch<T>(fn: () => T): T {
  if (batchStore) return fn(); // already batching (re-entrant)
  return withStoreLock(() => {
    batchStore = readStoreFromDisk();
    batchDirty = false;
    try {
      const out = fn();
      if (batchDirty) writeStoreToDisk(batchStore);
      return out;
    } finally {
      batchStore = null;
      batchDirty = false;
    }
  });
}

function readStoreFromDisk(): LearningsStore {
  let store: LearningsStore;
  if (existsSync(LEARNINGS_PATH)) {
    const raw = readFileSync(LEARNINGS_PATH, "utf-8");
    try {
      store = JSON.parse(raw);
      if (!store || !Array.isArray(store.learnings)) throw new Error("no learnings array");
    } catch (e) {
      const why = e instanceof Error ? e.message : String(e);
      const keep = `${LEARNINGS_PATH}.corrupt-${new Date().toISOString().replace(/[:.]/g, "-")}`;
      try { copyFileSync(LEARNINGS_PATH, keep); } catch { /* the original stays in place regardless */ }
      safeAppend("learning.store_unreadable", { path: LEARNINGS_PATH, bytes: raw.length, kept: keep, error: why });
      throw new Error(`${LEARNINGS_PATH} exists but is unreadable (${why}); refusing to start fresh over it. Copy kept at ${keep}. Another process may be mid-write: retry in a moment.`);
    }
    // Filter out corrupted entries missing required 'rule' field; a missing or unknown
    // category becomes "other" (two June-era records crashed list_learnings on 2026-09-05).
    store.learnings = store.learnings.filter((l) => typeof l.rule === "string" && l.rule.length > 0);
    for (const l of store.learnings) {
      if (typeof l.category !== "string" || !(LEARNING_CATEGORIES as readonly string[]).includes(l.category)) l.category = "other";
    }
  } else {
    store = { version: 1, count: 0, learnings: [] };
  }

  // [LOCKED] [A-READ-NEVER-WRITES-THE-STORE] - 2026-09-27
  // [NEVER] write the store from a read that does not hold the store lock, and never merge back a
  //         bundled default the owner deleted.
  // WHY: a plain read (listLearnings, searchLearnings, the index build) merged a missing bundled
  //      default and wrote the whole store WITHOUT the lock. With that read held 1.5 s before its
  //      write, a concurrent saver's 5 learnings, each saved with success, were gone (3 of 3,
  //      E2E_REVIEW_2026-09 B4-1); at natural speed the window is milliseconds and opens after every
  //      release that adds a default. And a deleted default came back at the next read, with a new id
  //      and no audit record: the delete never stuck. [LOCK] [STORE-NEVER-STARTS-FRESH-OVER-DATA]
  //      already said "never let two processes write it without the lock".
  // FIX: holding the lock (a save, a delete, a batch), the merge is written as before. A plain read
  //      takes the lock for it (re-reading inside), and if the lock is busy only shows the defaults,
  //      writing nothing. A deleted default is remembered in `dismissed_defaults`; every persisted
  //      merge is recorded as a learning.import of the bundled defaults.
  if (!hasMissingDefaults(store)) return store;
  if (lockDepth > 0) {
    const added = mergeDefaults(store);
    if (batchStore) batchDirty = true; else writeStoreToDisk(store);
    safeAppend("learning.import", { source: "bundled defaults", format: "json", imported: added, updated: 0, skipped: 0 });
    return store;
  }
  try {
    return withStoreLock(() => readStoreFromDisk());
  } catch {
    mergeDefaults(store); // the lock is busy: show them, persist at the next locked read or write
    return store;
  }
}

function hasMissingDefaults(store: LearningsStore): boolean {
  const probe: LearningsStore = { version: store.version, count: 0, learnings: store.learnings.slice(), dismissed_defaults: store.dismissed_defaults };
  return mergeDefaults(probe) > 0;
}

function loadStore(): LearningsStore {
  if (batchStore) return batchStore;
  return readStoreFromDisk();
}

function dailyBackup(): void {
  if (!existsSync(LEARNINGS_PATH)) return;
  const day = new Date().toISOString().slice(0, 10).replace(/-/g, "");
  const bak = `${LEARNINGS_PATH}.bak-${day}`;
  if (existsSync(bak)) return;
  try {
    copyFileSync(LEARNINGS_PATH, bak);
    const dir = dirname(LEARNINGS_PATH);
    const daily = readdirSync(dir).filter((f) => /^learnings\.json\.bak-\d{8}$/.test(f)).sort();
    for (const f of daily.slice(0, Math.max(0, daily.length - 7))) unlinkSync(join(dir, f));
  } catch (err) {
    // [LOCK] [EXEC-FAILURE-IS-NOT-EMPTY]: the daily copy is the store's only restore path. A copy that
    // failed must never block the save, and must never go unsaid: one line on stderr and one chained
    // record, which fleet health counts (2026-09-29, E2E_REVIEW_2026-09 C6-5).
    const error = err instanceof Error ? err.message : String(err);
    console.error(`[ContextEngine] daily learnings backup failed (${bak}): ${error}`);
    safeAppend("learning.backup_failed", { path: bak, error });
  }
}

// [LOCKED] [STORE-GROWTH-IS-A-TRIPWIRE-TOO] 2026-09-05
// [NEVER] let one write add more than MAX_GROWTH_PER_WRITE records to the store without the
//         explicit override, and never raise the limit to make an import "just work".
// WHY: the shrink guard below caught the wipe of 2026-09-05; the same evening two stale servers
//      wrote 1,766 records in one minute and nothing objected, because only shrinking was
//      guarded. Every legitimate write is small: an agent saves one rule, the strict auto-import
//      of a whole workspace produced 99 (replayed 2026-09-05), the largest real learnings file
//      a few dozen. Thousands in one write is a bug or old code, never a lesson.
// FIX: a write that grows the store by more than MAX_GROWTH_PER_WRITE over the file on disk
//      is refused with an audit event, unless CONTEXTENGINE_ALLOW_BULK=1 (set knowingly, for
//      one deliberate bulk import). The auto-import catches the refusal and reports it; the
//      server keeps running.
export const MAX_GROWTH_PER_WRITE = 200;

function writeStoreToDisk(store: LearningsStore): void {
  ensureDir();
  store.count = store.learnings.length;
  // Shrink tripwire: the exact shape of the 2026-09-05 loss was a near-empty store
  // written over a full one.
  if (existsSync(LEARNINGS_PATH) && process.env.CONTEXTENGINE_ALLOW_SHRINK !== "1") {
    let onDisk = -1;
    try { onDisk = (JSON.parse(readFileSync(LEARNINGS_PATH, "utf-8")).learnings || []).length; } catch { onDisk = -1; }
    if (onDisk >= 100 && store.learnings.length < onDisk / 2) {
      safeAppend("learning.store_shrink_refused", { on_disk: onDisk, attempted: store.learnings.length });
      throw new Error(`refusing to write ${store.learnings.length} learnings over a store of ${onDisk}: that is the shape of a wipe, not an edit. Set CONTEXTENGINE_ALLOW_SHRINK=1 if this is deliberate.`);
    }
  }
  // Growth tripwire. [LOCK] [STORE-GROWTH-IS-A-TRIPWIRE-TOO]
  if (existsSync(LEARNINGS_PATH) && process.env.CONTEXTENGINE_ALLOW_BULK !== "1") {
    let onDisk = -1;
    try { onDisk = (JSON.parse(readFileSync(LEARNINGS_PATH, "utf-8")).learnings || []).length; } catch { onDisk = -1; }
    const growth = store.learnings.length - onDisk;
    if (onDisk >= 0 && growth > MAX_GROWTH_PER_WRITE) {
      safeAppend("learning.store_growth_refused", { on_disk: onDisk, attempted: store.learnings.length, growth });
      throw new Error(`refusing to add ${growth} learnings in one write (store ${onDisk}, limit ${MAX_GROWTH_PER_WRITE}): that is the shape of a runaway import, not a lesson. Set CONTEXTENGINE_ALLOW_BULK=1 for one deliberate bulk import.`);
    }
  }
  dailyBackup();
  const tmp = `${LEARNINGS_PATH}.tmp-${process.pid}-${Date.now()}`;
  writeFileSync(tmp, JSON.stringify(store, null, 2));
  renameSync(tmp, LEARNINGS_PATH);
}

function saveStore(store: LearningsStore): void {
  if (batchStore) { batchStore = store; batchDirty = true; return; }
  writeStoreToDisk(store);
}

/** Test seam for the writer's tripwire; not part of the API. */
export function __writeStoreForTests(store: LearningsStore): void {
  withStoreLock(() => writeStoreToDisk(store));
}

/** Generate a short unique ID */
function generateId(): string {
  return Date.now().toString(36) + Math.random().toString(36).substring(2, 6);
}

/** Extract tags from rule + context text */
function extractTags(rule: string, context: string, category: string): string[] {
  const text = `${rule} ${context}`.toLowerCase();
  const tags = new Set<string>([category]);

  // Common tech keywords
  const techWords = [
    "flask", "laravel", "react", "expo", "docker", "nginx", "pm2",
    "mysql", "postgres", "redis", "node", "python", "php", "typescript",
    "git", "npm", "composer", "pip", "api", "cors", "jwt", "oauth",
    "ssl", "https", "ssh", "dns", "gps", "macos", "linux", "windows",
    "webpack", "vite", "cra", "nextjs", "flutter", "swift", "kotlin",
    "supervisor", "cron", "smtp", "queue", "cache", "migration",
    "unicode", "encoding", "permissions", "sandbox", "firewall",
  ];

  for (const word of techWords) {
    if (text.includes(word)) {
      tags.add(word);
    }
  }

  return Array.from(tags);
}

/** Minimum rule length — anything shorter is noise, not knowledge */
const MIN_RULE_LENGTH = 15;

/**
 * Save a new learning. Returns the created learning with ID.
 * Rejects rules shorter than MIN_RULE_LENGTH and auto-corrects "other" category.
 */
export function saveLearning(...args: Parameters<typeof saveLearningUnlocked>): Learning {
  return withStoreLock(() => saveLearningUnlocked(...args));
}

function saveLearningUnlocked(
  category: string,
  rule: string,
  context: string,
  project?: string,
  source?: string,
): Learning {
  const trimmedRule = rule.trim();

  // Quality gate: reject junk rules
  if (trimmedRule.length < MIN_RULE_LENGTH) {
    throw new Error(
      `Rule too short (${trimmedRule.length} chars, min ${MIN_RULE_LENGTH}). ` +
      `Learnings must be actionable sentences, not single words. Example: ` +
      `"Always restart Flask after model changes — stale to_dict() cache"`
    );
  }

  // Quality gate: auto-correct "other" category by inferring from rule + context
  if (category === "other") {
    const inferred = inferCategory(trimmedRule, context);
    if (inferred !== "other") {
      category = inferred;
    }
  }

  const store = loadStore();
  const now = new Date().toISOString();

  // Check for duplicate rules (fuzzy: same category + similar rule text)
  const ruleLower = rule.toLowerCase().trim();
  const existing = store.learnings.find(
    (l) =>
      l.category === category &&
      typeof l.rule === "string" && l.rule.toLowerCase().trim() === ruleLower
  );

  if (existing) {
    // A re-import that changes nothing must leave no trace: no write, no `updated` bump,
    // no audit event. Before 2026-09-05 every startup re-import emitted one learning.save
    // per rule (2,000 to 5,000 events per server start) for records that did not change.
    const newTags = extractTags(existing.rule, context, category);
    const sameTags = JSON.stringify(newTags) === JSON.stringify(existing.tags || []);
    const sameSource = !source || existing.source === source;
    if (existing.context === context && (!project || existing.project === project) && sameTags && sameSource) {
      return existing;
    }
    // Update existing learning with new context
    existing.context = context;
    existing.updated = now;
    if (project) existing.project = project;
    if (source) existing.source = source;
    existing.tags = newTags;
    saveStore(store);
    safeAppend("learning.save", {
      id: existing.id,
      category: existing.category,
      project: existing.project,
      rule_length: existing.rule.length,
      mode: "update",
    });
    return existing;
  }

  const learning: Learning = {
    id: generateId(),
    category: category as LearningCategory,
    rule,
    context,
    project,
    tags: extractTags(rule, context, category),
    created: now,
    updated: now,
  };
  if (source) learning.source = source;

  store.learnings.push(learning);
  saveStore(store);
  safeAppend("learning.save", {
    id: learning.id,
    category: learning.category,
    project: learning.project,
    rule_length: learning.rule.length,
    mode: "create",
  });
  return learning;
}

/**
 * Search learnings by keyword. Returns matches sorted by relevance.
 */
export function searchLearnings(query: string): Learning[] {
  const store = loadStore();
  const tokens = query
    .toLowerCase()
    .split(/\s+/)
    .filter((t) => t.length > 1);

  if (tokens.length === 0) return store.learnings;

  const scored: Array<{ learning: Learning; score: number }> = [];

  for (const learning of store.learnings) {
    // [LOCKED] [LEARNING-FIELDS-ARE-OPTIONAL-ON-READ] 2026-09-06
    // [NEVER] dereference an optional field of a store record (tags, context, project) without a
    //         fallback on a read path, and [NEVER] "fix" such a record by rewriting the store.
    // WHY: 20 agent-saved records (s57_*, s78_*, kept on purpose in the SESSION_25 prune) have no
    //      `tags` array. `learning.tags.join` threw here, inside the firewall's learning injection,
    //      so every tool that passes a context hint (search_context, score_project, ...) answered
    //      "Cannot read properties of undefined (reading 'join')" on every server, on 2.5.9 as on
    //      2.6.0, while save_learning (exempt from the firewall) worked. Another chat noticed.
    // FIX: read with fallbacks; the records stay as they are (the store is data, not ours to edit).
    const text = `${learning.category} ${learning.rule} ${learning.context ?? ""} ${learning.project || ""} ${(learning.tags ?? []).join(" ")}`.toLowerCase();
    let score = 0;

    for (const token of tokens) {
      if (text.includes(token)) {
        score += 1;
        // Bonus for matching rule text directly (the important part)
        if (typeof learning.rule === "string" && learning.rule.toLowerCase().includes(token)) score += 2;
        // Bonus for matching category
        if (learning.category.toLowerCase().includes(token)) score += 1;
      }
    }

    // Multi-term bonus
    const distinctMatches = tokens.filter((t) => text.includes(t)).length;
    if (distinctMatches > 1) score += distinctMatches * 2;

    if (score > 0) {
      scored.push({ learning, score });
    }
  }

  scored.sort((a, b) => b.score - a.score);
  return scored.map((s) => s.learning);
}

/**
 * Get learnings, optionally filtered by category and/or project.
 *
 * When `projects` is provided, only returns learnings that:
 * - match one of the given project names (case-insensitive), OR
 * - have no project set (universal learnings)
 *
 * This prevents cross-project IP leakage — e.g. CROWLR learnings
 * won't appear when working on VOILA.
 */
export function listLearnings(category?: string, projects?: string[]): Learning[] {
  const store = loadStore();
  let result = store.learnings;

  if (projects && projects.length > 0) {
    const lowerProjects = projects.map((p) => p.toLowerCase());
    result = result.filter(
      (l) => !l.project || lowerProjects.includes(l.project.toLowerCase())
    );
  }

  if (category) {
    result = result.filter(
      (l) => String(l.category || "other").toLowerCase() === category.toLowerCase()
    );
  }

  return result;
}

/**
 * Delete a learning by ID.
 */
export function deleteLearning(id: string): boolean {
  return withStoreLock(() => deleteLearningUnlocked(id));
}

function deleteLearningUnlocked(id: string): boolean {
  const store = loadStore();
  const index = store.learnings.findIndex((l) => l.id === id);
  if (index === -1) return false;
  const removed = store.learnings[index];
  store.learnings.splice(index, 1);
  // A deleted bundled default stays deleted. [LOCK] [A-READ-NEVER-WRITES-THE-STORE]
  const dismissed = typeof removed.rule === "string" && isBundledDefault(removed.rule);
  if (dismissed) {
    const key = removed.rule.toLowerCase().trim();
    store.dismissed_defaults = [...new Set([...(store.dismissed_defaults ?? []), key])];
  }
  saveStore(store);
  safeAppend("learning.delete", {
    id: removed.id,
    category: removed.category,
    project: removed.project,
    rule_length: typeof removed.rule === "string" ? removed.rule.length : 0,
    ...(dismissed ? { default_dismissed: true } : {}),
  });
  return true;
}

/**
 * Import learnings from a Markdown file.
 * Parses headings and bullet points to extract rules.
 *
 * Supported formats:
 * 1. **Structured Markdown** — H2 = category, H3 = rule, bullet = context
 *    ```md
 *    ## deployment
 *    ### Never docker build | tee
 *    - Pipeline signals kill builds. Use nohup > /tmp/log 2>&1 &
 *    ```
 *
 * 2. **Bullet-list Markdown** — Each bullet with "→" or "—" separator
 *    ```md
 *    - [deployment] Never docker build | tee → Pipeline signals kill builds
 *    ```
 *
 * 3. **JSON array** — Direct Learning[] import
 */
export interface ImportResult {
  imported: number;
  updated: number;
  skipped: number;
  /** Candidates the import rule left alone: headings, bold bullets and table rows outside a learnings scope. */
  ignored: number;
  errors: string[];
}

export interface ImportOptions {
  /** Import every heading, bold bullet and table row as a rule, the pre-2026-09-05 behaviour. */
  permissive?: boolean;
  /** Write the per-file learning.import record (default). The sweep passes false and writes its
   *  own records. [LOCK] [SWEEP-RECORDS-ONLY-WHAT-CHANGED] */
  record?: boolean;
}

// [LOCKED] [AUTO-IMPORT-ONLY-MARKED-LEARNINGS] 2026-09-05
// [NEVER] let the auto-import (autoImportFromSources, run by every MCP server on every doc change)
//         treat an H3 heading, a bold bullet or a table row in an ordinary doc as a learning again.
// WHY: measured 2026-09-05 (Session 25): of 3,005 store records, about 2,760 had been produced by
//      this importer from ~160 ordinary docs (copilot-instructions, session docs, Claude memory
//      files) and about 240 by an agent calling save_learning. In a spread sample of 70 imported
//      records, 32 were not rules at all ("Design Language:", "External References:", "Session 24
//      TODO", "Files created (Phase 1 foundation)"), and the category of the rest came from a
//      section title or a substring guess ("Flow A" under mobile). A count of headings is not a
//      knowledge base; every one of those docs is already searchable as a doc.
// FIX: a candidate becomes a learning only when the author marked it as one:
//      (1) an inline-category bullet `- [category] rule → context`, anywhere;
//      (2) any shape inside a file whose name says learnings (AGENT-LEARNINGS.md, LEARNINGS.md);
//      (3) any shape under a heading that says learnings / lessons / gotchas / pitfalls /
//          anti-patterns / "never repeat" / "the hard way" / mistakes (LEARNINGS_HEADING).
//          Not "rules": "## Key rules" and "### Security Rules" are ordinary doc sections, and
//          the word let 231 subsection headings back in on the evening this shipped;
//      (4) JSON files, which are explicit by construction.
//      `permissive: true` (MCP `import_learnings`, CLI `--permissive`) restores the old parser for
//      a file the user chose on purpose. Every imported record now carries `source`.
export const LEARNINGS_FILE_NAME = /learnings?\.md$/i;
export const LEARNINGS_HEADING =
  /\b(learnings?|lessons?|gotchas?|pitfalls?|anti-?patterns?|never repeat|do not repeat|don'?t repeat|the hard way|hard way|mistakes?)\b/i;

export function importLearningsFromFile(
  filePath: string,
  defaultCategory: string = "other",
  defaultProject?: string,
  opts: ImportOptions = {},
): ImportResult {
  if (!existsSync(filePath)) {
    return { imported: 0, updated: 0, skipped: 0, ignored: 0, errors: [`File not found: ${filePath}`] };
  }

  const content = readFileSync(filePath, "utf-8");
  const ext = filePath.split(".").pop()?.toLowerCase();
  const permissive = opts.permissive === true || LEARNINGS_FILE_NAME.test(filePath.split("/").pop() || "");

  // One load, one save for the whole file. [LOCK] [STORE-NEVER-STARTS-FRESH-OVER-DATA]
  const result = withStoreBatch(() => ext === "json"
    ? importFromJson(content, defaultProject, filePath)
    : importFromMarkdown(content, defaultCategory, defaultProject, { permissive, source: filePath }));

  // Aggregate event correlating the individual learning.save records emitted
  // inside the loop. Useful for compliance attribution: "this batch came from
  // file X".
  if (opts.record !== false) {
    safeAppend("learning.import", {
      source: filePath,
      format: ext === "json" ? "json" : "markdown",
      project: defaultProject,
      imported: result.imported,
      updated: result.updated,
      skipped: result.skipped,
      ignored: result.ignored,
      errors: result.errors.length,
    });
  }

  return result;
}

/** One entry of an imported JSON file. Untrusted: any field may be missing or of another type. */
interface ImportedEntry {
  rule?: unknown;
  category?: unknown;
  context?: unknown;
  project?: unknown;
}

function importFromJson(content: string, defaultProject?: string, source?: string): ImportResult {
  const result: ImportResult = { imported: 0, updated: 0, skipped: 0, ignored: 0, errors: [] };
  const startedAt = Date.now();

  try {
    const data: unknown = JSON.parse(content);
    const listed = Array.isArray(data) ? data : (data as { learnings?: unknown }).learnings;
    if (listed && !Array.isArray(listed)) throw new Error('"learnings" is not a list');
    const items: unknown[] = Array.isArray(listed) ? listed : [];

    for (const entry of items) {
      // [LOCKED] [IMPORT-SKIPS-A-BAD-ENTRY], 2026-09-29
      // [NEVER] read an entry's fields before checking that it is an object and its rule is text.
      // WHY: typed `any`, a null entry or a rule that is a number threw inside this loop, and the
      //      whole file was refused as "JSON parse error: Cannot read properties of null" although
      //      the JSON parsed: every good entry after the bad one was lost. Found while typing the
      //      `any` away (E2E review C7-2).
      // FIX: each entry is checked on its own; a bad one is skipped and named, the rest imports;
      //      a context or project that is not text is ignored (empty context, default project).
      const item: ImportedEntry = entry !== null && typeof entry === "object" ? entry : {};
      if (typeof item.rule !== "string" || !item.rule || !item.category) {
        result.skipped++;
        result.errors.push(`Skipped entry missing rule or category: ${JSON.stringify(entry).substring(0, 80)}`);
        continue;
      }
      if (item.rule.trim().length < MIN_RULE_LENGTH) {
        result.skipped++;
        continue;
      }
      const cat = typeof item.category === "string" && (LEARNING_CATEGORIES as readonly string[]).includes(item.category)
        ? item.category
        : "other";
      const context = typeof item.context === "string" ? item.context : "";
      const project = typeof item.project === "string" && item.project ? item.project : defaultProject;
      try {
        // "imported" means created by this call and "updated" means changed by it: the record
        // saveLearning() returns says so through its created and updated instants. A lookup by the
        // rule's own category cannot tell: saveLearning() infers the category of an "other" rule and
        // finds it there (50 such rules counted as imported on one sweep, 0 written).
        // [LOCK] [SWEEP-RECORDS-ONLY-WHAT-CHANGED]
        const saved = saveLearning(cat, item.rule, context, project, source);
        if (Date.parse(saved.created) >= startedAt) result.imported++;
        else if (Date.parse(saved.updated) >= startedAt) result.updated++;
      } catch {
        result.skipped++;
      }
    }
  } catch (e) {
    result.errors.push(`JSON parse error: ${e instanceof Error ? e.message : String(e)}`);
  }

  return result;
}

function importFromMarkdown(
  content: string,
  defaultCategory: string,
  defaultProject?: string,
  opts: { permissive: boolean; source?: string } = { permissive: false },
): ImportResult {
  const result: ImportResult = { imported: 0, updated: 0, skipped: 0, ignored: 0, errors: [] };
  const startedAt = Date.now();
  const lines = content.split("\n");

  let currentCategory = defaultCategory;
  let currentRule = "";
  let currentContext: string[] = [];
  // Learnings scope, [LOCK] [AUTO-IMPORT-ONLY-MARKED-LEARNINGS]: unmarked shapes (H3, bold bullet,
  // table row) count as rules only inside it. Three nested levels: the whole file (permissive,
  // learnings file name, or an H1 that says so), an H2 section, an H3 subsection.
  let fileScope = opts.permissive;
  let h2Scope = false;
  let h3Scope = false;
  const inScope = () => fileScope || h2Scope || h3Scope;
  // A candidate that arrives outside the scope is counted and dropped, never queued.
  function candidate(text: string): void {
    if (inScope()) currentRule = text; else result.ignored++;
  }

  function flushRule(): void {
    if (!currentRule) return;
    // Quality gate: skip rules that are too short (catches junk from headings/bullets)
    if (currentRule.trim().length < MIN_RULE_LENGTH) {
      result.skipped++;
      currentRule = "";
      currentContext = [];
      return;
    }
    const cat = normalizeCategory(currentCategory);
    const ctx = currentContext.join(" ").trim() || `Imported from file`;
    try {
      // "imported" is created by this call, "updated" is changed by it, see importFromJson().
      // [LOCK] [SWEEP-RECORDS-ONLY-WHAT-CHANGED]
      const saved = saveLearning(cat, currentRule, ctx, defaultProject, opts.source);
      if (Date.parse(saved.created) >= startedAt) result.imported++;
      else if (Date.parse(saved.updated) >= startedAt) result.updated++;
    } catch {
      result.skipped++;
    }
    currentRule = "";
    currentContext = [];
  }

  for (const line of lines) {
    const trimmed = line.trim();

    // H1 — file title, skip; a title that says learnings puts the whole file in scope
    if (trimmed.startsWith("# ") && !trimmed.startsWith("## ")) {
      if (LEARNINGS_HEADING.test(trimmed.slice(2))) fileScope = true;
      continue;
    }

    // H2 — category (e.g., "## deployment" or "## Security & Server Administration")
    if (trimmed.startsWith("## ")) {
      flushRule();
      const heading = trimmed.replace(/^##\s+/, "").toLowerCase().trim();
      currentCategory = heading;
      h2Scope = LEARNINGS_HEADING.test(heading);
      h3Scope = false;
      continue;
    }

    // H3 — rule (e.g., "### Never docker build | tee"), or a subsection that says learnings
    if (trimmed.startsWith("### ")) {
      flushRule();
      h3Scope = false; // an H3 subsection ends at the next H3
      const text = trimmed.replace(/^###\s+/, "").trim();
      if (!inScope() && LEARNINGS_HEADING.test(text)) {
        h3Scope = true; // "### Lessons learned" opens a scope; the heading itself is not a rule
        continue;
      }
      // Quality filter: skip short headings ("Fix", "UI", "DB")
      if (text.length >= MIN_RULE_LENGTH) candidate(text);
      continue;
    }

    // H4+ — sub-rule, treat as context for current rule
    if (trimmed.startsWith("#### ")) {
      if (currentRule) {
        currentContext.push(trimmed.replace(/^####\s+/, "").trim());
      }
      continue;
    }

    // Bullet with inline category: "- [deployment] Rule text → Context"
    const inlineCatMatch = trimmed.match(/^[-*]\s+\[(\w+)\]\s+(.+)/);
    if (inlineCatMatch) {
      flushRule();
      const [, cat, rest] = inlineCatMatch;
      currentCategory = cat;
      // Split on → or — for rule/context separation
      const sepMatch = rest.match(/^(.+?)(?:\s*[→—]\s*|\s+[-–]\s+)(.+)$/);
      // Marked by its author: imported in every mode. [LOCK] [AUTO-IMPORT-ONLY-MARKED-LEARNINGS]
      if (sepMatch) {
        const text = sepMatch[1].trim();
        if (text.length >= MIN_RULE_LENGTH) {
          currentRule = text;
          currentContext = [sepMatch[2].trim()];
          flushRule();
        }
      } else {
        const text = rest.trim();
        if (text.length >= MIN_RULE_LENGTH) {
          currentRule = text;
          flushRule();
        }
      }
      continue;
    }

    // Table rows: | Pattern | Example | Description |
    const tableMatch = trimmed.match(/^\|\s*\*\*(.+?)\*\*\s*\|(.+)\|(.+)\|/);
    if (tableMatch) {
      flushRule();
      const text = tableMatch[1].trim();
      if (text.length >= MIN_RULE_LENGTH) {
        candidate(text);
        if (currentRule) {
          currentContext = [tableMatch[2].trim() + " — " + tableMatch[3].trim()];
          flushRule();
        }
      }
      continue;
    }

    // Regular bullet — either starts a new rule or adds context to current
    if (trimmed.match(/^[-*]\s+\*\*(.+?)\*\*/)) {
      // Bold-start bullet = likely a rule
      flushRule();
      const boldMatch = trimmed.match(/^[-*]\s+\*\*(.+?)\*\*\s*(.*)$/);
      if (boldMatch) {
        const text = boldMatch[1].trim();
        // Quality filter: skip short/single-word headings
        if (text.length < MIN_RULE_LENGTH) {
          continue;
        }
        candidate(text);
        if (currentRule && boldMatch[2]) {
          // Strip leading separators
          currentContext = [boldMatch[2].replace(/^[\s—→:]+/, "").trim()];
        }
      }
      continue;
    }

    // Regular bullet or numbered item — context for current rule
    if ((trimmed.startsWith("- ") || trimmed.startsWith("* ") || trimmed.match(/^\d+\.\s/)) && currentRule) {
      const text = trimmed.replace(/^[-*\d.]+\s+/, "").trim();
      if (text) currentContext.push(text);
      continue;
    }

    // Plain text after a rule heading = context
    if (currentRule && trimmed.length > 10 && !trimmed.startsWith("|") && !trimmed.startsWith("```")) {
      currentContext.push(trimmed);
    }
  }

  flushRule(); // Flush last rule
  return result;
}

// [LOCKED] [CATEGORY-BY-WHOLE-WORD-SCORE] 2026-09-05
// [NEVER] go back to a first-hit `text.includes(keyword)` over an unanchored substring list,
//         in inferCategory() or in normalizeCategory().
// WHY: measured 2026-09-05 (Session 25) on 189 store records whose category an agent had
//      chosen by hand: 21 correct, 11%. "expose" matched "expo" (mobile), "access" matched
//      "css" (frontend), "restart" matched "rest" (api), "build" matched "ui", "login" matched
//      "log" (debugging), and the FIRST hit won whatever the rest of the text said, so
//      "Scoring internals are trade secrets, don't expose point values" was filed under mobile.
// FIX: whole-word and whole-phrase matches only; every match counts; a match in the rule text
//      weighs double a match in the context; the highest total wins; ties go to the more
//      specific category (CATEGORY_TIE_ORDER); no match at all is "other", never a guess.
//      Regression floors in src/learnings-category.test.ts against tests/fixtures/category-labels.json.

/** Terms per category. Single words match as whole tokens, phrases as whole phrases. */
const CATEGORY_TERMS: Record<Exclude<LearningCategory, "other">, string[]> = {
  deployment: ["deploy", "deploys", "deployed", "deploying", "deployment", "deployments", "rsync",
    "scp", "publish", "published", "publishing", "release", "releases", "released", "rollout",
    "rollback", "ship", "shipped", "shipping", "go live", "go-live", "cutover", "staging",
    "production", "prod", "tarball", "npm publish", "verify-release", "preflight", "hotfix",
    "live-verify"],
  devops: ["ci", "ci/cd", "cicd", "pipeline", "pipelines", "github actions", "workflow",
    "workflows", "docker", "dockerfile", "container", "containers", "compose", "kubernetes", "k8s",
    "cron", "crontab", "launchd", "scheduler", "scheduled", "automation", "automated",
    "orchestration"],
  infrastructure: ["nginx", "apache", "ssl", "tls", "certificate", "certificates", "letsencrypt",
    "server", "servers", "vps", "pm2", "ssh", "dns", "domain", "domains", "firewall", "ufw",
    "fail2ban", "systemd", "backup", "backups", "restore", "disk", "ovh", "gandi", "hosting",
    "smtp", "cloudflare", "proxy", "reverse proxy", "load balancer", "uptime", "monitoring", "ram",
    "cpu", "swap", "reboot", "restart", "restarted", "daemon",
    "box", "machine", "process", "processes", "host", "hosts"],
  api: ["api", "apis", "endpoint", "endpoints", "rest", "graphql", "webhook", "webhooks", "route",
    "routes", "router", "request", "requests", "response", "responses", "http", "https",
    "status code", "payload", "rate limit", "rate-limit", "throttle", "throttling", "header",
    "headers", "url", "urls", "fetch", "axios", "curl", "openapi", "swagger"],
  database: ["sql", "sqlite", "mysql", "postgres", "postgresql", "mongodb", "mongo", "mongoose",
    "query", "queries", "migration", "migrations", "schema", "table", "tables", "column", "columns",
    "collection", "collections", "aggregate", "redis", "orm", "sqlalchemy", "prisma", "eloquent",
    "transaction", "transactions", "row", "rows", "db", "database", "databases", "pg_dump",
    "setval", "primary key", "foreign key", "upsert", "insert",
    "index", "indexes", "join", "select", "sequence", "dump"],
  frontend: ["react", "vue", "svelte", "css", "html", "dom", "component", "components", "ui", "ux",
    "jsx", "tsx", "tailwind", "vite", "webpack", "render", "renders", "rendering", "rendered",
    "page", "pages", "button", "buttons", "modal", "chip", "chips", "localstorage", "browser",
    "usestate", "useeffect", "spinner", "layout", "responsive", "widget", "widgets", "form",
    "forms", "click", "scroll", "font", "fonts", "color", "colors", "colour", "colours", "contrast",
    "display", "screen", "screens", "frontend", "front-end", "pwa", "service worker", "bundle",
    "hydration"],
  backend: ["express", "node", "nodejs", "flask", "fastapi", "django", "laravel", "php", "python",
    "middleware", "uvicorn", "gunicorn", "worker", "workers", "queue", "queues", "controller",
    "controllers", "service", "services", "artisan", "i18n", "server-side", "backend", "back-end",
    "handler", "handlers", "model", "models", "trait", "setdefault", "asyncio", "celery",
    "cache_key"],
  security: ["auth", "authentication", "authorization", "oauth", "jwt", "token", "tokens", "cors",
    "xss", "csrf", "helmet", "encrypt", "encrypted", "encryption", "password", "passwords",
    "passkey", "passkeys", "webauthn", "credential", "credentials", "secret", "secrets", "vault",
    "permission", "permissions", "tenant", "isolation", "rbac", "hash", "hashed", "injection",
    "sanitize", "sanitise", "vulnerability", "vulnerabilities", "cve", "exposed", "expose",
    "cookie", "cookies", "login", "logout", "signin", "sign-in", "2fa", "mfa", "otp", "magic code",
    "allowlist", "whitelist", "trade secret", "trade secrets", "lockout",
    "origin", "leak", "leaks", "leaked"],
  performance: ["perf", "performance", "latency", "cache", "cached", "caching", "optimize",
    "optimise", "optimization", "optimisation", "slow", "slower", "bottleneck", "bottlenecks",
    "throughput", "memory leak", "n+1", "benchmark", "loop invariant", "nested loop", "timeout",
    "timeouts", "concurrency", "batch size",
    "parallel", "expensive"],
  testing: ["test", "tests", "testing", "tested", "vitest", "jest", "pytest", "spec", "specs",
    "assert", "assertion", "assertions", "mock", "mocks", "mocked", "fixture", "fixtures", "e2e",
    "end-to-end", "headless", "playwright", "cypress", "test suite", "regression", "tdd", "green",
    "red", "smoke", "smoke test", "collect", "collected", "harness", "canary"],
  debugging: ["debug", "debugging", "error", "errors", "stack trace", "traceback", "breakpoint",
    "log", "logs", "logging", "diagnose", "diagnosis", "diagnostic", "diagnostics", "symptom",
    "symptoms", "crash", "crashes", "crashed", "hang", "hangs", "freeze", "frozen", "root cause",
    "reproduce", "repro", "bug", "bugs", "silent", "silently", "off-by-one", "stale",
    "wrong", "invisible"],
  tooling: ["eslint", "lint", "linter", "prettier", "vscode", "vs code", "editor", "cli", "script",
    "scripts", "shell", "bash", "zsh", "terminal", "claude code", "agent", "agents", "subagent",
    "subagents", "mcp", "extension", "plugin", "plugins", "tsc", "compiler", "formatter",
    "makefile", "pipefail", "set -e", "grep", "sed", "regex", "quoting", "command", "commands",
    "flag", "flags", "dry run", "dry-run", "--check", "prompt", "prompts", "transcript",
    "transcripts", "copilot"],
  git: ["git", "commit", "commits", "committed", "branch", "branches", "merge", "merged", "rebase",
    "push", "pushed", "pull", "pull request", "pr", "prs", "checkout", "stash", "cherry-pick",
    "no-verify", "--no-verify", "pre-commit", "post-commit", "pre-push", "post-push", "gitignore",
    ".gitignore", "git push", "git pull", "bare repo", "worktree", "revert", "squash",
    "history", "remote", "remotes", "tag", "tags", "conflict", "conflicts", "hook", "hooks"],
  dependencies: ["npm", "package", "packages", "yarn", "pnpm", "pip", "composer", "dependency",
    "dependencies", "upgrade", "upgraded", "semver", "lockfile", "package.json", "node_modules",
    "requirements.txt", "sdk", "pubspec", "peer dependency", "bump", "bumped", "outdated", "npx",
    "version", "versions", "install", "installed", "pin", "pinned", "pinning"],
  architecture: ["pattern", "patterns", "refactor", "refactoring", "module", "modules", "design",
    "architecture", "single source of truth", "coupling", "boundary", "boundaries", "abstraction",
    "interface", "interfaces", "layer", "layers", "event bus", "invariant", "invariants", "guard",
    "guards", "contract", "contracts", "decision", "decisions", "encode", "encoded", "absence",
    "unknown", "responsibility", "coupled", "decoupled",
    "trace", "structure", "structural"],
  data: ["csv", "dataset", "datasets", "data", "categoriser", "categorizer", "categorisation",
    "categorization", "taxonomy", "parse", "parser", "parsed", "encoding", "unicode", "nfc", "nfd",
    "dedup", "deduplicate", "normalization", "normalisation", "etl", "classifier", "verdict",
    "verdicts", "denominator", "nutri-score", "catalog", "catalogue", "spreadsheet", "excel",
    "count", "counts", "figure", "figures", "json", "product", "products", "field", "fields", "label", "labels", "labelled", "coverage", "metric", "metrics", "import", "imports", "export", "exports", "record", "records"],
  mobile: ["ios", "android", "expo", "react native", "flutter", "dart", "swift", "kotlin", "xcode",
    "app store", "play store", "google play", "testflight", "apk", "aab", "ipa", "riverpod",
    "app store connect", "simulator", "emulator", "mobile", "gradle", "cocoapods", "pod", "pods",
    "mainactivity", "flutterfragmentactivity", "flutteractivity", "revenuecat", "subscription",
    "subscriptions", "guideline", "review team", "samsung", "iphone", "device", "devices",
    "widget tree"],
};

/** Unambiguous technology names: one occurrence outweighs two generic words. */
const STRONG_TERMS = new Set<string>([
  "rsync", "docker", "dockerfile", "kubernetes", "nginx", "fail2ban", "ufw", "pm2", "letsencrypt",
  "graphql", "webhook", "webhooks", "endpoint", "endpoints", "sqlite", "mysql", "postgres", "postgresql",
  "mongodb", "mongoose", "sqlalchemy", "prisma", "eloquent", "pg_dump", "react", "vue", "svelte",
  "tailwind", "usestate", "useeffect", "localstorage", "express", "flask", "fastapi", "django", "laravel",
  "uvicorn", "gunicorn", "artisan", "jwt", "csrf", "xss", "webauthn", "passkey", "passkeys", "oauth",
  "vitest", "jest", "pytest", "playwright", "cypress", "stack trace", "traceback", "eslint", "prettier",
  "vscode", "vs code", "rebase", "cherry-pick", "no-verify", "--no-verify", "pre-commit", "gitignore",
  "npm", "yarn", "pnpm", "pip", "composer", "semver", "package.json", "node_modules", "csv", "unicode",
  "flutter", "dart", "swift", "kotlin", "xcode", "testflight", "apk", "aab", "ipa", "riverpod", "expo",
  "react native", "app store", "play store", "google play", "app store connect", "pubspec",
  "single source of truth", "n+1", "memory leak", "loop invariant", "github actions", "trade secret",
  "trade secrets", "git push", "git pull", "pull request", "mongo", "redis", "migration", "migrations",
]);

/** When two categories tie, the earlier one wins: the more specific before the more generic. */
const CATEGORY_TIE_ORDER: LearningCategory[] = [
  "mobile", "database", "security", "git", "testing", "deployment", "api", "devops", "infrastructure",
  "frontend", "backend", "performance", "dependencies", "data", "tooling", "debugging", "architecture",
];

function normalizeForMatch(text: string): string {
  // Lowercase; every run of characters outside [a-z0-9+#./_-] becomes one space, so a term like
  // "ci/cd", "n+1", "--no-verify" or "package.json" survives as a phrase, and word boundaries
  // become spaces. Padded with spaces so a term can be looked up as " term ".
  return " " + text.toLowerCase().replace(/[^a-z0-9+#./_-]+/g, " ").trim() + " ";
}

/** Whole-word / whole-phrase occurrence check on a normalised string. */
function hasTerm(normalized: string, term: string): boolean {
  return normalized.includes(` ${term} `);
}

/** Score every category over rule (x2) and context (x1); the caller picks the winner. */
export function scoreCategories(rule: string, context: string): Map<LearningCategory, number> {
  const r = normalizeForMatch(rule);
  const c = normalizeForMatch(context || "");
  const scores = new Map<LearningCategory, number>();
  for (const [cat, terms] of Object.entries(CATEGORY_TERMS) as Array<[LearningCategory, string[]]>) {
    let s = 0;
    for (const term of terms) {
      const w = STRONG_TERMS.has(term) ? 2 : 1;
      if (hasTerm(r, term)) s += 2 * w;
      else if (hasTerm(c, term)) s += w;
    }
    if (s > 0) scores.set(cat, s);
  }
  return scores;
}

/** Infer a category from rule text + context. "other" only when nothing matches at all. */
export function inferCategory(rule: string, context: string): LearningCategory {
  const scores = scoreCategories(rule, context);
  let best: LearningCategory = "other";
  let bestScore = 0;
  for (const cat of CATEGORY_TIE_ORDER) {
    const s = scores.get(cat) || 0;
    if (s > bestScore) { best = cat; bestScore = s; }
  }
  return best;
}

/** Map free-form heading text to the closest LEARNING_CATEGORIES value. */
export function normalizeCategory(heading: string): LearningCategory {
  const h = normalizeForMatch(heading);
  // A heading that IS a category name ("## deployment", "## Testing") maps directly.
  for (const cat of LEARNING_CATEGORIES) {
    if (h.trim() === cat) return cat;
  }
  // A few heading words that the term lists do not carry as rule vocabulary.
  const headingWords: Array<[string, LearningCategory]> = [
    ["lessons", "other"], ["learnings", "other"], ["gotchas", "other"],
    ["hardening", "security"], ["malware", "security"], ["audit", "security"],
    ["terminal", "tooling"], ["commands", "tooling"], ["monitoring", "infrastructure"],
    ["bugs", "debugging"], ["fixes", "debugging"], ["speed", "performance"],
  ];
  for (const [word, cat] of headingWords) {
    if (hasTerm(h, word)) return cat;
  }
  return inferCategory(heading, "");
}

/**
 * Convert learnings to Chunks so they can be included in search_context.
 * This is the key integration — learnings auto-surface in hybrid search.
 *
 * When `projects` is provided, only includes learnings for those projects
 * (+ universal learnings with no project). This prevents cross-project
 * IP leakage — CROWLR secrets won't appear when searching in VOILA.
 */
export function learningsToChunks(projects?: string[]): Chunk[] {
  const store = loadStore();
  let learnings = store.learnings;

  if (projects && projects.length > 0) {
    const lowerProjects = projects.map((p) => p.toLowerCase());
    learnings = learnings.filter(
      (l) => !l.project || lowerProjects.includes(l.project.toLowerCase())
    );
  }

  return learnings.map((l) => ({
    source: "💡 Learnings Store",
    section: `[${l.category}] ${l.rule}`,
    content: [
      `**Rule:** ${l.rule}`,
      `**Category:** ${l.category}`,
      l.project ? `**Project:** ${l.project}` : "",
      l.context ? `**Context:** ${l.context}` : "",
      l.tags?.length ? `**Tags:** ${l.tags.join(", ")}` : "",
      l.created ? `_Learned: ${l.created.split("T")[0]}_` : "",
    ]
      .filter(Boolean)
      .join("\n"),
    lineStart: 0,
    lineEnd: 0,
  }));
}

/** What the last sweep of this process saw of a source; unchanged, and under the same trust list, it is skipped. */
const sweepMemo = new Map<string, { mtimeMs: number; size: number; trustKey: string }>();

export interface SweepResult {
  /** Sources that imported or updated at least one learning. */
  total: number;
  imported: number;
  updated: number;
  ignored: number;
  refused?: string;
  untrusted: string[];
  /** Markdown sources that exist. */
  sources: number;
  /** Sources read and parsed in this sweep. */
  scanned: number;
  /** Sources skipped: size, mtime and trust list as in the last sweep of this process. */
  unchanged: number;
  errors: number;
}

// [LOCKED] [SWEEP-RECORDS-ONLY-WHAT-CHANGED] - 2026-09-29
// [NEVER] write a learning.import record for a source that imported, updated or failed nothing,
//         and [NEVER] parse a source again while its size, mtime and the trust list are as in the
//         last sweep of this process.
// WHY: every sweep (each doc change, each start: 41 a day on the author's Mac) wrote one record per
//      source, about 896, whatever it found. Measured 2026-09-29 (E2E_REVIEW_2026-09 C3-1):
//      3,743,405 of the 4,963,143 records in the history said imported 0, updated 0: 75 % of the
//      records, 1.63 GB of the 2.06 GB, a rotation every 1.8 hours on busy days, and most of the
//      memory the daily chain check needed. "updated" also counted a rule that was already there,
//      so eleven files counted as updated at every sweep without changing.
// FIX: one learning.sweep record per sweep (sources, scanned, unchanged, imported, updated, ignored,
//      errors, untrusted, ms), a learning.import record only for a source that imported, updated or
//      failed, and a per-process memo (size, mtime, trust list) so an unchanged source is not
//      parsed again. A source that fails is not memoized, so it is tried again; a change of the
//      trust list re-reads everything once; a new process reads everything once.

/**
 * Auto-import learnings from discovered knowledge source files.
 *
 * Called during reindex — scans all source markdown files and extracts
 * rules into the permanent learning store. Deduplication is built-in,
 * so calling repeatedly on the same files is safe (no duplicates).
 *
 * This ensures documentation rules become searchable learnings without
 * requiring the user or agent to manually trigger `import_learnings`.
 */
export function autoImportFromSources(
  sources: Array<{ path: string; name: string }>,
): SweepResult {
  const t0 = Date.now();
  let totalImported = 0;
  let totalUpdated = 0;
  let totalIgnored = 0;
  let totalSkipped = 0;
  let totalErrors = 0;
  let processed = 0;
  let seen = 0;
  let scanned = 0;
  let unchanged = 0;
  let refused: string | undefined;
  // [LOCK] [AUTO-IMPORT-ONLY-FROM-TRUSTED-PROJECTS] (src/trusted-projects.ts): seeded, the first
  // time, with every project that already has learnings in the store.
  const trusted = trustedProjects(() => [...new Set(loadStore().learnings.map((l) => l.project).filter((p): p is string => !!p))]);
  const trustKey = [...trusted].sort().join("\n");
  const untrusted = new Set<string>();
  const perSource: Array<Record<string, unknown>> = [];
  const memoUpdates = new Map<string, { mtimeMs: number; size: number; trustKey: string }>();

  // One load and one save for the whole sweep (~880 files), instead of one full-file
  // rewrite per rule per file. [LOCK] [STORE-NEVER-STARTS-FRESH-OVER-DATA]
  try {
  withStoreBatch(() => {
  for (const source of sources) {
    // Only process markdown files
    if (!source.path.endsWith(".md")) continue;
    let st: { mtimeMs: number; size: number; isFile(): boolean };
    try {
      st = statSync(source.path);
    } catch {
      continue;
    }
    if (!st.isFile()) continue;
    seen++;
    const memo = sweepMemo.get(source.path);
    if (memo && memo.mtimeMs === st.mtimeMs && memo.size === st.size && memo.trustKey === trustKey) {
      unchanged++;
      continue;
    }
    scanned++;

    // Extract project name from source name (e.g., "ContextEngine — copilot-instructions.md")
    const project = source.name.split(" — ")[0]?.trim() || undefined;

    // A project the owner has not marked as theirs is searchable, never imported automatically.
    // [LOCK] [AUTO-IMPORT-ONLY-FROM-TRUSTED-PROJECTS]
    if (project && !trusted.has(project.toLowerCase())) {
      try {
        if (looksLikeMarkedLearnings(readFileSync(source.path, "utf-8"))) untrusted.add(project);
        memoUpdates.set(source.path, { mtimeMs: st.mtimeMs, size: st.size, trustKey });
      } catch {
        /* unreadable: nothing to import anyway, and no memo, so it is tried again */
      }
      continue;
    }

    // Strict by construction: only marked learnings. [LOCK] [AUTO-IMPORT-ONLY-MARKED-LEARNINGS]
    const result = importLearningsFromFile(source.path, "other", project, { record: false });
    totalImported += result.imported;
    totalUpdated += result.updated;
    totalIgnored += result.ignored;
    totalSkipped += result.skipped;
    totalErrors += result.errors.length;
    if (result.imported > 0 || result.updated > 0) processed++;
    if (result.imported > 0 || result.updated > 0 || result.errors.length > 0) {
      perSource.push({
        source: source.path,
        format: "markdown",
        project,
        imported: result.imported,
        updated: result.updated,
        skipped: result.skipped,
        ignored: result.ignored,
        errors: result.errors.length,
      });
    }
    if (result.errors.length === 0) memoUpdates.set(source.path, { mtimeMs: st.mtimeMs, size: st.size, trustKey });
  }
  });
  } catch (e) {
    // A refused write (growth or shrink tripwire, lock timeout) must not take the server down;
    // it is reported to the caller and the store is left as it was. [LOCK] [STORE-GROWTH-IS-A-TRIPWIRE-TOO]
    refused = e instanceof Error ? e.message : String(e);
    totalImported = 0;
    totalUpdated = 0;
    processed = 0;
    perSource.length = 0;
    memoUpdates.clear();
  }

  for (const [path, memo] of memoUpdates) sweepMemo.set(path, memo);
  // The records: per source only where something happened, then one for the sweep itself.
  for (const rec of perSource) safeAppend("learning.import", rec);
  safeAppend("learning.sweep", {
    sources: seen,
    scanned,
    unchanged,
    imported: totalImported,
    updated: totalUpdated,
    ignored: totalIgnored,
    skipped: totalSkipped,
    errors: totalErrors,
    untrusted: untrusted.size,
    ...(refused ? { refused } : {}),
    ms: Date.now() - t0,
  });

  return {
    total: processed,
    imported: totalImported,
    updated: totalUpdated,
    ignored: totalIgnored,
    refused,
    untrusted: [...untrusted],
    sources: seen,
    scanned,
    unchanged,
    errors: totalErrors,
  };
}

/**
 * Get the store stats.
 */
export function learningsStats(): { total: number; categories: Record<string, number> } {  const store = loadStore();
  const categories: Record<string, number> = {};
  for (const l of store.learnings) {
    categories[l.category] = (categories[l.category] || 0) + 1;
  }
  return { total: store.learnings.length, categories };
}

/**
 * Format learnings for display.
 */
// [LOCKED] [LEARNINGS-LIST-SHOWS-CREATED] 2026-09-05
// [NEVER] print a learning without its `created` instant, and [NEVER] answer "what was
//         saved since X" by probing learnings.json with a hand-written key.
// WHY: on 2026-09-05 an agent read a date field the records do not have (`createdAt`),
//      got an empty string for every record, and answered "0 saved today" with full
//      confidence; a second agent made the same mistake the same morning. A probe on a
//      missing key returns a confident zero, never an error. The store had 22 records
//      from that day, under `created`. Until then the listing showed the date only,
//      so "today" was also ambiguous around midnight between UTC and Yan's clock.
// FIX: one renderer shows `created` as the UTC instant plus the Europe/Zurich wall
//      time, and `--since today|yesterday|ISO` is a first-class filter whose empty
//      result names the boundary it applied. An unparseable spec is an error, not zero.
export const LEARNINGS_LOCAL_TZ = "Europe/Zurich";

/** `2026-09-05 10:30Z (12:30 CEST)`; `undated` when the record carries no usable instant. */
export function formatLearnedAt(iso: string | undefined, tz: string = LEARNINGS_LOCAL_TZ): string {
  if (!iso) return "undated";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "undated";
  const utc = d.toISOString().slice(0, 16).replace("T", " ") + "Z";
  const local = new Intl.DateTimeFormat("en-GB", {
    timeZone: tz, hour: "2-digit", minute: "2-digit", hour12: false, timeZoneName: "short",
  }).format(d);
  return `${utc} (${local})`;
}

/** Midnight of the given calendar day in `tz`, as a UTC instant. Offset read from Intl, never guessed. */
function localMidnightUtc(y: number, m: number, d: number, tz: string): Date {
  const guess = new Date(Date.UTC(y, m - 1, d, 0, 0, 0));
  const off = new Intl.DateTimeFormat("en-US", { timeZone: tz, timeZoneName: "longOffset" })
    .formatToParts(guess).find((p) => p.type === "timeZoneName")?.value ?? "GMT";
  const mm = /GMT([+-])(\d{2}):(\d{2})/.exec(off);
  const minutes = mm ? (mm[1] === "-" ? -1 : 1) * (parseInt(mm[2], 10) * 60 + parseInt(mm[3], 10)) : 0;
  return new Date(guess.getTime() - minutes * 60_000);
}

/** `today` | `yesterday` (calendar days in `tz`) | any ISO date or instant. `null` when unparseable. */
export function parseSince(spec: string, now: Date = new Date(), tz: string = LEARNINGS_LOCAL_TZ): Date | null {
  const s = spec.trim().toLowerCase();
  if (s === "today" || s === "yesterday") {
    const parts = new Intl.DateTimeFormat("en-CA", { timeZone: tz, year: "numeric", month: "2-digit", day: "2-digit" })
      .formatToParts(now);
    const get = (t: string) => parseInt(parts.find((p) => p.type === t)?.value ?? "0", 10);
    const midnight = localMidnightUtc(get("year"), get("month"), get("day"), tz);
    return s === "today" ? midnight : new Date(midnight.getTime() - 86_400_000);
  }
  if (!/^\d{4}-\d{2}-\d{2}/.test(spec.trim())) return null;
  const d = new Date(spec.trim());
  return Number.isNaN(d.getTime()) ? null : d;
}

/** Records created at or after `since`, oldest first. Undated records are excluded and counted by the caller. */
export function filterSince(learnings: Learning[], since: Date): Learning[] {
  return learnings
    .filter((l) => l.created && !Number.isNaN(new Date(l.created).getTime()) && new Date(l.created).getTime() >= since.getTime())
    .sort((a, b) => new Date(a.created).getTime() - new Date(b.created).getTime());
}

export interface FormatLearningsOptions {
  /** Already-parsed boundary; the caller resolves the spec so an invalid one errors before rendering. */
  since?: Date;
  /** The spec as typed, echoed in the header so the reader sees which boundary applied. */
  sinceSpec?: string;
}

export function formatLearnings(learnings: Learning[], opts: FormatLearningsOptions = {}): string {
  let sinceNote = "";
  if (opts.since) {
    learnings = filterSince(learnings, opts.since);
    sinceNote = ` since ${opts.sinceSpec ?? opts.since.toISOString()} = ${formatLearnedAt(opts.since.toISOString())}`;
  }
  if (learnings.length === 0) {
    if (opts.since) {
      return `0 learnings${sinceNote}. The boundary above is the one that was applied; if that looks wrong, the store is at ~/.contextengine/learnings.json and its date field is \`created\`.`;
    }
    return "No learnings stored yet. Use `save_learning` to add operational rules.";
  }

  const lines: string[] = [];
  lines.push(`# 💡 Learnings Store (${learnings.length} rules${sinceNote})\n`);

  // Group by category
  const byCategory = new Map<string, Learning[]>();
  for (const l of learnings) {
    const list = byCategory.get(l.category) || [];
    list.push(l);
    byCategory.set(l.category, list);
  }

  for (const [category, items] of byCategory) {
    lines.push(`## ${category} (${items.length})\n`);
    for (const l of items) {
      lines.push(`### ${l.rule}`);
      lines.push(`- **ID:** \`${l.id}\``);
      if (l.project) lines.push(`- **Project:** ${l.project}`);
      if (l.context) lines.push(`- **Context:** ${l.context}`);
      if (l.tags?.length) lines.push(`- **Tags:** ${l.tags.join(", ")}`);
      lines.push(`- **Learned:** ${formatLearnedAt(l.created)}`);
      lines.push("");
    }
  }

  return lines.join("\n");
}
