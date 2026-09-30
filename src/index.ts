#!/usr/bin/env node

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { loadSources, loadProjectDirs, loadConfig, resolveProjectDir, KnowledgeSource, findConfigFileWithOrigin, retiredAdaptersNote } from "./config.js";
import { ingestSources, lockGuardLine, Chunk } from "./ingest.js";
import { redactChunk } from "./secret-shapes.js";
import { summarizeSource } from "./source-summary.js";
import { searchChunks, SearchResult } from "./search.js";
import {
  initEmbeddings,
  embedChunks,
  embedKeyOf,
  vectorSearch,
  isEmbeddingsReady,
  EmbeddedChunk,
  VectorSearchResult,
} from "./embeddings.js";
import { collectProjectOps, collectSystemOps } from "./collectors.js";
import { repoStatus, type RepoStatus } from "./repo-status.js";
import { loadEmbeddingStore, compactEmbeddingStore } from "./embedding-store.js";
import {
  sharedIndexEnabled,
  corpusId,
  electIndexer,
  writeSharedIndex,
  readSharedIndex,
  sharedIndexMtime,
  type ServerRole,
} from "./shared-index.js";
import {
  listProjects,
  checkPorts,
  runComplianceAudit,
  formatProjectList,
  formatPortMap,
  formatPlan,
  scoreProject,
  formatScoreReport,
  runScoreCanary,
} from "./agents.js";
import {
  saveSession,
  loadSession,
  listSessions,
  formatSession,
  formatSessionList,
} from "./sessions.js";
import { autoRotateAuditLog, safeAppend, readVerifyState } from "./audit.js";
import { registerServer, listServers, formatServers, liveDaemonPid } from "./server-registry.js";
import { checkAgentRestart, recordAgentRestart, preflightBuild } from "./agent-restart.js";
import { secureCeHome } from "./ce-home.js";
import { trimDaemonLog } from "./daemon-log.js";
import { QUOTED_TEXT_NOTE } from "./framing.js";
import { computeFleetHealth, writeFleetHealth } from "./fleet-health.js";
import { anchorHealth, anchoringPolicy, anchorTickDue } from "./anchor.js";
import { startEventIngestServer } from "./http-server.js";
import {
  saveLearning,
  searchLearnings,
  listLearnings,
  deleteLearning,
  learningsToChunks,
  learningsStats,
  formatLearnings,
  autoImportFromSources,
  LEARNING_CATEGORIES, parseSince } from "./learnings.js";
import { readFileSync, existsSync, watch, statSync, writeFileSync, mkdirSync } from "fs";
import { basename, join, dirname } from "path";
import { homedir } from "os";
import { spawn } from "child_process";
import { setPriority } from "os";
import { scanCodeDir } from "./code-chunker.js";
import { fileURLToPath } from "url";
import { TOOL_COUNT, FREE_TOOL_COUNT, PREMIUM_TOOL_NAMES } from "./tools-manifest.js";

// Read version from package.json at startup
let PKG_VERSION = "1.21.3";
try {
  const __filename = fileURLToPath(import.meta.url);
  const __dirname = dirname(__filename);
  const pkg = JSON.parse(readFileSync(join(__dirname, "..", "package.json"), "utf-8"));
  PKG_VERSION = pkg.version || PKG_VERSION;
} catch { /* fallback */ }
import {
  gateCheckFresh,
  licenceCheckState,
  activate,
  getActivationStatus,
} from "./activation.js";
import { ProtocolFirewall } from "./firewall.js";

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------
let sources: KnowledgeSource[] = [];
let chunks: Chunk[] = [];
let embeddedChunks: EmbeddedChunk[] = [];
let activeProjectNames: string[] = [];
const firewall = new ProtocolFirewall();

// One indexer, many readers. [LOCK] [ONE-INDEXER-MANY-READERS]
// With the shared index off (default until the trial), every server is its own indexer, exactly
// as before, and only the content-addressed vector store below is new.
let role: ServerRole = "indexer";
let corpus: string | undefined;
let indexerPid: number | null = null;
let setRegistryRole: ((r: ServerRole) => void) | null = null;
let setRegistryEventPort: ((port: number | null) => void) | null = null;
/** The build this server registered with; the launchd agent leaves for a newer one. [LOCK] [THE-AGENT-FOLLOWS-THE-BUILD] */
let loadedBuild: string | null = null;
let lastRestartNote: string | null = null;
let preflightRunning = false;
let warnedRetiredAdapters = false;
/** key -> vector, loaded from ~/.contextengine/embeddings.bin and grown by what we embed. */
let vectorStore: Map<string, Float32Array> = new Map();
let indexSeq = 0;
let lastIndexMtime: number | null = null;
let modelInit: Promise<boolean> | null = null;

// Wire up learning search for auto-injection (avoids circular import)
firewall.setLearningSearchFn((query, projects) => {
  return searchLearnings(query)
    .filter((l) => {
      // Project-scoped: include if no project set OR project matches
      if (!projects || projects.length === 0) return true;
      if (!l.project) return true; // universal learning
      return projects.some(
        (p) => p.toLowerCase() === l.project!.toLowerCase()
      );
    })
    .slice(0, 10) // return generous set, firewall trims to INJECT_MAX
    .map((l) => ({ rule: l.rule, project: l.project, category: l.category }));
});

// [LOCKED] [COMMUNITY-RETIRED] - 2026-09-30
// [NEVER] let rules from outside this machine into the index again, or export the user's learnings
//         for publication, without the three guards the retired modules carried.
// WHY: the community rules (src/community-sync.ts, src/community-export.ts and the commands
//      sync-community-rules and export-learnings) were never used: no rules file on the owner's
//      Mac, no sync since August, 0 calls in any chat (E2E_REVIEW_2026-09 C2-3). Retired on the
//      owner's decision. What they had learned, kept here:
//      [COMMUNITY-TIER-A-IS-SIGNED] (2026-09-25): tier A was plain JSON from a public GitHub
//        repository, checked by nothing but TLS, so whoever could write to that repository wrote
//        into every user's search results; a sandbox accepted 5,001 unsigned rules, one of 200 KB
//        (A6-4). The fix was an Ed25519 signature of the exact bytes by the pinned licence key,
//        and caps on the count, the rule and context lengths, and the tags.
//      [COMMUNITY-SYNC-REPLAY-GUARD] (2026-06-25): a valid signature alone let a tier B response
//        captured by any past subscriber be replayed on any other machine for ever; the signed
//        payload had to name the licence token, the machine id and an expiry 24 hours away at most.
//      [COMMUNITY-EXPORT-SAFETY] (2026-06-24): the export was the only thing between the user's
//        personal learnings (production incidents, client fixes) and a public repository under
//        MIT, and one missed pattern is a leak with no take-back. Its redaction only ever grew,
//        its salt was a compile-time constant, and security, deployment and infrastructure
//        learnings never left in tier A.
// FIX: nothing on this side calls the server any more. The server side
//      (server/src/community-rules-server.ts, LOCK [COMMUNITY-RULES-SERVER], and
//      server/scripts/sign-community-rules.mjs) stays until the next server update, the owner's
//      call (2026-09-30). A revival starts from these three guards.
// [LOCKED] [ADAPTERS-RETIRED] - 2026-09-30
// [NEVER] import or run code that a config file names, in the MCP server or the CLI: every
//         dynamic import in src/ takes a path written in the source (tests/adapters-retired.test.ts).
// WHY: the plug-in adapters (src/adapters.ts, examples/adapters/) were never used: nothing was
//      configured on the owner's Mac (E2E_REVIEW_2026-09 batch 3 finding), and the owner retired
//      them. They were a door for code: a config named an ES module and the server imported it.
//      [ADAPTERS-ONLY-FROM-THE-USERS-OWN-CONFIG] (2026-09-25): without CONTEXTENGINE_CONFIG the
//      server reads ./contextengine.json from the folder it starts in, which for Claude Code is the
//      project opened, so a downloaded repository carrying a config and a module ran its own code
//      in the user's session when the project was opened (proven in a sandbox, A6-5), and a
//      relative path in the user's own config resolved from that folder too. The fix then: adapter
//      code only from CONTEXTENGINE_CONFIG or ~/.contextengine.json, paths from that file's folder.
//      Also found: an adapter's destroy() hook never ran, since the server has no shutdown path.
// FIX: a config that still lists adapters is told once on stderr that they are ignored
//      (retiredAdaptersNote() in src/config.ts), and no module it names is loaded. A revival starts
//      from the config-origin rule above and a shutdown path that runs destroy().
/**
 * Parse every source, collect ops and code, import learnings (indexer only), inject learnings.
 * Sets `sources`, `chunks`, `activeProjectNames`. No embedding
 * here. One body for startup and for every reindex; the two used to be separate copies.
 */
async function buildIndex(opts: { importLearnings: boolean }): Promise<void> {
  sources = loadSources();
  chunks = ingestSources(sources);

  // Collect operational data from project directories
  const config = loadConfig();
  const projectDirs = loadProjectDirs();
  activeProjectNames = projectDirs.map((d) => d.name);
  firewall.setProjectDirs(projectDirs);
  // [LOCK] [EXEC-FAILURE-IS-NOT-EMPTY]: a collector that could not run is counted here, never read as "nothing there".
  const collectorFailures: string[] = [];
  const onCollectorFailure = (collector: string, reason: string) => { collectorFailures.push(`${collector}: ${reason}`); };
  if (config.collectOps !== false) {
    let opsChunks = 0;
    for (const dir of projectDirs) {
      const ops = collectProjectOps(dir.path, dir.name, onCollectorFailure);
      chunks.push(...ops);
      opsChunks += ops.length;
    }
    if (opsChunks > 0) {
      console.error(
        `[ContextEngine] ⚙ Collected ${opsChunks} operational chunks from ${projectDirs.length} projects`
      );
    }
  }

  // Collect system-wide operational data
  if (config.collectSystemOps !== false) {
    const sysOps = collectSystemOps(onCollectorFailure);
    if (sysOps.length > 0) {
      chunks.push(...sysOps);
      console.error(
        `[ContextEngine] 🖥 Collected ${sysOps.length} system operational chunks`
      );
    }
  }
  if (collectorFailures.length > 0) {
    console.error(`[ContextEngine] ⚠ ${collectorFailures.length} collector(s) failed (${collectorFailures.join("; ")})`);
  }

  // Scan code files if configured
  if (config.codeDirs && config.codeDirs.length > 0) {
    let codeChunks = 0;
    for (const dir of projectDirs) {
      for (const codeDir of config.codeDirs) {
        const codePath = join(dir.path, codeDir);
        if (existsSync(codePath)) {
          const codeResults = scanCodeDir(codePath, dir.name);
          chunks.push(...codeResults);
          codeChunks += codeResults.length;
        }
      }
    }
    if (codeChunks > 0) {
      console.error(
        `[ContextEngine] 💻 Parsed ${codeChunks} code chunks from source files`
      );
    }
  }

  // Auto-import learnings from discovered doc sources. Dedup is built-in. Only the indexer of a
  // corpus writes the store from a sweep; a reader leaves that to it (one writer, not N).
  if (opts.importLearnings) {
    const autoImport = autoImportFromSources(
      sources.map((s) => ({ path: s.path, name: s.name }))
    );
    if (autoImport.imported > 0) {
      console.error(
        `[ContextEngine] 📥 Auto-imported ${autoImport.imported} new learnings from ${autoImport.total} doc sources (${autoImport.updated} updated)`
      );
    }
    if (autoImport.refused) {
      console.error(`[ContextEngine] ⛔ Auto-import write refused: ${autoImport.refused}`);
    }
    // [LOCK] [AUTO-IMPORT-ONLY-FROM-TRUSTED-PROJECTS]: say what was left out, and how to include it.
    if (autoImport.untrusted.length > 0) {
      console.error(
        `[ContextEngine] ⏸ Marked learnings in ${autoImport.untrusted.length} project(s) you have not marked as yours were not imported: ` +
          `${autoImport.untrusted.join(", ")}. If they are yours: contextengine trust ${autoImport.untrusted.map((p) => JSON.stringify(p)).join(" ")}`,
      );
    }
  }

  // Inject learnings as searchable chunks (project-scoped to prevent IP leakage)
  const learningChunks = learningsToChunks(activeProjectNames);
  if (learningChunks.length > 0) {
    chunks.push(...learningChunks);
    console.error(
      `[ContextEngine] 💡 Injected ${learningChunks.length} learning chunks into search index (scoped to ${activeProjectNames.length} projects)`
    );
  }

  // No community rules here since 2026-09-30. [LOCK] [COMMUNITY-RETIRED] (above buildIndex)

  // [LOCK] [INDEX-NEVER-SERVES-A-CREDENTIAL]
  chunks = chunks.map(redactChunk);

  // Plugin adapters retired 2026-09-30: a config that still lists some is told once, and no code it
  // names is loaded. [LOCK] [ADAPTERS-RETIRED] (above buildIndex)
  const adaptersNote = warnedRetiredAdapters ? null : retiredAdaptersNote(config, findConfigFileWithOrigin()?.path);
  if (adaptersNote) {
    warnedRetiredAdapters = true;
    console.error(adaptersNote);
  }
}

// [LOCK] [INDEX-NEVER-SERVES-A-CREDENTIAL]: redactChunk lives in src/secret-shapes.ts, shared with
// the CLI's index builder.

/** Load the model once; every caller shares the same promise. */
function ensureModel(): Promise<boolean> {
  if (!modelInit) modelInit = initEmbeddings();
  return modelInit;
}

/**
 * Vectors for the current chunks: from the store for every text it holds, embedded now for
 * the rest. [LOCK] [EMBEDDINGS-ARE-CONTENT-ADDRESSED]
 */
async function embedAll(): Promise<void> {
  if (!isEmbeddingsReady()) return;
  const snapshot = chunks;
  const r = await embedChunks(snapshot, vectorStore);
  if (snapshot !== chunks) return; // a newer build replaced these chunks meanwhile; its own embed follows
  embeddedChunks = r.embedded;
  console.error(`[ContextEngine] ✅ Semantic search ready: ${r.reused} vectors from the store, ${r.fresh} embedded now`);
  if (role === "indexer") {
    try {
      const c = compactEmbeddingStore(new Set(snapshot.map(embedKeyOf)));
      if (c.compacted) console.error(`[ContextEngine] 🧹 Embedding store compacted: ${c.before} -> ${c.after} records`);
    } catch (err) {
      console.error(`[ContextEngine] ⚠ embedding store compaction failed: ${(err as Error).message}`);
    }
  }
}

/** Indexer only: write the shared index for readers of this corpus. No-op otherwise. */
function publishIndex(): void {
  if (!corpus || role !== "indexer") return;
  try {
    indexSeq++;
    const r = writeSharedIndex({
      corpus,
      seq: indexSeq,
      writer: process.pid,
      sources,
      activeProjectNames,
      chunks,
      keys: chunks.map(embedKeyOf),
    });
    lastIndexMtime = sharedIndexMtime(corpus);
    safeAppend("index.write", { pid: process.pid, corpus, seq: indexSeq, chunks: chunks.length, vectors: embeddedChunks.length, bytes: r.bytes, ms: r.ms });
    console.error(`[ContextEngine] 📤 Shared index written: seq ${indexSeq}, ${chunks.length} chunks, ${Math.round(r.bytes / 1024)} KB, ${r.ms} ms`);
  } catch (err) {
    console.error(`[ContextEngine] ⚠ shared index write failed: ${(err as Error).message}`);
  }
}

/** Reader: take the indexer's chunks and resolve their vectors from the store. */
function adoptSharedIndex(): boolean {
  if (!corpus) return false;
  const f = readSharedIndex(corpus);
  if (!f) return false;
  sources = f.sources;
  chunks = f.chunks;
  activeProjectNames = f.activeProjectNames;
  try { firewall.setProjectDirs(loadProjectDirs()); } catch { /* scoping keeps its last value */ }
  vectorStore = loadEmbeddingStore().vectors;
  const vecs: EmbeddedChunk[] = [];
  let missing = 0;
  f.chunks.forEach((c, i) => {
    const v = vectorStore.get(f.keys[i]);
    if (v) vecs.push({ chunk: c, vector: v });
    else missing++;
  });
  embeddedChunks = vecs;
  indexSeq = f.seq;
  lastIndexMtime = sharedIndexMtime(corpus);
  console.error(
    `[ContextEngine] 📥 Shared index loaded: seq ${f.seq} from pid ${f.writer}, ${chunks.length} chunks, ${vecs.length} vectors${missing ? `, ${missing} not embedded yet` : ""}`
  );
  return true;
}

/**
 * (Re-)ingest all sources. Called at startup and on file changes by the indexer; a reader
 * never calls it on its own except as the fallback when no shared index exists yet.
 */
async function reindex(): Promise<void> {
  await buildIndex({ importLearnings: role === "indexer" });
  await embedAll();
  publishIndex();
}

// ---------------------------------------------------------------------------
// Hybrid Search: combine keyword + vector scores with temporal decay
// ---------------------------------------------------------------------------

/**
 * Temporal decay half-life in days.
 * Chunks older than this get a ~50% penalty; very recent chunks get a boost.
 * Set to 0 to disable temporal decay.
 */
const DECAY_HALF_LIFE_DAYS = 90;

/**
 * Compute a temporal decay multiplier for a chunk based on its indexedAt time.
 * Returns a value between 0.5 and 1.0 (exponential decay).
 * Formula: 0.5 + 0.5 * exp(-age_days * ln(2) / half_life)
 *
 * Age 0 days → 1.0 (no decay)
 * Age = half_life → 0.75
 * Age = 2 * half_life → 0.625
 * Very old → approaches 0.5
 */
function temporalDecay(chunk: Chunk): number {
  if (DECAY_HALF_LIFE_DAYS <= 0) return 1.0;
  if (!chunk.indexedAt) return 0.85; // Default for chunks without timestamp

  const now = Date.now();
  const indexedMs = new Date(chunk.indexedAt).getTime();
  if (isNaN(indexedMs)) return 0.85;

  const ageDays = (now - indexedMs) / (1000 * 60 * 60 * 24);
  const lambda = Math.LN2 / DECAY_HALF_LIFE_DAYS;
  return 0.5 + 0.5 * Math.exp(-ageDays * lambda);
}

interface HybridResult {
  chunk: Chunk;
  keywordScore: number;
  vectorScore: number;
  temporalMultiplier: number;
  combinedScore: number;
}

function hybridSearch(
  query: string,
  keywordResults: SearchResult[],
  vectorResults: VectorSearchResult[],
  topK: number
): HybridResult[] {
  const map = new Map<Chunk, HybridResult>();

  // Normalize keyword scores (max = 1.0)
  const maxKw = keywordResults.length > 0 ? keywordResults[0].score : 1;
  for (const r of keywordResults) {
    map.set(r.chunk, {
      chunk: r.chunk,
      keywordScore: r.score / maxKw,
      vectorScore: 0,
      temporalMultiplier: temporalDecay(r.chunk),
      combinedScore: 0,
    });
  }

  // Merge vector scores
  for (const r of vectorResults) {
    const existing = map.get(r.chunk);
    if (existing) {
      existing.vectorScore = r.score;
    } else {
      map.set(r.chunk, {
        chunk: r.chunk,
        keywordScore: 0,
        vectorScore: r.score,
        temporalMultiplier: temporalDecay(r.chunk),
        combinedScore: 0,
      });
    }
  }

  // Combined: 40% keyword + 60% semantic, multiplied by temporal decay
  for (const r of map.values()) {
    const rawScore = r.keywordScore * 0.4 + r.vectorScore * 0.6;
    r.combinedScore = rawScore * r.temporalMultiplier;
  }

  const results = Array.from(map.values());
  results.sort((a, b) => b.combinedScore - a.combinedScore);
  return results.slice(0, topK);
}

// ---------------------------------------------------------------------------
// File Watching
// ---------------------------------------------------------------------------
const watchers: ReturnType<typeof watch>[] = [];
let indexPoll: ReturnType<typeof setInterval> | null = null;
let rolePoll: ReturnType<typeof setInterval> | null = null;
const INDEX_POLL_MS = 3_000;
const ROLE_POLL_MS = 15_000;

function stopWatching(): void {
  for (const w of watchers) {
    try {
      w.close();
    } catch {
      /* ignore */
    }
  }
  watchers.length = 0;
}

/** Indexer only: one fs.watch per source; a change rebuilds, embeds the new chunks, publishes. */
function startWatching(): void {
  stopWatching();

  let debounceTimer: ReturnType<typeof setTimeout> | null = null;

  for (const source of sources) {
    if (!existsSync(source.path)) continue;

    try {
      const w = watch(source.path, () => {
        // Debounce: wait 500ms after last change before re-indexing
        if (debounceTimer) clearTimeout(debounceTimer);
        debounceTimer = setTimeout(async () => {
          if (role !== "indexer") return; // demoted while the timer ran
          console.error(
            `[ContextEngine] 📝 File changed: ${basename(source.path)} — re-indexing...`
          );
          await reindex();
          console.error(
            `[ContextEngine] ✅ Re-indexed: ${chunks.length} chunks from ${sources.length} sources`
          );
        }, 500);
      });
      watchers.push(w);
    } catch {
      // Can't watch this file (permission, network drive, etc.)
    }
  }

  console.error(
    `[ContextEngine] 👁 Watching ${watchers.length} source files for changes`
  );
}

/** Reader only: reload the shared index when its stamp moves. A stat every 3 s, nothing else. */
function startIndexPolling(): void {
  if (indexPoll || !corpus) return;
  indexPoll = setInterval(() => {
    if (role !== "reader" || !corpus) return;
    const m = sharedIndexMtime(corpus);
    if (m !== null && m !== lastIndexMtime) adoptSharedIndex();
  }, INDEX_POLL_MS);
  indexPoll.unref();
}

function stopIndexPolling(): void {
  if (indexPoll) clearInterval(indexPoll);
  indexPoll = null;
}

/** Who indexes, for the log: a pid, or nobody while every server of the corpus runs an old build. */
function indexerLabel(): string {
  if (indexerPid !== null) return `pid ${indexerPid}`;
  return role === "indexer" ? `pid ${process.pid}` : "none: every server of this corpus runs an old build, the last shared index is served";
}

/** Re-run the election; on a change of role, switch what this server does. */
function evaluateRole(reason: string): void {
  if (!corpus) return;
  let e: ReturnType<typeof electIndexer>;
  try {
    e = electIndexer(corpus, listServers().servers, process.pid);
  } catch (err) {
    console.error(`[ContextEngine] ⚠ election failed, staying ${role}: ${(err as Error).message}`);
    return;
  }
  indexerPid = e.indexer;
  if (e.role === role) return;
  const was = role;
  role = e.role;
  setRegistryRole?.(role);
  safeAppend("server.role", { pid: process.pid, corpus, role, indexer: indexerPid, reason });
  console.error(`[ContextEngine] 🧭 Role ${was} -> ${role} (${reason}; indexer ${indexerLabel()})`);
  if (role === "indexer") {
    stopIndexPolling();
    ensureModel().then(() => reindex()).then(() => startWatching()).catch((err) => {
      console.error(`[ContextEngine] ⚠ taking over as indexer failed: ${(err as Error).message}`);
    });
  } else {
    stopWatching();
    startIndexPolling();
  }
}

let healthTick = 0;
let lastStaleCount = -1;
let stopRegistry: (() => void) | null = null;
let ending = false;

/**
 * End this server. Everything that matters is already on disk (audit appends and store writes are
 * synchronous); the registry record is removed first. With the embedding model loaded, a normal exit
 * aborts in the model runtime's native teardown ("libc++abi: ... mutex lock failed", SIGABRT, 3 of 3
 * runs, releasing the model does not help) and leaves a macOS crash report per exit, so such a server
 * ends with SIGKILL, which skips that teardown. [LOCK] [A-CHAT-SERVER-ENDS-WITH-ITS-CHAT]
 */
function endThisServer(): void {
  if (ending) return;
  ending = true;
  try { stopRegistry?.(); } catch { /* the lister removes a dead record anyway */ }
  if (isEmbeddingsReady()) process.kill(process.pid, "SIGKILL");
  else process.exit(0);
}
const SERVER_STARTED_AT = Date.now();
let lastChainCheckSpawn = 0;

/**
 * The indexing server starts the daily full check of the audit chain, in its own process.
 * [LOCK] [HEALTH-SEES-THE-CHAIN] (src/fleet-health.ts): the check costs 26 s and 3.5 GB on 4.9M
 * records (measured 2026-09-27), so it never runs in this long-lived process, whose event loop
 * serves the receiver and the tools. A separate low-priority `audit-verify --scheduled`, at most
 * one attempt an hour, never in the first 10 minutes after a start, one at a time across processes
 * (its own lock). CONTEXTENGINE_CHAIN_CHECK=0 turns it off.
 */
function maybeScheduleChainCheck(): void {
  if (role !== "indexer" || process.env.CONTEXTENGINE_CHAIN_CHECK === "0") return;
  const now = Date.now();
  if (now - SERVER_STARTED_AT < 10 * 60_000 || now - lastChainCheckSpawn < 60 * 60_000) return;
  const state = readVerifyState();
  if (state && now - Date.parse(state.checkedAt) < 24 * 3_600_000) return;
  lastChainCheckSpawn = now;
  try {
    const cli = join(dirname(fileURLToPath(import.meta.url)), "cli.js");
    const child = spawn(process.execPath, [cli, "audit-verify", "--scheduled"], { stdio: "ignore", detached: true, env: process.env });
    if (child.pid) {
      try { setPriority(child.pid, 10); } catch { /* the check still runs, at normal priority */ }
    }
    child.unref();
    console.error(`[ContextEngine] 🔎 daily audit chain check started (pid ${child.pid ?? "?"})`);
  } catch (err) {
    console.error(`[ContextEngine] ⚠ could not start the daily audit chain check: ${(err as Error).message}`);
  }
}

let lastAnchorSpawn = 0;

/**
 * SealHour's hourly job, in its own low-priority process (`anchor tick --scheduled`), like the daily chain
 * check: it reads the history and talks to the time stamp services, never on this event loop. Started by
 * the indexing server only, when anchors/state.json says a checkpoint or a queued stamp is due; the job
 * itself takes the anchor lock, so a second indexer (shared index off) can never make a second chain.
 * Nothing at all unless the owner said yes on the enable screen. CONTEXTENGINE_ANCHOR=0 turns it off.
 * [LOCK] [ONE-EMITTER-PER-MACHINE] [LOCK] [NO-NETWORK-WITHOUT-ANCHOR-ENABLE] (src/anchor.ts)
 */
function maybeScheduleAnchorTick(): void {
  if (role !== "indexer" || process.env.CONTEXTENGINE_ANCHOR === "0") return;
  const now = Date.now();
  if (now - SERVER_STARTED_AT < 60_000 || now - lastAnchorSpawn < 5 * 60_000) return;
  let due = false;
  try {
    due = anchorTickDue(new Date(now));
  } catch {
    return;
  }
  if (!due) return;
  lastAnchorSpawn = now;
  try {
    const cli = join(dirname(fileURLToPath(import.meta.url)), "cli.js");
    const child = spawn(process.execPath, [cli, "anchor", "tick", "--scheduled"], { stdio: "ignore", detached: true, env: process.env });
    if (child.pid) {
      try { setPriority(child.pid, 10); } catch { /* the job still runs, at normal priority */ }
    }
    child.unref();
    console.error(`[ContextEngine] SealHour hourly job started (pid ${child.pid ?? "?"})`);
  } catch (err) {
    console.error(`[ContextEngine] could not start the SealHour hourly job: ${(err as Error).message}`);
  }
}

/**
 * The indexer writes ~/.contextengine/fleet-health.json once a minute: version drift, reindex
 * rate, today's blocks and refusals, the last verified release. Every surface reads that file.
 * [LOCK] [HEALTH-IS-MEASURED-NEVER-ESTIMATED]
 */
function publishHealth(): void {
  try {
    const h = computeFleetHealth({ version: PKG_VERSION });
    if (h.servers.stale.length !== lastStaleCount) {
      lastStaleCount = h.servers.stale.length;
      if (lastStaleCount > 0) console.error(`[ContextEngine] 🧭 ${lastStaleCount} server(s) on an old build: pid ${h.servers.stale.map((s) => s.pid).join(", ")}`);
    }
    if (role === "indexer") writeFleetHealth(h);
    maybeScheduleChainCheck();
    maybeScheduleAnchorTick();
  } catch (err) {
    console.error(`[ContextEngine] ⚠ fleet health failed: ${(err as Error).message}`);
  }
}

/**
 * The launchd agent leaves for a new build once its folder is quiet, and launchd starts it again on
 * that build. Chat servers never do. Said once per state in the log. [LOCK] [THE-AGENT-FOLLOWS-THE-BUILD]
 */
function followTheBuild(): void {
  if (process.env.OPSCONTEXT_DAEMON !== "1" || loadedBuild === null || ending || preflightRunning) return;
  const say = (note: string | null, icon = "🔄") => {
    if (note && note !== lastRestartNote) console.error(`[ContextEngine] ${icon} ${note}`);
    lastRestartNote = note;
  };
  const script = fileURLToPath(import.meta.url);
  let d: ReturnType<typeof checkAgentRestart>;
  try {
    d = checkAgentRestart({ script, loadedBuild, startedAt: SERVER_STARTED_AT });
  } catch (err) {
    say(`could not decide whether to restart for a new build: ${(err as Error).message}`, "⚠");
    return;
  }
  if (!d.restart) { say(d.note); return; }
  const { from, to } = d;
  preflightRunning = true;
  preflightBuild(script, to).then((p) => {
    preflightRunning = false;
    if (!p.ok) { say(`build ${to} on disk does not start (${p.error}); this agent stays on ${from}`, "⚠"); return; }
    try {
      // The marker first: without it a fresh agent could leave again for the same build.
      recordAgentRestart({ pid: process.pid, from, to });
    } catch (err) {
      say(`could not write the restart marker (${(err as Error).message}); this agent stays on ${from}`, "⚠");
      return;
    }
    safeAppend("server.self_restart", { pid: process.pid, from, to });
    console.error(`[ContextEngine] 🔄 build ${to} is on disk, quiet, and starts (this agent runs ${from}): leaving so launchd starts it on the new build`);
    endThisServer();
  });
}

function startRolePolling(): void {
  if (rolePoll) return;
  rolePoll = setInterval(() => {
    if (corpus) evaluateRole("periodic");
    followTheBuild();
    if (++healthTick % 4 === 0) publishHealth(); // every 60 s
  }, ROLE_POLL_MS);
  rolePoll.unref();
  setTimeout(publishHealth, 5_000).unref();
}

// ---------------------------------------------------------------------------
// MCP Server
// ---------------------------------------------------------------------------
const server = new McpServer({
  name: "ContextEngine",
  version: PKG_VERSION,
});

// ---------------------------------------------------------------------------
// Enforcement: Protocol Firewall — progressive response degradation
// ---------------------------------------------------------------------------
// The firewall instance is created above (in State section).
// It wraps EVERY tool response and escalates: silent → footer → header → degraded.
// At "degraded" level, tool output is truncated until the agent complies.
// See src/firewall.ts for the full design.

/** Helper: wrap a single-text tool response through the firewall */
function respond(toolName: string, text: string, contextHint?: string) {
  return {
    content: [{ type: "text" as const, text: firewall.wrap(toolName, text, contextHint) }],
  };
}

// ---------------------------------------------------------------------------
// Tool: search_context (hybrid: keyword + vector)
// ---------------------------------------------------------------------------
server.tool(
  "search_context",
  "Search across all indexed project knowledge (copilot-instructions, skills docs, runbooks, session docs). Uses hybrid BM25 keyword + semantic search with temporal decay. Returns the most relevant chunks with source file, section, and line numbers.",
  {
    query: z.string().describe("Natural language search query"),
    top_k: z
      .number()
      .int()
      .min(1)
      .max(30)
      .default(5)
      .describe("Number of results to return (default 5)"),
    mode: z
      .enum(["hybrid", "keyword", "semantic"])
      .default("hybrid")
      .describe("Search mode: hybrid (default), keyword-only, or semantic-only"),
  },
  async ({ query, top_k, mode }) => {
    let results: Array<{
      chunk: Chunk;
      score: number;
      label: string;
    }> = [];

    // A reader keeps its 300 MB model unloaded until someone asks for semantics; the first such
    // query is answered by keyword while the model loads. [LOCK] [EMBEDDINGS-ARE-CONTENT-ADDRESSED]
    if (mode !== "keyword" && !isEmbeddingsReady()) void ensureModel();

    if (mode === "keyword" || mode === "hybrid") {
      const kwResults = searchChunks(chunks, query, top_k * 2);

      if (mode === "keyword" || !isEmbeddingsReady()) {
        results = kwResults.map((r) => ({
          chunk: r.chunk,
          score: r.score,
          label: "keyword",
        }));
      } else {
        // Hybrid
        const vecResults = await vectorSearch(query, embeddedChunks, top_k * 2);
        const hybrid = hybridSearch(query, kwResults, vecResults, top_k);
        results = hybrid.map((r) => ({
          chunk: r.chunk,
          score: r.combinedScore,
          label: `kw:${r.keywordScore.toFixed(2)} sem:${r.vectorScore.toFixed(2)} age:${r.temporalMultiplier.toFixed(2)}`,
        }));
      }
    } else if (mode === "semantic") {
      if (!isEmbeddingsReady()) {
        return {
          content: [
            {
              type: "text" as const,
              text: "Semantic search unavailable — embeddings model not loaded. Use mode='keyword' or 'hybrid'.",
            },
          ],
          isError: true,
        };
      }
      const vecResults = await vectorSearch(query, embeddedChunks, top_k);
      results = vecResults.map((r) => ({
        chunk: r.chunk,
        score: r.score,
        label: "semantic",
      }));
    }

    results = results.slice(0, top_k);

    if (results.length === 0) {
      return {
        content: [
          {
            type: "text" as const,
            text: `No results found for: "${query}"`,
          },
        ],
      };
    }

    // Track how many results came from learnings (for value meter)
    const learningRecalls = results.filter(
      (r) => r.chunk.source.includes("Learnings") || r.chunk.source.includes("learning")
    ).length;
    if (learningRecalls > 0) {
      firewall.recordSearchRecalls(learningRecalls);
    }

    const searchMode = isEmbeddingsReady() ? mode : "keyword (embeddings loading)";
    const text = [
      `Search: "${query}" | Mode: ${searchMode} | ${results.length} results`,
      QUOTED_TEXT_NOTE, // [LOCK] [QUOTED-TEXT-IS-FRAMED-AS-DATA]
      "",
      ...results.map((r, i) =>
        [
          `--- Result ${i + 1} (${r.label}: ${r.score.toFixed(3)}) ---`,
          ...(r.chunk.locked
            ? ["🔒 LOCKED — This content has been verified. DO NOT re-audit or re-implement."]
            : []),
          ...(r.chunk.guardedBy?.length ? [lockGuardLine(r.chunk.guardedBy)] : []), // [LOCK] [LOCK-BLOCK-IS-FLAGGED-IN-CODE]
          `Source: ${r.chunk.source}`,
          `Section: ${r.chunk.section}`,
          `Lines: ${r.chunk.lineStart}-${r.chunk.lineEnd}`,
          "",
          r.chunk.content,
        ].join("\n")
      ),
    ].join("\n\n");

    return respond("search_context", text, query);
  }
);

// ---------------------------------------------------------------------------
// Tool: list_sources
// ---------------------------------------------------------------------------
server.tool(
  "list_sources",
  "List all knowledge sources indexed by ContextEngine, each with a one-line summary (from the file's own head: frontmatter description, title plus first sentence, or module docstring), status (found/missing) and chunk counts. Read the summary to pick the right source, then search_context for its passages.",
  {},
  async () => {
    const lines = sources.map((s) => {
      const exists = existsSync(s.path);
      const count = chunks.filter((c) => c.source === s.name).length;
      const embeddedCount = embeddedChunks.filter(
        (ec) => ec.chunk.source === s.name
      ).length;
      const status = exists
        ? `✅ ${count} chunks${embeddedCount > 0 ? ` (${embeddedCount} embedded)` : ""}`
        : "⚠ file not found";
      // A preview quotes the file: redacted like any chunk. [LOCK] [INDEX-NEVER-SERVES-A-CREDENTIAL]
      const summary = exists ? redactChunk({ content: summarizeSource(s) }).content : "";
      return `${s.name}: ${status}${summary ? `\n  ${summary}` : ""}\n  ${s.path}`;
    });

    const embStatus = isEmbeddingsReady()
      ? `✅ ${embeddedChunks.length} vectors`
      : "⏳ loading...";

    const text = [
      `ContextEngine v${PKG_VERSION}`,
      `Sources: ${sources.length} | Chunks: ${chunks.length} | Embeddings: ${embStatus}`,
      QUOTED_TEXT_NOTE, // [LOCK] [QUOTED-TEXT-IS-FRAMED-AS-DATA]
      "",
      ...lines,
    ].join("\n");

    return respond("list_sources", text);
  }
);

// ---------------------------------------------------------------------------
// Tool: reindex
// ---------------------------------------------------------------------------
server.tool(
  "reindex",
  "Force a full re-index of all knowledge sources. Use after adding new files or changing contextengine.json.",
  {},
  async () => {
    if (role === "reader" && corpus) {
      adoptSharedIndex();
      return respond(
        "reindex",
        `This server reads the shared index of corpus ${corpus} (indexer ${indexerLabel()}): reloaded seq ${indexSeq}, ${chunks.length} chunks, ${embeddedChunks.length} vectors. ` +
          (indexerPid !== null
            ? `Saving a doc makes the indexer rebuild; every reader picks it up within ${INDEX_POLL_MS / 1000} s.`
            : `Nothing rebuilds it until a server on the current build starts: reload a window, or restart the launchd agent. [LOCK] [ONE-INDEXER-MANY-READERS]`)
      );
    }
    await reindex();
    return respond("reindex", `Re-indexed: ${chunks.length} chunks from ${sources.length} sources. Embeddings: ${embeddedChunks.length} vectors.`);
  }
);

// ---------------------------------------------------------------------------
// Tool: list_projects (Multi-Agent Phase 1)
// ---------------------------------------------------------------------------
server.tool(
  "list_projects",
  "Discover and analyze all projects in the workspace. Shows tech stack (framework, runtime, key dependencies), infrastructure (git, docker, pm2), and git remote status for each project. Requires Pro license.",
  {},
  async () => {
    const gate = await gateCheckFresh("list_projects");
    if (gate) return { content: [{ type: "text" as const, text: gate }] };
    const projectDirs = loadProjectDirs();
    const projects = listProjects(projectDirs);
    const text = formatProjectList(projects);
    return respond("list_projects", text, "projects infrastructure stack");
  }
);

// ---------------------------------------------------------------------------
// Tool: check_ports (Multi-Agent Phase 1)
// ---------------------------------------------------------------------------
server.tool(
  "check_ports",
  "Scan all projects for port declarations (ecosystem.config.js, docker-compose.yml, .env, package.json) and detect port conflicts. Returns a port allocation map with conflict warnings. Requires Pro license.",
  {},
  async () => {
    const gate = await gateCheckFresh("check_ports");
    if (gate) return { content: [{ type: "text" as const, text: gate }] };
    const projectDirs = loadProjectDirs();
    const { ports, conflicts } = checkPorts(projectDirs);
    const text = formatPortMap(ports, conflicts);
    return respond("check_ports", text, "port conflicts allocation");
  }
);

// ---------------------------------------------------------------------------
// Tool: run_audit (Multi-Agent Phase 1 — Compliance Agent)
// ---------------------------------------------------------------------------
server.tool(
  "run_audit",
  "Run the Compliance Agent audit across all projects. Checks: port conflicts, git remotes (origin + gdrive), git hooks (post-commit auto-push), .env files (existence + gitignore), Docker config (restart policy, workdir), PM2 config (treekill, kill_timeout, no bash wrappers), version issues (EOL runtimes, outdated deps, MUI v4/v5 coexistence). Returns a structured plan with findings and remediation steps.",
  {
    scope: z
      .enum(["all", "compliance", "versions", "ports"])
      .default("all")
      .describe("Audit scope: all checks, compliance only, version checks only, or port conflicts only"),
  },
  async ({ scope }) => {
    const gate = await gateCheckFresh("run_audit");
    if (gate) return { content: [{ type: "text" as const, text: gate }] };
    const projectDirs = loadProjectDirs();
    const plan = runComplianceAudit(projectDirs);
    const text = formatPlan(plan);
    return respond("run_audit", text, `audit ${scope}`);
  }
);

// ---------------------------------------------------------------------------
// Tool: score_project (AI-Readiness Scoring)
// ---------------------------------------------------------------------------
server.tool(
  "score_project",
  "Score one or all projects on AI-readiness (0-100%). Checks documentation (copilot-instructions, README, CLAUDE.md, .cursorrules, SKILLS.md, .env.example), infrastructure (git, hooks, Docker, CI, deploy scripts, PM2), code quality (tests, TypeScript, linting, npm scripts), and security (.env gitignored, secrets exposure, lockfiles). Returns letter grade (A+ to F) with detailed breakdown.",
  {
    project: z
      .string()
      .optional()
      .describe("Project name OR absolute directory path to score. Omit to score all projects."),
  },
  async ({ project }) => {
    const gate = await gateCheckFresh("score_project");
    if (gate) return { content: [{ type: "text" as const, text: gate }] };

    // [LOCKED] [SCORE-CANARY-COVERS-EVERY-SCORER], 2026-08-19
    // [NEVER] let a scoring entry point run without the canary.
    // WHY: [SCORE-CANARY] was wired on the CLI only. This MCP tool — the path
    //    Claude Code actually scores through — had zero call sites, so a
    //    drifting scorer would have been caught when a human typed the
    //    command and missed entirely when an agent called the tool. Session
    //    21 §H2 found the same shape in the fleet-write guard: a guard that
    //    covers one caller reads, from the outside, exactly like one that works.
    // FIX: canary here too. This tool never writes SCORE.md, so a deviation
    //    is reported rather than fatal — but it is never silent.
    const canary = runScoreCanary();
    if (!canary.ok) {
      return {
        content: [{
          type: "text" as const,
          text:
            "🚨 Scoring canary FAILED — these scores are NOT trustworthy.\n\n" +
            canary.deviations.map((d) => `   • ${d}`).join("\n") +
            (canary.inconclusive
              ? "\n\nThe canary fixture could not be built, so the scorer is unverified. This is an unknown, not a pass."
              : "\n\nThe scorer no longer behaves as pinned. Fix the deviation or update the pin deliberately."),
        }],
      };
    }

    const projectDirs = loadProjectDirs();

    let scores;
    if (project) {
      // [SCORE-ACCEPTS-PATH] — resolve names and paths alike. This tool never writes
      // SCORE.md, so unlike the CLI its fleet-wide default is harmless and is kept.
      const dir = resolveProjectDir(project, projectDirs);
      if (!dir) {
        return {
          content: [
            {
              type: "text" as const,
              text: `Project "${project}" not found — not a known project name, and not an existing directory. Available: ${projectDirs.map((d) => d.name).join(", ")}`,
            },
          ],
        };
      }
      scores = [scoreProject(dir)];
    } else {
      scores = projectDirs.map(scoreProject);
    }

    const text = formatScoreReport(scores);
    return respond("score_project", text, project || "all projects scoring");
  }
);

// ---------------------------------------------------------------------------
// Tool: save_session (Session Persistence)
// ---------------------------------------------------------------------------
server.tool(
  "save_session",
  "Save a key-value entry to a named session. Use to persist decisions, context, plans, and findings between coding sessions. Each session can hold multiple keys (e.g., 'summary', 'active_tasks', 'decisions'). Keys are updated in place if they already exist.",
  {
    session: z
      .string()
      .describe("Session name (e.g., 'admin-crowlr-upgrade', 'compr-app-v2'). Will be created if it doesn't exist."),
    key: z
      .string()
      .describe("Entry key within the session (e.g., 'summary', 'active_tasks', 'decisions', 'blockers')"),
    value: z
      .string()
      .describe("Content to save — can be a summary, list of tasks, decisions, notes, code snippets, etc."),
  },
  async ({ session, key, value }) => {
    const result = saveSession(session, key, value);
    return respond("save_session", `✅ Saved key "${key}" to session "${session}" (${result.entries.length} entries total)`);
  }
);

// ---------------------------------------------------------------------------
// Tool: load_session (Session Persistence)
// ---------------------------------------------------------------------------
server.tool(
  "load_session",
  "Load a previously saved session by name. Returns all stored key-value entries with timestamps. Use at the start of a session to restore context from a previous conversation.",
  {
    session: z
      .string()
      .describe("Session name to load"),
  },
  async ({ session }) => {
    const result = loadSession(session);
    if (!result) {
      return {
        content: [
          {
            type: "text" as const,
            text: `No session found with name "${session}". Use \`list_sessions\` to see available sessions.`,
          },
        ],
      };
    }
    const text = formatSession(result);
    return respond("load_session", text);
  }
);

// ---------------------------------------------------------------------------
// Tool: list_sessions (Session Persistence)
// ---------------------------------------------------------------------------
server.tool(
  "list_sessions",
  "List all saved sessions. Shows session names, entry counts, and timestamps. Use to discover what context is available from previous conversations.",
  {},
  async () => {
    const sessions = listSessions();
    const text = formatSessionList(sessions);
    return respond("list_sessions", text);
  }
);

// ---------------------------------------------------------------------------
// Tool: end_session (End-of-Session Protocol Enforcer)
// ---------------------------------------------------------------------------
server.tool(
  "end_session",
  "MUST be called before ending any coding session. Checks all project repos for uncommitted changes, verifies documentation freshness (copilot-instructions.md, SKILLS.md, session docs), and returns a checklist of required actions. Will report PASS/FAIL for each check. The AI agent should resolve all FAIL items before ending.",
  {},
  async () => {
    const projectDirs = loadProjectDirs();
    const checks: string[] = [];
    let passCount = 0;
    let failCount = 0;

    checks.push("# End-of-Session Protocol\n");

    // --- Check 1: Uncommitted changes across all repos ---
    checks.push("## 1. Uncommitted Changes\n");
    const reposChecked = new Set<string>();

    // [LOCK] [EXEC-FAILURE-IS-NOT-EMPTY]: a repository git could not check is listed as UNCHECKED,
    // neither clean nor dirty, and the summary is never ALL CLEAR over it (2026-09-29, C6-5).
    let uncheckedCount = 0;
    const report = (name: string, st: RepoStatus) => {
      if (st.state === "not_git") return; // a plain folder: nothing to check
      if (st.state === "failed") {
        checks.push(`- ❔ **UNCHECKED** — \`${name}\` could not be checked: ${st.error}`);
        uncheckedCount++;
        return;
      }
      if (reposChecked.has(st.root)) return;
      reposChecked.add(st.root);
      const repoName = basename(st.root);
      if (st.state === "dirty") {
        checks.push(`- ❌ **FAIL** — \`${repoName}\` has ${st.files.length} uncommitted file(s)`);
        // Show first 5 files
        for (const f of st.files.slice(0, 5)) {
          checks.push(`  - \`${f.trim()}\``);
        }
        if (st.files.length > 5) checks.push(`  - ... and ${st.files.length - 5} more`);
        failCount++;
      } else {
        checks.push(`- ✅ **PASS** — \`${repoName}\` is clean`);
        passCount++;
      }
    };
    for (const dir of projectDirs) report(dir.name, repoStatus(dir.path));

    // Also check common doc repos that might not be in projectDirs
    const extraRepoPaths = [
      join(process.env.HOME || "", "FASTPROD"),
    ];
    for (const repoPath of extraRepoPaths) {
      if (!existsSync(repoPath) || reposChecked.has(repoPath)) continue;
      report(basename(repoPath), repoStatus(repoPath));
    }

    checks.push("");

    // --- Check 2: Documentation freshness ---
    checks.push("## 2. Documentation Freshness\n");
    const now = Date.now();
    const SESSION_THRESHOLD_MS = 4 * 60 * 60 * 1000; // 4 hours — if not modified in current session, flag it

    // Find copilot-instructions.md files across projects
    let copilotFound = false;
    for (const dir of projectDirs) {
      const copilotPath = join(dir.path, ".github", "copilot-instructions.md");
      if (existsSync(copilotPath)) {
        copilotFound = true;
        try {
          const stat = statSync(copilotPath);
          const ageMs = now - stat.mtimeMs;
          if (ageMs < SESSION_THRESHOLD_MS) {
            const mins = Math.round(ageMs / 60000);
            checks.push(`- ✅ **PASS** — \`${dir.name}/copilot-instructions.md\` updated ${mins}m ago`);
            passCount++;
          } else {
            const hours = Math.round(ageMs / 3600000);
            checks.push(`- ⚠️ **CHECK** — \`${dir.name}/copilot-instructions.md\` last modified ${hours}h ago — update if anything changed`);
            failCount++;
          }
        } catch {
          checks.push(`- ⚠️ **CHECK** — \`${dir.name}/copilot-instructions.md\` could not be read`);
        }
      }
    }
    if (!copilotFound) {
      checks.push("- ⚠️ **CHECK** — No copilot-instructions.md found in any project");
    }

    // Check SKILLS.md
    const skillsPaths = [
      join(process.env.HOME || "", "Projects", "EXO", "SKILLS.md"),
    ];
    for (const sp of skillsPaths) {
      if (existsSync(sp)) {
        try {
          const stat = statSync(sp);
          const ageMs = now - stat.mtimeMs;
          if (ageMs < SESSION_THRESHOLD_MS) {
            const mins = Math.round(ageMs / 60000);
            checks.push(`- ✅ **PASS** — \`SKILLS.md\` updated ${mins}m ago`);
            passCount++;
          } else {
            const hours = Math.round(ageMs / 3600000);
            checks.push(`- ⚠️ **CHECK** — \`SKILLS.md\` last modified ${hours}h ago — update if new capabilities were learned`);
            failCount++;
          }
        } catch {
          // Can't stat
        }
      }
    }

    // Check session doc
    const sessionDocPath = join(process.env.HOME || "", "FASTPROD", "docs", "CROWLR_COMPR_APPS_SESSION.md");
    if (existsSync(sessionDocPath)) {
      try {
        const stat = statSync(sessionDocPath);
        const ageMs = now - stat.mtimeMs;
        if (ageMs < SESSION_THRESHOLD_MS) {
          const mins = Math.round(ageMs / 60000);
          checks.push(`- ✅ **PASS** — \`SESSION.md\` updated ${mins}m ago`);
          passCount++;
        } else {
          const hours = Math.round(ageMs / 3600000);
          checks.push(`- ⚠️ **CHECK** — \`SESSION.md\` last modified ${hours}h ago — append session summary`);
          failCount++;
        }
      } catch {
        // Can't stat
      }
    }

    checks.push("");

    // --- SealHour: the outside time stamp of the audit chain, in the words of the contract. ---
    // [LOCK] [NOT-STAMPED-IS-NEVER-CALLED-STAMPED] (src/anchor.ts)
    checks.push("## 3. SealHour\n");
    try {
      const a = anchorHealth();
      const pol = anchoringPolicy();
      if (pol.required && (!a.enabled || a.problem)) {
        checks.push(`- ❌ **FAIL** — ${a.line} (required by ${pol.where})`);
        failCount++;
      } else if (a.problem) {
        checks.push(`- ⚠️ **CHECK** — ${a.line}`);
        failCount++;
      } else {
        checks.push(`- ${a.enabled ? "✅" : "ℹ️"} ${a.line}`);
      }
    } catch (err) {
      checks.push(`- ❔ **UNCHECKED** — SealHour status could not be read: ${(err as Error).message}`);
      uncheckedCount++;
    }
    checks.push("");

    // --- Summary ---
    checks.push("## Summary\n");
    const total = passCount + failCount + uncheckedCount;
    if (failCount === 0 && uncheckedCount > 0) {
      checks.push(`❔ **${uncheckedCount} check(s) could not run** — ${passCount}/${total} passed, nothing failed, but not every repo was seen (see UNCHECKED above).`);
    } else if (failCount === 0) {
      checks.push(`✅ **ALL CLEAR** — ${passCount}/${total} checks passed. Safe to end session.`);
    } else {
      checks.push(`⚠️ **${failCount} item(s) need attention** — ${passCount}/${total} passed.`);
      checks.push("");
      checks.push("**Before ending this session, please:**");
      checks.push("1. Commit and push all uncommitted changes");
      checks.push("2. Update copilot-instructions.md with version/feature changes");
      checks.push("3. Update SKILLS.md if new capabilities were used");
      checks.push("4. Append a session summary to SESSION.md");
      checks.push("5. Run `end_session` again to verify all clear");
    }

    return respond("end_session", checks.join("\n"));
  }
);

// ---------------------------------------------------------------------------
// Tool: save_learning (Permanent Learning Store)
// ---------------------------------------------------------------------------
server.tool(
  "save_learning",
  "Save a permanent operational rule learned during a coding session. Unlike sessions (ephemeral), learnings persist forever and auto-surface in search_context results so AI agents don't repeat mistakes. Duplicate rules (same category + rule text) are updated in place.",
  {
    category: z
      .enum(LEARNING_CATEGORIES)
      .describe("Category: deployment, api, database, frontend, backend, devops, security, performance, testing, debugging, tooling, git, dependencies, architecture, data, infrastructure, mobile, other"),
    rule: z
      .string()
      .describe("The operational rule — concise, actionable (e.g., 'Always restart Flask after model changes')"),
    context: z
      .string()
      .describe("Full context of how this was discovered — the bug, the fix, the symptoms (e.g., 'Avatar save returned 200 but field missing from API response — stale to_dict() cache')"),
    project: z
      .string()
      .optional()
      .describe("Project this learning applies to (e.g., 'CROWLR.io'). Omit if it's a general rule."),
  },
  async ({ category, rule, context, project }) => {
    try {
      const learning = saveLearning(category, rule, context, project);
      const stats = learningsStats();

      // Re-inject learnings into search index (project-scoped)
      const newChunks = learningsToChunks(activeProjectNames);
      // Remove old learning chunks and add new ones
      const nonLearningChunks = chunks.filter((c) => c.source !== "💡 Learnings Store");
      chunks.length = 0;
      chunks.push(...nonLearningChunks, ...newChunks);

      return respond("save_learning", [
              `✅ Learning saved: **${rule}**`,
              ``,
              `- **ID:** \`${learning.id}\``,
              `- **Category:** ${category}`,
              project ? `- **Project:** ${project}` : "",
              `- **Tags:** ${(learning.tags ?? []).join(", ")}`, // [LOCK] [LEARNING-FIELDS-ARE-OPTIONAL-ON-READ]
              ``,
              `📊 Store: ${stats.total} learnings across ${Object.keys(stats.categories).length} categories`,
              ``,
              `This learning will now auto-surface in \`search_context\` results when relevant.`,
            ]
              .filter(Boolean)
              .join("\n"));
    } catch (e) {
      return respond("save_learning", `❌ Learning rejected: ${e instanceof Error ? e.message : String(e)}`);
    }
  }
);

// ---------------------------------------------------------------------------
// Tool: list_learnings (Permanent Learning Store)
// ---------------------------------------------------------------------------
server.tool(
  "list_learnings",
  "List all permanent learnings, optionally filtered by category. Shows operational rules that have been discovered across sessions. Use search_context to find learnings by keyword — they're automatically included in search results.",
  {
    category: z
      .string()
      .optional()
      .describe("Filter by category (deployment, api, database, etc.). Omit to show all."),
    since: z
      .string()
      .optional()
      .describe("Only learnings created at or after this boundary: 'today', 'yesterday' (Europe/Zurich calendar days) or an ISO date/instant. Every entry shows its created instant, UTC plus Europe/Zurich."),
  },
  async ({ category, since }) => {
    // Project-scoped: only show learnings for active workspace projects + universal (no project)
    let sinceDate: Date | undefined;
    if (since) {
      const parsed = parseSince(since);
      if (!parsed) return respond("list_learnings", `❌ since="${since}" is not today, yesterday, or an ISO date. No list rendered, so this is not a zero.`);
      sinceDate = parsed;
    }
    const learnings = listLearnings(category, activeProjectNames);
    const text = formatLearnings(learnings, { since: sinceDate, sinceSpec: since });
    // Redacted like every chunk: a learning can quote a command with its password. [LOCK] [INDEX-NEVER-SERVES-A-CREDENTIAL]
    return respond("list_learnings", redactChunk({ content: text }).content);
  }
);

// ---------------------------------------------------------------------------
// Tool: delete_learning (Permanent Learning Store)
// ---------------------------------------------------------------------------
server.tool(
  "delete_learning",
  "Delete a learning by its ID. Use list_learnings first to find the ID of the learning you want to remove.",
  {
    id: z.string().describe("The unique ID of the learning to delete"),
  },
  async ({ id }) => {
    const deleted = deleteLearning(id);
    if (!deleted) {
      return respond("delete_learning", `❌ No learning found with ID "${id}". Use \`list_learnings\` to see available IDs.`);
    }
    // Re-inject learnings into search index
    const newChunks = learningsToChunks(activeProjectNames);
    const nonLearningChunks = chunks.filter((c) => c.source !== "💡 Learnings Store");
    chunks.length = 0;
    chunks.push(...nonLearningChunks, ...newChunks);
    return respond("delete_learning", `✅ Learning "${id}" deleted successfully.`);
  }
);

// ---------------------------------------------------------------------------
// Tool: activate (License Activation)
// ---------------------------------------------------------------------------
server.tool(
  "activate",
  "Activate a ContextEngine Pro license to unlock premium tools (score_project, run_audit, check_ports, list_projects, HTML reports). Get a license at https://api.compr.ch/contextengine/pricing",
  {
    license_key: z.string().describe("Your ContextEngine license key"),
    email: z.string().describe("Email associated with the license"),
  },
  async ({ license_key, email }) => {
    const result = await activate(license_key, email);
    return respond("activate", result.message);
  }
);

// ---------------------------------------------------------------------------
// Tool: activation_status (Check License)
// ---------------------------------------------------------------------------
server.tool(
  "activation_status",
  "Check current ContextEngine license status, plan, and available premium tools.",
  {},
  async () => {
    const status = getActivationStatus();
    const lines = [
      `## ContextEngine License Status\n`,
      `- **Activated**: ${status.activated ? "✅ Yes" : "❌ No"}`,
      `- **Plan**: ${status.plan}`,
      `- **Expires**: ${status.expiresAt}`,
      `- **Delta version**: ${status.deltaVersion}`,
      `- **Machine ID**: ${status.machineId}`,
      `- **Licence check**: ${licenceCheckState()}`, // [LOCK] [LICENSE-IS-CHECKED-DAILY]
      ``,
    ];
    if (status.premiumTools.length > 0) {
      lines.push(`### 🔓 Premium Tools Available`);
      for (const t of status.premiumTools) {
        lines.push(`- ${t}`);
      }
    } else {
      lines.push(`### 🔒 Premium Tools (requires activation)`);
      lines.push(`- score_project, run_audit, check_ports, list_projects`);
      lines.push(``);
      lines.push(`Get a license: https://api.compr.ch/contextengine/pricing`);
      lines.push(`Activate: \`npx contextengine activate <key> <email>\``);
    }
    return respond("activation_status", lines.join("\n"));
  }
);

// ---------------------------------------------------------------------------
// MCP Resources: expose each source as a browsable resource
// ---------------------------------------------------------------------------
function registerResources(): void {
  // Static resources for each discovered source — deduplicate by URI
  const registered = new Set<string>();
  for (const source of sources) {
    if (!existsSync(source.path)) continue;

    const uri = `context://${encodeURIComponent(source.name)}`;
    if (registered.has(uri)) continue;
    registered.add(uri);

    server.resource(
      source.name,
      uri,
      {
        description: `Knowledge source: ${source.name}`,
        mimeType: "text/markdown",
      },
      async () => {
        const content = existsSync(source.path)
          ? readFileSync(source.path, "utf-8")
          : `Source file not found: ${source.path}`;

        return {
          contents: [
            {
              uri,
              mimeType: "text/markdown",
              text: content,
            },
          ],
        };
      }
    );
  }

  console.error(
    `[ContextEngine] 📚 Registered ${registered.size} MCP resources (${sources.length - registered.size} duplicates skipped)`
  );
}

// ---------------------------------------------------------------------------
// Start
// ---------------------------------------------------------------------------
async function main() {
  // A build proving it starts, for the launchd agent about to leave for it: every static import has
  // been evaluated by now, and nothing is written. [LOCK] [THE-AGENT-FOLLOWS-THE-BUILD]
  if (process.env.CONTEXTENGINE_PREFLIGHT === "1") process.exit(0);
  // [LOCK] [CE-HOME-IS-PRIVATE]: the folder is 0700 before the registry, the index or the log write
  // into it.
  secureCeHome();
  // The launchd agent keeps its own log readable: above 50 MB, the last 5 MB are kept as
  // mcp-stderr.1.log and the open file is truncated in place. [LOCK] [DAEMON-LOG-TRIMS-ITSELF]
  if (process.env.OPSCONTEXT_DAEMON === "1") {
    const trim = trimDaemonLog();
    if (trim.trimmed) {
      console.error(
        `[ContextEngine] 🧹 daemon log trimmed: ${(trim.bytes / 1048576).toFixed(0)} MB, the last ${((trim.kept ?? 0) / 1048576).toFixed(1)} MB kept as ${trim.keptTo}`
      );
    }
  }
  // 0. Inventory this server FIRST, before indexing takes minutes: a server exists the moment it
  //    starts. [LOCK] [SERVERS-ARE-INVENTORIED]. With the shared index on, the registry is also
  //    the electorate: the record carries the corpus and the role. [LOCK] [ONE-INDEXER-MANY-READERS]
  if (sharedIndexEnabled()) {
    try {
      corpus = corpusId();
    } catch (err) {
      console.error("[ContextEngine] ⚠ corpus id failed, shared index off for this server:", err);
    }
  }
  try {
    const reg = registerServer({ version: PKG_VERSION, script: fileURLToPath(import.meta.url), corpus, role: corpus ? "reader" : undefined, daemon: process.env.OPSCONTEXT_DAEMON === "1", onSignal: endThisServer });
    stopRegistry = reg.stop;
    loadedBuild = reg.record.build;
    setRegistryRole = reg.setRole;
    setRegistryEventPort = reg.setEventPort;
    const fleet = listServers();
    if (corpus) {
      const e = electIndexer(corpus, fleet.servers, process.pid);
      role = e.role;
      indexerPid = e.indexer;
      reg.setRole(role);
      safeAppend("server.role", { pid: process.pid, corpus, role, indexer: indexerPid, reason: "start" });
    }
    console.error(`[ContextEngine] 🧭 ${formatServers(fleet)}`);
    if (corpus) console.error(`[ContextEngine] 🧭 This server: ${role} of corpus ${corpus}${role === "reader" ? ` (indexer ${indexerLabel()})` : ""}`);
    safeAppend("server.start", { pid: reg.record.pid, parent: reg.record.parent, version: reg.record.version, build: reg.record.build, cwd: reg.record.cwd, servers_running: fleet.servers.length, stale_builds: fleet.servers.filter((x) => x.staleBuild).length });
  } catch (err) {
    console.error("[ContextEngine] ⚠ Server registry failed:", err);
  }

  // 1. The index: a reader takes the indexer's; everyone else, or a reader with nothing to
  //    take yet, builds it (fast, keyword search available immediately).
  let adopted = false;
  if (role === "reader") adopted = adoptSharedIndex();
  if (!adopted) {
    if (role === "reader") console.error("[ContextEngine] 📥 No shared index yet; building locally once, without importing learnings");
    await buildIndex({ importLearnings: role === "indexer" });
  }

  // 2. Register MCP resources
  registerResources();

  // 2b. Auto-inject recent session context into search index
  const recentSessions = listSessions().filter((s) => !s.error); // an unreadable file is listed by list_sessions, never injected
  if (recentSessions.length > 0) {
    // Sort by updated desc, take the most recent
    recentSessions.sort((a, b) => new Date(b.updated).getTime() - new Date(a.updated).getTime());
    const recent = recentSessions[0];
    const recentSession = loadSession(recent.name);
    if (recentSession) {
      const ageHours = (Date.now() - new Date(recentSession.updated).getTime()) / 3600000;
      if (ageHours < 72) { // Only inject if session is less than 3 days old
        const sessionContent = recentSession.entries
          .map((e) => `### ${e.key}\n${e.value}`)
          .join("\n\n");

        chunks.push({
          source: `Session: ${recentSession.name}`,
          section: "Last Session Context",
          content: `# Previous Session: ${recentSession.name}\n_Updated: ${recentSession.updated}_\n\n${sessionContent}`,
          lineStart: 0,
          lineEnd: 0,
        });
        console.error(
          `[ContextEngine] 📋 Auto-injected session "${recentSession.name}" (${recentSession.entries.length} entries, ${Math.round(ageHours)}h ago)`
        );
      }
    }
  }

  // 3. Connect MCP transport (server is usable with keyword search now)
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("[ContextEngine] 🚀 MCP server running on stdio (keyword search ready)");

  // [LOCKED] [A-CHAT-SERVER-ENDS-WITH-ITS-CHAT] - 2026-09-27
  // [NEVER] let a server whose client closed its stdin keep running, unless it is the launchd agent.
  // WHY: the file watchers and the event receiver keep the event loop alive, and nothing listened for
  //      the end of stdin. When a chat's client died without stopping its server (3 of 3 runs,
  //      E2E_REVIEW_2026-09 B5-2), the server lived on, adopted by launchd, still the indexer, still
  //      holding the event port, running its build for good; new servers became its readers.
  // FIX: stdin's end or close ends a chat server (its registry record goes with it, and a reader takes
  //      over the index within one role poll, 15 s). The launchd agent (OPSCONTEXT_DAEMON=1) has
  //      stdin on /dev/null by design and is exempt. [LOCK] [AUTOSTART-IS-THE-STANDING-INDEXER]
  //      Ending goes through endThisServer(): with the embedding model loaded, a normal exit aborts in
  //      native code and leaves a macOS crash report each time, so such a server ends with SIGKILL
  //      after its record is removed; the stop signals (SIGTERM, SIGINT, SIGHUP) take the same path.
  if (process.env.OPSCONTEXT_DAEMON !== "1") {
    const leave = () => {
      console.error("[ContextEngine] 👋 the client closed the connection: this server stops");
      endThisServer();
    };
    process.stdin.once("end", leave);
    process.stdin.once("close", leave);
  }

  // 3a. Audit log auto-rotation. Deferred so the first requests are answered before the
  // synchronous verify + rewrite (a few seconds on a 500k-record chain) blocks the loop.
  // [LOCK] [AUTO-ROTATE-HYSTERESIS-AND-ONE-RUNNER]
  // Measured 2026-08-21: ~13k records/hour on this machine, so the 100k trigger is hours
  // away, not a day; a server that is never restarted must still rotate. Hourly recheck.
  const runAutoRotate = () => {
    try {
      const o = autoRotateAuditLog();
      if (o.action === "rotated" || o.action === "refused" || o.action === "error" || o.action === "in_progress" || o.action === "finished") {
        console.error(`[ContextEngine] 📦 audit auto-rotate (${o.action}): ${o.detail}`);
      }
    } catch (err) {
      console.error(`[ContextEngine] ⚠ audit auto-rotate failed: ${(err as Error).message}`);
    }
  };
  setTimeout(runAutoRotate, 3_000).unref();
  setInterval(runAutoRotate, 60 * 60_000).unref();

  // 3b. Write server-meta.json so the VS Code extension can read tool count
  // without needing an active MCP session. Single source of truth =
  // src/tools-manifest.ts (asserted by tests/tools-manifest.test.ts).
  try {
    const metaDir = join(homedir(), ".contextengine");
    mkdirSync(metaDir, { recursive: true });
    writeFileSync(
      join(metaDir, "server-meta.json"),
      JSON.stringify(
        {
          toolCount: TOOL_COUNT,
          freeCount: FREE_TOOL_COUNT,
          premiumCount: PREMIUM_TOOL_NAMES.length,
          version: PKG_VERSION,
          generatedAt: new Date().toISOString(),
        },
        null,
        2
      ),
    );
  } catch (err) {
    console.error("[ContextEngine] ⚠ Failed to write server-meta.json:", err);
  }

  // 4. Vectors. The store holds one vector per text ever embedded on this machine; the model
  //    always loads for whoever embeds or answers queries. [LOCK] [EMBEDDINGS-ARE-CONTENT-ADDRESSED]
  //    A reader that adopted the index already has its vectors and loads the model on its first
  //    semantic query, not before: 300 MB per process is worth waiting for.
  if (!adopted && role === "indexer") {
    vectorStore = loadEmbeddingStore().vectors;
    if (vectorStore.size > 0) console.error(`[ContextEngine] 💾 Embedding store: ${vectorStore.size} vectors`);
    publishIndex(); // keyword-searchable index for readers now; vectors follow
    ensureModel().then(async (ready) => {
      if (!ready) return;
      await embedAll();
      publishIndex();
    });
  } else if (!adopted) {
    // A reader that started before its indexer published (every window restarted at once):
    // keyword search from its own build, no embedding of its own, the index adopted the moment
    // it appears. Only indexers embed; that is the whole point. [LOCK] [ONE-INDEXER-MANY-READERS]
    console.error(`[ContextEngine] ⏳ Reader without an index: keyword search only until pid ${indexerPid ?? "?"} publishes`);
  }

  // 5. Watch (indexer) or poll (reader), and keep the election running
  if (role === "indexer") startWatching();
  else startIndexPolling();
  startRolePolling();

  // 5b. A daemon (launchd, OPSCONTEXT_DAEMON=1) has stdin on /dev/null, so the stdio transport
  // closes at once; as a reader it holds no watchers and every poller is unref'd, and the loop
  // would drain and exit 0, which KeepAlive turns into a restart every 10 s. Hold the loop open.
  // [LOCK] [AUTOSTART-IS-THE-STANDING-INDEXER]
  if (process.env.OPSCONTEXT_DAEMON === "1") {
    setInterval(() => { /* keep the event loop alive: this process serves the index, not a client */ }, 60_000);
    console.error("[ContextEngine] 🛡 Daemon mode: staying alive without an MCP client");
  }

  // 6. Boot the local HTTP event-ingest endpoint for the browser extension.
  // Local 127.0.0.1:7842 only; auth via shared secret at
  // ~/.contextengine/extension-secret (see init-extension-secret CLI).
  // No-op if secret is missing; the endpoint will refuse with 401 until
  // a secret is configured. Failure to bind (port collision) logs and
  // continues — the MCP server stays usable without browser capture.
  // [LOCK] [EVENT-PORT-BELONGS-TO-THE-DAEMON]: the launchd agent keeps trying until it holds the
  // port; a chat server takes it only while no agent is alive, and hands it over when one is.
  startEventIngestServer({
    daemon: process.env.OPSCONTEXT_DAEMON === "1",
    onPortChange: (port) => setRegistryEventPort?.(port),
    liveDaemon: () => liveDaemonPid(),
  }).catch((err) => {
    console.error("[ContextEngine] event-ingest start failed:", err);
  });
}

main().catch((err) => {
  console.error("[ContextEngine] Fatal:", err);
  process.exit(1);
});
