// 🔒 LOCKED [CLAUDE-HOOK-INSTALL] — 2026-06-23
// ⛔ NEVER overwrite existing entries in hooks.PostToolUse — must APPEND.
//    Users (and CE itself via the dogfood settings) commonly have
//    matcher-specific PostToolUse entries (e.g. "Read|Edit|Write" gating)
//    that would be silently destroyed by a replace.
// ⛔ NEVER write to ~/.claude/settings.json without parsing first. A typo
//    or non-JSON state means Claude Code refuses to start.
// ⛔ NEVER emit on PreToolUse — would double-count vs PostToolUse for the
//    `stuck` heuristic and skew `silent_failure` counts.
// WHY: Claude Code hook wiring is the ONLY way the user's terminal Claude
//    Code sessions get into the OpsContext audit log. The installer has to
//    be safe (idempotent, preserve existing) AND legible (clear error
//    messages) AND fast (one command). If users have to hand-edit JSON,
//    they won't.
// FIX: To add a new hook event, extend EVENT_KINDS + the splice block.
//    Keep the "preserve existing" discipline in every code path.

import { existsSync, readFileSync, writeFileSync, copyFileSync, chmodSync, mkdirSync } from "fs";
import { join, dirname } from "path";
import { homedir } from "os";
import { fileURLToPath } from "url";
import { execSync } from "child_process";
// [LOCK] [M2-ESM-FILENAME-FIX]: the package is "type": "module", so a bare __dirname is a
// ReferenceError at runtime. Found 2026-09-06 while adding the Stop gate: the defaults/ lookup
// below used `__dirname_esm`, and a real run against a throwaway HOME died with
// "__dirname is not defined": the installer had never worked from the published package.
const __dirname_esm = dirname(fileURLToPath(import.meta.url));

const CLAUDE_DIR = join(homedir(), ".claude");
const SETTINGS_FILE = join(CLAUDE_DIR, "settings.json");
const HOOKS_DIR = join(CLAUDE_DIR, "hooks");
const HOOK_SCRIPT = join(HOOKS_DIR, "opscontext-emit.sh");
/** The Stop gate: a wrapper that runs `session-gate` with the node and CLI that installed it.
 *  [LOCK] [SESSION-SAVE-IS-A-GATE] (src/session-gate.ts) */
const GATE_SCRIPT = join(HOOKS_DIR, "opscontext-session-gate.sh");
/** The simplicity gate: a PostToolUse hook on Edit/Write that reports complexity the edit just
 *  introduced in a Python file, compared with git HEAD. Optional: `--simplicity`.
 *  [LOCK] [SIMPLICITY-GATE-SILENT-WHEN-BLIND] (defaults/simplicity-gate.py) */
const SIMPLICITY_SCRIPT = join(HOOKS_DIR, "opscontext-simplicity-gate.py");
const SIMPLICITY_MATCHER = "Edit|Write|MultiEdit";
const OUR_SCRIPTS = [HOOK_SCRIPT, GATE_SCRIPT, SIMPLICITY_SCRIPT];

const EVENT_KINDS = ["UserPromptSubmit", "PostToolUse", "SessionStart"] as const;

export interface HookCommand {
  type: string;
  command: string;
  timeout?: number;
}

export interface HookEntry {
  matcher?: string;
  hooks: HookCommand[];
}

export interface Settings {
  hooks?: Record<string, HookEntry[]>;
  [k: string]: unknown;
}

function readSettings(): Settings {
  if (!existsSync(SETTINGS_FILE)) return {};
  try {
    return JSON.parse(readFileSync(SETTINGS_FILE, "utf-8")) as Settings;
  } catch (err) {
    throw new Error(
      `${SETTINGS_FILE} is not valid JSON — refusing to touch. (${err instanceof Error ? err.message : err})`,
    );
  }
}

function backupSettings(): string {
  if (!existsSync(SETTINGS_FILE)) return "";
  const ts = new Date().toISOString().replace(/[:.]/g, "-");
  const backup = `${SETTINGS_FILE}.bak-pre-opscontext-${ts}`;
  copyFileSync(SETTINGS_FILE, backup);
  return backup;
}

// [LOCKED] [HOOKS-COMPARED-BY-EXPANDED-PATH] - 2026-09-15
// [NEVER] compare a hook command with startsWith or any other literal text match again.
// WHY: settings.json held the emit hooks as "$HOME/.claude/hooks/opscontext-emit.sh <Kind>",
//      hand-wired on 2026-06-23 before this installer existed. On 2026-09-06 the 2.7.0 rollout
//      ran install-claude-hook; its startsWith(absolute path) check did not see them, printed
//      "4 hook entries added, 0 already present" and wrote a second set. From 2026-09-06
//      08:20:21Z every Claude Code event reached the audit log twice (0 doubled events in the 8
//      days before, 99.5 to 100 percent every day after), doubling the stuck and silent_failure
//      inputs that [OPSCONTEXT-CC-HOOK] protects.
// FIX: compare the script path after expanding $HOME, ${HOME} and a leading ~; installing also
//      removes extra copies of our own commands under the same matcher, and nothing else.

/** The first shell word of a command, quotes removed ('...', "...", backslash), and the rest. */
function splitFirstWord(command: string): { word: string; rest: string } {
  const s = command ?? "";
  let i = 0;
  while (i < s.length && /\s/.test(s[i])) i++;
  let word = "";
  while (i < s.length && !/\s/.test(s[i])) {
    const ch = s[i];
    if (ch === "'") {
      const j = s.indexOf("'", i + 1);
      word += j < 0 ? s.slice(i + 1) : s.slice(i + 1, j);
      i = j < 0 ? s.length : j + 1;
    } else if (ch === '"') {
      let j = i + 1;
      while (j < s.length && s[j] !== '"') {
        if (s[j] === "\\" && j + 1 < s.length) { word += s[j + 1]; j += 2; } else { word += s[j]; j++; }
      }
      i = j + 1;
    } else if (ch === "\\" && i + 1 < s.length) {
      word += s[i + 1];
      i += 2;
    } else {
      word += ch;
      i++;
    }
  }
  return { word, rest: s.slice(i).trim() };
}

/** The script path of a hook command, with $HOME, ${HOME} or a leading ~ expanded. */
export function hookScriptPath(command: string, home: string = homedir()): string {
  return splitFirstWord(command).word.replace(/^(?:\$HOME|\$\{HOME\}|~)(?=\/)/, home);
}

/** The command with its script path expanded, so two spellings of one call compare equal. */
function normalizedCommand(command: string, home: string): string {
  return `${hookScriptPath(command, home)} ${splitFirstWord(command).rest}`.trim();
}

// [LOCKED] [HOOK-PATHS-ARE-SHELL-QUOTED] - 2026-09-25
// [NEVER] write a script path into a hook command, or into the generated gate script, without
//         shellQuote(): Claude Code runs every hook command through a shell.
// WHY: with a home folder named "John Smith" the installer wrote `/Users/John Smith/.claude/...`
//      unquoted: every hook exited 127, the install's own count found 0 of ours and failed, and
//      each re-run added four more broken entries (4, then 8). A double quote in the path made the
//      shell exit 2, which for a Stop hook means "block the turn" (E2E_REVIEW_2026-09 A3-2, A3-4).
// FIX: shellQuote() leaves a plain path as it is (existing installs compare equal and do not
//      churn) and single-quotes anything else; splitFirstWord() reads commands the way the shell
//      does, so a quoted path compares equal to its plain spelling; an unquoted copy of one of our
//      paths that contains a space is recognised as ours and repaired.
export function shellQuote(value: string): string {
  return /^[A-Za-z0-9_./@%+=:,-]+$/.test(value) ? value : scriptQuote(value);
}

/** Always single-quoted: for the lines of a generated sh script. */
function scriptQuote(value: string): string {
  return `'${value.replace(/'/g, "'\\''")}'`;
}

/** An old install's unquoted command for one of our scripts whose path contains whitespace. */
function isBrokenUnquotedCopy(command: string, script: string): boolean {
  if (!/\s/.test(script)) return false;
  const c = (command ?? "").trim();
  return c === script || c.startsWith(`${script} `);
}

/** True when a hook command runs one of `scripts`, however it is spelled. */
function runsOneOf(command: string, scripts: string[], home: string = homedir()): boolean {
  return scripts.includes(hookScriptPath(command, home)) || scripts.some((s) => isBrokenUnquotedCopy(command, s));
}

/** Rewrites unquoted, broken copies of our commands to their quoted form (then dedup sees them). */
function repairUnquotedCommands(entries: HookEntry[], scripts: string[]): number {
  let repaired = 0;
  for (const e of entries) {
    for (const h of e.hooks ?? []) {
      const s = scripts.find((x) => isBrokenUnquotedCopy(h.command, x));
      if (!s) continue;
      h.command = `${shellQuote(s)} ${h.command.trim().slice(s.length).trim()}`.trim();
      repaired++;
    }
  }
  return repaired;
}

function hookAlreadyWired(entries: HookEntry[] | undefined, hookScript: string, home: string = homedir()): boolean {
  return (entries ?? []).some((e) => e.hooks?.some((h) => hookScriptPath(h.command, home) === hookScript));
}

/** Removes repeated registrations of our scripts under the same matcher. Keeps the first copy
 *  and every hook that is not ours; drops an entry only when that leaves it empty. */
export function dropDuplicateHooks(
  entries: HookEntry[],
  ourScripts: string[],
  home: string = homedir(),
): { entries: HookEntry[]; removed: number } {
  const seen = new Set<string>();
  let removed = 0;
  const kept: HookEntry[] = [];
  for (const entry of entries) {
    const before = entry.hooks ?? [];
    const hooks = before.filter((h) => {
      if (!ourScripts.includes(hookScriptPath(h.command, home))) return true;
      const key = `${entry.matcher ?? ""}\u0000${normalizedCommand(h.command, home)}`;
      if (seen.has(key)) {
        removed++;
        return false;
      }
      seen.add(key);
      return true;
    });
    if (hooks.length > 0 || before.length === 0) kept.push({ ...entry, hooks });
  }
  return { entries: kept, removed };
}

/** How many times each event runs `script`. A correct install has exactly 1 everywhere. */
export function countOurHooks(
  settings: Settings,
  events: readonly string[],
  script: string,
  home: string = homedir(),
): Record<string, number> {
  const count = (ev: string) =>
    (settings.hooks?.[ev] ?? []).flatMap((e) => e.hooks ?? []).filter((h) => hookScriptPath(h.command, home) === script).length;
  return Object.fromEntries(events.map((ev) => [ev, count(ev)]));
}

/** How many times Claude Code runs each OpsContext hook, read from settings.json: the three
 *  emit events, the Stop gate, and the optional simplicity gate as "PostToolUse(simplicity)".
 *  null when there is no readable settings.json. Shared by the install verification
 *  ([INSTALL-VERIFIES-BY-COUNT]) and fleet health, so both count the same way. */
export function claudeHookRegistrations(settingsPath: string = SETTINGS_FILE, home: string = homedir()): Record<string, number> | null {
  let settings: Settings;
  try {
    if (!existsSync(settingsPath)) return null;
    settings = JSON.parse(readFileSync(settingsPath, "utf-8")) as Settings;
  } catch {
    return null;
  }
  const hooksDir = join(home, ".claude", "hooks");
  const emit = join(hooksDir, "opscontext-emit.sh");
  return {
    ...countOurHooks(settings, EVENT_KINDS, emit, home),
    ...countOurHooks(settings, ["Stop"], join(hooksDir, "opscontext-session-gate.sh"), home),
    "PostToolUse(simplicity)": countOurHooks(settings, ["PostToolUse"], join(hooksDir, "opscontext-simplicity-gate.py"), home).PostToolUse,
  };
}

/** Path to a file bundled under defaults/ with this package. */
function bundledFile(name: string): string | null {
  // dist/install-claude-hook.js → ../defaults/<name> in dev tree,
  // or .../node_modules/@compr/opscontext-mcp/defaults/<name>
  // when globally / locally installed via npm. Both follow the same relative
  // shape because npm copies defaults/ via the `files` whitelist.
  const candidates = [join(__dirname_esm, "..", "defaults", name), join(__dirname_esm, "defaults", name)];
  for (const c of candidates) {
    if (existsSync(c)) return c;
  }
  return null;
}

/** Where the simplicity gate will find ruff: PATH, then the usual install dirs (the same
 *  order as the script itself). null when it is nowhere, so the install can say so. */
function findRuff(): string | null {
  try {
    const onPath = execSync("command -v ruff 2>/dev/null", { encoding: "utf-8" }).trim();
    if (onPath) return onPath;
  } catch {
    /* not on PATH */
  }
  const home = homedir();
  for (const c of ["/opt/homebrew/bin/ruff", "/usr/local/bin/ruff", join(home, ".local", "bin", "ruff"), join(home, ".cargo", "bin", "ruff")]) {
    if (existsSync(c)) return c;
  }
  return null;
}

/** dist/cli.js of a global install, when there is one (same preference as install-autostart). */
function globalCliPath(): string | null {
  try {
    const root = execSync("npm root -g 2>/dev/null", { encoding: "utf-8" }).trim();
    const c = join(root, "@compr", "opscontext-mcp", "dist", "cli.js");
    return existsSync(c) ? c : null;
  } catch {
    return null;
  }
}

export async function cliInstallClaudeHook(args: string[]): Promise<void> {
  const help = args.includes("-h") || args.includes("--help");
  if (help) {
    console.log(`Usage: opscontext install-claude-hook [--simplicity]

Wires OpsContext into Claude Code's hook system so every terminal Claude
Code session sends prompts + tool calls to the OpsContext audit log.

Events emitted (all go through the local HTTP endpoint, never the network):
  • UserPromptSubmit → vscode.prompt_submit  (feeds the loop heuristic)
  • PostToolUse      → vscode.tool_call      (feeds stuck + silent_failure)
  • SessionStart     → vscode.session_start
  • Stop             → the session gate: a turn cannot end while the repo's CE session
                       is older than the last commit (contextengine session-gate --help)
  • PostToolUse on Edit|Write|MultiEdit, with --simplicity → the simplicity gate: after an
                       edit to a Python file, ruff's complexity rules run on the file and on
                       its git HEAD version; functions the edit made new offenders or worse
                       are reported back to Claude (exit 2). Pre-existing complexity, files
                       outside git and a missing ruff are silent. Needs ruff (brew install ruff).

The installer:
  1. Copies the bundled hook script to ~/.claude/hooks/opscontext-emit.sh
     and writes ~/.claude/hooks/opscontext-session-gate.sh (node + this CLI, absolute paths);
     with --simplicity also ~/.claude/hooks/opscontext-simplicity-gate.py
  2. Splices four entries (five with --simplicity) into ~/.claude/settings.json under "hooks"
  3. Preserves every existing hook entry (idempotent, safe to re-run; a re-run without
     --simplicity keeps an installed simplicity gate and refreshes its script)

A timestamped backup is written next to settings.json before any change.

Pre-req: the MCP server must be auto-started or running (otherwise the hook
silently no-ops, which is the safe default — you won't lose events later).
Run: opscontext install-autostart
`);
    return;
  }
  const simplicityAsked = args.includes("--simplicity");

  // Parse settings.json before writing anything: a malformed file is refused with nothing changed
  // (it used to be refused after the emit script had already been copied).
  const original = existsSync(SETTINGS_FILE) ? readFileSync(SETTINGS_FILE, "utf-8") : null;
  const settings = readSettings();

  // Step 1: Install / verify the hook script
  mkdirSync(HOOKS_DIR, { recursive: true });
  const src = bundledFile("claude-code-hook.sh");
  if (!src) {
    console.error(`❌ Could not find bundled hook script defaults/claude-code-hook.sh.`);
    console.error(`   This means the install is incomplete. Reinstall opscontext:`);
    console.error(`     npm install -g @compr/opscontext-mcp`);
    process.exit(1);
  }
  copyFileSync(src, HOOK_SCRIPT);
  chmodSync(HOOK_SCRIPT, 0o755);
  console.log(`✅ Installed hook script: ${HOOK_SCRIPT}`);

  // Step 2: Splice into settings.json (written, after a backup, only if something changes)
  settings.hooks ??= {};
  const hookCmdPrefix = `${HOOK_SCRIPT}`; // compared by expanded path, [HOOKS-COMPARED-BY-EXPANDED-PATH]

  // [LOCK] [HOOKS-COMPARED-BY-EXPANDED-PATH]: remove extra copies before deciding what to add.
  // [LOCK] [HOOK-PATHS-ARE-SHELL-QUOTED]: first repair unquoted copies an older install wrote for a
  // path with a space, so the dedup below sees them as ours.
  let deduped = 0;
  for (const kind of [...EVENT_KINDS, "Stop"]) {
    const entries = settings.hooks[kind];
    if (!entries) continue;
    repairUnquotedCommands(entries, OUR_SCRIPTS);
    const r = dropDuplicateHooks(entries, OUR_SCRIPTS);
    settings.hooks[kind] = r.entries;
    deduped += r.removed;
  }

  let added = 0;
  let skipped = 0;

  for (const kind of EVENT_KINDS) {
    settings.hooks[kind] ??= [];
    if (hookAlreadyWired(settings.hooks[kind], hookCmdPrefix)) {
      skipped++;
      continue;
    }
    const entry: HookEntry = {
      hooks: [
        {
          type: "command",
          command: `${shellQuote(HOOK_SCRIPT)} ${kind}`,
          timeout: 5,
        },
      ],
    };
    // PostToolUse needs a matcher (PreToolUse/PostToolUse are tool-matched);
    // ".*" matches every tool. Other events are not tool-scoped.
    if (kind === "PostToolUse") entry.matcher = ".*";
    settings.hooks[kind].push(entry);
    added++;
  }

  // Step 3: the Stop gate. Absolute node + CLI paths: hooks run without the user's shell PATH.
  // Prefer the global install: an npx cache copy can be pruned and the hook would then exit 127.
  const cliPath = globalCliPath() ?? join(__dirname_esm, "cli.js");
  writeFileSync(
    GATE_SCRIPT,
    `#!/bin/sh\n# Generated by \`opscontext install-claude-hook\`: the CE session gate on Claude Code Stop.\n# Exit 2 = the turn may not end yet (reason on stderr). See: contextengine session-gate --help\nexec ${scriptQuote(process.execPath)} ${scriptQuote(cliPath)} session-gate\n`,
  );
  chmodSync(GATE_SCRIPT, 0o755);
  settings.hooks.Stop ??= [];
  if (hookAlreadyWired(settings.hooks.Stop, GATE_SCRIPT)) {
    skipped++;
  } else {
    settings.hooks.Stop.push({ hooks: [{ type: "command", command: shellQuote(GATE_SCRIPT), timeout: 15 }] });
    added++;
  }
  console.log(`✅ Installed session gate: ${GATE_SCRIPT}`);

  // Step 4: the simplicity gate, when asked for or already there (a plain re-run keeps it and
  // refreshes its script, so an upgrade reaches it too).
  const simplicityWired = hookAlreadyWired(settings.hooks.PostToolUse, SIMPLICITY_SCRIPT);
  const wantSimplicity = simplicityAsked || simplicityWired;
  if (wantSimplicity) {
    const gateSrc = bundledFile("simplicity-gate.py");
    if (!gateSrc) {
      console.error(`❌ Could not find bundled defaults/simplicity-gate.py. Reinstall opscontext.`);
      process.exit(1);
    }
    copyFileSync(gateSrc as string, SIMPLICITY_SCRIPT);
    chmodSync(SIMPLICITY_SCRIPT, 0o755);
    if (simplicityWired) {
      skipped++;
    } else {
      settings.hooks.PostToolUse.push({
        matcher: SIMPLICITY_MATCHER,
        hooks: [{ type: "command", command: shellQuote(SIMPLICITY_SCRIPT), timeout: 30 }],
      });
      added++;
    }
    console.log(`✅ Installed simplicity gate: ${SIMPLICITY_SCRIPT} (PostToolUse ${SIMPLICITY_MATCHER})`);
    const ruff = findRuff();
    if (ruff) console.log(`   ruff: ${ruff}`);
    else console.log(`⚠️  ruff not found (PATH, /opt/homebrew/bin, /usr/local/bin, ~/.local/bin, ~/.cargo/bin): the gate stays silent until it is installed (brew install ruff, or pipx install ruff).`);
  }

  // A re-run that changes nothing writes nothing and leaves no backup behind (a copy of
  // settings.json per run piled up, env values and all).
  let backup = "";
  const unchanged = original !== null && JSON.stringify(JSON.parse(original)) === JSON.stringify(settings);
  if (!unchanged) {
    backup = backupSettings();
    if (backup) console.log(`✅ Backed up settings.json → ${backup}`);
    writeFileSync(SETTINGS_FILE, JSON.stringify(settings, null, 2) + "\n");
  }
  const removedNote = deduped ? `, ${deduped} duplicate registrations removed` : "";
  console.log(`✅ ${added} hook entries added, ${skipped} already present${removedNote}.`);

  // [LOCKED] [INSTALL-VERIFIES-BY-COUNT] - 2026-09-15
  // [NEVER] treat the added/present counters above as proof of a correct install.
  // WHY: on 2026-09-06 this command printed "0 already present" over three existing hooks, and
  //      the session that ran it recorded "they were not there"; the doubled audit events then
  //      went unseen for nine days.
  // FIX: re-read settings.json from disk and require exactly one registration per event.
  const counts = claudeHookRegistrations() ?? {};
  // Every event exactly once; the optional gate exactly once when wanted, never otherwise (a
  // dedup pass alone never adds it).
  const expected: Record<string, number> = Object.fromEntries(Object.keys(counts).map((ev) => [ev, 1]));
  expected["PostToolUse(simplicity)"] = wantSimplicity ? 1 : 0;
  const wrong = Object.entries(counts).filter(([ev, n]) => n !== expected[ev]);
  if (wrong.length > 0) {
    const detail = wrong.map(([ev, n]) => `${ev}=${n}`).join(", ");
    console.error(`❌ settings.json must hold exactly one OpsContext hook per event, found ${detail}. Backup: ${backup || "none"}`);
    process.exit(1);
  }
  const once = Object.keys(expected).filter((ev) => expected[ev] === 1);
  console.log(`✅ Verified in settings.json: exactly one registration for ${once.join(", ")}.`);
  console.log(``);
  console.log(`Test live:`);
  console.log(`  1. Open a NEW VS Code terminal (settings.json is read at session start).`);
  console.log(`  2. Run \`claude\` and ask anything — Claude will use tools.`);
  console.log(`  3. In any other terminal:`);
  console.log(`     tail -f ~/.contextengine/audit.log | grep --line-buffered '"actor":"claude-code"'`);
  console.log(``);
  console.log(`To remove: opscontext uninstall-claude-hook   (or hand-edit ~/.claude/settings.json)`);
}

export async function cliUninstallClaudeHook(args: string[]): Promise<void> {
  if (args.includes("-h") || args.includes("--help")) {
    console.log(`Usage: opscontext uninstall-claude-hook [--simplicity]

Removes OpsContext hook entries from ~/.claude/settings.json. With --simplicity
only the simplicity gate entry is removed; the emit hooks and the Stop gate stay.
The hook script files under ~/.claude/hooks/ are left in place — delete
manually if you want them gone. The audit log is NOT touched.`);
    return;
  }
  // [LOCKED] [UNINSTALL-REMOVES-ONLY-OUR-COMMANDS] - 2026-09-25
  // [NEVER] drop a whole hook entry because one of its commands is ours, or recognise ours by a
  //         substring of the command text.
  // WHY: the uninstaller removed every entry whose command text contained one of our file names.
  //      In a sandbox it deleted a user's company-audit.sh that shared an entry with our emit hook,
  //      and a user's notify-opscontext-emit.sh.done that merely contained our name
  //      (E2E_REVIEW_2026-09 A3-1). [CLAUDE-HOOK-INSTALL] asks for the "preserve existing"
  //      discipline in every code path; this one broke it.
  // FIX: remove only the commands that run our scripts, compared by expanded path like the
  //      installer ([HOOKS-COMPARED-BY-EXPANDED-PATH]); drop an entry only when that leaves it
  //      empty; back up and write only when something was removed.
  const ours = args.includes("--simplicity") ? [SIMPLICITY_SCRIPT] : OUR_SCRIPTS;

  const settings = readSettings();
  if (!settings.hooks) {
    console.log(`   (no hooks block in settings.json — nothing to remove)`);
    return;
  }

  let removed = 0;
  for (const kind of [...EVENT_KINDS, "Stop"] as const) {
    const entries = settings.hooks[kind];
    if (!entries) continue;
    const kept: HookEntry[] = [];
    for (const e of entries) {
      const before = e.hooks ?? [];
      const hooks = before.filter((h) => !runsOneOf(h.command, ours));
      removed += before.length - hooks.length;
      if (hooks.length > 0 || before.length === 0) kept.push({ ...e, hooks });
    }
    if (kept.length === 0) {
      delete settings.hooks[kind];
    } else {
      settings.hooks[kind] = kept;
    }
  }

  if (removed > 0) {
    const backup = backupSettings();
    if (backup) console.log(`✅ Backed up settings.json → ${backup}`);
    writeFileSync(SETTINGS_FILE, JSON.stringify(settings, null, 2) + "\n");
  }
  console.log(`✅ Removed ${removed} OpsContext hook command(s); every other hook kept.`);
  console.log(`   Hook script kept at: ${HOOK_SCRIPT}`);
  console.log(`   Audit log untouched.`);
}
