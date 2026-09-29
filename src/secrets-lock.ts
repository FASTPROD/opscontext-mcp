// [LOCKED] [SECRETS-LOCK-NEVER-READS-A-SECRET] - 2026-09-27
// [NEVER] let this module open, stat, list, search or print a file the deny rules name, or print
//         a value out of a settings file (settings.json carries env values, allow rules and hook
//         commands): rule texts, scope names, booleans, folder paths and version numbers only.
// WHY: on 2026-09-27 a password reached a chat log without anyone printing it. The owner pasted it
//      into a gitignored credentials file while a Claude Code chat that had opened that file earlier
//      was running in the repo; the harness attached the file's diff to his next message as a
//      "file changed on disk" note. No tool call was involved, so no hook could see it. The only
//      fix is a rule Claude Code enforces before any tool runs, and a check that touched the file
//      to "prove" the lock would be that leak again, with the product's name on it.
// FIX: --check reads only the settings files Claude Code reads (user, project, local, managed),
//      compares their permissions.deny with SECRETS_LOCK_RULES by exact text and reports one line
//      per item. Tests: tests/secrets-lock.test.ts, in the throwaway HOME of src/test-setup.ts,
//      including "the report never contains a value from the settings file".

import { existsSync, readFileSync, writeFileSync, copyFileSync, mkdirSync, readdirSync, readlinkSync, rmSync } from "fs";
import { join, resolve, dirname, basename, sep } from "path";
import { homedir } from "os";
import { execSync } from "child_process";

const CREDENTIALS_FILE_RULES: readonly string[] = [
  "Read(//**/.copilot-credentials.md)",
  "Edit(//**/.copilot-credentials.md)",
  "Read(//**/copilot-credentials.md)",
  "Edit(//**/copilot-credentials.md)",
];
// [LOCKED] [SECRETS-LOCK-ENV-BY-NAME] - 2026-09-28
// [NEVER] put Read/Edit(//**/.env.*) back in ENV_FILE_RULES, or drop an exact name without first
//         measuring which env files git does not track would be left open.
// WHY: .env.* matched 31 files git tracks on the author's Mac (28 .env.example templates, 3 public
//      front-end .env.production): the agent could not update a template, and under the sandbox
//      git status, diff and add -A print "Operation not permitted" for each one. The names below
//      are the untracked env files measured under ~/Projects on 2026-09-27: .env.local (4),
//      .env.development.local (3), .env.production (1), .env.backup (1), plus .env.bak*.
//      .env.production stays although 3 tracked front-end copies are public: the untracked one may
//      hold a server's secrets. A one-off name (.env.jar, 1) belongs in the owner's own list.
// FIX: exact names. A .env.* rule already in someone's settings still counts (COVERED_BY_DRAFT_RULE),
//      and --apply adds the exact names beside it so the owner can remove it by hand.
const ENV_FILE_RULES: readonly string[] = [
  "Read(//**/.env)",
  "Edit(//**/.env)",
  "Read(//**/.env.local)",
  "Edit(//**/.env.local)",
  "Read(//**/.env.*.local)",
  "Edit(//**/.env.*.local)",
  "Read(//**/.env.production)",
  "Edit(//**/.env.production)",
  "Read(//**/.env.bak*)",
  "Edit(//**/.env.bak*)",
  "Read(//**/.env.backup*)",
  "Edit(//**/.env.backup*)",
];

/** The broad rules of the 2.13.0 drafts, installed on the author's Mac on 2026-09-27. */
export const DRAFT_ENV_RULES: readonly string[] = ["Read(//**/.env.*)", "Edit(//**/.env.*)"];

/** Each exact env name counts as present in a scope that holds the draft rule covering it. */
const COVERED_BY_DRAFT_RULE: ReadonlyMap<string, string> = new Map(
  ENV_FILE_RULES.filter((r) => r.includes("/.env.")).map((r) => [r, r.startsWith("Read(") ? DRAFT_ENV_RULES[0] : DRAFT_ENV_RULES[1]]),
);
const SECRETS_FOLDER_RULES: readonly string[] = ["Read(//**/secrets/**)", "Edit(//**/secrets/**)"];
const CERTIFICATE_RULES: readonly string[] = ["Read(//**/*.p12)", "Edit(//**/*.p12)"];

// The files no agent may read or edit, in every repo on the machine. The double-slash double-star
// prefix means anywhere on disk: a "/path" rule in user settings would anchor at ~/.claude/, not at
// the project. (A line comment on purpose: that prefix ends a block comment early.)
export const SECRETS_FILE_RULES: readonly string[] = [...CREDENTIALS_FILE_RULES, ...ENV_FILE_RULES, ...SECRETS_FOLDER_RULES, ...CERTIFICATE_RULES];

/** The agent may not loosen the lock: its settings files, its hook and helper folders, the MCP
 *  lists. Not `Edit(~/.claude/**)`: that would also block the memory notes under ~/.claude/projects. */
export const SELF_LOCK_RULES: readonly string[] = [
  "Edit(~/.claude/settings.json)",
  "Edit(~/.claude/settings.local.json)",
  "Edit(~/.claude/hooks/**)",
  "Edit(~/.claude/bin/**)",
  "Edit(~/.claude.json)",
  "Edit(//**/.claude/settings.json)",
  "Edit(//**/.claude/settings.local.json)",
  "Edit(//**/.mcp.json)",
];

export const SECRETS_LOCK_RULES: readonly string[] = [...SECRETS_FILE_RULES, ...SELF_LOCK_RULES];

export const RULE_GROUPS: ReadonlyArray<{ label: string; rules: readonly string[] }> = [
  { label: "credentials file (both spellings), read and edit", rules: CREDENTIALS_FILE_RULES },
  { label: "env files (.env, .env.local, .env.*.local, .env.production, .env.bak*, .env.backup*), read and edit", rules: ENV_FILE_RULES },
  { label: "secrets/ folders, read and edit", rules: SECRETS_FOLDER_RULES },
  { label: "*.p12 certificates, read and edit", rules: CERTIFICATE_RULES },
  { label: "self-lock (the agent cannot edit its own settings, hooks, bin folder or MCP list)", rules: SELF_LOCK_RULES },
];

/** Claude Code builds below these let the Edit (before 2.1.208) or Write (before 2.1.228) tool
 *  through a Read deny; the docs that describe the lock's behaviour are for 2.1.283. */
export const MIN_CLAUDE_CODE = { editBlocked: "2.1.208", writeBlocked: "2.1.228" } as const;

// ---------------------------------------------------------------------------
// The settings files Claude Code reads
// ---------------------------------------------------------------------------

export type Scope = "user" | "project" | "local" | "managed";

export interface SettingsScope {
  scope: Scope;
  path: string;
  exists: boolean;
  /** false: the file exists but is not a JSON object. Claude Code refuses to start on it; no rule in it counts. */
  valid: boolean;
  settings: Record<string, unknown>;
}

const MANAGED_SETTINGS_PATHS: Record<string, string> = {
  darwin: "/Library/Application Support/ClaudeCode/managed-settings.json",
  linux: "/etc/claude-code/managed-settings.json",
  win32: "C:\\Program Files\\ClaudeCode\\managed-settings.json",
};

/** CONTEXTENGINE_MANAGED_SETTINGS overrides the path (empty: no managed scope); the tests set it
 *  empty so a real managed file on the developer's machine never reaches a fixture. */
export function managedSettingsPath(platform: string = process.platform): string {
  const override = process.env.CONTEXTENGINE_MANAGED_SETTINGS;
  if (override !== undefined) return override;
  return MANAGED_SETTINGS_PATHS[platform] ?? MANAGED_SETTINGS_PATHS.linux;
}

export function userSettingsPath(home: string = homedir()): string {
  return join(home, ".claude", "settings.json");
}

export interface ScopeOptions {
  home?: string;
  /** The project folder for the project and local scopes; null reads user and managed only.
   *  Default: the working directory. */
  cwd?: string | null;
  platform?: string;
  /** Test hooks: another file in the user scope's place; null for no managed scope at all. */
  userSettingsPath?: string;
  managedSettingsPath?: string | null;
}

function readScope(scope: Scope, path: string): SettingsScope {
  if (!existsSync(path)) return { scope, path, exists: false, valid: true, settings: {} };
  try {
    const parsed: unknown = JSON.parse(readFileSync(path, "utf-8"));
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return { scope, path, exists: true, valid: false, settings: {} };
    return { scope, path, exists: true, valid: true, settings: parsed as Record<string, unknown> };
  } catch {
    return { scope, path, exists: true, valid: false, settings: {} };
  }
}

/** The settings files Claude Code reads, lowest precedence first: user, project, local, managed. */
export function readSettingsScopes(opts: ScopeOptions = {}): SettingsScope[] {
  const home = opts.home ?? homedir();
  const cwd = opts.cwd === undefined ? process.cwd() : opts.cwd;
  const scopes: SettingsScope[] = [readScope("user", opts.userSettingsPath ?? userSettingsPath(home))];
  if (cwd) {
    scopes.push(readScope("project", join(cwd, ".claude", "settings.json")));
    scopes.push(readScope("local", join(cwd, ".claude", "settings.local.json")));
  }
  const managed = opts.managedSettingsPath === undefined ? managedSettingsPath(opts.platform) : opts.managedSettingsPath;
  if (managed) scopes.push(readScope("managed", managed));
  return scopes;
}

function asObject(v: unknown): Record<string, unknown> {
  return v && typeof v === "object" && !Array.isArray(v) ? (v as Record<string, unknown>) : {};
}

function stringList(v: unknown): string[] {
  return Array.isArray(v) ? v.filter((x): x is string => typeof x === "string").map((x) => x.trim()) : [];
}

/** The deny rules of one scope, trimmed; none for an unreadable file. */
export function denyRules(s: SettingsScope): string[] {
  return s.valid ? stringList(asObject(s.settings.permissions).deny) : [];
}

export interface RulePresence {
  rule: string;
  /** The scopes whose deny list holds this exact rule. Empty: the rule is missing. */
  scopes: Scope[];
}

export function rulePresence(scopes: SettingsScope[], rules: readonly string[] = SECRETS_LOCK_RULES): RulePresence[] {
  const deny = scopes.map((s) => ({ scope: s.scope, rules: new Set(denyRules(s)) }));
  const holds = (d: { rules: Set<string> }, rule: string): boolean => {
    const draft = COVERED_BY_DRAFT_RULE.get(rule);
    return d.rules.has(rule) || (draft !== undefined && d.rules.has(draft));
  };
  return rules.map((rule) => ({ rule, scopes: deny.filter((d) => holds(d, rule)).map((d) => d.scope) }));
}

// ---------------------------------------------------------------------------
// The sandbox and the extra writable folders
// ---------------------------------------------------------------------------

export interface SandboxState {
  enabled: boolean | null;
  allowUnsandboxedCommands: boolean | null;
  autoAllowBashIfSandboxed: boolean | null;
  excludedCommands: string[];
  /** The scope whose value won for each key (the highest precedence that sets it). */
  from: Partial<Record<"enabled" | "allowUnsandboxedCommands" | "autoAllowBashIfSandboxed" | "excludedCommands", Scope>>;
}

/** The sandbox settings as Claude Code merges them: for each key, the highest-precedence scope wins. */
export function sandboxState(scopes: SettingsScope[]): SandboxState {
  const st: SandboxState = { enabled: null, allowUnsandboxedCommands: null, autoAllowBashIfSandboxed: null, excludedCommands: [], from: {} };
  for (const s of scopes) {
    if (!s.valid) continue;
    const sb = asObject(s.settings.sandbox);
    if (typeof sb.enabled === "boolean") { st.enabled = sb.enabled; st.from.enabled = s.scope; }
    if (typeof sb.allowUnsandboxedCommands === "boolean") { st.allowUnsandboxedCommands = sb.allowUnsandboxedCommands; st.from.allowUnsandboxedCommands = s.scope; }
    if (typeof sb.autoAllowBashIfSandboxed === "boolean") { st.autoAllowBashIfSandboxed = sb.autoAllowBashIfSandboxed; st.from.autoAllowBashIfSandboxed = s.scope; }
    if (Array.isArray(sb.excludedCommands)) { st.excludedCommands = stringList(sb.excludedCommands); st.from.excludedCommands = s.scope; }
  }
  return st;
}

export interface ExtraDirectory {
  path: string;
  scope: Scope;
  /** The home folder itself, or under ~/.ssh, ~/.gnupg, ~/.aws or ~/.claude. */
  sensitive: boolean;
  insideProject: boolean;
}

const SENSITIVE_UNDER_HOME = [".ssh", ".gnupg", ".aws", ".claude"];

function expandHome(p: string, home: string): string {
  if (p === "~") return home;
  if (p.startsWith("~/")) return join(home, p.slice(2));
  return p;
}

function isWithin(child: string, parent: string): boolean {
  return child === parent || child.startsWith(parent.endsWith(sep) ? parent : parent + sep);
}

/** Every permissions.additionalDirectories entry (arrays merge across scopes), ~ expanded, each once. */
export function additionalDirectories(scopes: SettingsScope[], home: string = homedir(), cwd: string | null = process.cwd()): ExtraDirectory[] {
  const out: ExtraDirectory[] = [];
  const seen = new Set<string>();
  const project = cwd ? resolve(cwd) : null;
  for (const s of scopes) {
    if (!s.valid) continue;
    for (const raw of stringList(asObject(s.settings.permissions).additionalDirectories)) {
      const path = resolve(expandHome(raw, home));
      if (seen.has(path)) continue;
      seen.add(path);
      // ~/.claude/projects holds the memory notes, which a chat is meant to write; the rest of ~/.claude is not.
      const sensitive = path === home || (SENSITIVE_UNDER_HOME.some((d) => isWithin(path, join(home, d))) && !isWithin(path, join(home, ".claude", "projects")));
      out.push({ path, scope: s.scope, sensitive, insideProject: project ? isWithin(path, project) : false });
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// Installed Claude Code builds
// ---------------------------------------------------------------------------

export function parseVersion(text: string): string | null {
  const m = /(\d+)\.(\d+)\.(\d+)/.exec(text);
  return m ? `${m[1]}.${m[2]}.${m[3]}` : null;
}

export function versionAtLeast(version: string, minimum: string): boolean {
  const a = version.split(".").map(Number);
  const b = minimum.split(".").map(Number);
  for (let i = 0; i < 3; i++) {
    const x = a[i] ?? 0, y = b[i] ?? 0;
    if (x !== y) return x > y;
  }
  return true;
}

/** The terminal build: `claude --version` on PATH, else the version folder ~/.local/bin/claude links to. */
export function terminalClaudeVersion(home: string = homedir()): string | null {
  try {
    const v = parseVersion(execSync("claude --version", { encoding: "utf-8", stdio: ["ignore", "pipe", "ignore"], timeout: 8000 }));
    if (v) return v;
  } catch {
    /* not on PATH, or it did not answer */
  }
  try {
    const v = parseVersion(basename(readlinkSync(join(home, ".local", "bin", "claude"))));
    if (v) return v;
  } catch {
    /* no launcher link */
  }
  return null;
}

export function extensionDirs(home: string = homedir()): string[] {
  return [".vscode", ".vscode-insiders", ".cursor", ".windsurf"].map((d) => join(home, d, "extensions"));
}

/** The newest Claude Code editor extension installed (folder anthropic.claude-code-<version>-<platform>). */
export function newestExtensionVersion(dirs: string[]): { version: string; path: string } | null {
  let best: { version: string; path: string } | null = null;
  for (const dir of dirs) {
    let entries: string[] = [];
    try {
      entries = readdirSync(dir);
    } catch {
      continue;
    }
    for (const e of entries) {
      const m = /^anthropic\.claude-code-(\d+\.\d+\.\d+)/.exec(e);
      if (!m) continue;
      if (!best || (m[1] !== best.version && versionAtLeast(m[1], best.version))) best = { version: m[1], path: join(dir, e) };
    }
  }
  return best;
}

// ---------------------------------------------------------------------------
// --check
// ---------------------------------------------------------------------------

export interface CheckLine {
  level: "PASS" | "FAIL" | "WARN" | "INFO";
  text: string;
}

export interface CheckOptions extends ScopeOptions {
  /** Detected when undefined; null means "not installed". */
  terminalVersion?: string | null;
  extensionVersion?: string | null;
}

export interface SecretsLockReport {
  scopes: SettingsScope[];
  rules: RulePresence[];
  lines: CheckLine[];
  fails: number;
  warns: number;
  /** Every rule is present in at least one scope Claude Code reads here. */
  inPlace: boolean;
  /** Every rule is present in the user or managed scope: it holds for every repo on the machine. */
  macWide: boolean;
}

export function tildePath(path: string, home: string = homedir()): string {
  return isWithin(path, home) ? "~" + path.slice(home.length) : path;
}

function versionLine(label: string, version: string | null, fix: string): CheckLine {
  if (!version) return { level: "INFO", text: `${label}: not found, nothing to lock there` };
  if (versionAtLeast(version, MIN_CLAUDE_CODE.writeBlocked)) {
    return { level: "PASS", text: `${label} ${version}: at or above ${MIN_CLAUDE_CODE.writeBlocked}, a Read deny also stops Edit and Write there` };
  }
  if (versionAtLeast(version, MIN_CLAUDE_CODE.editBlocked)) {
    return { level: "FAIL", text: `${label} ${version}: below ${MIN_CLAUDE_CODE.writeBlocked}, a Read deny does not stop the Write tool there (${fix})` };
  }
  return { level: "FAIL", text: `${label} ${version}: below ${MIN_CLAUDE_CODE.editBlocked}, a Read deny stops neither Edit nor Write there (${fix})` };
}

export function checkSecretsLock(opts: CheckOptions = {}): SecretsLockReport {
  const home = opts.home ?? homedir();
  const cwd = opts.cwd === undefined ? process.cwd() : opts.cwd;
  const scopes = readSettingsScopes({ ...opts, home, cwd });
  const t = (p: string) => tildePath(p, home);
  const lines: CheckLine[] = [];

  lines.push({
    level: "INFO",
    text: `settings read: ${scopes.map((s) => `${s.scope} ${t(s.path)} (${!s.exists ? "absent" : s.valid ? "present" : "NOT VALID JSON"})`).join("; ")}`,
  });
  for (const s of scopes) {
    if (s.exists && !s.valid) {
      lines.push({ level: "FAIL", text: `${s.scope} settings ${t(s.path)} is not valid JSON: Claude Code refuses to start on it, and no rule in it counts` });
    }
  }

  const rules = rulePresence(scopes);
  const where = new Map(rules.map((r) => [r.rule, r.scopes]));
  for (const g of RULE_GROUPS) {
    const missing = g.rules.filter((r) => (where.get(r) ?? []).length === 0);
    if (missing.length === 0) {
      const found = [...new Set(g.rules.flatMap((r) => where.get(r) ?? []))];
      lines.push({ level: "PASS", text: `${g.label}: denied (${found.join(", ")} settings)` });
    } else {
      lines.push({ level: "FAIL", text: `${g.label}: ${missing.length} of ${g.rules.length} rules missing: ${missing.join(", ")}` });
    }
  }
  const draftIn = scopes.filter((s) => denyRules(s).some((r) => DRAFT_ENV_RULES.includes(r))).map((s) => s.scope);
  if (draftIn.length > 0) {
    lines.push({
      level: "INFO",
      text: `env files: the broad .env.* rule (${draftIn.join(", ")} settings) counts, but it also blocks the .env.example templates git keeps, which the sandbox turns into git errors; --apply adds the exact names, then remove Read(//**/.env.*) and Edit(//**/.env.*) by hand`,
    });
  }
  const inPlace = rules.every((r) => r.scopes.length > 0);
  const macWide = rules.every((r) => r.scopes.some((s) => s === "user" || s === "managed"));
  if (inPlace && !macWide) {
    lines.push({ level: "WARN", text: "the lock is complete for this project only (project or local settings), not for every repo on this machine: run contextengine secrets-lock --apply in your own terminal" });
  }

  const sb = sandboxState(scopes);
  if (sb.enabled !== true) {
    lines.push({ level: "WARN", text: "sandbox: off (part C not done): a shell program that builds the file name from pieces can still read a secrets file, and a shell can still rewrite the settings" });
  } else if (sb.allowUnsandboxedCommands !== false) {
    lines.push({ level: "WARN", text: `sandbox: on (${sb.from.enabled} settings) but not strict: allowUnsandboxedCommands is ${sb.allowUnsandboxedCommands === null ? "not set" : "true"}, so a command can still ask to run outside it` });
  } else {
    lines.push({ level: "PASS", text: `sandbox: on and strict (${sb.from.enabled} settings; commands excluded from it: ${sb.excludedCommands.length > 0 ? sb.excludedCommands.join(", ") : "none"})` });
  }

  const extra = additionalDirectories(scopes, home, cwd).filter((d) => !d.insideProject);
  if (extra.length === 0) {
    lines.push({ level: "PASS", text: "additionalDirectories: none outside this project" });
  } else {
    const sensitive = extra.filter((d) => d.sensitive).map((d) => t(d.path));
    lines.push({
      level: "WARN",
      text: `additionalDirectories: ${extra.length} extra folder(s) outside this project where sandboxed commands may write${sensitive.length > 0 ? ` (sensitive: ${sensitive.join(", ")})` : ""}: ${extra.map((d) => t(d.path)).join(", ")}`,
    });
  }

  const terminal = opts.terminalVersion === undefined ? terminalClaudeVersion(home) : opts.terminalVersion;
  const extension = opts.extensionVersion === undefined ? (newestExtensionVersion(extensionDirs(home))?.version ?? null) : opts.extensionVersion;
  lines.push(versionLine("Claude Code terminal build", terminal, "run: claude update"));
  lines.push(versionLine("Claude Code editor extension (newest installed)", extension, "update the extension in your editor"));

  const managed = scopes.find((s) => s.scope === "managed");
  if (managed) {
    lines.push({
      level: "INFO",
      text: !managed.exists
        ? `managed settings: none (${managed.path}; part D makes the lock unchangeable by any chat)`
        : managed.valid
          ? `managed settings in force (${managed.path}, root-owned: no chat can change what it holds)`
          : `managed settings file present but unreadable (${managed.path})`,
    });
  }

  return {
    scopes,
    rules,
    lines,
    fails: lines.filter((l) => l.level === "FAIL").length,
    warns: lines.filter((l) => l.level === "WARN").length,
    inPlace,
    macWide,
  };
}

export function formatSecretsLockReport(r: SecretsLockReport): string {
  const out = ["Secrets lock: can the agent reach the secrets files on this machine? (Claude Code settings only; no secrets file is opened)"];
  for (const l of r.lines) out.push(`  ${l.level.padEnd(4)}  ${l.text}`);
  const passes = r.lines.filter((l) => l.level === "PASS").length;
  const counts = `${r.fails} FAIL, ${r.warns} WARN, ${passes} PASS`;
  if (!r.inPlace) out.push(`Result: ${counts}. The agent can still reach secrets files here. Fix, in your own terminal (never from a chat): contextengine secrets-lock --apply`);
  else if (r.fails > 0) out.push(`Result: ${counts}. The deny rules are in place; fix the FAIL lines above.`);
  else out.push(`Result: ${counts}. The lock is in place${r.warns > 0 ? "; the WARN lines are the next steps" : ""}.`);
  return out.join("\n");
}

// ---------------------------------------------------------------------------
// --apply
// ---------------------------------------------------------------------------

// [LOCKED] [SECRETS-LOCK-APPLY-IS-OWNER-RUN] - 2026-09-27
// [NEVER] let --apply run from inside an agent session, take the CLAUDECODE check out because a
//         chat or a test finds it inconvenient, or write settings.json without parsing it first
//         and re-reading what was written.
// WHY: the lock's last rule is that the agent cannot edit the settings that hold it. An --apply
//      that an agent can run from a chat is a way around that rule with the product's name on it:
//      the mechanism that adds rules can drop them. Claude Code's own docs put every change to
//      permissions in the owner's hands, and the owner types one command in his own terminal.
// FIX: refuse when CLAUDECODE is in the environment (Claude Code sets it for every command it
//      runs) and print the command for the owner's terminal; back up, merge (every existing entry
//      kept, missing rules appended), write, re-read; a second run reports "in place" and writes
//      nothing. Exercising --apply from a chat is done against a throwaway HOME only
//      (`env -i HOME=<temp> ...`), never against the real file; an env -i run that forgot HOME is
//      refused too, because Node would then fall back to the real home folder.

export interface ApplyOptions {
  home?: string;
  env?: NodeJS.ProcessEnv;
  now?: Date;
  userSettingsPath?: string;
}

export interface ApplyResult {
  /** Why nothing was done, or null. */
  refused: string | null;
  path: string;
  backup: string | null;
  added: string[];
  present: string[];
  wrote: boolean;
}

export function applySecretsLock(opts: ApplyOptions = {}): ApplyResult {
  const env = opts.env ?? process.env;
  const home = opts.home ?? homedir();
  const path = opts.userSettingsPath ?? userSettingsPath(home);
  if (env.CLAUDECODE) return { refused: "inside an agent session (CLAUDECODE is set)", path, backup: null, added: [], present: [], wrote: false };
  // An `env -i` run that forgot HOME=<throwaway> would make Node fall back to the passwd entry and
  // write the real file. Callers that name a home or a path explicitly are tests and skip this.
  if (!opts.home && !opts.userSettingsPath && !env.HOME) {
    return { refused: "without HOME in the environment (an env -i run without HOME=<throwaway folder> would write the real settings file)", path, backup: null, added: [], present: [], wrote: false };
  }

  const scope = readScope("user", path);
  if (scope.exists && !scope.valid) {
    throw new Error(`${path} is not valid JSON, refusing to touch it (Claude Code would refuse to start on it too)`);
  }
  const settings = scope.settings;
  const perms = asObject(settings.permissions);
  settings.permissions = perms;
  const deny: unknown[] = Array.isArray(perms.deny) ? [...(perms.deny as unknown[])] : [];
  const have = new Set(stringList(deny));
  const present = SECRETS_LOCK_RULES.filter((r) => have.has(r));
  const added = SECRETS_LOCK_RULES.filter((r) => !have.has(r));
  if (added.length === 0) return { refused: null, path, backup: null, added, present, wrote: false };
  perms.deny = [...deny, ...added];

  let backup: string | null = null;
  if (scope.exists) {
    const ts = (opts.now ?? new Date()).toISOString().replace(/[:.]/g, "-");
    backup = `${path}.bak-secrets-lock-${ts}`;
    copyFileSync(path, backup);
  }
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, JSON.stringify(settings, null, 2) + "\n");
  try {
    const back = JSON.parse(readFileSync(path, "utf-8")) as { permissions?: { deny?: unknown } };
    const written = back.permissions?.deny;
    if (!Array.isArray(written) || !SECRETS_LOCK_RULES.every((r) => written.includes(r))) throw new Error("the rules are not in the file after writing");
  } catch (err) {
    if (backup) copyFileSync(backup, path);
    else rmSync(path, { force: true });
    throw new Error(`the written settings did not read back (${err instanceof Error ? err.message : String(err)}); ${backup ? `restored from ${backup}` : "the new file was removed"}`);
  }
  return { refused: null, path, backup, added, present, wrote: true };
}

// ---------------------------------------------------------------------------
// The two surfaces that read the lock without a command: fleet health and the score
// ---------------------------------------------------------------------------

export interface SecretsLockHealth {
  inPlace: boolean;
  missing: number;
  total: number;
}

/** The lock for every repo on this machine (user and managed settings). null: no settings file at
 *  all, which is "Claude Code not set up here", not a problem to warn about. */
export function secretsLockHealth(opts: Pick<ScopeOptions, "userSettingsPath" | "managedSettingsPath" | "platform"> = {}): SecretsLockHealth | null {
  const scopes = readSettingsScopes({ ...opts, cwd: null });
  if (!scopes.some((s) => s.exists)) return null;
  const rules = rulePresence(scopes);
  const missing = rules.filter((r) => r.scopes.length === 0).length;
  return { inPlace: missing === 0, missing, total: rules.length };
}

/** For the score: how many of the file rules the effective settings of `projectDir` hold, and where. */
export function projectSecretsLock(projectDir: string, opts: Omit<ScopeOptions, "cwd"> = {}): { present: number; total: number; scopes: Scope[] } {
  const rules = rulePresence(readSettingsScopes({ ...opts, cwd: projectDir }), SECRETS_FILE_RULES);
  return {
    present: rules.filter((r) => r.scopes.length > 0).length,
    total: rules.length,
    scopes: [...new Set(rules.flatMap((r) => r.scopes))],
  };
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

// [LOCKED] [SECRETS-LOCK-CLAIMS-ARE-MEASURED] - 2026-09-28
// [NEVER] promise, in this help, the test card or the README, that the deny rules stop a command
//         the agent runs in Bash while the sandbox is off.
// WHY: the 2.13.0 draft said cat/head/tail/sed/tee naming the file were stopped. The owner's test
//      on fake files (2026-09-27, SESSION_31 "A4 results", Claude Code 2.1.283, auto mode) refused
//      the Read, Edit and Write tools, but cat on a file under secrets/ printed it and a grep of
//      the folder read all three files. A user trusting that line would believe in a lock that
//      is not there.
// FIX: say what was measured: the file tools are stopped, Bash is open until the sandbox is on.
//      Test: "the help and the test card never promise that Bash is stopped without the sandbox".
export const USAGE = `Usage: contextengine secrets-lock [--check | --apply]

Can the coding agent reach your secrets files? Claude Code enforces permissions.deny rules
before any tool runs. This command checks them and, from your own terminal, installs them.

  --check (default)  Reads the settings files Claude Code reads (user, project, local, managed)
                     and prints one PASS / FAIL / WARN line per item: the deny rules for the
                     credentials file (both spellings), env files, secrets/ folders and *.p12
                     certificates; the self-lock rules (the agent cannot edit its own settings,
                     hooks, bin folder or MCP list); the sandbox (WARN while off); the extra
                     folders commands may write to; the installed Claude Code builds against the
                     ${MIN_CLAUDE_CODE.editBlocked} and ${MIN_CLAUDE_CODE.writeBlocked} minimums.
                     Writes nothing and opens no secrets file. Exit 1 on any FAIL.
  --apply            Adds the missing rules to ~/.claude/settings.json (user scope: every repo on
                     this machine), keeps every existing entry, writes a dated backup beside the
                     file, re-reads what it wrote, then prints the test card. A second run reports
                     "in place" and writes nothing. Refused inside an agent session: run it in
                     your own terminal.

Env files are denied by name (.env, .env.local, .env.*.local, .env.production, .env.bak*,
.env.backup*), not as .env.*, so the agent can still read and update the .env.example templates
git keeps. A .env.* rule from an earlier version still counts.

What the rules stop: the Read, Edit and Write tools and, best effort, Grep, Glob, @-mentions
and the editor selection.
What they do not stop: commands the agent runs in Bash. Measured on 2026-09-27 (Claude Code
2.1.283, auto mode): cat on a file under secrets/ and a grep of its folder both read the file,
and a program that builds the file name from pieces is not stopped by the rules either. Only
the sandbox closes Bash (sandbox.enabled with allowUnsandboxedCommands false), which the check
reports as "part C".
`;

/** What the owner tests after --apply, on fake files only. */
export function secretsLockTestCard(): string {
  return [
    "Test it now, in a NEW chat, on FAKE files only (never a real secret). Make the fake files",
    "yourself, in a repo you have open, and check that git ignores them (git check-ignore <file>):",
    "  mkdir -p denytest && printf 'FAKE=FAKE-VALUE-4242\\n' > denytest/.env && printf '# fake\\n`FAKE-VALUE-4242`\\n' > denytest/.copilot-credentials.md",
    "  1. Ask the agent to read denytest/.env with its Read tool: refused.",
    "  2. Ask it to search for FAKE-VALUE-4242 in denytest/ with its Grep tool: note whether the line shows",
    "     (best effort per the docs). A grep in Bash reads it while the sandbox is off.",
    "  3. Ask it to run cat on the file: note what answered. While the sandbox is off, expect it to get",
    "     through (measured 2026-09-27: cat printed a fake file under secrets/).",
    "  4. Ask it to read the file from python with the name built from two pieces: the rules do not stop",
    "     this; only the sandbox does (part C in contextengine secrets-lock --check). In auto mode Claude",
    "     Code's classifier may refuse it; that is a judgement call, not the lock.",
    "  5. Add a line to a fake file yourself while the chat is open, then send any message: no",
    "     \"file changed on disk\" note appears.",
    "  6. Select text in a fake file with the chat open: the text never reaches the agent (at most the path).",
    "  7. Ask it to edit ~/.claude/settings.json: refused (the lock protects itself).",
    "  8. Its memory notes under ~/.claude/projects still work.",
    "  9. contextengine servers and the Stop hook still work (hooks run outside the sandbox).",
    "Known change: the agent can no longer read .env.production files, public or not; it will ask you for the",
    "variable names. .env.example templates stay readable.",
  ].join("\n");
}

export async function cliSecretsLock(args: string[]): Promise<void> {
  if (args.includes("-h") || args.includes("--help")) {
    console.log(USAGE);
    return;
  }
  const t = (p: string) => tildePath(p);
  if (args.includes("--apply")) {
    let result: ApplyResult;
    try {
      result = applySecretsLock();
    } catch (err) {
      console.error(`❌ ${err instanceof Error ? err.message : String(err)}`);
      process.exit(1);
      return;
    }
    if (result.refused) {
      console.error(`Refused: this command changes your Claude Code settings and was started ${result.refused}.`);
      console.error(`Run it yourself, in your own terminal, not in a chat:`);
      console.error(`  contextengine secrets-lock --apply`);
      process.exit(1);
      return;
    }
    if (!result.wrote) {
      console.log(`✅ In place: all ${SECRETS_LOCK_RULES.length} deny rules are already in ${t(result.path)}. Nothing written.`);
    } else {
      if (result.backup) console.log(`✅ Backed up ${t(result.path)} → ${t(result.backup)}`);
      console.log(`✅ Added ${result.added.length} deny rule(s) to ${t(result.path)} (${result.present.length} already there); every other entry kept; the file was re-read and is valid JSON.`);
      console.log(`   The lock is live for every new chat on this machine; no restart needed.`);
    }
    console.log("");
    const report = checkSecretsLock();
    console.log(formatSecretsLockReport(report));
    console.log("");
    console.log(secretsLockTestCard());
    process.exit(report.inPlace ? 0 : 1);
    return;
  }
  const report = checkSecretsLock();
  console.log(formatSecretsLockReport(report));
  process.exit(report.fails > 0 ? 1 : 0);
}
