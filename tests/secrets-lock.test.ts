// [LOCK] [SECRETS-LOCK-NEVER-READS-A-SECRET] [SECRETS-LOCK-APPLY-IS-OWNER-RUN]: every fixture lives in
// the throwaway HOME of src/test-setup.ts; the real ~/.claude/settings.json is never read or written.
import { describe, it, expect, beforeAll } from "vitest";
import { mkdirSync, mkdtempSync, writeFileSync, readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";

let L: typeof import("../src/secrets-lock.js");
let H: typeof import("../src/fleet-health.js");
const HOME = process.env.HOME as string;

beforeAll(async () => {
  expect(HOME).toMatch(/ce-test-home-/); // never the real HOME
  L = await import("../src/secrets-lock.js");
  H = await import("../src/fleet-health.js");
});

function home(): string {
  return mkdtempSync(join(HOME, "lock-"));
}
function settingsPath(h: string): string {
  return join(h, ".claude", "settings.json");
}
function writeUser(h: string, body: unknown): string {
  mkdirSync(join(h, ".claude"), { recursive: true });
  writeFileSync(settingsPath(h), typeof body === "string" ? body : JSON.stringify(body, null, 2) + "\n");
  return settingsPath(h);
}
function writeProject(dir: string, file: "settings.json" | "settings.local.json", body: unknown): void {
  mkdirSync(join(dir, ".claude"), { recursive: true });
  writeFileSync(join(dir, ".claude", file), JSON.stringify(body, null, 2) + "\n");
}
type CheckOpts = NonNullable<Parameters<typeof L.checkSecretsLock>[0]>;
const opts = (h: string, extra: Partial<CheckOpts> = {}): CheckOpts => ({
  home: h, cwd: null, managedSettingsPath: null, terminalVersion: "2.1.283", extensionVersion: "2.1.283", ...extra,
});
const byLevel = (r: ReturnType<typeof L.checkSecretsLock>, level: string) => r.lines.filter((l) => l.level === level).map((l) => l.text);
const without = (o: Record<string, unknown>, key: string) => Object.fromEntries(Object.entries(o).filter(([k]) => k !== key));

describe("the rule list", () => {
  it("holds the 20 file rules and the 8 self-lock rules, each once, and never Edit(~/.claude/**)", () => {
    expect(L.SECRETS_FILE_RULES).toHaveLength(20);
    expect(L.SELF_LOCK_RULES).toHaveLength(8);
    expect(new Set(L.SECRETS_LOCK_RULES).size).toBe(28);
    expect(L.SECRETS_LOCK_RULES).not.toContain("Edit(~/.claude/**)"); // that would block the memory notes
    for (const r of L.SECRETS_FILE_RULES) expect(r).toMatch(/^(Read|Edit)\(\/\/\*\*\//); // anywhere on disk, user scope
  });

  // [LOCK] [SECRETS-LOCK-ENV-BY-NAME]
  it("names the env files one by one, never .env.*, so the .env.example templates git keeps stay readable", () => {
    for (const r of L.DRAFT_ENV_RULES) expect(L.SECRETS_LOCK_RULES).not.toContain(r);
    for (const name of [".env", ".env.local", ".env.*.local", ".env.production", ".env.bak*", ".env.backup*"]) {
      expect(L.SECRETS_FILE_RULES).toContain(`Read(//**/${name})`);
      expect(L.SECRETS_FILE_RULES).toContain(`Edit(//**/${name})`);
    }
  });
});

describe("the broad .env.* rule of the 2.13.0 drafts", () => {
  const draftSettings = () => [...L.SECRETS_LOCK_RULES.filter((r) => !r.includes("/.env.")), ...L.DRAFT_ENV_RULES];

  it("still counts for every exact env name, in the check, the health line and the score, and the check says how to move off it", () => {
    const h = home();
    writeUser(h, { permissions: { deny: draftSettings() } });
    const r = L.checkSecretsLock(opts(h));
    expect(r.inPlace).toBe(true);
    expect(r.fails).toBe(0);
    expect(byLevel(r, "PASS")).toEqual(expect.arrayContaining([expect.stringMatching(/^env files .*: denied \(user settings\)$/)]));
    expect(byLevel(r, "INFO").join("\n")).toMatch(/the broad \.env\.\* rule \(user settings\) counts, .*remove Read\(\/\/\*\*\/\.env\.\*\) and Edit\(\/\/\*\*\/\.env\.\*\) by hand/);
    expect(L.secretsLockHealth({ userSettingsPath: settingsPath(h), managedSettingsPath: null })).toEqual({ inPlace: true, missing: 0, total: 28 });
    expect(L.projectSecretsLock(mkdtempSync(join(h, "repo-")), { home: h, managedSettingsPath: null })).toMatchObject({ present: 20, total: 20 });
  });

  it("does not cover .env itself, the Edit rule never stands in for Read, and an empty deny entry covers nothing", () => {
    const h = home();
    writeUser(h, { permissions: { deny: draftSettings().filter((r) => r !== "Read(//**/.env)") } });
    expect(byLevel(L.checkSecretsLock(opts(h)), "FAIL").join("\n")).toMatch(/^env files .*: 1 of 12 rules missing: Read\(\/\/\*\*\/\.env\)$/m);
    writeUser(h, { permissions: { deny: draftSettings().filter((r) => r !== "Read(//**/.env.*)") } });
    expect(byLevel(L.checkSecretsLock(opts(h)), "FAIL").join("\n")).toMatch(/^env files .*: 5 of 12 rules missing: Read\(\/\/\*\*\/\.env\.local\)/m);
    writeUser(h, { permissions: { deny: [...L.SECRETS_LOCK_RULES.filter((r) => !r.includes("/.env.")), "", "  "] } });
    const r = L.checkSecretsLock(opts(h));
    expect(byLevel(r, "FAIL").join("\n")).toMatch(/^env files .*: 10 of 12 rules missing/m);
    expect(byLevel(r, "INFO").join("\n")).not.toMatch(/broad \.env\.\* rule/);
    writeUser(h, { permissions: { deny: ["", "  "] } });
    expect(L.checkSecretsLock(opts(h)).fails).toBe(5);
    expect(L.secretsLockHealth({ userSettingsPath: settingsPath(h), managedSettingsPath: null })).toEqual({ inPlace: false, missing: 28, total: 28 });
  });

  it("--apply adds the exact names beside it and keeps it, for the owner to remove by hand", () => {
    const h = home();
    writeUser(h, { permissions: { deny: draftSettings() } });
    const r = L.applySecretsLock({ home: h, env: {} });
    expect(r.wrote).toBe(true);
    expect(r.added).toEqual(L.SECRETS_FILE_RULES.filter((x) => x.includes("/.env.")));
    expect(r.added).toHaveLength(10);
    const deny = JSON.parse(readFileSync(settingsPath(h), "utf-8")).permissions.deny;
    for (const d of L.DRAFT_ENV_RULES) expect(deny).toContain(d);
    expect(L.applySecretsLock({ home: h, env: {} }).wrote).toBe(false);
  });
});

describe("checkSecretsLock", () => {
  it("passes every group when all rules are in the user settings, and calls it Mac-wide", () => {
    const h = home();
    writeUser(h, { permissions: { deny: [...L.SECRETS_LOCK_RULES] } });
    const r = L.checkSecretsLock(opts(h));
    expect(r.inPlace).toBe(true);
    expect(r.macWide).toBe(true);
    expect(r.fails).toBe(0);
    expect(byLevel(r, "PASS")).toEqual(expect.arrayContaining([
      expect.stringMatching(/^credentials file \(both spellings\), read and edit: denied \(user settings\)$/),
      expect.stringMatching(/^env files .*: denied \(user settings\)$/),
      expect.stringMatching(/^secrets\/ folders.*: denied/),
      expect.stringMatching(/^\*\.p12 certificates.*: denied/),
      expect.stringMatching(/^self-lock .*: denied \(user settings\)$/),
    ]));
    expect(L.formatSecretsLockReport(r)).toMatch(/Result: 0 FAIL, 1 WARN, 8 PASS\. The lock is in place; the WARN lines are the next steps\./);
  });

  it("fails every group and names the missing rules when there is no settings file", () => {
    const h = home();
    const r = L.checkSecretsLock(opts(h));
    expect(r.inPlace).toBe(false);
    expect(r.fails).toBe(5);
    const fails = byLevel(r, "FAIL");
    expect(fails[0]).toMatch(/^credentials file .*: 4 of 4 rules missing: Read\(\/\/\*\*\/\.copilot-credentials\.md\), Edit\(/);
    expect(fails[1]).toMatch(/^env files .*: 12 of 12 rules missing: Read\(\/\/\*\*\/\.env\), Edit\(\/\/\*\*\/\.env\), Read\(\/\/\*\*\/\.env\.local\)/);
    expect(fails[4]).toMatch(/^self-lock .*: 8 of 8 rules missing/);
    const text = L.formatSecretsLockReport(r);
    expect(text).toMatch(/settings read: user ~\/\.claude\/settings\.json \(absent\)/);
    expect(text).toMatch(/Result: 5 FAIL, 1 WARN, 3 PASS\. The agent can still reach secrets files here\. Fix, in your own terminal \(never from a chat\): contextengine secrets-lock --apply/);
  });

  it("half a lock: the present groups pass, the missing groups name their rules", () => {
    const h = home();
    writeUser(h, { permissions: { deny: [...L.SECRETS_FILE_RULES, "Edit(~/.claude/settings.json)"] } });
    const r = L.checkSecretsLock(opts(h));
    expect(byLevel(r, "PASS").filter((t) => /: denied/.test(t))).toHaveLength(4);
    expect(byLevel(r, "FAIL")).toEqual([
      expect.stringMatching(/^self-lock .*: 7 of 8 rules missing: Edit\(~\/\.claude\/settings\.local\.json\), Edit\(~\/\.claude\/hooks\/\*\*\), Edit\(~\/\.claude\/bin\/\*\*\), Edit\(~\/\.claude\.json\), Edit\(\/\/\*\*\/\.claude\/settings\.json\), Edit\(\/\/\*\*\/\.claude\/settings\.local\.json\), Edit\(\/\/\*\*\/\.mcp\.json\)$/),
    ]);
    expect(r.inPlace).toBe(false);
  });

  it("rules in the project's own settings count for that project, are named by scope, and are not Mac-wide", () => {
    const h = home();
    const project = mkdtempSync(join(h, "repo-"));
    writeProject(project, "settings.json", { permissions: { deny: [...L.SECRETS_FILE_RULES] } });
    writeProject(project, "settings.local.json", { permissions: { deny: [...L.SELF_LOCK_RULES] } });
    const r = L.checkSecretsLock(opts(h, { cwd: project }));
    expect(r.inPlace).toBe(true);
    expect(r.macWide).toBe(false);
    expect(r.fails).toBe(0);
    expect(byLevel(r, "WARN")).toEqual(expect.arrayContaining([expect.stringMatching(/complete for this project only .*secrets-lock --apply/)]));
    expect(byLevel(r, "PASS")).toEqual(expect.arrayContaining([
      expect.stringMatching(/^credentials file .*\(project settings\)$/),
      expect.stringMatching(/^self-lock .*\(local settings\)$/),
    ]));
    expect(byLevel(r, "INFO")[0]).toMatch(/project .*\/\.claude\/settings\.json \(present\); local .*\/\.claude\/settings\.local\.json \(present\)/);
  });

  it("a settings file that is not JSON is a FAIL and counts no rule, and a rule with spaces around it still counts", () => {
    const h = home();
    writeUser(h, "{ not json");
    const r = L.checkSecretsLock(opts(h));
    expect(byLevel(r, "FAIL")[0]).toMatch(/^user settings ~\/\.claude\/settings\.json is not valid JSON: Claude Code refuses to start on it/);
    expect(r.fails).toBe(6);
    writeUser(h, { permissions: { deny: L.SECRETS_LOCK_RULES.map((x) => ` ${x} `) } });
    expect(L.checkSecretsLock(opts(h)).inPlace).toBe(true);
  });

  it("sandbox: off is a WARN naming part C, on without allowUnsandboxedCommands false is not strict, on and strict passes, and the highest scope wins", () => {
    const h = home();
    const project = mkdtempSync(join(h, "repo-"));
    writeUser(h, { permissions: { deny: [...L.SECRETS_LOCK_RULES] } });
    expect(byLevel(L.checkSecretsLock(opts(h, { cwd: project })), "WARN")).toEqual([expect.stringMatching(/^sandbox: off \(part C not done\)/)]);
    writeUser(h, { permissions: { deny: [...L.SECRETS_LOCK_RULES] }, sandbox: { enabled: true } });
    expect(byLevel(L.checkSecretsLock(opts(h, { cwd: project })), "WARN")).toEqual([expect.stringMatching(/^sandbox: on \(user settings\) but not strict: allowUnsandboxedCommands is not set/)]);
    writeProject(project, "settings.local.json", { sandbox: { enabled: true, allowUnsandboxedCommands: false, excludedCommands: ["ssh", "scp"] } });
    const strict = L.checkSecretsLock(opts(h, { cwd: project }));
    expect(byLevel(strict, "WARN")).toEqual([]);
    expect(byLevel(strict, "PASS")).toEqual(expect.arrayContaining([expect.stringMatching(/^sandbox: on and strict \(local settings; commands excluded from it: ssh, scp\)$/)]));
    writeProject(project, "settings.local.json", { sandbox: { enabled: false } });
    expect(byLevel(L.checkSecretsLock(opts(h, { cwd: project })), "WARN")).toEqual([expect.stringMatching(/^sandbox: off/)]); // local overrides user
  });

  it("lists additionalDirectories outside the project as one WARN, marks the sensitive ones, skips those inside the project and repeats", () => {
    const h = home();
    const project = mkdtempSync(join(h, "repo-"));
    writeUser(h, { permissions: { deny: [...L.SECRETS_LOCK_RULES], additionalDirectories: ["~/.ssh", join(h, "Projects", "other"), join(project, "src"), "~/.ssh", "~/.claude/projects/x"] } });
    const r = L.checkSecretsLock(opts(h, { cwd: project }));
    const warn = byLevel(r, "WARN").filter((t) => /^additionalDirectories/.test(t));
    expect(warn).toHaveLength(1);
    // the memory folder under ~/.claude/projects is listed but not sensitive: a chat is meant to write there
    expect(warn[0]).toMatch(/^additionalDirectories: 3 extra folder\(s\) outside this project where sandboxed commands may write \(sensitive: ~\/\.ssh\): ~\/\.ssh, ~\/Projects\/other, ~\/\.claude\/projects\/x$/);
    writeUser(h, { permissions: { deny: [...L.SECRETS_LOCK_RULES] } });
    expect(byLevel(L.checkSecretsLock(opts(h, { cwd: project })), "PASS")).toContain("additionalDirectories: none outside this project");
  });

  it("versions: below 2.1.228 is a FAIL that says what to run, not installed is not a FAIL, 2.1.283 passes", () => {
    const h = home();
    writeUser(h, { permissions: { deny: [...L.SECRETS_LOCK_RULES] } });
    const old = L.checkSecretsLock(opts(h, { terminalVersion: "2.1.217", extensionVersion: null }));
    expect(byLevel(old, "FAIL")).toEqual([expect.stringMatching(/^Claude Code terminal build 2\.1\.217: below 2\.1\.228, a Read deny does not stop the Write tool there \(run: claude update\)$/)]);
    expect(byLevel(old, "INFO")).toEqual(expect.arrayContaining([expect.stringMatching(/^Claude Code editor extension \(newest installed\): not found, nothing to lock there$/)]));
    expect(old.inPlace).toBe(true);
    expect(L.formatSecretsLockReport(old)).toMatch(/The deny rules are in place; fix the FAIL lines above\./);
    const older = L.checkSecretsLock(opts(h, { terminalVersion: "2.1.100" }));
    expect(byLevel(older, "FAIL")[0]).toMatch(/below 2\.1\.208, a Read deny stops neither Edit nor Write there/);
    expect(byLevel(L.checkSecretsLock(opts(h)), "PASS")).toEqual(expect.arrayContaining([
      expect.stringMatching(/^Claude Code terminal build 2\.1\.283: at or above 2\.1\.228/),
      expect.stringMatching(/^Claude Code editor extension \(newest installed\) 2\.1\.283: at or above 2\.1\.228/),
    ]));
    expect(L.versionAtLeast("2.1.228", "2.1.228")).toBe(true);
    expect(L.versionAtLeast("2.1.217", "2.1.228")).toBe(false);
    expect(L.versionAtLeast("2.2.0", "2.1.228")).toBe(true);
    expect(L.versionAtLeast("10.0.0", "9.9.9")).toBe(true);
    expect(L.parseVersion("2.1.217 (Claude Code)")).toBe("2.1.217");
    expect(L.parseVersion("nothing")).toBeNull();
  });

  it("newestExtensionVersion takes the highest Claude Code install folder across editors", () => {
    const h = home();
    const vs = join(h, ".vscode", "extensions");
    const cu = join(h, ".cursor", "extensions");
    for (const v of ["2.1.269", "2.1.283", "2.1.9"]) mkdirSync(join(vs, `anthropic.claude-code-${v}-darwin-arm64`), { recursive: true });
    mkdirSync(join(vs, "someone.claude-code-9.9.9"), { recursive: true });
    mkdirSync(join(cu, "anthropic.claude-code-2.1.290-darwin-arm64"), { recursive: true });
    expect(L.newestExtensionVersion([vs])?.version).toBe("2.1.283");
    expect(L.newestExtensionVersion(L.extensionDirs(h))).toEqual({ version: "2.1.290", path: join(cu, "anthropic.claude-code-2.1.290-darwin-arm64") });
    expect(L.newestExtensionVersion([join(h, "nowhere")])).toBeNull();
  });

  it("names the managed settings file and reads its rules as Mac-wide", () => {
    const h = home();
    const managed = join(h, "managed-settings.json");
    expect(byLevel(L.checkSecretsLock(opts(h, { managedSettingsPath: managed })), "INFO")).toEqual(expect.arrayContaining([expect.stringMatching(/^managed settings: none \(.*managed-settings\.json; part D/)]));
    writeFileSync(managed, JSON.stringify({ permissions: { deny: [...L.SECRETS_LOCK_RULES] } }));
    const r = L.checkSecretsLock(opts(h, { managedSettingsPath: managed }));
    expect(r.inPlace).toBe(true);
    expect(r.macWide).toBe(true);
    expect(byLevel(r, "INFO")).toEqual(expect.arrayContaining([expect.stringMatching(/^managed settings in force/)]));
    expect(byLevel(r, "PASS")[0]).toMatch(/\(managed settings\)$/);
  });

  it("never prints a value from the settings file", () => {
    const h = home();
    const value = "FAKE-VALUE-4242-KEEP-OUT";
    writeUser(h, {
      env: { SOME_NAME: value, OTHER_NAME: `note ${value}` },
      permissions: { allow: [`Bash(echo ${value})`], deny: [...L.SECRETS_LOCK_RULES], additionalDirectories: ["~/x"] },
      hooks: { Stop: [{ hooks: [{ type: "command", command: `x ${value}` }] }] },
    });
    const text = L.formatSecretsLockReport(L.checkSecretsLock(opts(h)));
    expect(text).not.toContain(value);
    expect(text).not.toContain("SOME_NAME");
    expect(text).not.toContain("echo");
  });
});

describe("applySecretsLock", () => {
  const env = {}; // no CLAUDECODE: the owner's own terminal

  it("creates the file with every rule when there is none, without a backup, and the check then passes", () => {
    const h = home();
    const r = L.applySecretsLock({ home: h, env });
    expect(r).toMatchObject({ refused: null, wrote: true, backup: null, present: [], path: settingsPath(h) });
    expect(r.added).toEqual([...L.SECRETS_LOCK_RULES]);
    expect(JSON.parse(readFileSync(settingsPath(h), "utf-8"))).toEqual({ permissions: { deny: [...L.SECRETS_LOCK_RULES] } });
    expect(readFileSync(settingsPath(h), "utf-8").endsWith("\n")).toBe(true);
    expect(L.checkSecretsLock(opts(h)).inPlace).toBe(true);
  });

  it("keeps every existing entry in its order, writes a dated backup beside the file, and reads back valid JSON", () => {
    const h = home();
    const before = {
      theme: "dark",
      env: { X: "1" },
      permissions: { allow: ["Bash(ls *)"], deny: ["Read(//**/*.pem)", "Read(//**/.env)"], additionalDirectories: ["~/x"] },
      hooks: { Stop: [{ hooks: [{ type: "command", command: "echo" }] }] },
    };
    writeUser(h, before);
    const r = L.applySecretsLock({ home: h, env, now: new Date("2026-09-27T20:00:00.000Z") });
    expect(r.wrote).toBe(true);
    expect(r.backup).toBe(`${settingsPath(h)}.bak-secrets-lock-2026-09-27T20-00-00-000Z`);
    expect(JSON.parse(readFileSync(r.backup as string, "utf-8"))).toEqual(before);
    expect(r.present).toEqual(["Read(//**/.env)"]);
    expect(r.added).toHaveLength(L.SECRETS_LOCK_RULES.length - 1);
    const after = JSON.parse(readFileSync(settingsPath(h), "utf-8"));
    expect(Object.keys(after)).toEqual(Object.keys(before));
    expect(without(after, "permissions")).toEqual(without(before, "permissions"));
    expect(after.permissions.allow).toEqual(before.permissions.allow);
    expect(after.permissions.additionalDirectories).toEqual(before.permissions.additionalDirectories);
    expect(after.permissions.deny.slice(0, 2)).toEqual(before.permissions.deny); // existing entries first, in their order
    expect(after.permissions.deny).toEqual([...before.permissions.deny, ...r.added]);
    expect(new Set(after.permissions.deny).size).toBe(after.permissions.deny.length);
  });

  it("is idempotent: a second run reports in place, writes nothing and leaves no new backup", () => {
    const h = home();
    writeUser(h, { permissions: { allow: ["Bash(ls *)"] } });
    L.applySecretsLock({ home: h, env });
    const bytes = readFileSync(settingsPath(h), "utf-8");
    const files = readdirSync(join(h, ".claude"));
    expect(files).toHaveLength(2); // the file and one backup
    const again = L.applySecretsLock({ home: h, env });
    expect(again).toMatchObject({ refused: null, wrote: false, backup: null, added: [] });
    expect(again.present).toEqual([...L.SECRETS_LOCK_RULES]);
    expect(readFileSync(settingsPath(h), "utf-8")).toBe(bytes);
    expect(readdirSync(join(h, ".claude"))).toEqual(files);
  });

  it("refuses inside an agent session (CLAUDECODE set) and writes nothing; an empty CLAUDECODE is not a session", () => {
    const h = home();
    writeUser(h, { permissions: { allow: ["Bash(ls *)"] } });
    const bytes = readFileSync(settingsPath(h), "utf-8");
    const r = L.applySecretsLock({ home: h, env: { CLAUDECODE: "1" } });
    expect(r.refused).toMatch(/inside an agent session \(CLAUDECODE is set\)/);
    expect(r.wrote).toBe(false);
    expect(readFileSync(settingsPath(h), "utf-8")).toBe(bytes);
    expect(readdirSync(join(h, ".claude"))).toEqual(["settings.json"]);
    expect(L.applySecretsLock({ home: home(), env: { CLAUDECODE: "" } }).refused).toBeNull();
  });

  it("refuses without HOME in the environment: an env -i test that forgot HOME must not reach the real file", () => {
    const r = L.applySecretsLock({ env: {} });
    expect(r.refused).toMatch(/without HOME in the environment/);
    expect(r.wrote).toBe(false);
    expect(r.backup).toBeNull();
  });

  it("refuses a settings file that is not JSON and leaves it untouched", () => {
    const h = home();
    writeUser(h, "{ not json");
    expect(() => L.applySecretsLock({ home: h, env })).toThrow(/not valid JSON, refusing to touch it/);
    expect(readFileSync(settingsPath(h), "utf-8")).toBe("{ not json");
    expect(readdirSync(join(h, ".claude"))).toEqual(["settings.json"]);
  });

  it("the test card sends the owner to fake files and lists the nine checks", () => {
    const card = L.secretsLockTestCard();
    expect(card).toMatch(/FAKE files only/);
    expect(card).toMatch(/FAKE-VALUE-4242/);
    for (let i = 1; i <= 9; i++) expect(card).toMatch(new RegExp(`^  ${i}\\. `, "m"));
    expect(card).toMatch(/file changed on disk/);
    expect(card).not.toMatch(/—/); // no em-dash, anywhere
  });

  // [LOCK] [SECRETS-LOCK-CLAIMS-ARE-MEASURED]
  it("the help and the test card never promise that Bash is stopped without the sandbox", () => {
    const card = L.secretsLockTestCard();
    const help = L.USAGE;
    // The 2.13.0 draft promised these; the owner's fake-file test on 2026-09-27 disproved them.
    expect(help).not.toMatch(/cat\/head\/tail/);
    expect(help).not.toMatch(/name the file in Bash/);
    expect(card).not.toMatch(/rule itself inside Bash/);
    expect(card).not.toMatch(/gets the path, not the text/);
    // What was measured is said instead.
    expect(help).toMatch(/What they do not stop: commands the agent runs in Bash/);
    expect(help).toMatch(/Only\s+the sandbox closes Bash/);
    expect(card).toMatch(/expect it to get\s+through/);
    for (const text of [help, card]) expect(text).not.toMatch(/[—–]/);
  });
});

describe("the two surfaces without a command", () => {
  it("secretsLockHealth is null without a settings file, MISSING with the count when rules are absent, in place after apply", () => {
    const h = home();
    const p = settingsPath(h);
    expect(L.secretsLockHealth({ userSettingsPath: p, managedSettingsPath: null })).toBeNull();
    writeUser(h, { hooks: {} });
    expect(L.secretsLockHealth({ userSettingsPath: p, managedSettingsPath: null })).toEqual({ inPlace: false, missing: 28, total: 28 });
    L.applySecretsLock({ home: h, env: {} });
    expect(L.secretsLockHealth({ userSettingsPath: p, managedSettingsPath: null })).toEqual({ inPlace: true, missing: 0, total: 28 });
  });

  it("fleet health carries the lock, prints its line, and warns while it is missing", () => {
    const h = home();
    const audit = join(h, "missing.log");
    const rep = { servers: [], removed: 0, warnings: [] as string[] };
    const now = new Date("2026-09-27T10:00:00.000Z");
    writeUser(h, { permissions: { deny: ["Read(//**/.env)"] } });
    const missing = H.computeFleetHealth({ now, auditPath: audit, report: rep, settingsPath: settingsPath(h) });
    expect(missing.secretsLock).toEqual({ inPlace: false, missing: 27, total: 28 });
    expect(missing.warnings).toEqual([expect.stringMatching(/^agent lock on secrets files: MISSING \(27 of 28 deny rules absent from Claude Code's user settings\): .*secrets-lock --apply in your own terminal$/)]);
    expect(H.formatFleetHealth(missing)).toMatch(/^  agent lock on secrets files: MISSING \(27 of 28 rules\)$/m);
    L.applySecretsLock({ home: h, env: {} });
    const ok = H.computeFleetHealth({ now, auditPath: audit, report: rep, settingsPath: settingsPath(h) });
    expect(ok.secretsLock).toEqual({ inPlace: true, missing: 0, total: 28 });
    expect(ok.warnings).toEqual([]);
    expect(H.formatFleetHealth(ok)).toMatch(/^  agent lock on secrets files: in place$/m);
    const none = H.computeFleetHealth({ now, auditPath: audit, report: rep, settingsPath: join(h, "no-such.json") });
    expect(none.secretsLock).toBeNull();
    expect(none.warnings).toEqual([]); // Claude Code not set up here is not a problem
    expect(H.formatFleetHealth(none)).toMatch(/agent lock on secrets files: no Claude Code settings on this machine/);
  });

  it("projectSecretsLock counts the file rules from the user and project settings together, and names the scopes", () => {
    const h = home();
    const project = mkdtempSync(join(h, "repo-"));
    const o = { home: h, managedSettingsPath: null };
    expect(L.projectSecretsLock(project, o)).toEqual({ present: 0, total: 20, scopes: [] });
    writeUser(h, { permissions: { deny: L.SECRETS_FILE_RULES.slice(0, 6) } });
    expect(L.projectSecretsLock(project, o)).toEqual({ present: 6, total: 20, scopes: ["user"] });
    writeProject(project, "settings.json", { permissions: { deny: L.SECRETS_FILE_RULES.slice(6) } });
    expect(L.projectSecretsLock(project, o)).toEqual({ present: 20, total: 20, scopes: ["user", "project"] });
  });
});
