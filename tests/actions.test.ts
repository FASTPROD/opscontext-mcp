// `contextengine actions`: the owner's open action points, read from the `actions` key of every
// saved session. Fixtures in the throwaway CE home that src/test-setup.ts points every test file at;
// nothing is written outside it, nothing reaches the network.
import { describe, it, expect, beforeEach } from "vitest";
import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { actionsReport, formatActions, parseActionsArgs } from "../src/actions.js";

const sessions = join(process.env.CONTEXTENGINE_HOME as string, "sessions");

function session(name: string, entries: Array<{ key: string; value: string; timestamp?: string }>, updated = "2026-11-02T10:00:00.000Z"): void {
  mkdirSync(sessions, { recursive: true });
  const body = {
    name,
    created: "2026-10-01T08:00:00.000Z",
    updated,
    entries: entries.map((e) => ({ key: e.key, value: e.value, timestamp: e.timestamp ?? updated })),
  };
  writeFileSync(join(sessions, `${name}.json`), JSON.stringify(body, null, 2));
}

const opts = (over: Partial<ReturnType<typeof parseActionsArgs> extends { ok: true; opts: infer O } ? O : never> = {}) =>
  ({ all: false, since: undefined, project: undefined, ...over });

beforeEach(() => {
  rmSync(sessions, { recursive: true, force: true });
});

describe("actionsReport", () => {
  it("reports an empty store as no sessions, without creating the folder", () => {
    const r = actionsReport(opts());
    expect(r.sessions).toBe(0);
    expect(r.actions).toEqual([]);
    expect(formatActions(r, opts())).toContain("No saved sessions");
  });

  it("lists the open lines of every session sorted by date, oldest first, each with its session and timestamp", () => {
    session("admin-crowlr-php-cve", [
      { key: "summary", value: "prose" },
      { key: "actions", value: "2026-11-08 | open | admin.CROWLR | read Sunday's two health mails\n2026-11-07 | open | admin.CROWLR | invoc-ovh's weekly must mail nothing", timestamp: "2026-11-02T10:01:00.000Z" },
    ]);
    session("contextengine-actions", [
      { key: "actions", value: "2026-11-03 | open | ContextEngine | run npm run build, then the commit", timestamp: "2026-11-02T18:30:00.000Z" },
    ]);
    const r = actionsReport(opts());
    expect(r.sessions).toBe(2);
    expect(r.actions.map((a) => [a.date, a.project, a.what, a.session])).toEqual([
      ["2026-11-03", "ContextEngine", "run npm run build, then the commit", "contextengine-actions"],
      ["2026-11-07", "admin.CROWLR", "invoc-ovh's weekly must mail nothing", "admin-crowlr-php-cve"],
      ["2026-11-08", "admin.CROWLR", "read Sunday's two health mails", "admin-crowlr-php-cve"],
    ]);
    expect(r.actions[0].timestamp).toBe("2026-11-02T18:30:00.000Z");
    const text = formatActions(r, opts());
    expect(text).toMatch(/^3 open action points/);
    expect(text).toContain("2026-11-03 | open | ContextEngine | run npm run build, then the commit");
    expect(text).toContain("contextengine-actions, written 2026-11-02 18:30Z (19:30 CET)");
  });

  it("hides done lines unless --all, and says how many it hid", () => {
    session("s", [{ key: "actions", value: "2026-10-30 | done | PLANK.io | the push\n2026-11-05 | open | PLANK.io | check the live site" }]);
    const r = actionsReport(opts());
    expect(r.actions.map((a) => a.state)).toEqual(["open"]);
    expect(r.hiddenDone).toBe(1);
    expect(formatActions(r, opts())).toContain("1 done line hidden (--all shows them)");
    const all = actionsReport(opts({ all: true }));
    expect(all.actions.map((a) => a.state)).toEqual(["done", "open"]);
    expect(formatActions(all, opts({ all: true }))).toMatch(/^1 open and 1 done action points/);
  });

  it("keeps only the lines dated at or after --since", () => {
    session("s", [{ key: "actions", value: "2026-11-01 | open | A | one\n2026-11-02 | open | A | two\n2026-11-03 | open | A | three" }]);
    const r = actionsReport(opts({ since: "2026-11-02" }));
    expect(r.actions.map((a) => a.what)).toEqual(["two", "three"]);
    expect(formatActions(r, opts({ since: "2026-11-02" }))).toContain("since 2026-11-02");
  });

  it("keeps only one project with --project, matching admin-CROWLR to admin.CROWLR whatever the case", () => {
    session("s", [{ key: "actions", value: "2026-11-01 | open | admin.CROWLR | one\n2026-11-02 | open | PLANK.io | two\n2026-11-03 | open | Admin-crowlr | three" }]);
    const r = actionsReport(opts({ project: "admin.crowlr" }));
    expect(r.actions.map((a) => a.what)).toEqual(["one", "three"]);
    expect(formatActions(r, opts({ project: "admin.crowlr" }))).toContain("for project admin.crowlr");
  });

  it("names a session file that does not parse instead of skipping it", () => {
    session("good", [{ key: "actions", value: "2026-11-04 | open | X | fine" }]);
    mkdirSync(sessions, { recursive: true });
    writeFileSync(join(sessions, "broken.json"), "{ not json");
    writeFileSync(join(sessions, "no-entries.json"), JSON.stringify({ name: "no-entries" }));
    const r = actionsReport(opts());
    expect(r.sessions).toBe(3);
    expect(r.actions).toHaveLength(1);
    expect(r.unreadable.map((u) => u.file).sort()).toEqual(["broken.json", "no-entries.json"]);
    const text = formatActions(r, opts());
    expect(text).toContain("2 session files could not be read");
    expect(text).toContain("broken.json");
    expect(text).toContain("no-entries.json");
  });

  it("counts the sessions without an actions key and names the newest", () => {
    session("older", [{ key: "summary", value: "x" }], "2026-10-20T09:00:00.000Z");
    session("newest-without", [{ key: "open", value: "prose" }], "2026-11-02T14:00:00.000Z");
    session("with", [{ key: "actions", value: "2026-11-09 | open | P | w" }], "2026-11-01T00:00:00.000Z");
    const r = actionsReport(opts());
    expect(r.withoutKey.map((s) => s.name)).toEqual(["newest-without", "older"]);
    expect(formatActions(r, opts())).toContain("2 sessions without an actions key, newest: newest-without 2026-11-02");
  });

  it("names a line that is not in the convention instead of dropping it silently", () => {
    session("s", [{ key: "actions", value: "2026-11-04 | open | X | fine\njust some prose\n2026-11-05 | later | X | bad state\n\n- 2026-11-06 | open | X | a bullet is tolerated" }]);
    const r = actionsReport(opts());
    expect(r.actions.map((a) => a.what)).toEqual(["fine", "a bullet is tolerated"]);
    expect(r.malformed.map((m) => m.line)).toEqual(["just some prose", "2026-11-05 | later | X | bad state"]);
    const text = formatActions(r, opts());
    expect(text).toContain('s: not an action line, left out: "just some prose"');
  });

  it("keeps the text after a fourth pipe inside the what", () => {
    session("s", [{ key: "actions", value: "2026-11-04 | open | X | run a | b | c" }]);
    expect(actionsReport(opts()).actions[0].what).toBe("run a | b | c");
  });
});

describe("parseActionsArgs", () => {
  it("accepts --all, --since and --project in any order", () => {
    const r = parseActionsArgs(["--project", "PLANK.io", "--all", "--since", "2026-11-01"]);
    expect(r).toEqual({ ok: true, opts: { all: true, since: "2026-11-01", project: "PLANK.io" } });
  });
  it("refuses a --since that is not a YYYY-MM-DD day", () => {
    const r = parseActionsArgs(["--since", "yesterday"]);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error).toContain("--since");
  });
  it("refuses a flag without its value and an unknown flag", () => {
    expect(parseActionsArgs(["--project"]).ok).toBe(false);
    expect(parseActionsArgs(["--json"]).ok).toBe(false);
  });
});
