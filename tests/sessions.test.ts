import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { existsSync, rmSync, mkdirSync, mkdtempSync } from "fs";
import { join } from "path";
import { homedir, tmpdir } from "os";
import {
  saveSession,
  loadSession,
  listSessions,
  formatSession,
  formatSessionList,
} from "../src/sessions.js";

const SESSIONS_DIR = join(homedir(), ".contextengine", "sessions");
const TEST_SESSION = "vitest-session-temp";

describe("sessions", () => {
  // Clean up test session before and after
  beforeEach(() => {
    const path = join(SESSIONS_DIR, `${TEST_SESSION}.json`);
    if (existsSync(path)) rmSync(path);
  });

  afterEach(() => {
    const path = join(SESSIONS_DIR, `${TEST_SESSION}.json`);
    if (existsSync(path)) rmSync(path);
  });

  it("saveSession creates a new session", () => {
    const session = saveSession(TEST_SESSION, "status", "in-progress");
    expect(session.name).toBe(TEST_SESSION);
    expect(session.entries).toHaveLength(1);
    expect(session.entries[0].key).toBe("status");
    expect(session.entries[0].value).toBe("in-progress");
  });

  it("saveSession appends entries to existing session", () => {
    saveSession(TEST_SESSION, "key1", "value1");
    const session = saveSession(TEST_SESSION, "key2", "value2");
    expect(session.entries).toHaveLength(2);
  });

  it("saveSession updates existing key", () => {
    saveSession(TEST_SESSION, "status", "draft");
    const session = saveSession(TEST_SESSION, "status", "done");
    // Should have 1 entry (updated in place), not 2
    const statusEntries = session.entries.filter((e) => e.key === "status");
    expect(statusEntries).toHaveLength(1);
    expect(statusEntries[0].value).toBe("done");
  });

  it("loadSession returns null for non-existent session", () => {
    const result = loadSession("nonexistent-session-xyz-12345");
    expect(result).toBeNull();
  });

  it("loadSession returns saved session data", () => {
    saveSession(TEST_SESSION, "branch", "main");
    const loaded = loadSession(TEST_SESSION);
    expect(loaded).not.toBeNull();
    expect(loaded!.name).toBe(TEST_SESSION);
    expect(loaded!.entries[0].key).toBe("branch");
    expect(loaded!.entries[0].value).toBe("main");
  });

  it("listSessions returns array", () => {
    const sessions = listSessions();
    expect(Array.isArray(sessions)).toBe(true);
  });

  it("listSessions includes test session after save", () => {
    saveSession(TEST_SESSION, "test", "data");
    const sessions = listSessions();
    const found = sessions.find((s) => s.name === TEST_SESSION);
    expect(found).toBeDefined();
    expect(found!.entries).toBe(1);
  });

  it("formatSession produces readable output", () => {
    const session = saveSession(TEST_SESSION, "branch", "main");
    const text = formatSession(session);
    expect(text).toContain(TEST_SESSION);
    expect(text).toContain("branch");
    expect(text).toContain("main");
  });

  it("formatSessionList produces readable output", () => {
    saveSession(TEST_SESSION, "key", "val");
    const sessions = listSessions();
    const text = formatSessionList(sessions);
    expect(typeof text).toBe("string");
    expect(text.length).toBeGreaterThan(0);
  });

  it("session name is sanitized for filesystem", () => {
    // Names with special chars should not throw
    const session = saveSession("test/with:special<chars>", "k", "v");
    expect(session.name).toBeDefined();
    // Every character outside [A-Za-z0-9_.-] becomes "_" in the file name.
    const file = join(SESSIONS_DIR, "test_with_special_chars_.json");
    expect(existsSync(file)).toBe(true);
    rmSync(file);
  });
});

// [LOCK] [EXEC-FAILURE-IS-NOT-EMPTY] at the session list. E2E_REVIEW_2026-09 C6-5: a session file that
// could not be parsed was dropped from the list in silence, as if it had never been saved.
import { writeFileSync } from "fs";
describe("a session file that cannot be read", () => {
  const CORRUPT = "vitest-corrupt-temp";
  const corruptPath = join(SESSIONS_DIR, `${CORRUPT}.json`);
  afterEach(() => { if (existsSync(corruptPath)) rmSync(corruptPath); });

  it("is listed by its file name with the error, not dropped", () => {
    mkdirSync(SESSIONS_DIR, { recursive: true });
    writeFileSync(corruptPath, "{ not json");
    const entry = listSessions().find((s) => s.name === CORRUPT);
    expect(entry).toBeDefined();
    expect(entry!.error).toMatch(/JSON/);
    expect(formatSessionList(listSessions())).toMatch(new RegExp(`\\| ${CORRUPT} \\| could not be read: `));
  });
});

// [LOCK] [SESSIONS-FOLLOW-THE-CE-HOME] (src/ce-home.ts). The store fixed the login home's folder at
// import while the session gate read CONTEXTENGINE_HOME, so a scratch CE home still wrote into the
// real sessions folder (E2E_REVIEW_2026-09 C1-2).
describe("the sessions folder follows CONTEXTENGINE_HOME, read at every call", () => {
  it("a session saved after the CE home changes lands in the new home, not the login home's", () => {
    const before = process.env.CONTEXTENGINE_HOME;
    const other = mkdtempSync(join(tmpdir(), "ce-sessions-home-"));
    process.env.CONTEXTENGINE_HOME = other;
    try {
      saveSession("probe-home", "k", "v");
      expect(existsSync(join(other, "sessions", "probe-home.json"))).toBe(true);
      expect(existsSync(join(homedir(), ".contextengine", "sessions", "probe-home.json"))).toBe(false);
      expect(listSessions().map((x) => x.name)).toContain("probe-home");
      expect(loadSession("probe-home")?.entries[0].value).toBe("v");
    } finally {
      process.env.CONTEXTENGINE_HOME = before;
      rmSync(other, { recursive: true, force: true });
    }
  });
});
