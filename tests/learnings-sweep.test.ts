// [LOCK] [SWEEP-RECORDS-ONLY-WHAT-CHANGED] (src/learnings.ts). E2E_REVIEW_2026-09 C3-1: 75 % of the
// audit history was "imported nothing" records, one per source per sweep, 41 sweeps a day. Three
// of these tests fail on the code before the fix: the first sweep wrote one record per source
// (now one for the sweep plus one for the source that imported), the second sweep wrote them all
// again (now one record saying "3 unchanged"), and a touched file whose rule was already in the
// store counted as "updated" (now nothing).
import { describe, it, expect, beforeEach } from "vitest";
import { existsSync, mkdirSync, readFileSync, rmSync, statSync, utimesSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import * as L from "../src/learnings.js";
import { trustProjects } from "../src/trusted-projects.js";

const home = () => process.env.CONTEXTENGINE_HOME as string;
const records = () =>
  existsSync(join(home(), "audit.log"))
    ? readFileSync(join(home(), "audit.log"), "utf8").trim().split("\n").filter(Boolean).map((l) => JSON.parse(l))
    : [];
const sweeps = () => records().filter((r) => r.event === "learning.sweep");
const imports = () => records().filter((r) => r.event === "learning.import" && r.payload.source !== "bundled defaults");

let dir: string;
let n = 0;
beforeEach(() => {
  mkdirSync(home(), { recursive: true });
  rmSync(join(home(), "learnings.json.lock"), { recursive: true, force: true });
  rmSync(join(home(), "audit.log"), { force: true });
  rmSync(join(home(), "trusted-projects.json"), { force: true });
  dir = join(home(), `sweep-${++n}-${Date.now()}`);
  mkdirSync(join(dir, "docs"), { recursive: true });
  mkdirSync(join(dir, "other"), { recursive: true });
});

const src = (file: string, project = "demo") => ({ path: join(dir, file), name: `${project} — ${file}` });
const marked = (rule: string) => `# Learnings\n\n- [testing] ${rule} → because the test says so\n`;
const RULE = "run the whole suite twice before every release of the package";

function threeSources() {
  writeFileSync(join(dir, "AGENT-LEARNINGS.md"), marked(RULE));
  writeFileSync(join(dir, "README.md"), "# Demo\n\nA plain document with nothing marked.\n");
  writeFileSync(join(dir, "docs", "NOTES.md"), "# Notes\n\nStill nothing marked here.\n");
  trustProjects(["demo"]);
  return [src("AGENT-LEARNINGS.md"), src("README.md"), src("docs/NOTES.md")];
}

describe("the auto-import sweep records only what changed", () => {
  it("first sweep: one record for the sweep, one for the source that imported, none for the rest", () => {
    const sources = threeSources();
    const r = L.autoImportFromSources(sources);
    expect(r.imported).toBe(1);
    expect(r.sources).toBe(3);
    expect(r.scanned).toBe(3);
    expect(r.unchanged).toBe(0);
    const s = sweeps();
    expect(s).toHaveLength(1);
    expect(s[0].payload).toMatchObject({ sources: 3, scanned: 3, unchanged: 0, imported: 1, updated: 0, errors: 0 });
    const i = imports();
    expect(i).toHaveLength(1);
    expect(i[0].payload.source).toMatch(/AGENT-LEARNINGS\.md$/);
    expect(i[0].payload.imported).toBe(1);
  });

  it("a second sweep with nothing changed reads nothing, writes one sweep record and does not touch the store", () => {
    const sources = threeSources();
    L.autoImportFromSources(sources);
    const before = statSync(join(home(), "learnings.json")).mtimeMs;
    const r = L.autoImportFromSources(sources);
    expect(r.scanned).toBe(0);
    expect(r.unchanged).toBe(3);
    expect(r.imported).toBe(0);
    expect(sweeps()).toHaveLength(2);
    expect(sweeps()[1].payload).toMatchObject({ sources: 3, scanned: 0, unchanged: 3, imported: 0, updated: 0 });
    expect(imports()).toHaveLength(1);
    expect(statSync(join(home(), "learnings.json")).mtimeMs).toBe(before);
  });

  it("a changed source is read again; a record appears only when it imports something", () => {
    const sources = threeSources();
    L.autoImportFromSources(sources);
    writeFileSync(join(dir, "README.md"), "# Demo\n\nA plain document, now longer, with nothing marked.\n");
    let r = L.autoImportFromSources(sources);
    expect(r.scanned).toBe(1);
    expect(r.unchanged).toBe(2);
    expect(imports()).toHaveLength(1);
    writeFileSync(join(dir, "README.md"), "# Demo\n\n## Learnings\n\n- [tooling] always pin the node version in the workflow file of the demo → drift\n");
    r = L.autoImportFromSources(sources);
    expect(r.imported).toBe(1);
    expect(imports()).toHaveLength(2);
    expect(imports()[1].payload.source).toMatch(/README\.md$/);
  });

  it("a touched file whose rule is already in the store counts as nothing, not as updated", () => {
    const sources = threeSources();
    L.autoImportFromSources(sources);
    const later = new Date(Date.now() + 5000);
    utimesSync(join(dir, "AGENT-LEARNINGS.md"), later, later);
    const r = L.autoImportFromSources(sources);
    expect(r.scanned).toBe(1);
    expect(r.updated).toBe(0);
    expect(r.imported).toBe(0);
    expect(imports()).toHaveLength(1);
    expect(sweeps()[1].payload).toMatchObject({ scanned: 1, unchanged: 2, updated: 0 });
  });

  it("a project newly marked as trusted is read again without a file change", () => {
    threeSources();
    writeFileSync(join(dir, "other", "AGENT-LEARNINGS.md"), marked("check the licence server log after every purchase test"));
    const sources = [src("AGENT-LEARNINGS.md"), src("other/AGENT-LEARNINGS.md", "other")];
    let r = L.autoImportFromSources(sources);
    expect(r.untrusted).toEqual(["other"]);
    expect(imports().filter((i) => /other\/AGENT-LEARNINGS\.md$/.test(i.payload.source))).toHaveLength(0);
    trustProjects(["other"]);
    r = L.autoImportFromSources(sources);
    expect(r.untrusted).toEqual([]);
    expect(r.imported).toBe(1);
    expect(imports().filter((i) => /other\/AGENT-LEARNINGS\.md$/.test(i.payload.source))).toHaveLength(1);
  });
});

describe("what counts as imported", () => {
  it("a rule already in the store under another category is nothing, and a changed context is an update", () => {
    threeSources();
    const rule = "run the vitest suite and the pytest suite before every release";
    const readme = join(dir, "README.md");
    // saved under "testing"; the bullet says "other", which saveLearning() infers back to "testing"
    L.saveLearning("testing", rule, "because the suite is the proof", "demo", readme);
    writeFileSync(readme, `# Demo\n\n## Learnings\n\n- [other] ${rule} → because the suite is the proof\n`);
    let r = L.autoImportFromSources([src("README.md")]);
    expect(r.imported).toBe(0);
    expect(r.updated).toBe(0);
    expect(imports()).toHaveLength(0);
    expect(sweeps()[0].payload).toMatchObject({ imported: 0, updated: 0 });
    writeFileSync(readme, `# Demo\n\n## Learnings\n\n- [other] ${rule} → because the suite is the proof, twice\n`);
    r = L.autoImportFromSources([src("README.md")]);
    expect(r.imported).toBe(0);
    expect(r.updated).toBe(1);
    expect(imports()).toHaveLength(1);
    expect(imports()[0].payload).toMatchObject({ imported: 0, updated: 1 });
  });
});
