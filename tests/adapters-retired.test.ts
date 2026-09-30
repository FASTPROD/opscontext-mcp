// [LOCK] [ADAPTERS-RETIRED] (src/index.ts). E2E_REVIEW_2026-09 batch 4: the plug-in adapters were retired
// unused. A config that still lists some is told so, and no code a config names can run: every
// dynamic import in src/ takes a path written in the source.
import { describe, it, expect } from "vitest";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { retiredAdaptersNote, type ContextEngineConfig } from "../src/config.js";

describe("plug-in adapters, retired 2026-09-30", () => {
  it("a config that still lists adapters is told they are ignored, naming the file", () => {
    const cfg = { adapters: [{ name: "feeds", module: "./adapters/rss-adapter.js" }] } as ContextEngineConfig;
    const note = retiredAdaptersNote(cfg, "/somewhere/contextengine.json");
    expect(note).toMatch(/retired in 2\.17\.0/);
    expect(note).toContain("/somewhere/contextengine.json");
    expect(note).toMatch(/1 adapter entry .* is ignored, and no adapter code is loaded/);
    expect(retiredAdaptersNote({ adapters: [1, 2] } as ContextEngineConfig)).toMatch(/2 adapter entries in the config are ignored/);
  });

  it("says nothing when no adapter is listed", () => {
    expect(retiredAdaptersNote({} as ContextEngineConfig)).toBeNull();
    expect(retiredAdaptersNote({ adapters: [] } as ContextEngineConfig)).toBeNull();
  });

  it("no module in src/ imports a path it did not write itself", () => {
    const dir = join(process.cwd(), "src");
    const offenders: string[] = [];
    for (const f of readdirSync(dir).filter((n) => n.endsWith(".ts") && !n.endsWith(".test.ts"))) {
      // Comments may mention import(); only code counts. "://" inside a URL is not a comment.
      const code = readFileSync(join(dir, f), "utf-8")
        .replace(/\/\*[\s\S]*?\*\//g, "")
        .replace(/(^|[^:])\/\/.*$/gm, "$1");
      for (const m of code.matchAll(/\bimport\(\s*([^)]*)\)/g)) {
        if (!/^(["'])[^"']+\1$/.test(m[1].trim())) offenders.push(`${f}: import(${m[1]})`);
      }
    }
    expect(offenders).toEqual([]);
  });
});
