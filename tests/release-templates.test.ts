/**
 * The public copy's workflows are written from release/public-ci.yml and release/public-codeql.yml.
 * The update bot watches .github/workflows only: when it moves a build step there, nothing moves
 * the templates. On 2026-10-02 they were three major versions behind, found by hand. This test
 * makes that gap a red test: a pull request that moves a build step here fails until the
 * templates follow.
 *
 * It compares only the steps both sides use. A step the templates use alone (CodeQL today) has
 * no counterpart here and stays a thing to look at by hand.
 */
import { describe, it, expect } from "vitest";
import { existsSync, readdirSync, readFileSync } from "fs";
import { join } from "path";

const OWN = ".github/workflows";
const TEMPLATES = "release";

/** action -> version -> the files that pin it. `github/codeql-action/init` counts as `github/codeql-action`. */
function pins(dir: string): Map<string, Map<string, string[]>> {
  const found = new Map<string, Map<string, string[]>>();
  for (const file of readdirSync(dir).filter((f) => /\.ya?ml$/.test(f)).sort()) {
    for (const line of readFileSync(join(dir, file), "utf8").split("\n")) {
      const m = /^\s*(?:-\s+)?uses:\s*["']?([^@\s"']+)@([^\s"'#]+)/.exec(line);
      if (!m) continue;
      const action = m[1].split("/").slice(0, 2).join("/");
      const versions = found.get(action) ?? new Map<string, string[]>();
      versions.set(m[2], [...(versions.get(m[2]) ?? []), file]);
      found.set(action, versions);
    }
  }
  return found;
}

// The public copy has no release/ folder: there the templates ARE the workflows.
describe.skipIf(!existsSync(TEMPLATES))("the public copy's workflow templates", () => {
  it("pin the same version as this repo's workflows for every build step both use", () => {
    const own = pins(OWN);
    const templates = pins(TEMPLATES);
    const shared = [...templates.keys()].filter((action) => own.has(action));
    // If this is empty the comparison below proves nothing: the reading broke, or the files moved.
    expect(shared).toContain("actions/checkout");

    const behind: string[] = [];
    for (const action of shared) {
      const ownVersions = [...own.get(action)!.keys()];
      for (const [version, files] of templates.get(action)!) {
        if (!ownVersions.includes(version)) {
          behind.push(`${action}@${version} in ${TEMPLATES}/${files.join(", ")}, but ${OWN} uses @${ownVersions.join(", @")}`);
        }
      }
    }
    expect(behind).toEqual([]);
  });

  // 2026-10-02, Node 24 plan phase 1b: the plan said this test kept the two CI files aligned, but
  // it compared build steps only. The Node versions a release is tested on are part of the promise.
  it("test on the same Node versions as this repo's CI", () => {
    const nodes = (file: string) =>
      /node-version:\s*\[([^\]]*)\]/.exec(readFileSync(file, "utf8"))?.[1].split(",").map((v) => v.trim()) ?? [];
    const own = nodes(join(OWN, "ci.yml"));
    // If this is empty the comparison below proves nothing: the matrix moved or changed shape.
    expect(own.length).toBeGreaterThan(0);
    expect(nodes(join(TEMPLATES, "public-ci.yml"))).toEqual(own);
  });

  it("pin one version of each build step, here and in the templates", () => {
    const mixed: string[] = [];
    for (const [where, found] of [[OWN, pins(OWN)], [TEMPLATES, pins(TEMPLATES)]] as const) {
      for (const [action, versions] of found) {
        if (versions.size > 1) mixed.push(`${action} in ${where}: @${[...versions.keys()].join(", @")}`);
      }
    }
    expect(mixed).toEqual([]);
  });
});
