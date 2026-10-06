// [LOCK] [AUTOSTART-WAITS-FOR-LAUNCHD]: install-autostart against a fake launchctl that behaves like
// the real one on 2026-10-02: `bootout` returns while launchd is still removing the old agent, and a
// `bootstrap` in that window fails with "5: Input/output error". Throwaway HOME, fake launchctl and
// lsof first in PATH (guarded): the real launchd and the real agent are never touched.
import { describe, it, expect } from "vitest";
import { mkdirSync, mkdtempSync, writeFileSync, readFileSync, chmodSync, existsSync, rmSync } from "node:fs";
import { join, dirname } from "node:path";
import { tmpdir } from "node:os";
import { spawnSync, execFileSync } from "node:child_process";

const AGENT_PID = 4242;
const CHAT_PID = 5151;

interface Fake {
  /** what launchd holds before the install: nothing, or the old agent */
  start: "gone" | "running";
  /** how many `launchctl print` calls still find the old agent after `bootout` */
  teardownPrints: number;
  /** what the new agent does once bootstrapped */
  agent: "takes-port" | "crashes" | "port-stays-with-chat";
}

function run(fake: Fake) {
  const root = mkdtempSync(join(tmpdir(), "ce-autostart-launchd-"));
  const home = join(root, "home");
  const shims = join(root, "shims");
  mkdirSync(home, { recursive: true });
  mkdirSync(shims, { recursive: true });
  const state = join(root, "launchd.state");
  const log = join(root, "calls.log");
  writeFileSync(state, fake.start === "running" ? "running" : "gone");
  // States: gone | running | teardown:N (bootout done, N more prints still find it) | crashed
  writeFileSync(
    join(shims, "launchctl"),
    `#!/bin/sh
S='${state}'; echo "launchctl $1" >> '${log}'
st=$(cat "$S")
case "$1" in
  print)
    case "$st" in
      gone) echo "Could not find service \\"com.opscontext.mcp\\" in domain for user gui: 501" >&2; exit 113 ;;
      teardown:0) echo gone > "$S"; echo "Could not find service" >&2; exit 113 ;;
      teardown:*) n=\${st#teardown:}; echo "teardown:$((n - 1))" > "$S"; printf '\\tstate = not running\\n'; exit 0 ;;
      running) printf '\\tstate = running\\n\\tpid = ${AGENT_PID}\\n\\tlast exit code = (never exited)\\n\\t\\tstate = active\\n'; exit 0 ;;
      crashed) printf '\\tstate = not running\\n\\tlast exit code = 1\\n'; exit 0 ;;
    esac ;;
  bootout)
    if [ "$st" = gone ]; then exit 3; fi
    echo "teardown:${fake.teardownPrints}" > "$S"; exit 0 ;;
  bootstrap)
    if [ "$st" != gone ]; then echo "Bootstrap failed: 5: Input/output error" >&2; exit 5; fi
    echo "${fake.agent === "crashes" ? "crashed" : "running"}" > "$S"; exit 0 ;;
esac
exit 0
`,
  );
  // lsof -t: the pid holding :7842. A chat server holds it until the new agent runs and takes it.
  const holder = fake.agent === "takes-port" ? `[ "$(cat '${state}')" = running ] && h=${AGENT_PID} || h=${CHAT_PID}` : `h=${CHAT_PID}`;
  writeFileSync(
    join(shims, "lsof"),
    `#!/bin/sh
echo "lsof $*" >> '${log}'
${holder}
case " $* " in *" -t "*) echo "$h" ;; esac
exit 0
`,
  );
  for (const n of ["launchctl", "lsof"]) chmodSync(join(shims, n), 0o755);
  const env = {
    HOME: home,
    PATH: `${shims}:${dirname(process.execPath)}:/usr/bin:/bin`,
    CONTEXTENGINE_HOME: join(home, ".contextengine"),
    TMPDIR: root,
    OPSCONTEXT_AUTOSTART_WAIT_SECONDS: "2",
  };
  // Guard: the fake launchctl must be the one found, or the test would stop the real agent.
  expect(execFileSync("/bin/sh", ["-c", "command -v launchctl"], { env, encoding: "utf8" }).trim()).toBe(join(shims, "launchctl"));
  const cli = join(process.cwd(), "dist", "cli.js");
  const r = spawnSync(process.execPath, [cli, "install-autostart", "--entry", cli], { cwd: root, env, encoding: "utf8", timeout: 60_000 });
  const calls = existsSync(log) ? readFileSync(log, "utf8").trim().split("\n") : [];
  rmSync(root, { recursive: true, force: true });
  return { status: r.status, out: r.stdout + r.stderr, calls: calls.filter((c) => c.startsWith("launchctl")).map((c) => c.slice(10)) };
}

describe.skipIf(process.platform !== "darwin")("install-autostart waits for launchd", () => {
  it("starts the new agent only once launchd has finished removing the old one", () => {
    const r = run({ start: "running", teardownPrints: 3, agent: "takes-port" });
    expect(r.status, r.out).toBe(0);
    const out = r.calls.indexOf("bootout");
    const boot = r.calls.indexOf("bootstrap");
    expect(out).toBeGreaterThanOrEqual(0);
    expect(boot).toBeGreaterThan(out);
    expect(r.calls.filter((c) => c === "bootstrap")).toHaveLength(1);
    // Every print between bootout and bootstrap was spent waiting: at least the four the fake needs.
    expect(r.calls.slice(out + 1, boot).filter((c) => c === "print").length).toBeGreaterThanOrEqual(4);
    expect(r.out).toContain(`pid ${AGENT_PID}`);
  });

  it("does not start anything, and says what to run, when the old agent never goes away", () => {
    const r = run({ start: "running", teardownPrints: 1000, agent: "takes-port" });
    expect(r.status, r.out).toBe(1);
    expect(r.calls).not.toContain("bootstrap");
    expect(r.out).toContain("launchctl bootstrap gui/");
  });

  it("fails when launchd does not keep the agent running, even though something holds the port", () => {
    const r = run({ start: "gone", teardownPrints: 0, agent: "crashes" });
    expect(r.status, r.out).toBe(1);
    expect(r.out).not.toMatch(/now running as a LaunchAgent/);
    expect(r.out).toContain("last exit code 1");
  });

  it("warns, without failing, while the port is still with a chat server", () => {
    const r = run({ start: "gone", teardownPrints: 0, agent: "port-stays-with-chat" });
    expect(r.status, r.out).toBe(0);
    expect(r.out).toContain(`pid ${CHAT_PID}`);
    expect(r.out).not.toMatch(/now running as a LaunchAgent/);
  });
});
