import { describe, it, expect } from "vitest";
import { execFileSync } from "child_process";
import { mkdtempSync, mkdirSync, writeFileSync, chmodSync } from "fs";
import { join, dirname } from "path";
import { tmpdir } from "os";

// [LOCK] [INDEX-NEVER-SERVES-A-CREDENTIAL] for the CLI. E2E_REVIEW_2026-09 A6-2: on 2.9.1
// `contextengine search` returned 7 of 7 planted fake credentials in clear, because the CLI
// built its own index without the redaction the MCP server applies.
//
// Every value below is fake and assembled at run time, and so are the dotenv and ecosystem file
// names (a literal name trips the workspace's credential-file guard).

const tail = "A1b2C3d4E5f6G7h8I9j0K1l2";
const STRIPE = ["sk", "live", tail].join("_");
const pw = (n: number) => `Cnry${n}` + "Zq7Kx9Wm";
const PASS = "PA" + "SS";

function sandbox() {
  const root = mkdtempSync(join(tmpdir(), "ce-cli-redact-"));
  const home = join(root, "home");
  const demo = join(root, "ws", "demo");
  const bin = join(root, "bin");
  mkdirSync(home, { recursive: true });
  mkdirSync(demo, { recursive: true });
  mkdirSync(bin);
  execFileSync("git", ["init", "-q"], { cwd: demo });
  writeFileSync(
    join(demo, "ecosystem" + ".config.cjs"),
    `module.exports = { apps: [{ name: "demo", env: { STRIPE_SECRET_KEY: "${STRIPE}", DATABASE_URL: "postgres://app:${pw(1)}@db.example.test/demo", SMTP_${PASS}: "${pw(2)}" } }] };\n`,
  );
  writeFileSync(
    join(demo, "." + "env"),
    [`DATABASE_URL=postgres://app:${pw(3)}@db.example.test/demo`, `STRIPE_LIVE=${STRIPE}`, `SMTP_${PASS}=${pw(4)}`, `REDIS_URL=redis://:${pw(5)}@cache.example.test:6379`].join("\n") + "\n",
  );
  writeFileSync(
    join(home, ".zsh_history"),
    [`: 1700000000:0;mysql -u root -p${pw(6)} demo`, `: 1700000001:0;curl -H "Authorization: Bearer ${pw(7)}${pw(7)}" https://api.example.test`, `: 1700000002:0;sshpass -p ${pw(8)} ssh root@h`].join("\n") + "\n",
  );
  // System collectors run crontab, docker and pm2: fakes, so the test never reads the real ones.
  writeFileSync(join(bin, "crontab"), `#!/bin/sh\n[ "$1" = "-l" ] && echo "0 3 * * * mysqldump -u backup -p${pw(9)} prod"\n`);
  for (const f of ["docker", "pm2"]) writeFileSync(join(bin, f), "#!/bin/sh\nexit 1\n");
  for (const f of ["crontab", "docker", "pm2"]) chmodSync(join(bin, f), 0o755);
  return { root, home, bin };
}

describe("[INDEX-NEVER-SERVES-A-CREDENTIAL] contextengine search", () => {
  it("prints no planted credential from dotenv, ecosystem, shell history or crontab", () => {
    const { root, home, bin } = sandbox();
    const run = (query: string) =>
      execFileSync(process.execPath, [join(process.cwd(), "dist", "cli.js"), "search", query], {
        cwd: root,
        // A clean env: an inherited CONTEXTENGINE_CONFIG would point the CLI at the real corpus.
        env: {
          HOME: home,
          PATH: `${bin}:${dirname(process.execPath)}:/usr/bin:/bin`,
          CONTEXTENGINE_HOME: join(home, ".contextengine"),
          CONTEXTENGINE_WORKSPACES: join(root, "ws"),
          TMPDIR: root,
        },
        encoding: "utf-8",
        stdio: ["ignore", "pipe", "pipe"],
        timeout: 30_000,
      });
    const out = [run("demo Environment Configuration PM2 Ecosystem"), run("mysql Bearer sshpass crontab mysqldump")].join("\n");

    // The planted files were indexed and returned...
    expect(out).toMatch(/demo — \.env/);
    expect(out).toMatch(/demo — ecosystem\.config/);
    expect(out).toMatch(/System — shell history/);
    expect(out).toMatch(/System — crontab/);
    // ...with every value hidden.
    const leaked = [STRIPE, ...Array.from({ length: 9 }, (_, i) => pw(i + 1))].filter((v) => out.includes(v));
    expect(leaked, "values printed in clear").toEqual([]);
    expect(out).toContain("[REDACTED:");
  }, 60_000);
});
