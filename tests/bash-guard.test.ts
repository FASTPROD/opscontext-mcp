// The Bash guard: a Claude Code PreToolUse hook that refuses, before it runs, the four commands
// that have cost the fleet the most (see src/bash-guard.ts). Pure functions: no shell is run here.
import { describe, it, expect } from "vitest";
import { guardCommand, guardAllowedDomains, guardVerdict, guardHookOutput } from "../src/bash-guard.js";

const refused = (command: string, why: RegExp) => {
  const reason = guardCommand(command);
  expect(reason, command).not.toBeNull();
  expect(reason, command).toMatch(why);
};
const allowed = (command: string) => expect(guardCommand(command), command).toBeNull();

describe("guardCommand: rsync --delete", () => {
  it("refuses every spelling of a deleting rsync, also behind sudo, a full path, ssh or a cd", () => {
    for (const c of [
      "rsync -av --delete /src/ host:/var/www/site/",
      "rsync -a --delete-after a b",
      "rsync -a --delete-excluded a b",
      "rsync --del a b",
      "sudo rsync -a --delete a b",
      "/usr/bin/rsync -a --delete a b",
      "ssh box 'rsync -a --delete /a/ /b/'",
      'ssh -p 22 user@box "cd /var/www && rsync -a --delete /a/ /b/"',
      "cd /Users/yan/Projects/x && rsync -a --delete . host:/var/www/",
      "ls && rsync -a --delete a b",
      "bash -c 'rsync -a --delete a b'",
    ]) refused(c, /rsync --delete is refused/);
  });

  it("lets an rsync without --delete, a dry run, and the words inside a commit message or an echo through", () => {
    for (const c of [
      "rsync -av /src/ host:/dst/",
      "rsync -n -av --dry-run a b",
      'git commit -m "guard: refuse rsync --delete before it runs"',
      'echo "rsync --delete is refused"',
      'grep -rn "rsync --delete" docs/',
    ]) allowed(c);
  });
});

describe("guardCommand: scp -r", () => {
  it("refuses a recursive scp, the flag alone or inside a cluster, also behind ssh", () => {
    for (const c of [
      "scp -r dist/ host:/var/www/site/",
      "scp -rp dir host:",
      "scp -pr dir host:",
      "scp -P 22 -r dir host:",
      "sudo scp -r dir host:",
      "ssh box 'scp -r a b'",
    ]) refused(c, /scp -r is refused/);
  });

  it("lets a single-file scp through, and a letter r that is the argument of another flag", () => {
    for (const c of [
      "scp file.txt host:/tmp/",
      "scp -i ~/.ssh/key file host:",
      "scp -P 22 file host:",
      "scp -oProxyCommand=corkscrew file host:",
      "scp -o ProxyCommand=rr file host:",
      'echo "scp -r x y"',
    ]) allowed(c);
  });
});

describe("guardCommand: a script started without its full path", () => {
  it("refuses a relative script, with or without an interpreter, unless the same line first cd's to an absolute folder", () => {
    for (const c of [
      "./deploy.sh backend",
      "bash deploy.sh",
      "sh scripts/deploy.sh --check",
      "scripts/deploy.sh",
      "../other/run.sh",
      "cd scripts && ./deploy.sh",
      "python3 tools/x.py",
      "node scripts/x.mjs",
      "source ./env.sh",
      ". ./env.sh",
      "ls; ./deploy.sh",
      "./deploy.sh | tee out.log",
      "ssh box './deploy.sh'",
    ]) refused(c, /relative path is refused/);
  });

  it("lets a full path, an anchored cd, inline code, modules and plain programs through", () => {
    for (const c of [
      "/Users/yan/Projects/x/deploy.sh --check",
      "~/bin/x.sh",
      "$HOME/bin/x.sh",
      'node "$TMPDIR/run.mjs" arg',
      "cd /Users/yan/Projects/x && ./deploy.sh backend",
      "cd ~/Projects/x && bash scripts/d.sh",
      "(cd /abs && ./x.sh)",
      'cd "$HOME/Projects/x" && ./x.sh',
      "cd /abs; ./x.sh",
      "pushd /abs && ./x.sh",
      "cd /abs && cd sub && ./x.sh",
      "npm run build",
      "npx vitest run tests/x.test.ts",
      "ls scripts/",
      "cat scripts/deploy.sh",
      "bash -c 'ls -la'",
      'python3 -c "print(1)"',
      'node -e "1"',
      "python3 -m pytest",
      "git status",
      "bash --version",
    ]) allowed(c);
  });
});

// The attacking pass of 2026-11-02: wrappers and contexts the first write looked through.
describe("guardCommand: where a command hides", () => {
  it("looks through a -- after the host, xargs, command substitution and backticks", () => {
    for (const c of [
      "ssh box -- rsync -a --delete a b",
      "find . -name x | xargs rsync -a --delete",
      "xargs -I {} scp -r {} host:",
      "echo $(rsync -a --delete a b)",
      "out=`./deploy.sh`",
      "echo $(cd /abs && ./x.sh) $(./y.sh)",
    ]) refused(c, /is refused/);
    allowed("echo $(cd /abs && ./x.sh)");
  });

  it("reads a heredoc body as text, so a document line is not a command", () => {
    for (const c of [
      "cat > notes.md <<'EOF'\n./deploy.sh backend\nrsync -a --delete a b\nEOF",
      'git commit -F - <<EOF\nfix: ./deploy.sh ran from the wrong folder\nscp -r never again\nEOF',
      "cat <<-X\n\t./x.sh\n\tX",
    ]) allowed(c);
    refused("cat > f <<'EOF'\n./x.sh\nEOF\n./deploy.sh", /relative path is refused/); // after the body, a command again
    refused("cat <<EOF > f && rsync -a --delete a b\nhello\nEOF", /rsync --delete is refused/); // the rest of the opening line is still a command
    refused("cat <<EOF\nhello\nEOF\nrsync -a --delete a b", /rsync --delete is refused/);
    allowed("(cd /abs && ./x.sh)");
    refused("(cd /abs && ./x.sh); ./y.sh", /relative path is refused/); // the subshell's cd ends with it
  });
});

describe("guardAllowedDomains", () => {
  it("refuses github.com, its subdomains, a wildcard, a port and any letter case", () => {
    for (const d of [["github.com"], ["api.github.com"], ["*.github.com"], ["GitHub.com:443"], [" github.com. "], ["registry.npmjs.org", "github.com"]]) {
      expect(guardAllowedDomains(d), d.join(",")).toMatch(/github\.com is refused/);
    }
  });
  it("lets other sites, a look-alike and an absent list through", () => {
    for (const d of [["registry.npmjs.org"], ["notgithub.com"], ["github.community"], [], undefined, "github.com"]) {
      expect(guardAllowedDomains(d), JSON.stringify(d)).toBeNull();
    }
  });
});

describe("the hook body", () => {
  const deny = (text: string) => JSON.parse(text).hookSpecificOutput as { hookEventName: string; permissionDecision: string; permissionDecisionReason: string };

  it("prints a PreToolUse deny with the reason for a refused Bash call, and nothing for an allowed one", () => {
    const out = guardHookOutput(JSON.stringify({ tool_name: "Bash", tool_input: { command: "scp -r a host:/b" } }));
    expect(deny(out)).toMatchObject({ hookEventName: "PreToolUse", permissionDecision: "deny" });
    expect(deny(out).permissionDecisionReason).toMatch(/scp -r is refused/);
    expect(guardHookOutput(JSON.stringify({ tool_name: "Bash", tool_input: { command: "git status" } }))).toBe("");
    expect(guardHookOutput(JSON.stringify({ tool_name: "Bash", tool_input: { command: "git status", allowed_domains: ["github.com"] } }))).toMatch(/github\.com is refused/);
  });

  it("ignores another tool and fails closed on input it cannot read", () => {
    expect(guardHookOutput(JSON.stringify({ tool_name: "Read", tool_input: { file_path: "./deploy.sh" } }))).toBe("");
    expect(deny(guardHookOutput("not json")).permissionDecisionReason).toMatch(/could not read/);
    expect(deny(guardHookOutput("")).permissionDecisionReason).toMatch(/could not read/);
  });

  it("names the folder a relative script would run in, and says that a cd to the current folder is not enough", () => {
    // Measured 2026-11-02 with the hook input logged: `cd /Users/yan/Projects/ContextEngine && node dist/cli.js x`,
    // sent from a chat whose folder is /Users/yan/Projects/ContextEngine, reached the hook as `node dist/cli.js x`
    // with the folder in the JSON as cwd: Claude Code removes a leading cd to its current folder. The guard
    // cannot tell that from a bare `./deploy.sh` (the incident), so it refuses both, names the folder and
    // asks for the full path.
    const out = deny(guardHookOutput(JSON.stringify({ tool_name: "Bash", cwd: "/Users/me/Projects/FC_project", tool_input: { command: "./deploy.sh backend" } })));
    expect(out.permissionDecisionReason).toMatch(/would run in \/Users\/me\/Projects\/FC_project\b/);
    expect(out.permissionDecisionReason).toMatch(/full path/);
    expect(out.permissionDecisionReason).toMatch(/Claude Code removes a leading cd to the current folder/);
    // Without a cwd (the --check mode), no folder is named: nothing is invented.
    expect(guardCommand("./deploy.sh backend")).not.toMatch(/would run in/);
    expect(guardCommand("./deploy.sh backend")).toMatch(/full path/);
    // A cwd that is not a string is ignored, never printed.
    expect(guardVerdict({ tool_name: "Bash", cwd: 42, tool_input: { command: "./deploy.sh" } })).not.toMatch(/would run in/);
  });

  it("guardVerdict reports the first refusal: the command before the sites", () => {
    expect(guardVerdict({ tool_name: "Bash", tool_input: { command: "./x.sh", allowed_domains: ["github.com"] } })).toMatch(/relative path is refused/);
    expect(guardVerdict({ tool_name: "Bash", tool_input: { command: 1 } })).toBeNull();
  });
});
