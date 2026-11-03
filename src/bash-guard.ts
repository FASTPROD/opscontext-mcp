// [LOCKED] [BASH-GUARD-REFUSES-BEFORE-IT-RUNS] - 2026-11-02
// [NEVER] turn one of the four refusals into a warning, make the guard fail open on input it
//         cannot read, or let it run any part of the command to decide (it reads text only).
// WHY: each refusal is an incident. rsync --delete and scp -r against a shared server: a wrong
//      target empties or overwrites a sibling site (compR.fr lost its .htaccess in 2025; the fleet
//      rule since 2026-06-25). A script started by a relative path: the tool's working folder
//      silently reverts between calls, and on 2026-08-16 a bare ./deploy.sh ran another project's
//      deploy script against the wrong server, harmless by luck. github.com in a command's allowed
//      sites: GitHub is reached from the owner's own terminal only, so the agent can never push,
//      delete or rewrite a branch with the owner's stored credentials. Text rules in CLAUDE.md
//      asked for all four and were broken anyway; only a hook that answers before the tool runs
//      is a rule.
// FIX: a Claude Code PreToolUse hook on Bash (install-claude-hook --guard) runs this module on
//      the tool call's JSON. It splits the command line into segments at && || | ; & and newlines
//      outside quotes, reads each segment as words the way the shell does, looks through sudo,
//      env, ssh, bash -c and eval, and answers a deny with the reason, or nothing. A cd or pushd
//      to an absolute folder earlier on the same line anchors the relative scripts after it
//      (a terminal accepts cd /absolute/path && ./script args; a Claude Code chat needs the full path, see
//      [CLAUDE-CODE-STRIPS-CD-TO-CWD] below). Command substitution ($(...))
//      is read as plain text. Tests: tests/bash-guard.test.ts.

export interface GuardInput {
  tool_name?: unknown;
  tool_input?: unknown;
  /** Claude Code sends the folder the command runs in; it is named in a refusal, never trusted as an anchor. */
  cwd?: unknown;
}

export const GUARD_REASONS = {
  rsync:
    "rsync --delete is refused before it runs: a wrong target empties everything else at the destination (a sibling site on a shared server). Use the project's deploy script (a whitelist of files, a dry run, a snapshot, a live check), never a mirror. If this is really wanted, the owner runs it in their own terminal.",
  scp:
    "scp -r is refused before it runs: a tree copied into a shared folder overwrites what is there. Copy files by name, or use the project's deploy script. If this is really wanted, the owner runs it in their own terminal.",
  script:
    "a script started by a relative path is refused: the shell's folder is not reliable between tool calls, and the wrong project's deploy script has run that way. Give the script's full path (cd /absolute/path && /absolute/path/script args): Claude Code removes a leading cd to the current folder before the guard sees the command, so that cd alone is not enough.",
  github:
    "github.com is refused in the allowed sites of a command: GitHub is reached from the owner's own terminal only (git push, gh). Commit, and the owner publishes.",
} as const;

/** Drop the body lines of every heredoc (<<EOF, <<'EOF', <<-EOF): they are text, not commands.
 *  The rest of the line that opens one is still a command. A here-string (<<<) is left alone. */
export function stripHeredocs(command: string): string {
  const lines = command.split("\n");
  const out: string[] = [];
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    out.push(line);
    const m = /(?<!<)<<(?!<)(-?)\s*(?:'([^']+)'|"([^"]+)"|([A-Za-z_][\w-]*))/.exec(line);
    if (!m) continue;
    const delimiter = m[2] ?? m[3] ?? m[4];
    const dash = m[1] === "-";
    i++;
    while (i < lines.length && (dash ? lines[i].replace(/^\t+/, "") : lines[i]) !== delimiter) i++;
  }
  return out.join("\n");
}

export interface Segment {
  text: string;
  /** How many $(...), `...` or (subshells) enclose it: a cd inside one ends with it. */
  depth: number;
  /** The innermost of those, numbered in order of opening (0 at the top level), so two siblings
   *  at the same depth are told apart. */
  scope: number;
}

/** Split a command line at && || | ; & and newlines outside quotes. A $(...), a `...` and a
 *  (subshell) are segments of their own, one level deeper, also inside double quotes.
 *  `2>&1` and `&>` stay whole. */
export function shellSegments(command: string): Segment[] {
  const out: Segment[] = [];
  let cur = "";
  // What we are inside of, innermost last: a quote, a command substitution, a backtick, a subshell.
  const stack: Array<{ kind: "'" | '"' | "$(" | "`" | "("; id: number }> = [];
  let opened = 0;
  const top = () => stack[stack.length - 1]?.kind;
  const push = (kind: "'" | '"' | "$(" | "`" | "(") => stack.push({ kind, id: kind === "'" || kind === '"' ? 0 : ++opened });
  const frames = () => stack.filter((f) => f.kind !== "'" && f.kind !== '"');
  const cut = () => {
    const f = frames();
    out.push({ text: cur, depth: f.length, scope: f[f.length - 1]?.id ?? 0 });
    cur = "";
  };
  for (let i = 0; i < command.length; i++) {
    const ch = command[i];
    const inside = top();
    if (inside === "'") {
      cur += ch;
      if (ch === "'") stack.pop();
      continue;
    }
    if (inside === '"') {
      if (ch === "\\" && i + 1 < command.length) {
        cur += ch + command[++i];
      } else if (ch === "$" && command[i + 1] === "(") {
        cut();
        push("$(");
        i++;
      } else if (ch === "`") {
        cut();
        push("`");
      } else {
        cur += ch;
        if (ch === '"') stack.pop();
      }
      continue;
    }
    // Outside quotes (at the top level, inside a $(...), a `...` or a subshell).
    if (ch === "\\" && i + 1 < command.length) {
      cur += ch + command[++i];
      continue;
    }
    if (ch === "'" || ch === '"') {
      push(ch);
      cur += ch;
      continue;
    }
    if (ch === "$" && command[i + 1] === "(") {
      cut();
      push("$(");
      i++;
      continue;
    }
    if (ch === "`") {
      cut();
      if (inside === "`") stack.pop();
      else push("`");
      continue;
    }
    if (ch === "(") {
      cut();
      push("(");
      continue;
    }
    if (ch === ")") {
      cut();
      if (inside === "$(" || inside === "(") stack.pop();
      continue;
    }
    if (ch === "&" && (cur.endsWith(">") || cur.endsWith("<") || command[i + 1] === ">")) {
      cur += ch;
      continue;
    }
    if (ch === "\n" || ch === ";" || ch === "|" || ch === "&") {
      if ((ch === "&" || ch === "|") && command[i + 1] === ch) i++;
      cut();
      continue;
    }
    cur += ch;
  }
  cut();
  return out.map((s) => ({ ...s, text: s.text.trim() })).filter((s) => s.text);
}

/** The words of one segment, quotes removed the way the shell removes them. */
export function shellWords(segment: string): string[] {
  const words: string[] = [];
  let cur = "";
  let has = false;
  let quote: "'" | '"' | null = null;
  const flush = () => {
    if (has) words.push(cur);
    cur = "";
    has = false;
  };
  for (let i = 0; i < segment.length; i++) {
    const ch = segment[i];
    if (quote) {
      if (ch === quote) quote = null;
      else if (quote === '"' && ch === "\\" && i + 1 < segment.length) cur += segment[++i];
      else cur += ch;
      continue;
    }
    if (ch === "\\" && i + 1 < segment.length) {
      cur += segment[++i];
      has = true;
      continue;
    }
    if (ch === "'" || ch === '"') {
      quote = ch;
      has = true;
      continue;
    }
    if (/\s/.test(ch)) {
      flush();
      continue;
    }
    cur += ch;
    has = true;
  }
  flush();
  return words;
}

const basename = (word: string): string => word.slice(word.lastIndexOf("/") + 1);
const isAbsolute = (word: string): boolean => /^[/~$]/.test(word);

/** Programs that only wrap the real one. The options listed take an argument. */
const WRAPPERS: Record<string, string[]> = {
  sudo: ["-u", "-g", "-p", "-C", "-D", "-h", "-r", "-t", "-T", "-U"],
  doas: ["-u", "-C"],
  env: ["-u", "-C", "-S"],
  nice: ["-n"],
  nohup: [],
  time: [],
  command: [],
  exec: [],
  builtin: [],
  caffeinate: ["-t", "-w"],
  timeout: ["-k", "-s"],
  xargs: ["-I", "-n", "-P", "-L", "-s", "-E", "-d", "-a", "-J", "-R"],
};
const SHELLS = new Set(["sh", "bash", "zsh", "dash", "ksh", "fish"]);
const INTERPRETERS = new Set([...SHELLS, "source", ".", "node", "deno", "bun", "python", "python2", "python3", "perl", "ruby", "php", "osascript"]);
/** Interpreter options that mean "run this text", not a file. */
const INLINE_FLAGS = new Set(["-c", "-e", "-p", "-m", "-r", "-i"]);
const SCRIPT_EXT = /\.(?:sh|bash|zsh|ksh|mjs|cjs|js|ts|py|pl|rb|php|scpt|applescript)$/i;
/** ssh options that take an argument (the host is the first word that is not one). */
const SSH_ARG_OPTS = new Set(["-b", "-c", "-D", "-E", "-e", "-F", "-I", "-i", "-J", "-L", "-l", "-m", "-O", "-o", "-p", "-Q", "-R", "-S", "-W", "-w", "-B", "-P"]);
/** scp single-letter options that take an argument: the letters after them in a cluster are that argument. */
const SCP_ARG_LETTERS = "cFiJloPS";

/** A path to a script that is not absolute: ./x, ../x, scripts/x, or (via an interpreter) x.sh. */
function isRelativeScript(word: string, viaInterpreter: boolean): boolean {
  if (!word || isAbsolute(word)) return false;
  if (word.includes("/")) return true;
  return viaInterpreter && SCRIPT_EXT.test(word);
}

/** The file an interpreter is asked to run, or null for inline code, a module, or no file. */
function scriptArgument(args: string[]): string | null {
  for (const a of args) {
    if (INLINE_FLAGS.has(a)) return null;
    if (a === "--") continue;
    if (a.startsWith("-")) continue;
    return a;
  }
  return null;
}

function rsyncDeletes(args: string[]): boolean {
  return args.some((a) => /^--del(?:ete)?(?:-[a-z-]+)?$/.test(a));
}

function scpRecursive(args: string[]): boolean {
  for (const a of args) {
    if (a === "--") return false;
    if (!a.startsWith("-") || a.startsWith("--")) continue;
    for (const letter of a.slice(1)) {
      if (letter === "r") return true;
      if (SCP_ARG_LETTERS.includes(letter)) break;
    }
  }
  return false;
}

/** The command ssh is asked to run on the host, or null for an interactive ssh. */
function sshRemoteCommand(args: string[]): string | null {
  let i = 0;
  while (i < args.length && args[i].startsWith("-")) {
    if (SSH_ARG_OPTS.has(args[i]) && args[i].length === 2) i++;
    i++;
  }
  const rest = args.slice(i + 1); // after the host
  return rest.length > 0 ? rest.join(" ") : null;
}

interface Step {
  reason: string | null;
  /** A cd or pushd to an absolute folder has run earlier on this line. */
  anchored: boolean;
}

function guardWords(words: string[], anchored: boolean): Step {
  let i = 0;
  while (i < words.length) {
    const w = words[i];
    if (w === "--" || /^[A-Za-z_][A-Za-z0-9_]*=/.test(w)) {
      i++;
      continue;
    }
    const wrap = WRAPPERS[basename(w)];
    if (!wrap) break;
    i++;
    if (basename(w) === "timeout") {
      while (i < words.length && words[i].startsWith("-")) i += wrap.includes(words[i]) ? 2 : 1;
      i++; // the duration
      continue;
    }
    while (i < words.length && words[i].startsWith("-")) i += wrap.includes(words[i]) ? 2 : 1;
  }
  if (i >= words.length) return { reason: null, anchored };
  const prog = words[i];
  const base = basename(prog);
  const args = words.slice(i + 1);
  const ok: Step = { reason: null, anchored };

  if (base === "cd" || base === "pushd") {
    const target = args.find((a) => !a.startsWith("-") || a === "-");
    if (target === undefined) return { reason: null, anchored: true }; // cd alone: the home folder
    if (target === "-") return ok; // the previous folder: unknown, keeps what was known
    return { reason: null, anchored: anchored || isAbsolute(target) };
  }
  if (base === "rsync") return rsyncDeletes(args) ? { reason: GUARD_REASONS.rsync, anchored } : ok;
  if (base === "scp") return scpRecursive(args) ? { reason: GUARD_REASONS.scp, anchored } : ok;
  if (base === "ssh") {
    const remote = sshRemoteCommand(args);
    const reason = remote ? guardCommand(remote) : null;
    return reason ? { reason, anchored } : ok;
  }
  if (base === "eval") {
    const reason = guardCommand(args.join(" "));
    return reason ? { reason, anchored } : ok;
  }
  if (SHELLS.has(base)) {
    const c = args.indexOf("-c");
    if (c >= 0) {
      const reason = args[c + 1] ? guardCommand(args[c + 1]) : null;
      return reason ? { reason, anchored } : ok;
    }
  }
  if (!anchored) {
    if (isRelativeScript(prog, false)) return { reason: GUARD_REASONS.script, anchored };
    if (INTERPRETERS.has(base)) {
      const file = scriptArgument(args);
      if (file && isRelativeScript(file, true)) return { reason: GUARD_REASONS.script, anchored };
    }
  }
  return ok;
}

/** The reason a command line is refused, or null when it may run. Text only: nothing is executed. */
// [LOCKED] [CLAUDE-CODE-STRIPS-CD-TO-CWD] - 2026-11-02
// [NEVER] treat the hook's cwd as an anchor for a relative script, or stop naming it in the refusal
// WHY: measured 2026-11-02 with the hook's stdin logged: `cd /Users/yan/Projects/ContextEngine &&
//      node dist/cli.js x`, sent from a chat whose folder is that one, reached the hook as
//      `node dist/cli.js x` with the folder in the JSON as cwd (Claude Code removes a leading cd to
//      its current folder). The guard cannot tell that from a bare `./deploy.sh`, the exact shape of
//      the 2026-08-16 incident, so it refuses both; a cwd anchor would let every bare script through.
// FIX: refuse, name the folder the script would run in (the hook's cwd) and ask for the full path,
//      cd /abs && /abs/script args. One retry fixes it, and the agent has read where it would have run.
export function guardCommand(command: string, cwd?: string): string | null {
  // One "anchored" flag per nesting level: a deeper level starts with its parent's, and what a
  // cd does inside a $(...) or a (subshell) is forgotten when it closes (a sibling that opens
  // next at the same depth has another scope id and starts from the parent again).
  const levels: Array<{ scope: number; anchored: boolean }> = [{ scope: 0, anchored: false }];
  for (const { text, depth, scope } of shellSegments(stripHeredocs(command))) {
    while (levels.length - 1 > depth) levels.pop();
    while (levels.length - 1 < depth) levels.push({ scope, anchored: levels[levels.length - 1].anchored });
    if (levels[depth].scope !== scope) levels[depth] = { scope, anchored: depth === 0 ? false : levels[depth - 1].anchored };
    const words = shellWords(text.replace(/^\{\s*/, "").replace(/\s*\}$/, ""));
    if (words.length === 0) continue;
    const step = guardWords(words, levels[depth].anchored);
    if (step.reason === GUARD_REASONS.script && cwd) return `${step.reason} Here it would run in ${cwd}.`;
    if (step.reason) return step.reason;
    levels[depth].anchored = step.anchored;
  }
  return null;
}

/** The reason an allowed_domains list is refused (github.com or one of its subdomains), or null. */
export function guardAllowedDomains(domains: unknown): string | null {
  if (!Array.isArray(domains)) return null;
  for (const d of domains) {
    if (typeof d !== "string") continue;
    const host = d.trim().toLowerCase().replace(/^\*\.?/, "").replace(/:\d+$/, "").replace(/\.$/, "");
    if (host === "github.com" || host.endsWith(".github.com")) return GUARD_REASONS.github;
  }
  return null;
}

/** The verdict on one tool call: the command's refusal first, then the sites'. null = may run. */
export function guardVerdict(input: GuardInput): string | null {
  if (input.tool_name !== "Bash") return null;
  const ti = input.tool_input && typeof input.tool_input === "object" ? (input.tool_input as Record<string, unknown>) : {};
  const cwd = typeof input.cwd === "string" && input.cwd ? input.cwd : undefined;
  const fromCommand = typeof ti.command === "string" ? guardCommand(ti.command, cwd) : null;
  return fromCommand ?? guardAllowedDomains(ti.allowed_domains);
}

const deny = (reason: string): string =>
  JSON.stringify({ hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: "deny", permissionDecisionReason: reason } });

/** The hook body: the PreToolUse JSON in, a deny JSON line out, or "" when the call may run.
 *  Input it cannot read is refused too (a guard that fails open is not one). */
export function guardHookOutput(stdinText: string): string {
  let parsed: unknown;
  try {
    parsed = JSON.parse(stdinText);
  } catch {
    parsed = null;
  }
  if (!parsed || typeof parsed !== "object") {
    return deny("the Bash guard could not read the tool call (not the JSON Claude Code sends to a PreToolUse hook): refusing until it can. contextengine bash-guard --help");
  }
  const reason = guardVerdict(parsed as GuardInput);
  return reason ? deny(reason) : "";
}

export const BASH_GUARD_USAGE = `Usage: contextengine bash-guard [--check "<command>"]

The body of a Claude Code PreToolUse hook on Bash (installed by: contextengine install-claude-hook --guard).
Reads the tool call as JSON on stdin and refuses, before it runs:
  - rsync with --delete (any spelling), also behind sudo, ssh, bash -c or a cd
  - scp -r (alone or in a cluster such as -rp)
  - a script started by a relative path (./x.sh, bash x.sh, scripts/x.sh) unless the same line
    first runs cd /absolute/folder; the full path is always accepted
  - github.com, or one of its subdomains, in the command's allowed sites (allowed_domains)
A refusal is a JSON deny with the reason on stdout, exit 0; an allowed call prints nothing.
Input that is not JSON is refused too: the guard never fails open.

  --check "<command>"   Prints the verdict for one command line and exits 2 when refused, 0 when allowed.
`;

async function readStdin(): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const c of process.stdin) chunks.push(c as Buffer);
  return Buffer.concat(chunks).toString("utf8");
}

/* eslint-disable no-console -- a CLI command and a hook body: stdout is the answer, never the MCP stream */
export async function cliBashGuard(args: string[]): Promise<void> {
  if (args.includes("-h") || args.includes("--help")) {
    console.log(BASH_GUARD_USAGE);
    return;
  }
  const check = args.indexOf("--check");
  if (check >= 0) {
    const command = args[check + 1];
    if (command === undefined) {
      console.error('--check needs a command line in quotes: contextengine bash-guard --check "rsync -a --delete a b"');
      process.exit(1);
    }
    const reason = guardCommand(command);
    console.log(reason ? `refused: ${reason}` : "allowed");
    process.exit(reason ? 2 : 0);
  }
  const out = guardHookOutput(await readStdin());
  if (out) console.log(out);
  process.exit(0);
}
/* eslint-enable no-console */
