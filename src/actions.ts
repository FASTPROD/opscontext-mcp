// `contextengine actions`: the owner's action points, across every saved session. Each chat ends
// with things the owner does (a command to run, a date to watch, a word to give); they used to live
// in the chat's last message, in a PROMPT_*.md and in the chat's session, project by project, and
// nothing showed them together. The convention (docs/AGENT_RULES_CE.md § 5): a session key
// `actions`, one line per action, `YYYY-MM-DD | open | <project> | <what the owner does>`, `done`
// once the owner says so. Read-only: the sessions folder is read, never created or written; no
// network. [LOCK] [EXEC-FAILURE-IS-NOT-EMPTY] (src/sessions.ts): a session file that does not parse
// is named in the report, never skipped in silence; so is a line that is not in the convention.
import { existsSync, readdirSync, readFileSync } from "fs";
import { join } from "path";
import { sessionsDir } from "./ce-home.js";
import { formatLearnedAt } from "./learnings.js";
import type { Session } from "./sessions.js";

export type ActionState = "open" | "done";

export interface ActionLine {
  date: string;
  state: ActionState;
  project: string;
  what: string;
  /** The session the line was read from. */
  session: string;
  /** When the `actions` entry was last saved (the entry's timestamp, ISO). */
  timestamp: string;
}

export interface ActionsOptions {
  /** Include the done lines. */
  all: boolean;
  /** Keep the lines dated at or after this day (YYYY-MM-DD). */
  since: string | undefined;
  /** Keep one project (compared with case and punctuation folded: admin-CROWLR is admin.CROWLR). */
  project: string | undefined;
}

export interface ActionsReport {
  /** Session files found, readable or not. */
  sessions: number;
  /** The lines that passed the filters, oldest date first. */
  actions: ActionLine[];
  /** Done lines left out because `all` was off (after the other filters). */
  hiddenDone: number;
  /** Readable sessions with no `actions` key, newest `updated` first. */
  withoutKey: Array<{ name: string; updated: string }>;
  /** Files that could not be read or are not a session. */
  unreadable: Array<{ file: string; error: string }>;
  /** Lines of an `actions` entry that are not in the convention. */
  malformed: Array<{ session: string; line: string }>;
}

export const ACTIONS_KEY = "actions";
const DAY = /^\d{4}-\d{2}-\d{2}$/;

/** `admin.CROWLR`, `admin-CROWLR` and `Admin crowlr` are one project. */
export function normalizeProject(name: string): string {
  return name.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "");
}

/** One line of the convention, or null when it is not one (the caller names it). A leading bullet is tolerated. */
export function parseActionLine(raw: string): Omit<ActionLine, "session" | "timestamp"> | null {
  const line = raw.trim().replace(/^[-*]\s+/, "");
  const parts = line.split("|").map((p) => p.trim());
  if (parts.length < 4) return null;
  const [date, stateRaw, project, ...rest] = parts;
  const state = stateRaw.toLowerCase();
  if (!DAY.test(date) || (state !== "open" && state !== "done") || !project) return null;
  const what = rest.join(" | ");
  if (!what) return null;
  return { date, state, project, what };
}

function readSessionFile(dir: string, file: string): { session: Session } | { error: string } {
  try {
    const parsed = JSON.parse(readFileSync(join(dir, file), "utf-8")) as Partial<Session>;
    if (!parsed || !Array.isArray(parsed.entries)) return { error: "no entries array: not a session file" };
    return { session: { name: typeof parsed.name === "string" && parsed.name ? parsed.name : file.slice(0, -5), created: parsed.created ?? "", updated: parsed.updated ?? "", entries: parsed.entries } };
  } catch (err) {
    return { error: err instanceof Error ? err.message : String(err) };
  }
}

export function actionsReport(opts: ActionsOptions): ActionsReport {
  const report: ActionsReport = { sessions: 0, actions: [], hiddenDone: 0, withoutKey: [], unreadable: [], malformed: [] };
  const dir = sessionsDir();
  if (!existsSync(dir)) return report;
  let files: string[];
  try {
    files = readdirSync(dir).filter((f) => f.endsWith(".json")).sort();
  } catch (err) {
    report.unreadable.push({ file: dir, error: err instanceof Error ? err.message : String(err) });
    return report;
  }
  const wanted = opts.project ? normalizeProject(opts.project) : null;
  const all: ActionLine[] = [];
  for (const file of files) {
    report.sessions++;
    const read = readSessionFile(dir, file);
    if ("error" in read) { report.unreadable.push({ file, error: read.error }); continue; }
    const { session } = read;
    const entry = session.entries.find((e) => e && e.key === ACTIONS_KEY);
    if (!entry) { report.withoutKey.push({ name: session.name, updated: session.updated }); continue; }
    for (const raw of String(entry.value ?? "").split("\n")) {
      if (!raw.trim()) continue;
      const line = parseActionLine(raw);
      if (!line) { report.malformed.push({ session: session.name, line: raw.trim() }); continue; }
      all.push({ ...line, session: session.name, timestamp: entry.timestamp ?? "" });
    }
  }
  const filtered = all.filter((a) => (!opts.since || a.date >= opts.since) && (!wanted || normalizeProject(a.project) === wanted));
  report.hiddenDone = opts.all ? 0 : filtered.filter((a) => a.state === "done").length;
  report.actions = filtered
    .filter((a) => opts.all || a.state === "open")
    .map((a, i) => ({ a, i }))
    .sort((x, y) => x.a.date.localeCompare(y.a.date) || x.a.session.localeCompare(y.a.session) || x.i - y.i)
    .map(({ a }) => a);
  report.withoutKey.sort((x, y) => (y.updated || "").localeCompare(x.updated || ""));
  return report;
}

const plural = (n: number, one: string, many = `${one}s`): string => `${n} ${n === 1 ? one : many}`;

export function formatActions(report: ActionsReport, opts: ActionsOptions): string {
  const lines: string[] = [];
  const scope = [opts.since ? `since ${opts.since}` : "", opts.project ? `for project ${opts.project}` : ""].filter(Boolean).join(", ");
  const open = report.actions.filter((a) => a.state === "open").length;
  const done = report.actions.length - open;
  if (report.sessions === 0) {
    lines.push("No saved sessions, so no action points.");
  } else if (report.actions.length === 0) {
    lines.push(`No open action points${scope ? " " + scope : ""}.`);
  } else {
    const head = opts.all ? `${open} open and ${done} done action points` : `${open} open action point${open === 1 ? "" : "s"}`;
    lines.push(`${head}${scope ? " " + scope : ""} (oldest first):`);
    for (const a of report.actions) {
      lines.push(`  ${a.date} | ${a.state} | ${a.project} | ${a.what}`);
      lines.push(`      ${a.session}, written ${formatLearnedAt(a.timestamp)}`);
    }
  }
  if (report.hiddenDone > 0) lines.push(`${plural(report.hiddenDone, "done line")} hidden (--all shows them).`);
  if (report.sessions > 0) {
    const newest = report.withoutKey[0];
    const tail = newest ? `, newest: ${newest.name} ${(newest.updated || "").slice(0, 10) || "undated"}` : "";
    lines.push(`${plural(report.withoutKey.length, "session")} without an actions key${tail}`);
  }
  if (report.unreadable.length > 0) {
    lines.push(`${plural(report.unreadable.length, "session file")} could not be read:`);
    for (const u of report.unreadable) lines.push(`  ${u.file}: ${u.error}`);
  }
  for (const m of report.malformed) lines.push(`${m.session}: not an action line, left out: "${m.line}"`);
  return lines.join("\n");
}

export type ParsedActionsArgs = { ok: true; opts: ActionsOptions } | { ok: false; error: string };

export function parseActionsArgs(args: string[]): ParsedActionsArgs {
  const opts: ActionsOptions = { all: false, since: undefined, project: undefined };
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === "--all") { opts.all = true; continue; }
    if (a === "--since" || a === "--project") {
      const v = args[i + 1];
      if (!v || v.startsWith("--")) return { ok: false, error: `${a} needs a value` };
      if (a === "--since") {
        if (!DAY.test(v)) return { ok: false, error: `--since "${v}" is not a day as YYYY-MM-DD. Refusing to answer with a zero.` };
        opts.since = v;
      } else {
        opts.project = v;
      }
      i++;
      continue;
    }
    return { ok: false, error: `unknown argument: ${a}` };
  }
  return { ok: true, opts };
}

export const ACTIONS_USAGE = `Usage: contextengine actions [--all] [--since YYYY-MM-DD] [--project NAME]

The owner's open action points, read from the \`actions\` key of every saved session
(~/.contextengine/sessions/*.json), sorted by date, oldest first, each with the session it comes
from and when that entry was written (UTC and Europe/Zurich). One line per action, written by the
agent whenever it hands the owner a command or a date:

  YYYY-MM-DD | open | <project> | <what the owner does, plain words>

\`done\` instead of \`open\` once the owner says it is done. Then one line counts the sessions that
have no \`actions\` key and names the newest, so the gap shows. A session file that does not parse,
and a line that is not in that form, are named, never skipped. Read-only, no network, exit 0.

  --all                 Include the done lines.
  --since YYYY-MM-DD    Only the lines dated on or after that day.
  --project NAME        Only one project (admin-CROWLR and admin.CROWLR are the same).
`;
