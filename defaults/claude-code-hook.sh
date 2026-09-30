#!/usr/bin/env bash
# OpsContext — Claude Code hook emitter
#
# [LOCKED] [OPSCONTEXT-CC-HOOK], 2026-06-23
# [NEVER] block on success or fail loudly. Claude Code waits for hooks to
#    complete before continuing — any error must exit 0 + silent.
# [NEVER] emit on PreToolUse. PostToolUse alone, PreToolUse would double-
#    count vs PostToolUse for the `stuck` heuristic and skew `silent_failure`.
# [NEVER] print to stdout (would be interpreted as a hook decision message).
# WHY: This hook is the ONLY way Claude Code terminal sessions get into the
#    OpsContext audit log. If it's slow or breaks, the user disables it and
#    loses cross-surface drift visibility — the entire wedge collapses.
# FIX: To support a new Claude Code hook event, add a case branch. Keep the
#    exit-0-on-any-error discipline. Events go via HTTP (NOT direct file
#    write) so the running MCP server's in-process chain cache prevents the
#    concurrent-write race.

set +e

EVENT_KIND="${1:-}"
SECRET_FILE="$HOME/.contextengine/extension-secret"
ENDPOINT="${OPSCONTEXT_EVENT_URL:-http://127.0.0.1:7842/events}"

# Bail fast if not initialized — never block Claude Code
[ -r "$SECRET_FILE" ] || exit 0
SECRET=$(cat "$SECRET_FILE" 2>/dev/null)
[ -n "$SECRET" ] || exit 0

INPUT=$(cat)
[ -n "$INPUT" ] || exit 0

NOW=$(date -u +%Y-%m-%dT%H:%M:%S.000Z)

case "$EVENT_KIND" in
  UserPromptSubmit)
    PAYLOAD=$(printf '%s' "$INPUT" | jq -c --arg ts "$NOW" '{
      v: 1, ts: $ts, event: "vscode.prompt_submit", actor: "claude-code",
      payload: {
        surface: "claude-code",
        text: ((.prompt // "")[:4000]),
        session: (.session_id // ""),
        cwd: (.cwd // ""),
        char_count: ((.prompt // "") | length)
      }
    }' 2>/dev/null)
    ;;
  PostToolUse)
    # [LOCKED] [HOOK-TOLERATES-EVERY-RESULT-SHAPE] - 2026-09-29
    # [NEVER] index .tool_response or .tool_input as if it were always an object.
    # WHY: Claude Code hands a Bash result as an object, an MCP result as a LIST of content
    #      blocks, and some results as a plain string. `.tool_response.is_error` on a list is a
    #      jq error, the script exited 0 with nothing sent, and no MCP tool call ever reached the
    #      audit log: 0 of 93 in one day, while every Bash call did (E2E_REVIEW_2026-09 C1-3).
    # FIX: `objects` keeps only the object case and `//` supplies the default for every other
    #      shape, so each call yields a record; only an object can carry is_error, error or
    #      interrupt. tests/claude-code-hook.test.ts drives the real script on each shape.
    #      input_chars is the size of the whole tool input, no content: it tells two Edits of one file
    #      apart in fleet health ([DOUBLED-IS-THE-SAME-INPUT-TWICE], src/fleet-health.ts).
    PAYLOAD=$(printf '%s' "$INPUT" | jq -c --arg ts "$NOW" '{
      v: 1, ts: $ts, event: "vscode.tool_call", actor: "claude-code",
      payload: ({
        surface: "claude-code",
        tool: (.tool_name // ""),
        input_chars: ((.tool_input // "") | tostring | length),
        args_preview: (
          ((.tool_input | objects | (.command // .file_path // .pattern // tostring))
            // ((.tool_input // "") | tostring)
          )[:200]
        ),
        session: (.session_id // ""),
        cwd: (.cwd // "")
      } + (
        if (((.tool_response | objects | .is_error) // false) == true)
            or (((.tool_response | objects | .error) // "") != "")
            or (((.tool_response | objects | .interrupt) // false) == true)
        then { error: (((.tool_response | objects | .error)
                        // ((.tool_response | objects | (.content // empty)) | tostring)
                        // "tool reported error")[:500]) }
        else {}
        end
      ))
    }' 2>/dev/null)
    ;;
  SessionStart)
    PAYLOAD=$(printf '%s' "$INPUT" | jq -c --arg ts "$NOW" '{
      v: 1, ts: $ts, event: "vscode.session_start", actor: "claude-code",
      payload: {
        surface: "claude-code",
        session: (.session_id // ""),
        cwd: (.cwd // ""),
        source: (.source // "")
      }
    }' 2>/dev/null)
    ;;
  *)
    exit 0
    ;;
esac

[ -n "$PAYLOAD" ] || exit 0

# POST with 1s hard timeout. Any error → silent (curl >/dev/null 2>&1, exit 0).
# [LOCKED] [HOOK-KEEPS-PROMPT-AND-SECRET-OFF-ARGV] - 2026-09-25
# [NEVER] put $PAYLOAD or $SECRET in curl's arguments (`--data "..."`, `-H "...: $SECRET"`).
# WHY: a process's arguments are readable by every program on the machine (`ps`), for as long
#      as curl runs, up to the 1 s timeout. Until 2.8.4 each prompt (up to 4,000 characters)
#      and the receiver's shared secret rode there.
# FIX: printf is a shell builtin, so it starts no process: it pipes the body into curl's
#      standard input (--data-binary @-), and writes the header into a process-substitution
#      file (-H @file, curl 7.55 and later), which only curl reads.
printf '%s' "{\"events\":[$PAYLOAD]}" | curl -sS --max-time 1.0 \
  -H "Content-Type: application/json" \
  -H @<(printf 'X-OpsContext-Secret: %s\n' "$SECRET") \
  --data-binary @- \
  "$ENDPOINT" >/dev/null 2>&1

exit 0
