#!/usr/bin/env sh
# osv-guard PreToolUse hook.
#
# All the logic lives in the osv-guard CLI (`osv-guard hook`), which reads the
# tool call on stdin and writes the permission decision on stdout. This wrapper
# only has to find a node and get out of the way.
#
# Any failure here exits 0 with no output, which Claude Code reads as "no
# opinion" — a broken guard must never wedge a session.

set -u
export PATH="/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:$PATH"

ROOT="${CLAUDE_PLUGIN_ROOT:-$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)}"
CLI="$ROOT/dist/cli.js"

if [ ! -f "$CLI" ] || ! command -v node >/dev/null 2>&1; then
  exit 0
fi

exec node "$CLI" hook
