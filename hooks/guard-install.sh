#!/usr/bin/env sh
# osv-guard PreToolUse hook.
#
# The logic lives in the osv-guard CLI (`osv-guard hook`), which reads the tool
# call on stdin and writes the permission decision on stdout. This wrapper only
# finds a way to run it.
#
# Any failure exits 0 with no output, which Claude Code reads as "no opinion".
# A broken guard must never wedge a session.

set -u
export PATH="/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:$PATH"

ROOT="${CLAUDE_PLUGIN_ROOT:-$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)}"

# 1. The copy bundled with this plugin — the normal path, and the fast one.
if [ -f "$ROOT/dist/cli.js" ] && command -v node >/dev/null 2>&1; then
  exec node "$ROOT/dist/cli.js" hook
fi

# 2. An osv-guard already on PATH (installed globally or in the project).
if command -v osv-guard >/dev/null 2>&1; then
  exec osv-guard hook
fi

# 3. Last resort, so a missing bundle degrades to slow rather than to silent.
if command -v npx >/dev/null 2>&1; then
  exec npx -y osv-guard@latest hook
fi

exit 0
