#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="/Users/mdmac/Projects/monarch-mcp-server"
UV_BIN="/opt/homebrew/bin/uv"

echo "[1/3] Go to repo: $REPO_DIR"
cd "$REPO_DIR"

echo "[2/3] Pull latest from your fork (origin/main)"
git pull --ff-only

echo "[3/3] Sync Python dependencies (pinned to Python 3.12)"
"$UV_BIN" sync -p 3.12 --managed-python

cat <<'MSG'

Done.
- If Monarch tools misbehave in Claude Desktop: Quit and reopen Claude Desktop.
- If login breaks: rerun login_setup.py (MFA) and retry.
MSG
