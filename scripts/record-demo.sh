#!/usr/bin/env bash
# Re-record docs/assets/demo.gif from the published v1.6.1 wheel + repo fixtures.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
STAGE="${TMPDIR:-/tmp}/lmt-demo-record-$$"
WHEEL_URL="https://github.com/chriswayneh/local-mcp-toolbox/releases/download/v1.6.1/local_mcp_toolbox-1.6.1-py3-none-any.whl"
VENV="$STAGE/venv"

cleanup() {
  rm -rf "$STAGE"
}
trap cleanup EXIT

command -v vhs >/dev/null || { echo "vhs is required (https://github.com/charmbracelet/vhs)" >&2; exit 1; }
command -v ttyd >/dev/null || { echo "ttyd is required by vhs" >&2; exit 1; }

mkdir -p "$STAGE/work"
cp -a "$ROOT/demo/agent-configs" "$STAGE/work/agent-configs"
cp "$ROOT/config/restricted.yml" "$STAGE/work/restricted.yml"
cp "$ROOT/scripts/demo.tape" "$STAGE/work/demo.tape"

python3 -m venv "$VENV"
"$VENV/bin/python" -m pip install -q "$WHEEL_URL"

export LMT_BIN_DIR="$VENV/bin"
export LMT_DEMO_HOME="$STAGE/work"
export PATH="$LMT_BIN_DIR:$PATH"

(
  cd "$STAGE/work"
  vhs demo.tape
)

mkdir -p "$ROOT/docs/assets"
cp "$STAGE/work/demo.gif" "$ROOT/docs/assets/demo.gif"
echo "Wrote $ROOT/docs/assets/demo.gif"
