# Terminal demo

The README GIF replays actual output captured from the published
`local-mcp-toolbox` **v1.6.1** release wheel on 2026-11-05 (America/Chicago),
using only the synthetic fixtures under `demo/agent-configs/` and the
`config/restricted.yml` profile. Timing and line wrapping are adjusted for
README readability. It is a recorded replay, not a live CI run.

## What it shows

1. Confirm the installed package version (`1.6.1`).
2. Run `doctor` against the restricted profile (no approved roots, no optional
   integrations). Status is `attention` because the audit parent directory is
   created on first use; everything else is skipped or passes.
3. Audit `demo/agent-configs/benign` — status `clean`.
4. Audit `demo/agent-configs/risky --limit 5` — status `findings_detected`
   (14 findings; the first five are shown). Credentials in snippets are already
   redacted by the tool as `[REDACTED_SECRET]`. Exit code **1** is expected when
   findings meet the default `--fail-on low` threshold.

## Run it yourself

Use Python 3.12 or newer in an isolated environment. Install the published
release wheel from GitHub Releases (the package is not on PyPI), then run from
a checkout of this repository so the demo fixtures are available:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install \
  "https://github.com/chriswayneh/local-mcp-toolbox/releases/download/v1.6.1/local_mcp_toolbox-1.6.1-py3-none-any.whl"

.venv/bin/python -c 'import mcp_toolbox as m; print("local-mcp-toolbox", m.__version__)'
.venv/bin/local-mcp-toolbox doctor --config config/restricted.yml | python -m json.tool
.venv/bin/local-mcp-toolbox audit-agent-configs demo/agent-configs/benign
.venv/bin/local-mcp-toolbox audit-agent-configs demo/agent-configs/risky --limit 5
```

On Windows, use `.\.venv\Scripts\` instead of `.venv/bin/`. If your shell stops
on nonzero status, allow the risky audit's expected exit code 1 before
continuing.

The commands only read the synthetic fixtures and write the tool's own audit
log under the path in `config/restricted.yml` (`./audit/events.jsonl`). They do
not start the MCP server, open a Docker socket, or contact the network.

## Re-record the GIF

Requires [vhs](https://github.com/charmbracelet/vhs) (and its `ttyd` dependency)
plus a monospace font such as JetBrains Mono. From the repository root:

```bash
./scripts/record-demo.sh
```

That script stages a throwaway work directory with copies of the fixtures,
renders `docs/assets/demo.gif` from `scripts/demo.tape`, and leaves no Docker
containers running. Review the frames before committing.

## Text alternative

The [Quick start](../README.md#try-the-agent-config-auditor) section and the
[demo walkthrough](demo-walkthrough.md) cover the same auditor flow in text,
including the planted findings in `demo/agent-configs/risky`.
