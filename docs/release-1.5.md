# v1.5 release and operations

## Supported release contract

Local MCP Toolbox v1.5 is a local, single-operator, read-only inspection server.
Its feature scope is complete. Version 1.5.1 was published on 2026-09-13;
the v1.5.2 closeout corrects defects found by clean-install and live-transport
acceptance. It adds no planned future features and does not replace existing tags.

Supported interfaces are the installed Typer CLI (`doctor`, `serve`,
`serve-http`), MCP tools/resources/prompts over stdio, optional authenticated
loopback Streamable HTTP, and attached stdio in the supplied Linux container.
Python 3.12+ is required. CI covers Linux Python 3.12, 3.13, and 3.14 and Windows
Python 3.12. Local closeout acceptance uses Windows Python 3.13 and Docker
Desktop's Linux engine 29.7.2 with Python 3.12.13 in the toolbox image.

The [tool catalog](tools.md) defines the shipped capabilities: core host/file
inspection, allowlisted Git and GitHub metadata, static Python environment
auditing, Docker metadata/health/logs, bounded local logs, fixed Bandit scanning,
top-level infrastructure inventory, deterministic incident evidence, and
aggregate runtime metrics. Resources and prompts do not grant additional access.

Every optional integration requires explicit policy. Canonical containment,
central redaction, output limits, and sanitized JSONL auditing remain mandatory.
There is no generic shell, lifecycle management, file mutation, Kubernetes
inspection, generation surface, dashboard, or remote execution capability.
The only intentional server writes are its own audit records and rotation.

## Install and verify

Use a fresh directory and the published tag, not an existing working environment:

```powershell
git clone --branch v1.5.2 https://github.com/chriswayneh/local-mcp-toolbox.git
Set-Location local-mcp-toolbox
py -3.13 -m venv .venv
.\.venv\Scripts\python -m pip install -e ".[dev,docker,release]"
.\.venv\Scripts\local-mcp-toolbox doctor --config config/restricted.yml
.\.venv\Scripts\python -m pytest -q
.\.venv\Scripts\python -m ruff format --check .
.\.venv\Scripts\python -m ruff check .
.\.venv\Scripts\python -m mypy src
.\.venv\Scripts\python -m bandit -q -r src
.\.venv\Scripts\python -m pip_audit
.\.venv\Scripts\python scripts/validate_docs.py
.\.venv\Scripts\python -m build
```

On Linux use `python3 -m venv .venv` and `.venv/bin/python` or
`.venv/bin/local-mcp-toolbox`. Development/release extras are for verification;
operators can install the downloaded wheel alone, or its Docker extra when
needed. Releases are distributed through GitHub, not a verified PyPI publication.

Follow [client configuration](client-configuration.md) with absolute paths.
`doctor` validates prerequisites; it does not establish a client session or prove
that every remote dependency is healthy. Confirm `toolbox_server_status`, then
run the [synthetic demo](demo-walkthrough.md). A stdio process waiting silently
for protocol input is normal. Never send startup banners to stdout.

## Container acceptance

Run from the repository root. Use these project names only for disposable
acceptance resources, never for unrelated deployments:

```powershell
docker build -t local-mcp-toolbox:acceptance .
docker compose -p toolbox-acceptance-demo -f demo/compose.yaml up -d
docker compose -p toolbox-acceptance-proxy --profile docker up -d docker-socket-proxy
docker compose -p toolbox-acceptance-demo -f demo/compose.yaml ps
# Wait until the two services report healthy and intentionally unhealthy.
.\.venv\Scripts\python scripts/verify_container_acceptance.py --image local-mcp-toolbox:acceptance --network toolbox-acceptance-proxy_docker_api --healthy toolbox-acceptance-demo-healthy-1 --unhealthy toolbox-acceptance-demo-unhealthy-1
```

The script launches an ephemeral non-root, read-only toolbox container, connects
over real stdio, checks both named services and bounded logs, and verifies an
oversized log request is denied. Its audit storage is temporary. Normal Compose
deployment uses a persistent audit volume instead. The script does not mutate
the inspected containers. Clean up only the disposable projects:

```powershell
docker compose -p toolbox-acceptance-demo -f demo/compose.yaml down
docker compose -p toolbox-acceptance-proxy --profile docker down
```

## Acceptance record

Acceptance date: 2026-09-20. Baseline: fresh GitHub clone at
`c119119318d38aa9e14ffe3ec694992061c5585b`, containing v1.5.1 plus a README-only
license clarification. Existing work and license text were preserved.

| Check actually performed | Result and qualification |
| --- | --- |
| Clean Windows checkout and new Python 3.13 environment | Editable install with dev, Docker, and release extras succeeded; baseline 156 tests passed, 3 symlink tests skipped for missing Windows privilege |
| Candidate automated suite | 159 passed, 3 Windows symlink skips; retained real-transport regression tests |
| Installed stdio launch outside checkout | Initialization, status, demo logs/infrastructure, incident defaults, redaction, outside-root denial, disabled Docker denial, strict JSONL audit passed |
| Real loopback HTTP socket | Missing/wrong token 401, invalid Host 421, invalid Origin 403, oversized body 413, authenticated initialization and status passed; token absent from captured diagnostics/audit |
| Client templates | All four parse and startup arguments are tested; actual desktop application interfaces were not automated |
| Quality and security | Ruff, mypy, Bandit, and dependency audit run; project itself is skipped by pip-audit because it is not on PyPI, not silently declared vulnerability-free |
| Package and documentation | Isolated sdist/wheel build and local documentation-link validation run; published artifacts verified separately below |
| Container runtime | Linux image build and restricted doctor passed with read-only root, dropped capabilities, and no-new-privileges; real container stdio verified healthy/unhealthy demo services, bounded logs, and oversized-request denial through the proxy |
| Socket proxy | Corrected digest-pinned image starts with read-only root; version GET allowed, image GET and mutation POST rejected with 403 |

The baseline existing suite covers permissions, traversal and sensitive-path
denials, central redaction, strict audit records/rotation, environment-auditor
edge cases, GitHub allowlists, and fixed-command restrictions. Tests of external
GitHub/scanner failures use controlled fixtures where indicated in their source;
this is not certification of every external service or scanner installation.
Windows symlink skips must not be counted as passes; Linux CI exercises those
cases. A third-party Starlette/AnyIO deprecation warning is non-failing.

### Defects corrected during acceptance

- Log summaries and both incident tools defaulted to 200 or 500 lines, exceeding
  the default 100-record ceiling. Defaults are now 100; policy limits are unchanged.
- The proxy image tag omitted its required `v` prefix. The corrected reference
  is pinned to the verified manifest digest, with bounded startup tmpfs storage.
- The opt-in container profiles did not select or package the Docker-only policy.
  The restricted core profile remains unchanged.
- The SDK's `container.image` property issued an image API request that the proxy
  correctly denied. Image names now use already-retrieved container metadata;
  the image API remains disabled. Regression fixtures reject any image-property
  access.
- Client documentation incorrectly denied HTTP support; the demo lacked an
  explicit standard-profile configuration for its optional modules.

### Artifacts and provenance

The existing v1.5.1 release was downloaded independently. Its wheel, sdist, and
CycloneDX SBOM matched `SHA256SUMS`; the manifest matched the GitHub asset digest.
SBOM format/UUID validation passed. GitHub build-provenance verification passed
for both distributions and identified release commit
`99f50c78d46bae6b59559974ffd5855169a1d856` and
[release workflow 34774045119](https://github.com/chriswayneh/local-mcp-toolbox/actions/runs/34774045119).

For any new release, download all four assets into a new empty directory and
verify before installation. PowerShell checksum verification:

```powershell
gh release download v1.5.2 --repo chriswayneh/local-mcp-toolbox --dir release-assets
Get-Content release-assets/SHA256SUMS | ForEach-Object {
  $digest, $name = $_ -split '\s+', 2
  if ((Get-FileHash (Join-Path release-assets $name) -Algorithm SHA256).Hash -ne $digest) {
    throw "Checksum mismatch: $name"
  }
}
gh attestation verify release-assets/local_mcp_toolbox-1.5.2-py3-none-any.whl --repo chriswayneh/local-mcp-toolbox
gh attestation verify release-assets/local_mcp_toolbox-1.5.2.tar.gz --repo chriswayneh/local-mcp-toolbox
.\.venv\Scripts\python scripts/validate_release_sbom.py release-assets/sbom.cdx.json
```

The protected release workflow builds once, verifies checksums, attests build
provenance and the SBOM, and refuses to overwrite an existing release. An
attestation establishes artifact origin, not absence of vulnerabilities. Tags
freeze project source, not future dependency resolutions or advisory databases.
No bit-for-bit rebuild guarantee is claimed.

## Limitations and operator responsibilities

- Local single-operator use only. HTTP is loopback-only, with one shared bearer
  credential, no TLS termination, OIDC, tenant isolation, or public hosting model.
  Protect and rotate the environment-provided token; restart after rotation.
- Read-only is the exposed operation contract, not an operating-system sandbox.
  Run as a low-privilege account and approve small, stable roots. Do not allow
  concurrent hostile path replacement; hard links and kernel-level races remain
  limitations described in the [environment auditor](environment-auditor.md).
- Redaction is pattern-based, not a guarantee that arbitrary sensitive prose is
  recognized. Keep credentials outside approved roots and treat results as
  untrusted evidence, not instructions or proof of root cause.
- The Docker proxy has host-socket authority and broad container GET access.
  Only toolbox responses are field-filtered/redacted. Isolate its private network;
  no per-container allowlist or hostile-container containment is claimed.
  Direct socket mounting remains advanced/high-risk and was not accepted as the
  recommended deployment.
- The static environment auditor does not execute Python or prove importability,
  package authenticity, runtime health, or vulnerability status. Incomplete
  metadata can only support partial/unverifiable conclusions.
- Lowering `limits.max_records` below a tool's default requires callers to supply
  a compatible explicit limit. The server rejects, rather than silently expands,
  out-of-policy requests.
- Audits are local files, not tamper-proof remote evidence. Protect their directory,
  monitor disk space, retain required closed segments, and use one writer per
  audit path. Metrics reset when the process restarts.
- No manual macOS, ARM, desktop-client UI, long-duration load, or independent
  penetration-test acceptance is claimed. Security scans do not certify the host,
  Docker daemon, every transitive container package, or all future dependencies.

## Upgrade, rollback, and troubleshooting

Stop the client-owned server. Retain the current policy and audit directory.
Verify the target release assets, install into a new virtual environment, run
`doctor`, update the client's absolute executable path, and repeat the demo.
Review any changed dependency resolution. For rollback, point the client to the
previous retained environment and compatible policy; do not retag releases or
delete audit history. Container upgrades rebuild from the selected tag and retain
the audit volume. This release introduces no audit-schema migration.

- **No tools from an optional module:** check `profile: standard`, its integration
  switch, and its dedicated allowlist. Do not broaden all roots as a workaround.
- **HTTP 401/403/421:** check the token, exact loopback address/port, and Origin.
  Do not disable authentication or bind to all interfaces.
- **Container connection closed:** inspect stderr, image build, selected config,
  proxy health, network membership, and audit-directory ownership. Keep stdout
  exclusively for MCP.
- **Audit failure:** restore writable private audit storage and available disk
  capacity. Do not bypass the audit requirement to make a call succeed.

Optional v2-v4 proposals in the [roadmap](../ROADMAP.md) are outside this completed
scope and require independent requirements and security review.
