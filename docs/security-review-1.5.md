# Version 1.5 Security Review

Date: 2026-09-12

## Scope

The review covered the Version 1.5 branch changes from commit `28bc04e` through
the release candidate. It used source-backed threat modeling, independent
finding discovery, focused proof tests, remediation, and regression testing.
The review lens emphasized zero trust, least privilege, credential recipients,
resource exhaustion, audit integrity, release provenance, and insider misuse.

## Findings and disposition

| Finding | Severity | Disposition |
| --- | --- | --- |
| A generation tool was not an inspection-only operation and lacked a complete compute budget | Medium | Removed from the product and configuration schema |
| Kubernetes credential providers could execute ambient kubeconfig commands | Medium | Kubernetes integration removed from the product and configuration schema |
| Unknown tool names created unbounded metrics-label cardinality | Medium | Unknown labels collapse into one fixed bucket; metrics responses use the central byte limit |
| Kubernetes pod responses could allocate unbounded data before output checks | Low | Integration removed |
| Kubernetes deployment responses could allocate unbounded data before output checks | Low | Integration removed |
| Kubernetes credential refresh could rewrite ambient kubeconfig | Low | Integration removed |
| Authenticated GitHub requests could inherit default redirect behavior | Defense in depth | All redirects are rejected before a credential can cross the fixed API origin |

## Added controls

- Authenticated Streamable HTTP is disabled by default and accepts only literal
  loopback bind addresses.
- Exactly one strict bearer header is required. The token is loaded from a named
  environment variable, hashed immediately, and compared through fixed-length
  digests using constant-time comparison.
- Host, Origin, request-body size, active sessions, and idle session duration
  are bounded.
- Audit events use durable append, strict JSONL validation, synchronized writes,
  immutable rotation, and closed-segment retention.
- Release builds run without write authority. A separately protected publish job
  receives narrow write permissions only after exact tag, commit, ancestry,
  artifact, checksum, SBOM, and provenance checks.
- GitHub Actions are commit-pinned and checkout credentials are not persisted.

## Verification evidence

This section preserves the original v1.5 review results. The later
[v1.5 release closeout](release-1.5.md) records fresh installation, live
transport/container checks, and patch-release acceptance separately.

- 149 tests passed locally.
- Three symbolic-link tests were skipped because the Windows account lacked the
  operating-system privilege to create symbolic links. Equivalent Windows
  junction escape tests passed.
- A real loopback socket test returned HTTP 401 without authentication and HTTP
  200 for an authenticated MCP initialize request.
- Ruff formatting and lint, strict mypy, Bandit, pip-audit, documentation checks,
  Compose validation, and workflow YAML parsing passed.
- The 1.5.0 wheel and source distribution built successfully. The wheel was
  installed outside the repository, imported at the expected version, and its
  installed CLI was exercised.

## Residual operator responsibilities

- Keep approved roots narrow, stable, and protected by operating-system access
  controls.
- Prefer the Docker socket-proxy deployment. Direct Docker socket access remains
  a high-authority deployment choice even when registered operations are reads.
- Protect the `release` environment and `v*` tags with repository rulesets before
  publishing a release.
- Back up audit segments according to organizational retention and recovery
  requirements. The application does not provide centralized storage or
  cross-host replication.
