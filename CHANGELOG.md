# Changelog

All notable changes to Local MCP Toolbox are documented here. The project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

- Passwords written as JSON, such as `"password": "hunter2"`, are now redacted.
  Before, the password rule only matched `password=...` or `password: ...`, so
  quoted JSON keys slipped through. Also, in structured data, any text value
  under a secret-named key (`password`, `secret`, `token`, `api_key`, and
  similar) is now replaced with `[REDACTED_SENSITIVE_FIELD]` even when the value
  does not look like a known secret format.
- That secret-named-key rule now replaces the whole value even when another
  pattern already redacted part of it (for example a home path followed by the
  real secret), and only an exact marker such as `[REDACTED_PASSWORD]` counts as
  already redacted; a value that merely starts with `[REDACTED_` is redacted.
- Quoted passwords are redacted up to the closing quote, so short passwords and
  ones containing spaces, commas, braces, or escaped quotes no longer leak in
  part or in full. Unquoted `password=...` values keep their full previous
  coverage, and a value an earlier rule already replaced is not counted twice.
- Keyed secrets (`password`/`pwd`, `*secret*`, `*token`, `*api_key`) have no
  minimum length any more, so 1-3 character values are redacted. Unquoted
  values are redacted to the end of the line (or up to an existing redaction
  marker), so values with spaces or punctuation cannot leak their tail; quoted
  values honor YAML's doubled-quote escape. Only an exact marker followed by a
  delimiter is skipped; `[REDACTED_X]realsecret` is redacted. URL passwords
  containing a space are redacted too.
- A list or mapping stored under a secret-named key is now replaced as a whole
  (before, `{"secret": ["a", "b"]}` passed through). Plain-text `privateKey`,
  `credentials`, `pass`, and XML elements such as `<password>...</password>` are
  redacted. An empty `"password": ""` is left intact instead of swallowing the
  rest of the line, and name-like keys such as `tokenizer` or `private_key_path`
  keep their values.
- Text after an existing redaction marker on the same line is now redacted
  (`password=[REDACTED_X] realsecret`), as are values glued to empty quotes
  (`password=''hunter2`); only an exact `"k": ""` is kept. camelCase keys such
  as `authToken`, `accessToken`, `refreshToken`, `idToken`, and `myApiKey`,
  prefixed keys such as `client_credentials` and `user_pass`, and XML elements
  with attributes, prefixes, suffixes, camelCase, or all-caps names
  (`<password type="x">`, `<db_password>`, `<secretKey>`, `<SECRETKEY>`,
  `<userPasswd>`, `<userPwd>`, `<authToken>`, `<AUTHTOKEN>`, `<MYAPIKEY>`) are
  redacted, as are all-caps keys without a separator (`AUTHTOKEN`, `MYAPIKEY`;
  plural count settings such as `MAXTOKENS=4096` are left alone). A quoted
  marker or empty quoted value is treated as already safe only when the rest of
  the line is closing brackets or trailing commas (or, when the secret key
  itself is quoted before `:`, when `,` precedes a quoted identifier key and
  structured value start, with CRLF lines supported), so
  `password="[REDACTED_X]", hunter22`, `password: "[REDACTED_X]", "a": hunter22`,
  and `password='[REDACTED_X]''[REDACTED_X]':hunter22` are redacted.
  Pathological long lines no longer take seconds to redact (several patterns,
  the XML tag rule, and the trailing-marker trim were made linear).
- `security_scan_repository` no longer reports findings for files outside the
  approved scan root or files that match a blocked pattern. Bandit follows
  symlinks on its own, so a link inside the root could pull in a file from
  elsewhere, and the result used to show it by file name. Those findings are
  now left out, and the response has a `withheld_findings` count so you can
  see that some were skipped.
- Bandit now scans a private copy of only the `.py`/`.pyw` files that are
  authorized when the scan starts, instead of the live directory. Before, the
  path check ran after Bandit had read the files, so a symlink swapped during or
  after the scan could slip an outside file's finding through, and a link
  retargeted between checks could make the whole scan return an error. Findings
  are now matched back to the copied files, so neither can happen.
- The security scan snapshot also refuses a symlink whose own name matches a
  blocked pattern, even when it points at an allowed file.
- The security scan snapshot now opens every path component without following
  symlinks (POSIX), so a directory swapped between check and open cannot leak
  an outside file; Windows keeps a resolve-and-verify fallback. FIFOs, devices
  and hard-linked files are skipped (a FIFO no longer hangs the scan), files
  over 5 MB or past a 50 MB total are withheld, and the response reports
  `withheld_files` and `snapshot_truncated`.
- Git tools no longer run programs that a repository's own settings ask for.
  A repository could set `core.fsmonitor`, hooks, an external diff tool, or a `.gitattributes` filter
  driver (`filter.*.clean`/`process`) in
  `.git/config`, and Git would run that program during a status check. The
  toolbox now passes `--no-lazy-fetch`, sets `GIT_NO_LAZY_FETCH=1`,
  `GIT_ASKPASS=false`, and `SSH_ASKPASS=false`, overrides those settings
  (including `protocol.allow=never`, `core.sshCommand=false`,
  `core.askPass=false`, `core.alternateRefsCommand=false`, and
  `credential.helper=`) via `-c` and `GIT_CONFIG_COUNT` /
  `GIT_CONFIG_KEY_<n>` / `GIT_CONFIG_VALUE_<n>`, and refuses repositories with
  malformed `.git/config` or filter driver names containing `=` or
  non-printable characters, so inspecting an untrusted repository (including a
  partial clone with `.promisor` packs) is safe. `git status` also no longer
  refreshes or locks the index, so the repository is left exactly as it was.
- Recent-commit inspection passes `--no-show-signature`, so a repository that
  sets `log.showSignature` and `gpg.program` cannot make the toolbox run its
  chosen signature verifier.
- Status and diff summaries no longer look inside submodule work trees
  (`--ignore-submodules=dirty`), because a submodule's own config, such as a
  filter driver defined only there, is not covered by the parent overrides. A
  submodule whose checked-out commit moved is still reported; uncommitted edits
  inside a submodule are not.
- Git status and diff summaries no longer report uncommitted edits inside a
  submodule's own work tree (`--ignore-submodules=dirty`); docs/tools.md now
  lists the exact flags and overrides.
- `git_diff_summary` now runs `git diff-files -z --raw --numstat` instead of
  `git diff --numstat` (keeping `--no-ext-diff`, `--no-textconv` and
  `--ignore-submodules=dirty`), so it no longer rewrites `.git/index` (which happened
  even with `GIT_OPTIONAL_LOCKS=0`). Only stat-only rows
  (status M, same mode, 0/0 lines, such as a touched file) are omitted;
  deletions, additions, type changes and mode changes are still reported.

## [1.5.3] - 2026-10-04

- Reject `profile: advanced` when configuration is loaded. It is not an elevated
  mode.
- Document the shipped restricted-profile limits, schema ceilings, inactive
  integration defaults, and the fact that email and IP redaction are off unless
  enabled. The 1.0.0 tag is not a security-fix line.
- Make `doctor` report `attention` when any check warns, instead of `ready`.

## [1.5.2] - 2026-09-20

- Align log-summary and incident default windows with the existing 100-record
  policy limit. Explicit oversized requests remain rejected.
- Repair the Docker proxy image reference, pin its digest, and provide bounded
  temporary storage without removing read-only or capability restrictions.
- Include and select the existing Docker-only container policy in opt-in profiles.
- Read image names from container metadata instead of triggering a disallowed
  image API request through the SDK.
- Add real stdio/HTTP acceptance tests, reproducible container acceptance, and
  release operations documentation with explicit verification limitations.
- Separate completed v1.5 scope from optional future roadmap proposals.

## [1.5.1] - 2026-09-13

- Restore the CycloneDX UUID serial number required by GitHub's SBOM
  attestation parser.
- Validate the SBOM format, specification version, and UUID serial number in
  the build job before the immutable release bundle reaches the protected
  publish job.

## [1.5.0] - 2026-09-12

- Add an opt-in read-only GitHub integration for allowlisted repository,
  issue, and pull-request metadata through bounded API requests.
- Require separate GitHub, external-network, and exact repository allowlist
  authorization before any GitHub request is made.
- Add thread-safe, content-free aggregate request and latency metrics populated
  through the existing audit middleware.
- Add an opt-in Python virtual-environment auditor that reads only bounded
  `pyvenv.cfg` and installed distribution metadata, never executes the target,
  and refuses false missing-dependency claims when evidence is incomplete.
- Combine the pending checkout, Python setup, and artifact upload updates to
  version 7, plus the reviewed development and optional dependency ranges.
- Clarify the README, installation steps, manual startup behavior, and client
  connection process. Keep zero trust and least privilege explicit.
- Remove Kubernetes inspection because kubeconfig credential providers can
  execute commands or persist refreshed credentials outside the tool boundary.
- Remove generation capabilities because they are not read-only inspection.
- Collapse unknown metrics labels into a fixed bucket and apply the central
  response-size boundary to metrics snapshots.
- Reject every authenticated GitHub redirect to keep credentials bound to the
  fixed API origin.
- Add authenticated loopback HTTP with strict host, origin, token, session, and
  request-size controls.

## [1.0.0] - 2026-08-13

First stable release of the secure, local-first, read-only MCP toolbox.

### Added

- MCP stdio server with typed tools, resources, prompts, startup validation,
  safe response contracts, and sanitized audit middleware.
- Deny-by-default profiles, canonical approved-root checks, integration
  allowlists, bounded outputs, and centralized secret redaction.
- Read-only system, filesystem, Git, Docker, log, security, infrastructure,
  and incident evidence tools.
- Native and hardened container workflows, socket-proxy guidance, operator
  diagnostics, and cross-platform task commands.
- Client configuration examples for Codex, Claude Desktop, Claude Code, and
  Visual Studio Code.
- Synthetic demo services, logs, and explicitly non-production insecure
  inventory fixtures.
- GitHub Actions quality, security, documentation, package, SBOM, and protected
  release workflows plus Dependabot and contribution templates.

### Security

- Version 1 exposes no generic shell, mutation, container lifecycle, or remote
  network tool.
- Tool results are treated as untrusted evidence, bounded, redacted, and
  represented through structured contracts.
- GitHub private vulnerability reporting is enabled for confidential reports.

[1.5.1]: https://github.com/chriswayneh/local-mcp-toolbox/compare/v1.5.0...v1.5.1
[1.5.2]: https://github.com/chriswayneh/local-mcp-toolbox/compare/v1.5.1...v1.5.2
[1.5.0]: https://github.com/chriswayneh/local-mcp-toolbox/compare/v1.0.0...v1.5.0
[1.0.0]: https://github.com/chriswayneh/local-mcp-toolbox/releases/tag/v1.0.0
