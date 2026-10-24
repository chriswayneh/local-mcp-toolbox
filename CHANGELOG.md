# Changelog

All notable changes to Local MCP Toolbox are documented here. The project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

- On Windows, `security_audit_agent_configs` and `audit-agent-configs` now
  check the real path of each file they open, the same way the Bandit snapshot
  does, and skip the file unless it is the checked path inside the approved
  root. This closes a race where a folder swapped for a link during the open
  could make the auditor read a file outside the root.

- On Windows, `security_scan_repository` now asks Windows for the real path of
  each file it opened for the Bandit snapshot and copies the file only if that
  path is the checked one inside the approved root. This closes the small race
  where a folder swapped for a link during the open could leak a file from
  outside the root. If the path cannot be read, the file is skipped (issue #43).
- `git_repository_status` now reports the real branch name in a new repository
  that has no commits yet. Before, it returned Git's sentence
  `No commits yet on main` as the branch name.

## [1.6.0] - 2026-10-23

- Add `security_audit_agent_configs` and the `local-mcp-toolbox audit-agent-configs`
  CLI command to statically audit agent instruction files (`SKILL.md`, `AGENTS.md`,
  `CLAUDE.md`, `.cursorrules`, `.github/copilot-instructions.md`, and related rules)
  and MCP client configuration files (`.mcp.json`, `mcp.json`,
  `claude_desktop_config.json`) across five deterministic categories:
  `hidden_unicode`, `prompt_override`, `dangerous_execution`, `credential_or_exfil`,
  and `mcp_config_risk`.
- Add synthetic benign and risky agent configuration fixtures under
  `demo/agent-configs/`.
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
- Git tools now pin Git to the approved repository: they pass explicit
  `--git-dir=<repo>/.git` and `--work-tree=<repo>`, set
  `GIT_CEILING_DIRECTORIES`, and refuse a repository whose `.git` is a file
  (`gitdir: ...`) or a symlink. Before, a repository-local `core.worktree` or a
  `.git` file could point Git at a directory or repository outside the
  allowlist. Linked worktrees and submodule checkouts can no longer be approved
  directly; approve the main working tree instead.
- Git tools also refuse a `.git` directory that contains a `commondir` file, or
  whose `objects/info/alternates` points outside the approved repository, since
  either makes Git read refs, objects, or config from somewhere else.
- The alternates check follows the whole alternates chain, including relative
  entries, so a store inside the repository cannot forward to one outside.
  Every refusal now names its reason (symlinked `.git`, `gitdir:` file from a
  linked worktree or submodule checkout, `commondir`, or outside alternates such
  as `git clone --shared`/`--reference`).
- A symlink at `.git/objects`, `refs`, `HEAD`, `config`, `packed-refs`, `logs`,
  `info`, or `worktrees` is refused, and `objects` and `refs` must resolve
  inside the repository. The containment check runs again right before Git
  starts and after it exits, and if the `.git` directory, its object or ref
  store, `commondir`, or alternates changed in between, the output is discarded
  and the call is refused.
- A symlink anywhere under `.git/objects` or `.git/refs` (for example a loose
  object fan-out directory or `objects/pack`) is refused. `http-alternates` and a
  `GIT_ALTERNATE_OBJECT_DIRECTORIES` setting in the server environment each get
  their own refusal reason.
- Git runs with `GIT_COMMON_DIR` and `GIT_OBJECT_DIRECTORY` pinned. On Linux it
  reads objects through a private view of descriptors opened without following
  links, closing the race where `objects/pack` was swapped for a symlink while
  Git ran. The full containment check now runs once per call; before and after
  exec a cheap fingerprint of object and ref directories must still match, and
  the cost does not grow with the number of packs. In-repository alternate
  object stores receive the same symlink, loose-object, and pack checks and get
  their own descriptor-pinned private views, and the `.git` directory
  fingerprint includes `st_ctime_ns` so `os.utime()` cannot mask a mid-run swap.
  The remaining accepted risk (hardlinked packs or objects) is documented in the
  security model.
- A symlinked or non-regular loose object anywhere under `.git/objects/<hh>/`
  (or an in-repository alternate store) is refused, and repositories with more
  than 50,000 loose objects across all stores are refused with a "run `git gc`"
  message. Non-regular files (such as FIFOs) in `.git` metadata (`HEAD`,
  `packed-refs`, `config`, `index`, `objects/info/alternates`), `refs`, or
  `objects/pack` are refused and metadata files are opened non-blocking, so a
  planted FIFO can no longer hang the server.
- **Git tools are now Linux-only.** On macOS and Windows they refuse with
  `UNSUPPORTED_OPERATION` and never start Git, because there a `.git` folder
  swapped and quickly swapped back while Git runs could go unnoticed and leak
  another repository's data. Run the toolbox in the Linux container to use them
  on those hosts. Tracked in [#44](https://github.com/chriswayneh/local-mcp-toolbox/issues/44).
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
- Over-long or post-redaction-expanded audit identifiers (`request_id`,
  `tool_name`, `tool_module`, `client_identifier`) and argument keys no longer
  break the request or drop the audit record; values exceeding their field limit
  before or after redaction are stored as a deterministic `sha256:` digest, and
  dictionary keys in audit summaries and `Redactor.redact_value` are redacted
  and counted alongside values.
- Docker container logs are now redacted before they are cut to the size limit.
  Before, the logs were cut first, which could split a token in half at the
  cut, and neither half was recognized as a secret. Now the whole tail is
  redacted first and the cleaned text is trimmed afterwards.

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

[Unreleased]: https://github.com/chriswayneh/local-mcp-toolbox/compare/v1.6.0...HEAD
[1.6.0]: https://github.com/chriswayneh/local-mcp-toolbox/compare/v1.5.3...v1.6.0
[1.5.3]: https://github.com/chriswayneh/local-mcp-toolbox/compare/v1.5.2...v1.5.3
[1.5.1]: https://github.com/chriswayneh/local-mcp-toolbox/compare/v1.5.0...v1.5.1
[1.5.2]: https://github.com/chriswayneh/local-mcp-toolbox/compare/v1.5.1...v1.5.2
[1.5.0]: https://github.com/chriswayneh/local-mcp-toolbox/compare/v1.0.0...v1.5.0
[1.0.0]: https://github.com/chriswayneh/local-mcp-toolbox/releases/tag/v1.0.0
