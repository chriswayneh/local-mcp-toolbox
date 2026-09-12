# Python Environment Configuration Auditor

## Product requirement

The environment auditor gives an MCP client a bounded, static view of one
operator-approved Python virtual environment without activating it or trusting
its code. It answers one narrow question: does the installed distribution
metadata contain a dependency inconsistency that can be established from the
available evidence?

The tool is disabled by default and accepts only an absolute `environment_path`
and a bounded presentation `limit`. It does not accept an interpreter, command,
requirements file, lockfile, URL, or package selector.

### User stories

- As a developer, I can identify statically missing or version-incompatible
  installed dependencies without executing the target environment.
- As a security-conscious operator, I can authorize dedicated environment roots
  without widening the generic filesystem extension allowlist.
- As an auditor, I can confirm that the request was authorized and completed
  without storing raw paths, package identities, requirements, or credentials in
  the JSONL audit record.
- As a QE, I can distinguish a complete clean observation from incomplete
  evidence and can reproduce deterministic results under configured bounds.

### Acceptance criteria

- The integration is opt-in and rejected by the restricted profile.
- Every requested and derived path remains inside both an approved root and the
  selected environment after canonical resolution.
- Every path component is checked for symbolic links and Windows junctions.
- Directory and file identities are checked before and after inspection.
- The implementation contains no subprocess, shell, target import, interpreter,
  Pip, activation, or network path.
- Only root `pyvenv.cfg` and immediate `.dist-info/METADATA` files in recognized
  Windows or POSIX `site-packages` layouts are opened.
- Only `Name`, `Version`, and bounded `Requires-Dist` headers are parsed.
- Missing, repeated, oversized, or invalid identity headers make metadata
  unusable. Legacy `.egg-info` is counted but never opened.
- Markers, extras, direct references, invalid requirements, duplicate package
  names, system-site-packages, and truncated evidence are reported as
  unverifiable or partial; URLs and raw requirement strings are never returned.
- A dependency is classified as missing only when the package inventory is
  complete. Any incomplete evidence makes the overall assessment `partial`,
  even when another dependency has a confirmed issue.
- All returned strings pass through central redaction and the final UTF-8 byte
  limit. The inspected tree is unchanged after the call.

## Static inspection boundary

The only permitted content paths are:

```text
<venv>/pyvenv.cfg
<venv>/Lib/site-packages/<distribution>.dist-info/METADATA
<venv>/lib/pythonX.Y/site-packages/<distribution>.dist-info/METADATA
```

The implementation never reads package source, `.pth`, `sitecustomize.py`,
activation scripts, `RECORD`, `direct_url.json`, `entry_points.txt`, `WHEEL`,
`INSTALLER`, `REQUESTED`, Pip configuration, or `.egg-info` contents.

## Configuration

```yaml
profile: standard
integrations:
  environment: true
environment:
  approved_roots:
    - C:\absolute\path\to\approved-projects
  blocked_patterns: [".env", ".env.*", "id_rsa", "id_ed25519", "*.pem", "*.key", "credentials*"]
  max_directory_entries: 1000
  max_metadata_files: 500
  max_config_file_bytes: 32768
  max_metadata_file_bytes: 262144
  max_dependency_records: 5000
  max_dependencies_per_distribution: 500
```

The environment root must already exist when the server starts. Prefer the
smallest stable parent directory that contains the virtual environments to be
audited.

## Result semantics

| Assessment | Meaning |
| --- | --- |
| `invalid` | The target could not be safely recognized from a valid `pyvenv.cfg`. |
| `partial` | Some evidence was incomplete or could not be evaluated. Confirmed issue counts remain visible, but absence is not classified as missing. |
| `issues_detected` | Complete inspected metadata proves at least one missing or incompatible dependency. |
| `no_detected_issues` | Complete inspected metadata contained no detected inconsistency. This does not prove runtime health, importability, authenticity, vulnerability status, or safety. |

The response includes bounded package records, abnormal dependency findings,
aggregate counts, warning codes, and explicit presentation/inventory truncation
flags. It deliberately excludes the environment path.

## Edge cases

- Windows, POSIX, multiple POSIX-version, mixed, and missing layouts.
- CRLF and UTF-8-BOM configuration, duplicate keys, unknown system-site-package
  policy, invalid versions, and byte-limit boundaries.
- Duplicate normalized package names, legacy metadata, malformed headers,
  invalid PEP 440 versions, folded requirements, cycles, self-dependencies,
  markers, extras, and credential-bearing direct references.
- Directory, metadata-file, per-distribution dependency, global dependency,
  returned-record, and final encoded-output limits.
- Traversal, outside-root paths, symlinks, junctions, reparse inspection errors,
  path replacement, directory identity drift, and metadata replacement.

## Residual risks

Canonical containment cannot identify an operator-created hard link whose inode
also has a name outside the approved root. On Windows, `O_NOFOLLOW` is not
available, so component reparse checks, descriptor identity checks, and
post-read reauthorization reduce but cannot eliminate every kernel-level race.
Operators should approve trusted parent directories and avoid auditing a target
that is being concurrently installed or modified.
