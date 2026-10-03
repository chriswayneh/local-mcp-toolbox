# Security Policy

## Limits in force

Security fixes are applied to the 1.5.x line on `main`. The running default is the restricted profile in `config/restricted.yml`:

- No approved filesystem roots and no enabled integrations.
- File reads stop at 240,000 bytes, directory scans at 500 entries, responses at 100 records and 262,144 bytes, and subprocess or GitHub calls at 10 seconds.
- Home-directory paths are redacted. Email addresses and IP addresses are not redacted unless the policy enables those options.
- Audit events are capped at 8,192 bytes, segments at 8,388,608 bytes, and closed segments are retained for 30 days.
- HTTP is disabled. `profile: advanced` is rejected at load time.

Schema ceilings and integration-specific defaults are listed in the [security model](docs/security-model.md#limits-in-force). These controls are local policy. They are not an operating-system sandbox, and this repository does not claim a third-party security assessment.

Please do not open public issues for suspected vulnerabilities. Use
[GitHub private vulnerability reporting](https://github.com/chriswayneh/local-mcp-toolbox/security/advisories/new)
to contact the repository maintainer privately.

Include affected version/commit, reproduction steps, impact, and any suggested mitigation. Do not include live credentials, private keys, or sensitive customer data. Reports are acknowledged, investigated, and disclosed on a coordinated timeline.

## Supported versions

| Version | Security fixes |
| --- | --- |
| 1.5.x on `main` | Yes |
| 1.0.0 tag | No. The tag remains published. There is no 1.0 maintenance branch. |
| Earlier prereleases | No |
