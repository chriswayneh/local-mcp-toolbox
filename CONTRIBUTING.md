# Contributing

Thank you for contributing. This project treats security boundaries as product behavior.

Before opening a pull request, run the formatter, linter, type checker, tests, and security checks described in [CI and release](docs/ci-and-release.md). These checks are enforced by the repository workflows. Keep tools narrow, read-only in Version 1, typed, bounded, and covered by both unit and adversarial tests. Do not add a generic command executor or place real credentials in fixtures.

Use conventional commits and explain user-facing/security impact in pull requests. Changes that expand filesystem, network, Docker, or connected-service access require an ADR and threat-model update.

## Crediting AI tools in commits

From now on, a commit made with AI help carries a `Co-authored-by` trailer for each tool that helped, on its own line at the end of the commit message. Examples:

```text
Co-authored-by: Codex <codex@openai.com>
Co-authored-by: Claude <noreply@anthropic.com>
Co-authored-by: Grok Bot
Co-authored-by: Cursor cloud agent
```

If a tool has an official noreply address, use it. If it does not have one, write the tool name on its own, as in the Grok Bot and Cursor lines above. Do not make up an email address.
