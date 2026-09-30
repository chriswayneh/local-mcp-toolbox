# Contributing

Thank you for contributing. This project treats security boundaries as product behavior.

Before opening a pull request, run the formatter, linter, type checker, tests, and security checks described in [CI and release](docs/ci-and-release.md). These checks are enforced by the repository workflows. Keep tools narrow, read-only in Version 1, typed, bounded, and covered by both unit and adversarial tests. Do not add a generic command executor or place real credentials in fixtures.

Use conventional commits and explain user-facing/security impact in pull requests. Changes that expand filesystem, network, Docker, or connected-service access require an ADR and threat-model update.
