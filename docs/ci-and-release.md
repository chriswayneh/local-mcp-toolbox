# CI and release controls

GitHub Actions checks every pull request and change to `main`; scheduled
security checks run each Monday.  Workflows use read-only permissions unless a
manual release needs to create a GitHub release.

| Workflow | Trigger | Checks and outputs |
| --- | --- | --- |
| `Quality` | Pull requests and `main` | Python 3.12/3.13 install, formatting, lint, typing, and tests. |
| `Security and supply chain` | Pull requests, `main`, weekly schedule, manual | Bandit, pip-audit, and a CycloneDX SBOM artifact. |
| `Documentation` | Documentation/example changes and `main` | Local Markdown links, documented task targets, client-example parsing, and demo Compose safety. |
| `Release` | Manual only | Validates an existing version tag, runs all release checks, builds artifacts and an SBOM, then creates a GitHub release. |

Dependabot checks Python packages and GitHub Actions weekly.  Automated updates
still require the same review and CI checks as any other pull request.

## Local equivalents

Install the release tools once when preparing a package or SBOM:

```powershell
.\.venv\Scripts\python -m pip install -e ".[dev,docker,release]"
.\scripts\tasks.ps1 docs-validate
.\scripts\tasks.ps1 package-build
.\scripts\tasks.ps1 sbom
```

`docs-validate` verifies repository-local Markdown links and confirms that the
documented Make targets exist; it also runs the client/demo asset test.  It does
not execute untrusted snippets found in documentation.

## Release gate

1. Complete [the Version 1 release checklist](release-checklist.md).
2. Update `pyproject.toml` to the intended release version and ensure the
   documentation reflects that behavior.
3. Merge the release candidate through the normal pull-request process.
4. Create and push an annotated `v<version>` tag pointing at the reviewed
   commit.
5. In GitHub Actions, run **Release**, supply the version without `v`, and type
   `RELEASE` exactly.
6. Require approval through the repository's protected `release` environment.
   Configure that environment in GitHub before the first real release.

The workflow checks that `pyproject.toml`, the requested version, and the
checked-out tag agree.  It does not create tags, publish to PyPI, or bypass
branch/environment protection.  A release can be retried only after resolving
the failed validation or deliberately handling an already-created GitHub
release.
