# CI and release controls

GitHub Actions checks every pull request and change to `main`; scheduled
security checks run each Monday. Workflows use read-only permissions unless the
protected publish job needs to attest artifacts and create a GitHub release.
Third-party actions are pinned to reviewed commit SHAs, checkout credentials are
not persisted, and every job has a timeout and concurrency policy.

| Workflow | Trigger | Checks and outputs |
| --- | --- | --- |
| `Quality` | Pull requests and `main` | Ubuntu Python 3.12/3.13/3.14 plus Windows Python 3.12 install, formatting, lint, typing, and tests. |
| `Security and supply chain` | Pull requests, `main`, weekly schedule, manual | Bandit, pip-audit, and a CycloneDX SBOM artifact. |
| `Documentation` | Documentation/example changes and `main` | Local Markdown links, documented task targets, client-example parsing, and demo Compose safety. |
| `Release` | Manual only | A read-only build job validates an annotated tag on `main`, runs release checks, smoke-tests the wheel outside the source tree, and uploads a short-lived checksummed bundle. A protected publish job verifies that exact bundle, creates provenance and SBOM attestations, then creates the GitHub release. |

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
   commit on protected `main`.
5. From the matching `v<version>` workflow ref in GitHub Actions, run
   **Release**, supply the version without `v`, and type `RELEASE` exactly.
6. Require approval through the repository's protected `release` environment.
   Configure that environment to allow deployments only from the protected
   release-tag pattern before the first real release. Protect release tags from
   force updates or deletion with a repository ruleset.

The workflow rejects non-canonical versions, dispatch refs other than the exact
requested `v<version>` tag, lightweight tags, tags whose commit differs from
the dispatch SHA or is not on `main`, and disagreements between the tag,
checkout, input, and `pyproject.toml`. The build job has only `contents: read`
permission and uploads one immutable artifact by ID containing exactly the
wheel, source distribution, an SBOM generated from a clean wheel installation,
and `SHA256SUMS`. The protected `release` environment gates a separate publish
job; only that job receives `contents`, attestation, artifact metadata, and OIDC
write permissions.

Before publication, GitHub verifies the uploaded artifact digest, the job
rejects extra files, and every distributable artifact is rechecked against
`SHA256SUMS`. The protected job checks the exact annotated tag object and
current `main` ancestry before attestation and again immediately before release
creation. Build-provenance attestations cover the release bundle, and the
CycloneDX SBOM is separately attested to both Python distributions. The
workflow refuses to overwrite an existing release. It does not create tags,
publish to PyPI, or bypass branch/environment protection.
