# Version 1 release checklist

Use this checklist for every Version 1 release. Every checked item should be
evidence-backed, not assumed.

The Version 1.0.0 release record is preserved in the GitHub release and its
attached artifacts. Keep this file as the reusable checklist for later releases
rather than marking the template itself complete.

The current completed scope and actual acceptance results are maintained in
the [v1.5 release record](release-1.5.md). Unchecked boxes below are a reusable
template, not outstanding v1.5 feature requirements.

## Scope and security

- [ ] Confirm the release contains only read-only, typed, bounded tools and no
  generic command executor.
- [ ] Review changes to filesystem, Docker, network, and connected services
  provider boundaries.
- [ ] Update the threat model and an ADR for any boundary expansion.
- [ ] Confirm documentation, examples, and demo fixtures contain no real
  credentials, private paths, customer data, or raw audit output.
- [ ] Confirm `SECURITY.md` has a working private reporting contact.

## Validation

- [ ] `python -m pytest`
- [ ] `python -m ruff format --check .`
- [ ] `python -m ruff check .`
- [ ] `python -m mypy src`
- [ ] `python -m bandit -q -r src`
- [ ] `python -m pip_audit`
- [ ] `python scripts/validate_docs.py`
- [ ] `docker compose --profile core -f compose.yaml config`
- [ ] `python -m build`
- [ ] Generate the CycloneDX SBOM from a clean installation of the built wheel

## Version and release

- [ ] Update the version in `pyproject.toml` and verify it matches release
  notes.
- [ ] Update [README.md](../README.md), [ROADMAP.md](../ROADMAP.md), and the
  tool catalog if the public surface changed.
- [ ] Review dependency updates and the generated CycloneDX SBOM.
- [ ] Merge through a reviewed pull request with all required checks green.
- [ ] Create an annotated `v<version>` tag on the approved commit.
- [ ] Run the protected manual Release workflow with the exact version and
  explicit `RELEASE` confirmation.
- [ ] Verify the generated GitHub release contains exactly the source
  distribution, wheel, `sbom.cdx.json`, and `SHA256SUMS`.
- [ ] Verify build-provenance and SBOM attestations for both distributions.
- [ ] Smoke-test installation from the release artifacts in a clean virtual
  environment before announcing availability.
