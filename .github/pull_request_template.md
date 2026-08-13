## Summary

Describe the user-visible and security impact.

## Validation

- [ ] Tests pass locally.
- [ ] Formatting, linting, type checking, and security checks pass.
- [ ] Documentation and examples are updated when behavior changes.
- [ ] No credentials, private keys, host-specific data, or raw audit output were added.

## Security boundary review

- [ ] This does not add generic command execution or a write operation.
- [ ] New filesystem, network, Docker, Kubernetes, or AI-provider access is explicit, least-privilege, and documented.
- [ ] An ADR and threat-model update are included if the access boundary expands.
