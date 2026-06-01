# Project TODO

This backlog captures concrete, near-term tasks to keep the project accurate, reproducible, and presentation-ready without changing the core lab concepts.

## Priority A (Immediate)

- [ ] Validate that all documented defaults match runtime settings in secure_server/core/config.py and tests/conftest.py.
- [ ] Add an explicit .env.example file with non-secret placeholders for Keycloak and Postgres variables.
- [ ] Pin and verify Keycloak image version compatibility in documentation and test instructions.
- [ ] Add a one-command local validation target (for example, make test or a script) that runs unit tests and checks formatting.
- [ ] Document exact startup sequence for reproducible demos: infrastructure, secure server, vulnerable server, attack script, and tests.

## Priority B (Short Term)

- [ ] Add a dedicated architecture diagram to Docs with versioned source assets (not only rendered images).
- [ ] Add API contract examples for protected routes, including expected 401 and 403 responses.
- [ ] Add a traceability table from report claims to specific test cases.
- [ ] Add CI workflow for linting and python -m pytest on pull requests.
- [ ] Add dependency review and security scanning workflow (for example, pip-audit and Dependabot).

## Priority C (Medium Term)

- [ ] Add performance-baseline checks for token validation paths.
- [ ] Add structured logging guidance and sample redaction-safe log policy.
- [ ] Add release tagging and changelog policy for educational milestones.
- [ ] Add reproducible report build instructions with a locked TeX toolchain version.
- [ ] Add a contributor onboarding checklist with expected local environment validation.

## Ownership and Tracking

- [ ] Assign an owner and target date to each task.
- [ ] Review this list at least once per sprint or milestone.
- [ ] Move completed items into a dated completion log section.
