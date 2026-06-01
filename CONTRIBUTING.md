# Contributing

Thank you for improving this lab. Contributions should preserve the existing project structure and keep the vulnerable and secure implementations conceptually separated.

## What to Change

- Improve documentation, tests, and lab clarity without changing the overall layout.
- Prefer focused fixes that preserve the current demonstration flow.
- Keep intentional vulnerabilities intact unless the task is specifically to harden them.

## Local Setup

1. Create and activate a Python virtual environment.
2. Install runtime and test dependencies with `pip install -r requirements-dev.txt`.
3. Start the lab stack with `docker compose up -d` when you need live Keycloak testing.

## Testing Expectations

- Run the unit and integration suite with `python -m pytest -v` before opening a pull request.
- Add or update tests whenever you change auth logic, middleware behavior, or documentation that describes a workflow.
- Prefer deterministic unit tests for branch coverage and use the live integration tests only for end-to-end lab behavior.

## Code Style

- Keep changes small and easy to review.
- Match the naming, error handling, and layout already used in the repository.
- Avoid restructuring modules unless it is required to fix the issue.

## Pull Request Checklist

- The README still describes the project accurately.
- Any documentation changes are reflected in [Docs/README.md](Docs/README.md).
- Tests pass locally.
- The change does not alter the intended lab behavior unless that is the goal.

## Security Notes

This repository is meant for research, training, and controlled demonstrations. Do not use the vulnerable server in production or on an untrusted network.