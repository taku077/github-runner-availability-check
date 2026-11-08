# Public runner availability smoke test

This repository is a standalone, public, **manual-only** GitHub Actions runner availability test.
It contains no private source code, forensic data, credentials, hostnames, monitoring rules,
or private repository references. It does not test or run any private project.

## Purpose

Determine whether GitHub Actions can start the standard hosted runners:
`ubuntu-24.04`, `windows-2022`, and `windows-2025` in an independent public repository.
These standard hosted runners are documented as free for public repositories.
This cannot prove the cause of any private-repository failure or bypass account-level restrictions.

## Run

1. Create a **new independent public** repository on GitHub. Never change an existing private repository's visibility.
2. Upload these files while preserving `.github/workflows/runner-smoke.yml`.
3. Open **Actions > Public standard runner smoke > Run workflow** on the default branch.
4. Check the three jobs and the `RUNNER_START_CONFIRMED` output in each job.
5. Record the exact workflow run URL, UTC time, commit SHA, job names, and results.

Only `workflow_dispatch` is enabled: no automatic runs on push or pull requests.
This workflow uses standard runners, requests only read access, does not checkout code,
does not use external actions or secrets, and has a five-minute per-job timeout.
A result from this public project **does not validate private software**.

Official reference: https://docs.github.com/en/actions/reference/runners/github-hosted-runners

## Publication boundary

No private repository files or Git history may be copied here without independent
file-by-file authorization, an appropriate license, privacy review, and security review.
For this standalone smoke test, no third-party license is needed for dependencies:
no packages or third-party code are vendored. The content is provided as a diagnostic example.
