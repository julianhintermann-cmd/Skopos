# Contributing to Skopos

Thanks for your interest in improving Skopos! This document explains how to get
a development environment running and what we expect from contributions.

There is no CLA and no DCO sign-off requirement — opening a pull request means
you agree to license your contribution under the project license (AGPL-3.0).

## Development setup

Requirements:

- Go ≥ 1.24
- Node.js ≥ 22 (for the web UI)
- GNU Make
- Linux for the capture/firewall code paths (macOS/Windows can build and run
  the demo mode, but AF_PACKET and nftables are Linux-only)

```sh
git clone https://github.com/julianhintermann-cmd/skopos
cd skopos
make build        # builds web UI + Go binary into ./bin/skopos
make test         # Go unit tests + web type-check
make run-demo     # starts Skopos with synthetic traffic on :8686 (no privileges needed)
```

Useful targets: `make lint` (golangci-lint + tsc), `make fmt` (gofmt),
`make web-dev` (Vite dev server proxying to a running backend).

Capture and firewall features need privileges. For real-traffic testing run the
built binary with capabilities:

```sh
sudo setcap cap_net_raw,cap_net_admin+eip bin/skopos
bin/skopos serve --config ./config/config.yaml
```

The nftables integration tests run in an isolated network namespace and need
root: `make test-integration` (CI runs them on every pull request).

## Commit conventions

Skopos uses [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/).
CI rejects commits that do not match. Types in use:

| Type       | Use for                                            |
| ---------- | -------------------------------------------------- |
| `feat`     | user-visible features                              |
| `fix`      | bug fixes                                          |
| `docs`     | documentation only                                 |
| `refactor` | code change that neither fixes nor adds behaviour  |
| `test`     | adding or improving tests                          |
| `chore`    | tooling, dependencies, repo housekeeping           |
| `ci`       | CI/CD workflow changes                             |
| `perf`     | performance improvements                           |

Scope is encouraged (`feat(detect): …`, `fix(api): …`). Keep commits atomic:
one logical change per commit, with tests in the same commit as the change
they cover.

## Pull requests

1. Fork and create a feature branch from `main`.
2. Make your change; add or update tests. New features need tests.
3. Update documentation if behaviour or configuration changes
   (`README.md`, `deploy/config.example.yaml`).
4. Run `make lint test` locally.
5. Open the PR with a clear description of the problem and the approach.
   Small, focused PRs are reviewed much faster than large ones.

For larger changes (new detectors, new firewall backends, schema changes),
please open an issue first so the design can be discussed before you invest
significant time.

## Reporting bugs & security issues

- Bugs: use the bug report issue template and include your `config.yaml`
  (redact secrets!), Skopos version, and relevant log output.
- Security vulnerabilities: please do **not** open a public issue — see
  [SECURITY.md](SECURITY.md) for private reporting.

## Code of Conduct

Everyone participating in this project is expected to follow the
[Code of Conduct](CODE_OF_CONDUCT.md).
