# Contributing to Veyl

Veyl is a Go/Linux project. Focus contributions on the documented behavior and
keep changes small enough to review. Read the [architecture](docs/architecture.md)
and [security model](docs/security.md) before changing authorization or storage.

## Development setup

Use the Go version in [go.mod](go.mod) or newer. Install gocryptfs, fuse3
(`fusermount3`) and a graphical pinentry. Real mount tests require read/write
access to `/dev/fuse`, a kernel supporting `openat2` and `statx` mount IDs, and
permission to create user FUSE mounts and Unix sockets. Run as a normal user;
the CLI deliberately rejects root mounting.

From a local checkout:

```sh
go mod download
go build -buildvcs=false -o bin/veyl ./cmd/veyl
./bin/veyl help
```

Use `go install ./cmd/veyl/` to update your installed CLI after changes.
See [first run](docs/quick-start.md) for a new isolated demonstration store.
Never use personal stores for development tests.

## Repository structure

- `cmd/veyl`: CLI entry point and full CLI integration test.
- `internal/app`: setup/configuration/discovery, control socket, user service and foreground lifecycle.
- `internal/auth`, `internal/credential`, `internal/policy`: authentication,
  credential input and session authorization.
- `internal/storage`: gocryptfs processes, mount ownership and cleanup.
- `internal/ghostfs`, `internal/mountpoint`: FUSE namespace and path validation.
- `docs`: user guides, architecture, security model and troubleshooting.

## Checks

Format changed Go files with `gofmt -w`, then run:

```sh
go test -count=1 ./...
go test -race -count=1 ./...
go test -tags=integration -count=1 -v ./...
go test -race -tags=integration -count=1 -v ./...
go vet ./...
go build -buildvcs=false -o bin/veyl ./cmd/veyl
```

Most unit tests do not need FUSE. Tagged integration tests initialize new
synthetic encrypted stores and exercise actual mounts, reads, revocation and
cleanup. Credential tests use deterministic pinentry helpers and PTYs; they do
not establish that a physical GUI dialog works on your desktop. Test setup may
lower gocryptfs work factors for disposable fixtures only.

Run these checks sequentially. Keep temporary mount fixtures dot-prefixed so Go
package discovery cannot traverse live test filesystems. Avoid other recursive
repository scans while mount tests run. Desktop visibility/eject tests intentionally
use isolated non-dot fixture names: GNOME ignores dot paths regardless of the
visibility hint. These fixtures are removed only after confirmed unmount.

Inspect verbose output for `SKIP`: a passing suite with mount/socket tests
skipped does not verify those paths. Use a native Linux environment when a
container or sandbox blocks FUSE or Unix sockets. Report failures and skips in
your PR. If a test retains a fixture after cleanup failure, inspect mount
metadata and follow [recovery instructions](docs/troubleshooting.md); never
recursively delete a possible plaintext mount.

For service changes, use only an isolated synthetic store and user-service test
resources. Do not restart your real desktop target to test logout behavior; a
dedicated user target can exercise the same PartOf stop/start relationship. Wait
for the dependent Veyl unit to become inactive before asserting cleanup: stopping
a target can return before its dependent stop finishes. Remove only test-created
unit files/links after disabling and confirming all mounts are gone. Never change
unrelated services or enable lingering. See [service lifecycle](docs/service.md).

## Local build metadata and source-only publication

The development version remains `0.1.0-rc.1`. To build locally with the checkout
commit and UTC build time embedded:

```sh
sh scripts/build-release.sh 0.1.0-rc.1 bin/veyl
./bin/veyl version
```

Despite its historical name, this script only builds a local executable. It
never creates a tag, release, package, or upload. A checkout with no commit
reports `unknown`; ordinary `go install` builds report an unknown build time.

`.github/workflows/release.yml` is retained as a manually dispatched source-check
workflow. It runs tests and vet, checks formatting, and uploads no artifacts.
There are no push/tag triggers or automatic publishing/deployment steps. This
first publication contains source only; it does not establish a stable release.

Before proposing files for a public commit, inspect the complete file list.
Ignore rules are a precaution, not a substitute for checking for real stores,
plaintext mounts, credentials, local configuration and private logs. Preserve
synthetic test fixtures and security design documentation.

## Code conventions

Use standard Go formatting and descriptive package/function/test names. Add
focused tests for changed behavior and regressions, and update affected docs.
Keep dependency changes justified by the actual change.

Preserve explicit read-only configuration, session epochs, descriptor/mount identity
checks, lock ordering and retained ownership on cleanup failure. Do not log
credentials, pass them through argv/environment, or introduce plaintext password
files. Do not remove safety checks merely to make a test run in a restricted
environment. Security-sensitive changes should explain their assumptions.

## Pull requests and bug reports

Open a pull request with the problem, resulting behavior, relevant test commands
and results, and any known limitations. Include a small reproduction when useful.
Avoid unrelated refactoring or generated binaries. Changes are welcome without
assuming a particular review schedule or response time.

For ordinary bugs, open a GitHub issue with Veyl/Go versions, Linux distribution
and kernel, dependency versions, exact commands, expected/actual behavior and
whether FUSE is available. Use a synthetic reproduction; redact personal paths,
configuration details and logs as needed. Never include passwords, plaintext
personal files, real encrypted stores or private runtime directories.

For vulnerabilities, follow [SECURITY.md](SECURITY.md) instead of posting exploit
details publicly.
