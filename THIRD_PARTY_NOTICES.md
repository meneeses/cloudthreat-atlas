# Third-party notices

CloudThreat Atlas includes open-source dependencies. Their authors retain all
rights granted by their respective licenses.

- Go dependencies linked into the CLI are listed with their complete license
  texts in [`demo/GO_THIRD_PARTY_LICENSES.txt`](demo/GO_THIRD_PARTY_LICENSES.txt).
- JavaScript dependencies bundled into the dashboard are listed with their
  complete license texts in `THIRD_PARTY_LICENSES.md` inside each production
  web build, including the dashboard embedded in the Go binary.

Both artifacts are generated from the dependency versions locked by `go.mod`
and `web/package-lock.json`. They are served by `atlas demo` so a binary-only
distribution retains the applicable notices.
