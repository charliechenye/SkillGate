# GitHub-First Node Wrapper

SkillGate's Python scanner remains the canonical implementation. The Node
wrapper is only a launcher: it downloads a standalone SkillGate binary from the
latest stable GitHub Release, verifies the release manifest checksum, caches the
binary, and forwards CLI arguments.

This path does not require PyPI publication and does not require an npm registry
package. Until a package is published to npm, use the explicit GitHub package
specifier:

```bash
npx --yes github:charliechenye/SkillGate#v0 -- scan .
```

Bare `npx skillgate scan .` is intentionally documented as future work because
it requires an npm package name to be published. The root `package.json` stays
`"private": true` until that publication strategy is chosen.

## Release Assets

Each stable GitHub Release should upload these assets with stable names:

- `skillgate-release.json`
- `skillgate-linux-x64`
- `skillgate-linux-arm64`
- `skillgate-darwin-x64`
- `skillgate-darwin-arm64`
- `skillgate-win32-x64.exe`

The wrapper downloads `skillgate-release.json` from:

```text
https://github.com/charliechenye/SkillGate/releases/latest/download/skillgate-release.json
```

When `SKILLGATE_VERSION` is set, the wrapper downloads from that release tag
instead of `latest`:

```bash
SKILLGATE_VERSION=v0.1.3 npx --yes github:charliechenye/SkillGate#v0 -- scan .
```

## Cache And Verification

The manifest contains the release version, asset names, sizes, and SHA-256
hashes. The wrapper verifies the hash before executing a downloaded binary and
caches binaries by release version.

Downloads are bounded before buffering:

- `skillgate-release.json` is limited to 1 MB.
- Binary downloads are limited by the selected asset's `size_bytes` value.
- Responses with `Content-Length` larger than the limit are rejected.
- Streams that exceed the limit while downloading are aborted.

Network downloads use HTTPS by default. `file:` URLs remain supported for local
tests. Insecure `http:` URLs are rejected unless
`SKILLGATE_ALLOW_INSECURE_HTTP_FOR_TESTS=1` is set for a test-only fixture.

Useful environment variables:

- `SKILLGATE_VERSION`: pin the downloaded binary release tag.
- `SKILLGATE_CACHE_DIR`: choose a cache directory for CI.
- `SKILLGATE_NO_UPDATE_CHECK=1`: run the currently cached binary without
  network access.
- `SKILLGATE_ALLOW_INSECURE_HTTP_FOR_TESTS=1`: allow `http:` downloads only in
  tests.

For immutable environments, pin both the wrapper ref and the binary version:

```bash
SKILLGATE_VERSION=v0.1.3 npx --yes github:charliechenye/SkillGate#FULL_COMMIT_SHA -- scan .
```
