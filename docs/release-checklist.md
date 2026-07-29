# SkillGate Release Checklist

Use this checklist to publish and validate `v0.1.3`. Run commands from a clean
`main` branch unless a step says otherwise.

## Maintainer Responsibilities

Pushing tags, creating the GitHub Release, moving the stable `v0` tag, and
validating GitHub Actions require maintainer credentials and approval. GitHub
Actions is the only builder and uploader of standalone release assets. Do not
build or upload release assets from a workstation. PyPI and npm publication are
deferred for `v0.1.3`.

## 1. Preflight

Confirm the package version and working tree:

```powershell
git status --short
uv sync --locked --group dev
uv run python -c "import tomllib, pathlib; print(tomllib.loads(pathlib.Path('pyproject.toml').read_text())['project']['version'])"
uv run python -c "from skillgate import __version__; print(__version__)"
```

For `v0.1.3`, both version commands should print `0.1.3`.

Confirm release notes and release-prep state:

```powershell
Select-String -Path CHANGELOG.md -Pattern "## 0.1.3 \(Unreleased\) - Review evidence foundations"
Test-Path docs\release-notes\0.1.3.md
Select-String -Path docs\sessions\README.md -Pattern "SkillGate Review Sessions"
Select-String -Path .github\workflows\release-binaries.yml -Pattern "needs.resolve-tag.outputs.release_tag"
```

Before tagging, change the `0.1.3` heading from `Unreleased` and add the final
release date. The curated GitHub notes live in `docs/release-notes/0.1.3.md`.

## 2. Tests And Static Checks

```powershell
uv run pytest
uv run ruff check .
uv run ruff format --check .
uv run python tools\update_snapshots.py --check
uv run python tools\validate_social_preview.py
npm test
```

If snapshot output changed intentionally, review the artifacts and then run:

```powershell
uv run python tools\update_snapshots.py --accept
```

Commit accepted snapshot changes before releasing.

## 2a. Review Workflow Smoke Tests

Run the user-facing local paths without contacting GitHub or executing scanned
content:

```powershell
uv run skillgate review schema --output test-outputs\skillgate-review.schema.json
uv run skillgate review preinstall examples\preinstall-starter --json-output test-outputs\starter-review.json
uv run skillgate demo skill --output test-outputs\reviewable-skill --validate --scan
uv run skillgate demo mcpb --output test-outputs\reviewable-node.mcpb --scan
```

Confirm the starter packet has a digest, the schema reports version `2`, and
the demos complete without running their reviewed content.

## 3. Benchmark Fixture Verification

```powershell
uv run skillgate fixtures summary fixtures\benchmark --format text
uv run skillgate fixtures summary fixtures\benchmark --format json
```

Review any mismatches before publishing. Public-pattern fixtures should keep
their reduced examples and machine-readable attribution metadata.

## 4. GitHub Package Verification

Do not build the release package locally. The `package-smoke` GitHub Actions job
builds the wheel, runs Twine checks, verifies `py.typed`, installs the wheel in
a clean environment, and exercises the starter review workflow. Confirm that
job passes for the exact release commit before tagging.

## 5. Create The `v0.1.3` Tag

Make sure local `main` has the exact commit you intend to release:

```powershell
git switch main
git pull --ff-only
git status --short
git tag -a v0.1.3 -m "SkillGate v0.1.3"
git push origin v0.1.3
```

Do not move the stable `v0` tag yet. Move it only after the release and assets
are validated.

## 6. Create The GitHub Release

Create the release from the pushed `v0.1.3` tag in the GitHub UI, or use the
GitHub CLI:

```powershell
gh release create v0.1.3 --title "SkillGate v0.1.3" --notes-file docs\release-notes\0.1.3.md
gh run list --workflow release-binaries.yml --limit 5
```

The release-published event triggers the release-binary workflow, which is the
only builder and uploader of standalone assets. If it does not, manually
dispatch the workflow against the same tag:

```powershell
gh workflow run release-binaries.yml -f tag=v0.1.3
gh run watch
```

## 7. Verify Release Binary Assets

The release-binary workflow must build from the same tag that receives the
assets. Confirm the workflow uses `needs.resolve-tag.outputs.release_tag` for
build checkout, publish checkout, manifest version, and release upload.
The `darwin-x64` matrix entry should use the current Intel macOS runner label
`macos-15-intel`; do not revert it to deprecated `macos-13`.

After the workflow completes, verify the uploaded assets:

```powershell
gh release view v0.1.3 --json tagName,assets
gh release download v0.1.3 -p skillgate-release.json -D test-outputs\release-v0.1.3
Get-Content test-outputs\release-v0.1.3\skillgate-release.json
```

The release should include:

- `skillgate-release.json`
- `skillgate-linux-x64`
- `skillgate-linux-arm64`
- `skillgate-darwin-x64`
- `skillgate-darwin-arm64`
- `skillgate-win32-x64.exe`

The manifest should record `v0.1.3`, SHA-256 hashes, and positive `size_bytes`
values for every platform asset.

## 8. Verify GitHub Install Paths

Before moving `v0`, verify tagged GitHub installs through the paths customers
may use when they require commit or tag pinning:

```powershell
python -m pip install --force-reinstall "git+https://github.com/charliechenye/SkillGate.git@v0.1.3"
skillgate rules list
pipx run --spec "git+https://github.com/charliechenye/SkillGate.git@v0.1.3" skillgate rules list
$env:SKILLGATE_VERSION="v0.1.3"; npx --yes github:charliechenye/SkillGate#v0.1.3 -- scan .
```

GitHub installs require `git` on the customer machine. For teams that require
immutable installs, replace `v0.1.3` with the full release commit SHA.

## 9. Deferred PyPI Publication

Do not run this section for `v0.1.3`. GitHub tag installs and GitHub Release
assets are the supported distribution paths for this release. Keep these notes
for a later, explicitly approved PyPI publication.

Use PyPI Trusted Publishing if it is configured for this repository. If Trusted
Publishing is not configured, use a scoped upload token from a clean maintainer
environment.

Optional TestPyPI rehearsal:

```powershell
python -m twine upload --repository testpypi dist\*
python -m pip install --index-url https://test.pypi.org/simple --extra-index-url https://pypi.org/simple openevalgate-skillgate
skillgate rules list
```

For production PyPI:

```powershell
python -m twine upload dist\*
python -m pip install --force-reinstall openevalgate-skillgate
skillgate rules list
pipx run openevalgate-skillgate scan fixtures\benchmark\01-safe-documentation-skill
uvx openevalgate-skillgate scan fixtures\benchmark\01-safe-documentation-skill
```

If a bad distribution is published, prefer yanking the affected file or version
on PyPI with a clear reason rather than deleting history. Then publish a fixed
patch release and update GitHub release notes, README install guidance, and any
public scan reports that mention the affected version.

## 10. Move And Verify Stable `v0`

After the `v0.1.3` release assets and install paths are validated, move the
stable `v0` compatibility tag:

```powershell
git tag -f v0 v0.1.3
git push origin v0 --force
git ls-remote https://github.com/charliechenye/SkillGate.git refs/tags/v0
git ls-remote https://github.com/charliechenye/SkillGate.git refs/tags/v0.1.3
```

Then verify the public examples:

```powershell
npx --yes github:charliechenye/SkillGate#v0 -- scan .
```

In a test repository, verify README and `docs/examples/github-action-minimal.md`
workflows using `charliechenye/SkillGate@v0`, including:

- `step-summary`
- `summary-output`
- `json-output`

## 11. Deferred npm Publication

Do not publish the root npm package until the package name and distribution
strategy are intentionally chosen. The root `package.json` is marked
`"private": true` so `npm publish` is blocked by default.

When npm publication is ready:

```powershell
npm pack --dry-run
npm publish --dry-run
```

Before the real publish, remove `"private": true`, confirm the npm package name,
confirm 2FA, automation token, or npm provenance requirements, and verify the
packed files only include the intended launcher, README, and license. After the
real publish, test from a clean environment with:

```powershell
npx skillgate scan .
```

Only then update README and `docs/node-wrapper.md` to promote bare
`npx skillgate scan .` as a supported install path.

## 12. Post-Release Verification

Also verify:

- GitHub shows the `v0.1.3` release and the `v0` tag.
- README Action examples use `charliechenye/SkillGate@v0`.
- README install instructions accurately distinguish the current GitHub-tag path
  from the PyPI `pipx install openevalgate-skillgate` path after publication.
- The social preview renders correctly on GitHub.
- Repository description and topics match the README FAQ and discovery notes.
