# SkillGate Release Checklist

Use this checklist to publish and validate `v0.1.2`. Run commands from a clean
`main` branch unless a step says otherwise.

## What Assistant Cannot Do For You

Assistant can prepare files, run local checks, and build artifacts. Pushing tags,
creating the GitHub Release, moving the stable `v0` tag, and validating GitHub
Actions require your repository credentials and final maintainer approval.
Uploading distributions to npm is intentionally deferred. PyPI publication is an
explicit maintainer step for distribution-ready releases.

## 1. Preflight

Confirm the package version and working tree:

```powershell
git status --short
python -c "import tomllib, pathlib; print(tomllib.loads(pathlib.Path('pyproject.toml').read_text())['project']['version'])"
python -c "from skillgate import __version__; print(__version__)"
```

For `v0.1.2`, both version commands should print `0.1.2`.

Confirm release notes and release-prep state:

```powershell
Select-String -Path CHANGELOG.md -Pattern "## Unreleased"
Select-String -Path docs\sessions\README.md -Pattern "SkillGate Review Sessions"
Select-String -Path .github\workflows\release-binaries.yml -Pattern "needs.resolve-tag.outputs.release_tag"
```

The `Unreleased` entry should describe the final 0.1.2 scope before tagging.

## 2. Tests And Static Checks

```powershell
python -m pytest
python -m ruff check .
python -m ruff format --check .
python tools\update_snapshots.py --check
python tools\validate_social_preview.py
```

If snapshot output changed intentionally, review the artifacts and then run:

```powershell
python tools\update_snapshots.py --accept
```

Commit accepted snapshot changes before releasing.

## 3. Benchmark Fixture Verification

```powershell
skillgate fixtures summary fixtures\benchmark --format text
skillgate fixtures summary fixtures\benchmark --format json
```

Review any mismatches before publishing. Public-pattern fixtures should keep
their reduced examples and machine-readable attribution metadata.

## 4. Package Build Verification

Install release build tools in the active environment if they are not already
available:

```powershell
python -m pip install build twine
```

Remove old local build artifacts if needed, then build the source distribution
and wheel:

```powershell
python -m build
python -m twine check dist\*
```

Inspect the generated artifacts:

```powershell
Get-ChildItem dist
```

The `twine check` command should report that every artifact passed.

## 5. Clean Install Smoke Tests

Create a disposable virtual environment and install the wheel:

```powershell
python -m venv .venv-release
.\.venv-release\Scripts\python -m pip install --upgrade pip
.\.venv-release\Scripts\python -m pip install dist\openevalgate_skillgate-0.1.2-py3-none-any.whl
.\.venv-release\Scripts\skillgate rules list
.\.venv-release\Scripts\skillgate scan fixtures\benchmark\01-safe-documentation-skill
```

Delete `.venv-release` after the smoke test if you do not want to keep it.

Also verify the post-publication user paths from a clean shell after the package
is published:

```powershell
pipx run openevalgate-skillgate rules list
pipx install --force openevalgate-skillgate
skillgate scan fixtures\benchmark\01-safe-documentation-skill
uvx openevalgate-skillgate scan fixtures\benchmark\01-safe-documentation-skill
```

## 6. Create The `v0.1.2` Tag

Make sure local `main` has the exact commit you intend to release:

```powershell
git switch main
git pull --ff-only
git status --short
git tag -a v0.1.2 -m "SkillGate v0.1.2"
git push origin v0.1.2
```

Do not move the stable `v0` tag yet. Move it only after the release and assets
are validated.

## 7. Create The GitHub Release

Create the release from the pushed `v0.1.2` tag in the GitHub UI, or use the
GitHub CLI:

```powershell
gh release create v0.1.2 --title "SkillGate v0.1.2" --notes-file CHANGELOG.md
gh run list --workflow release-binaries.yml --limit 5
```

The release-published event should trigger the release-binary workflow. If it
does not, manually dispatch the workflow against the same tag:

```powershell
gh workflow run release-binaries.yml -f tag=v0.1.2
gh run watch
```

## 8. Verify Release Binary Assets

The release-binary workflow must build from the same tag that receives the
assets. Confirm the workflow uses `needs.resolve-tag.outputs.release_tag` for
build checkout, publish checkout, manifest version, and release upload.
The `darwin-x64` matrix entry should use the current Intel macOS runner label
`macos-15-intel`; do not revert it to deprecated `macos-13`.

After the workflow completes, verify the uploaded assets:

```powershell
gh release view v0.1.2 --json tagName,assets
gh release download v0.1.2 -p skillgate-release.json -D test-outputs\release-v0.1.2
Get-Content test-outputs\release-v0.1.2\skillgate-release.json
```

The release should include:

- `skillgate-release.json`
- `skillgate-linux-x64`
- `skillgate-linux-arm64`
- `skillgate-darwin-x64`
- `skillgate-darwin-arm64`
- `skillgate-win32-x64.exe`

The manifest should record `v0.1.2`, SHA-256 hashes, and positive `size_bytes`
values for every platform asset.

## 9. Verify GitHub Install Paths

Before moving `v0`, verify tagged GitHub installs through the paths customers
may use when they require commit or tag pinning:

```powershell
python -m pip install --force-reinstall "git+https://github.com/charliechenye/SkillGate.git@v0.1.2"
skillgate rules list
pipx run --spec "git+https://github.com/charliechenye/SkillGate.git@v0.1.2" skillgate rules list
$env:SKILLGATE_VERSION="v0.1.2"; npx --yes github:charliechenye/SkillGate#v0.1.2 -- scan .
```

GitHub installs require `git` on the customer machine. For teams that require
immutable installs, replace `v0.1.2` with the full release commit SHA.

## 10. Publish To PyPI

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

## 11. Move And Verify Stable `v0`

After the `v0.1.2` release assets and install paths are validated, move the
stable `v0` compatibility tag:

```powershell
git tag -f v0 v0.1.2
git push origin v0 --force
git ls-remote https://github.com/charliechenye/SkillGate.git refs/tags/v0
git ls-remote https://github.com/charliechenye/SkillGate.git refs/tags/v0.1.2
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

## 12. Deferred npm Publication

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

## 13. Post-Release Verification

Also verify:

- GitHub shows the `v0.1.2` release and the `v0` tag.
- README Action examples use `charliechenye/SkillGate@v0`.
- README install instructions accurately distinguish the current GitHub-tag path
  from the PyPI `pipx install openevalgate-skillgate` path after publication.
- The social preview renders correctly on GitHub.
- Repository description and topics match the README FAQ and discovery notes.
