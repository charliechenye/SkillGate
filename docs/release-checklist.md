# SkillGate Release Checklist

Use this checklist to publish and validate `v0.1.1`. Run commands from a clean
`main` branch unless a step says otherwise.

## What Assistant Cannot Do For You

Assistant can prepare files, run local checks, and build artifacts. Pushing tags,
creating the GitHub Release, moving the stable `v0` tag, and validating GitHub
Actions require your repository credentials and final maintainer approval.
Uploading distributions to npm or PyPI is intentionally deferred.

## 1. Preflight

Confirm the package version and working tree:

```powershell
git status --short
python -c "import tomllib, pathlib; print(tomllib.loads(pathlib.Path('pyproject.toml').read_text())['project']['version'])"
python -c "from skillgate import __version__; print(__version__)"
```

For `v0.1.1`, both version commands should print `0.1.1`.

Confirm release notes and release-prep state:

```powershell
Select-String -Path CHANGELOG.md -Pattern "## 0.1.1 - Release consistency and review ergonomics"
Select-String -Path future_steps.md -Pattern "Maintainer Validation And Publication For `v0.1.1`"
Select-String -Path .github\workflows\release-binaries.yml -Pattern "needs.resolve-tag.outputs.release_tag"
```

The `0.1.1` changelog entry should be release-ready, not marked planned.

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

## 5. Optional Clean Install Smoke Test

Create a disposable virtual environment and install the wheel:

```powershell
python -m venv .venv-release
.\.venv-release\Scripts\python -m pip install --upgrade pip
.\.venv-release\Scripts\python -m pip install dist\openevalgate_skillgate-0.1.1-py3-none-any.whl
.\.venv-release\Scripts\skillgate rules list
```

Delete `.venv-release` after the smoke test if you do not want to keep it.

## 6. Create The `v0.1.1` Tag

Make sure local `main` has the exact commit you intend to release:

```powershell
git switch main
git pull --ff-only
git status --short
git tag -a v0.1.1 -m "SkillGate v0.1.1"
git push origin v0.1.1
```

Do not move the stable `v0` tag yet. Move it only after the release and assets
are validated.

## 7. Create The GitHub Release

Create the release from the pushed `v0.1.1` tag in the GitHub UI, or use the
GitHub CLI:

```powershell
gh release create v0.1.1 --title "SkillGate v0.1.1" --notes-file CHANGELOG.md
gh run list --workflow release-binaries.yml --limit 5
```

The release-published event should trigger the release-binary workflow. If it
does not, manually dispatch the workflow against the same tag:

```powershell
gh workflow run release-binaries.yml -f tag=v0.1.1
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
gh release view v0.1.1 --json tagName,assets
gh release download v0.1.1 -p skillgate-release.json -D test-outputs\release-v0.1.1
Get-Content test-outputs\release-v0.1.1\skillgate-release.json
```

The release should include:

- `skillgate-release.json`
- `skillgate-linux-x64`
- `skillgate-linux-arm64`
- `skillgate-darwin-x64`
- `skillgate-darwin-arm64`
- `skillgate-win32-x64.exe`

The manifest should record `v0.1.1`, SHA-256 hashes, and positive `size_bytes`
values for every platform asset.

## 9. Verify GitHub Install Paths

Before moving `v0`, verify tagged installs through the paths customers are
expected to use:

```powershell
python -m pip install --force-reinstall "git+https://github.com/charliechenye/SkillGate.git@v0.1.1"
skillgate rules list
pipx run --spec "git+https://github.com/charliechenye/SkillGate.git@v0.1.1" skillgate rules list
$env:SKILLGATE_VERSION="v0.1.1"; npx --yes github:charliechenye/SkillGate#v0.1.1 -- scan .
```

GitHub installs require `git` on the customer machine. For teams that require
immutable installs, replace `v0.1.1` with the full release commit SHA.

## 10. Move And Verify Stable `v0`

After the `v0.1.1` release assets and install paths are validated, move the
stable `v0` compatibility tag:

```powershell
git tag -f v0 v0.1.1
git push origin v0 --force
git ls-remote https://github.com/charliechenye/SkillGate.git refs/tags/v0
git ls-remote https://github.com/charliechenye/SkillGate.git refs/tags/v0.1.1
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

## 12. Deferred PyPI Publication

Do not upload to PyPI for this GitHub-first release. When you decide to publish
to PyPI later, choose between trusted publishing and credential-based upload,
rebuild clean artifacts, validate them, and upload:

```powershell
python -m build
python -m twine check dist\*
python -m twine upload dist\*
```

If you use TestPyPI first, upload to TestPyPI, install from TestPyPI in a clean
environment, and rebuild clean artifacts before the production PyPI upload. Once
PyPI publication is complete, verify `python -m pip install
openevalgate-skillgate` from a clean environment and update the README so that
command is the first install path.

## 13. Post-Release Verification

Also verify:

- GitHub shows the `v0.1.1` release and the `v0` tag.
- README Action examples use `charliechenye/SkillGate@v0`.
- README install instructions lead with a GitHub-tag install.
- The social preview renders correctly on GitHub.
- Repository description and topics match the README FAQ and discovery notes.
