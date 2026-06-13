# SkillGate Release Checklist

Use this checklist for the first public `v0.1.0` GitHub release and later
maintenance releases. Run commands from a clean main branch unless a step says
otherwise.

## What Assistant Cannot Do For You

Assistant can prepare files, run local checks, and build artifacts. Pushing tags and
creating the GitHub Release require your repository credentials and final
maintainer approval. Uploading distributions to PyPI is intentionally deferred
for the first release; if you publish there later, it also requires PyPI
credentials or trusted publisher setup.

## 1. Preflight

Confirm the package version and working tree:

```powershell
git status --short
python -c "import tomllib, pathlib; print(tomllib.loads(pathlib.Path('pyproject.toml').read_text())['project']['version'])"
python -c "from skillgate import __version__; print(__version__)"
```

For `v0.1.0`, both version commands should print `0.1.0`.

Confirm release notes and planning state:

```powershell
Select-String -Path CHANGELOG.md -Pattern "## 0.1.0 - Initial public release"
Select-String -Path CHANGELOG.md -Pattern "## Unreleased"
Select-String -Path future_steps.md -Pattern "Operational Launch Checklist"
```

`CHANGELOG.md` should not contain an `Unreleased` section for this release.

## 2. Tests And Static Checks

```powershell
python -m pytest
python -m ruff check .
python -m ruff format --check .
python tools\update_snapshots.py --check
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
.\.venv-release\Scripts\python -m pip install dist\skillgate-0.1.0-py3-none-any.whl
.\.venv-release\Scripts\skillgate rules list
```

Delete `.venv-release` after the smoke test if you do not want to keep it.

## 6. Create GitHub Tags

Create the immutable release tag:

```powershell
git tag -a v0.1.0 -m "SkillGate v0.1.0"
git push origin v0.1.0
```

Create or move the stable `v0` GitHub Action tag to the same commit:

```powershell
git tag -f v0 v0.1.0
git push origin v0 --force
```

`v0` is a moving compatibility tag for `0.x` releases. Teams that require
immutable GitHub Action references should pin to a full commit SHA instead.

## 7. Create The GitHub Release

Create the release from the pushed `v0.1.0` tag in the GitHub UI, or use the
GitHub CLI:

```powershell
gh release create v0.1.0 dist\* --title "SkillGate v0.1.0" --notes-file CHANGELOG.md
```

Review the rendered release notes before announcing the release.

## 8. Verify GitHub Install Paths

After the tag is pushed, verify tagged installs through the paths customers are
expected to use:

```powershell
python -m pip install "git+https://github.com/charliechenye/SkillGate.git@v0.1.0"
skillgate rules list
pipx install "git+https://github.com/charliechenye/SkillGate.git@v0.1.0"
pipx run --spec "git+https://github.com/charliechenye/SkillGate.git@v0.1.0" skillgate rules list
uv tool install "git+https://github.com/charliechenye/SkillGate.git@v0.1.0"
```

GitHub installs require `git` on the customer machine. For teams that require
immutable installs, replace `v0.1.0` with the full release commit SHA.

## 9. Deferred PyPI Publication

Do not upload to PyPI for the first GitHub-first release. When you decide to
publish to PyPI later, rebuild clean artifacts, validate them, and upload:

```powershell
python -m build
python -m twine check dist\*
python -m twine upload dist\*
```

If you use TestPyPI first, upload to TestPyPI, install from TestPyPI in a clean
environment, and rebuild clean artifacts before the production PyPI upload. Once
PyPI publication is complete, update the README so `python -m pip install
skillgate` is the first install path.

## 10. Post-Release Verification

Also verify:

- GitHub shows the `v0.1.0` release and the `v0` tag.
- README Action examples use `charliechenye/SkillGate@v0`.
- README install instructions lead with a GitHub-tag install.
- The social preview renders correctly on GitHub.
- Repository description and topics match the README SEO and FAQ language.
