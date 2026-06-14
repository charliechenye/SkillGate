from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "fixtures" / "benchmark"
REGISTRY_COMPARE_FIXTURE = ROOT / "fixtures" / "registry-compare-drift"
TEST_OUTPUTS = ROOT / "test-outputs"
runner = CliRunner()
FAKE_COMMIT_SHA = "0123456789abcdef0123456789abcdef01234567"
FINGERPRINT_ERROR = (
    "policy.waivers.entries.finding.fingerprint must be sha256 followed by "
    "64 lowercase hex characters"
)


def clean_test_dir(name: str) -> Path:
    path = TEST_OUTPUTS / name
    if path.exists():
        for child in sorted(path.rglob("*"), reverse=True):
            if child.is_file():
                child.unlink()
            elif child.is_dir():
                child.rmdir()
        path.rmdir()
    path.mkdir(parents=True)
    return path
