from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from conftest import FAKE_COMMIT_SHA, ROOT

from skillgate.sources import SparseFetchResult, parse_github_repo_url
from tools.evaluate_public_skills import evaluate_sample


def test_public_skill_catalog_uses_pinned_sources_and_records_licenses() -> None:
    catalog = json.loads((ROOT / "fixtures/public-skills/catalog.json").read_text())
    assert len(catalog["samples"]) == 10
    assert len({sample["id"] for sample in catalog["samples"]}) == 10
    for sample in catalog["samples"]:
        repo = parse_github_repo_url(sample["source_url"])
        assert repo.ref and len(repo.ref) == 40
        assert sample["license"]["path"]
        assert len(sample["license"]["sha256"]) == 64
        assert sample["expected"]["files"]


@pytest.mark.parametrize("changed_hash", [False, True])
def test_public_acceptance_detects_changed_input_and_cleans_materialized_files(
    tmp_path: Path, monkeypatch, changed_hash: bool
) -> None:
    cleanup = tmp_path / "materialized"
    root = cleanup / "test-skill"
    root.mkdir(parents=True)
    content = b"---\nname: test-skill\ndescription: Static acceptance fixture.\n---\n"
    (root / "SKILL.md").write_bytes(content)
    license_text = "Authored acceptance license fixture.\n"
    sample = {
        "id": "test-skill",
        "source_url": f"https://github.com/example/skills/tree/{FAKE_COMMIT_SHA}/skills/test-skill",
        "license": {
            "path": "LICENSE",
            "sha256": hashlib.sha256(license_text.encode()).hexdigest(),
        },
        "expected": {
            "files": [
                {
                    "path": "SKILL.md",
                    "sha256": "0" * 64 if changed_hash else hashlib.sha256(content).hexdigest(),
                    "size_bytes": len(content),
                }
            ],
            "skipped_files": [],
            "coverage": "complete",
            "validation_rule_ids": [],
            "evidence": [],
        },
    }
    sparse = SparseFetchResult(
        root=root,
        cleanup_path=cleanup,
        fetched_paths=["SKILL.md"],
        missing_references=[],
        manifest={"resolved_commit_sha": FAKE_COMMIT_SHA, "skipped_files": []},
    )
    monkeypatch.setattr("tools.evaluate_public_skills.request_text", lambda *_a, **_k: license_text)
    monkeypatch.setattr("tools.evaluate_public_skills.fetch_github_sparse", lambda _url: sparse)

    result = evaluate_sample(sample)

    assert result["passed"] is not changed_hash
    assert result["checks"]["files"] is not changed_hash
    assert result["checks"]["materialized_local_parity"] is True
    assert result["coverage_gate_expected_exit"] == 0
    assert not cleanup.exists()


def test_public_acceptance_rejects_mutable_refs_before_network_access(monkeypatch) -> None:
    def unexpected_request(*_args, **_kwargs):
        pytest.fail("A mutable source must be rejected before fetching")

    monkeypatch.setattr("tools.evaluate_public_skills.request_text", unexpected_request)
    with pytest.raises(ValueError, match="immutable commit SHAs"):
        evaluate_sample({"source_url": "https://github.com/example/skills/tree/main/skills/test"})
