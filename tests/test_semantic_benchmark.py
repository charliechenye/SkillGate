from __future__ import annotations

from collections import Counter
from pathlib import Path

import pytest
from conftest import ROOT

from skillgate.semantic_benchmark import (
    SemanticBenchmarkError,
    load_semantic_benchmark_cases,
    semantic_category_metrics,
    validate_semantic_benchmark_corpus,
    validate_semantic_benchmark_inventory,
)

SEMANTIC_FIXTURES = ROOT / "fixtures" / "semantic-artifacts"


def test_semantic_benchmark_corpus_has_the_reviewed_case_mix() -> None:
    cases = load_semantic_benchmark_cases(SEMANTIC_FIXTURES)

    assert len(cases) == 24
    assert Counter(case.fixture_class for case in cases) == {
        "positive": 12,
        "negative": 6,
        "compatibility": 4,
        "deferred": 2,
    }
    assert Counter(category for case in cases for category in case.semantic_categories) == {
        "SA001": 6,
        "SA002": 6,
    }


def test_semantic_benchmark_inventory_is_deterministic_and_preserves_sg007() -> None:
    cases = load_semantic_benchmark_cases(SEMANTIC_FIXTURES)

    validate_semantic_benchmark_corpus(cases)
    for case in cases:
        validate_semantic_benchmark_inventory(case)


def test_semantic_metrics_are_isolated_by_reserved_category() -> None:
    cases = load_semantic_benchmark_cases(SEMANTIC_FIXTURES)
    sa001_case = next(case for case in cases if case.semantic_categories == ("SA001",))
    sa002_case = next(case for case in cases if case.semantic_categories == ("SA002",))
    negative_case = next(case for case in cases if case.fixture_class == "negative")

    metrics = semantic_category_metrics(
        cases,
        {
            sa001_case.case_id: ["SA001"],
            sa002_case.case_id: ["SA002"],
            negative_case.case_id: ["SA001"],
        },
    )

    assert metrics["SA001"] == {
        "true_positive": 1,
        "false_positive": 1,
        "false_negative": 5,
        "precision": 0.5,
        "recall": pytest.approx(1 / 6),
        "f1": 0.25,
    }
    assert metrics["SA002"] == {
        "true_positive": 1,
        "false_positive": 0,
        "false_negative": 5,
        "precision": 1.0,
        "recall": pytest.approx(1 / 6),
        "f1": pytest.approx(2 / 7),
    }


def _write_case(root: Path, name: str, expectations: str) -> None:
    artifact = root / name / "artifact"
    artifact.mkdir(parents=True)
    (artifact / "SKILL.md").write_text("Review the supplied files.\n", encoding="utf-8")
    (artifact.parent / "expectations.yaml").write_text(expectations, encoding="utf-8")


def test_semantic_benchmark_rejects_invalid_metadata_and_duplicate_ids(tmp_path: Path) -> None:
    invalid = tmp_path / "invalid"
    _write_case(
        invalid,
        "01-invalid",
        "\n".join(
            [
                'schema_version: "1"',
                "id: 01-invalid",
                "fixture_class: positive",
                "semantic_categories: [SA999]",
                "expected_blocks: []",
                "expected_existing_rule_ids: []",
            ]
        )
        + "\n",
    )
    with pytest.raises(SemanticBenchmarkError, match="unknown rule"):
        load_semantic_benchmark_cases(invalid)

    duplicate = tmp_path / "duplicate"
    for name in ("01-first", "02-second"):
        _write_case(
            duplicate,
            name,
            "\n".join(
                [
                    'schema_version: "1"',
                    "id: duplicate-id",
                    "fixture_class: negative",
                    "semantic_categories: []",
                    "expected_blocks: []",
                    "expected_existing_rule_ids: []",
                ]
            )
            + "\n",
        )
    with pytest.raises(SemanticBenchmarkError, match="duplicate semantic benchmark id"):
        load_semantic_benchmark_cases(duplicate)


def test_semantic_benchmark_rejects_blocks_outside_the_selected_inventory(tmp_path: Path) -> None:
    root = tmp_path / "outside-source"
    artifact = root / "01-unselected-readme" / "artifact"
    artifact.mkdir(parents=True)
    (artifact / "README.md").write_text("Documentation only.\n", encoding="utf-8")
    (artifact.parent / "expectations.yaml").write_text(
        "\n".join(
            [
                'schema_version: "1"',
                "id: 01-unselected-readme",
                "fixture_class: negative",
                "semantic_categories: []",
                "expected_blocks:",
                "  - file_path: README.md",
                "    line_number: 1",
                "    end_line: 1",
                "    source_role: documentation",
                "    structured_field: null",
                "    agent_consumption: unlikely",
                "expected_existing_rule_ids: []",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    case = load_semantic_benchmark_cases(root)[0]

    with pytest.raises(SemanticBenchmarkError, match="inventory blocks did not match"):
        validate_semantic_benchmark_inventory(case)
