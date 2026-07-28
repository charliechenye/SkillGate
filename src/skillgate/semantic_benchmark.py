"""Internal fixture validation and future-rule metrics for semantic linting."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from skillgate.scan import scan_repository
from skillgate.semantic import analyze_semantic_repository, semantic_text_inventory_repository

SEMANTIC_BENCHMARK_SCHEMA_VERSION = "1"
SEMANTIC_RULE_IDS = {"SA001", "SA002"}
FIXTURE_CLASSES = {"positive", "negative", "compatibility", "deferred"}
SOURCE_ROLES = {
    "agent_instruction",
    "tool_description",
    "prompt_template",
    "manifest_metadata",
    "documentation",
    "test_fixture",
    "source_comment",
    "unknown",
}
AGENT_CONSUMPTION = {"direct", "possible", "unlikely"}
_EXPECTATION_KEYS = {
    "schema_version",
    "id",
    "fixture_class",
    "semantic_categories",
    "expected_blocks",
    "expected_existing_rule_ids",
}
_BLOCK_KEYS = {
    "file_path",
    "line_number",
    "end_line",
    "source_role",
    "structured_field",
    "agent_consumption",
}


class SemanticBenchmarkError(ValueError):
    """Raised when the internal semantic corpus is malformed or does not match inventory."""


@dataclass(frozen=True)
class SemanticBenchmarkCase:
    case_id: str
    fixture_class: str
    semantic_categories: tuple[str, ...]
    expected_blocks: tuple[dict[str, object], ...]
    expected_existing_rule_ids: tuple[str, ...]
    artifact_root: Path


def _load_yaml(path: Path) -> dict[str, Any]:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise SemanticBenchmarkError(f"Unable to load semantic benchmark metadata: {path}") from exc
    if not isinstance(data, dict):
        raise SemanticBenchmarkError(f"{path} must contain a mapping")
    return data


def _require_string(data: dict[str, Any], key: str, path: Path) -> str:
    value = data.get(key)
    if not isinstance(value, str) or not value:
        raise SemanticBenchmarkError(f"{path} {key} must be a non-empty string")
    return value


def _string_list(data: dict[str, Any], key: str, path: Path) -> list[str]:
    value = data.get(key)
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        raise SemanticBenchmarkError(f"{path} {key} must be a list of non-empty strings")
    if len(set(value)) != len(value):
        raise SemanticBenchmarkError(f"{path} {key} must not contain duplicates")
    return value


def _validate_block(value: object, path: Path) -> dict[str, object]:
    if not isinstance(value, dict):
        raise SemanticBenchmarkError(f"{path} expected_blocks entries must be mappings")
    unknown = set(value) - _BLOCK_KEYS
    missing = _BLOCK_KEYS - set(value)
    if unknown or missing:
        raise SemanticBenchmarkError(
            f"{path} expected_blocks entries must contain exactly {', '.join(sorted(_BLOCK_KEYS))}"
        )
    file_path = value["file_path"]
    if (
        not isinstance(file_path, str)
        or not file_path
        or Path(file_path).is_absolute()
        or ".." in Path(file_path).parts
    ):
        raise SemanticBenchmarkError(f"{path} expected block file_path must be a relative string")
    for key in ("line_number", "end_line"):
        if not isinstance(value[key], int) or value[key] < 1:
            raise SemanticBenchmarkError(f"{path} expected block {key} must be a positive integer")
    if value["end_line"] < value["line_number"]:
        raise SemanticBenchmarkError(f"{path} expected block end_line must not precede line_number")
    if value["source_role"] not in SOURCE_ROLES:
        raise SemanticBenchmarkError(f"{path} expected block source_role is not supported")
    if value["agent_consumption"] not in AGENT_CONSUMPTION:
        raise SemanticBenchmarkError(f"{path} expected block agent_consumption is not supported")
    if value["structured_field"] is not None and not isinstance(value["structured_field"], str):
        raise SemanticBenchmarkError(
            f"{path} expected block structured_field must be a string or null"
        )
    return {key: value[key] for key in sorted(_BLOCK_KEYS)}


def load_semantic_benchmark_cases(root: Path) -> list[SemanticBenchmarkCase]:
    """Load a fixed-schema, repository-owned semantic fixture corpus."""

    root = root.expanduser().resolve()
    if not root.is_dir():
        raise SemanticBenchmarkError(f"semantic benchmark root must be a directory: {root}")
    cases: list[SemanticBenchmarkCase] = []
    seen_ids: set[str] = set()
    for case_root in sorted(path for path in root.iterdir() if path.is_dir()):
        expectations_path = case_root / "expectations.yaml"
        artifact_root = case_root / "artifact"
        if not expectations_path.is_file() or not artifact_root.is_dir():
            raise SemanticBenchmarkError(
                f"{case_root} must contain expectations.yaml and an artifact directory"
            )
        data = _load_yaml(expectations_path)
        if set(data) != _EXPECTATION_KEYS:
            raise SemanticBenchmarkError(
                f"{expectations_path} must contain exactly {', '.join(sorted(_EXPECTATION_KEYS))}"
            )
        if data["schema_version"] != SEMANTIC_BENCHMARK_SCHEMA_VERSION:
            raise SemanticBenchmarkError(
                f"{expectations_path} schema_version must be {SEMANTIC_BENCHMARK_SCHEMA_VERSION}"
            )
        case_id = _require_string(data, "id", expectations_path)
        if case_id in seen_ids:
            raise SemanticBenchmarkError(f"duplicate semantic benchmark id: {case_id}")
        seen_ids.add(case_id)
        fixture_class = _require_string(data, "fixture_class", expectations_path)
        if fixture_class not in FIXTURE_CLASSES:
            raise SemanticBenchmarkError(f"{expectations_path} fixture_class is not supported")
        categories = _string_list(data, "semantic_categories", expectations_path)
        if not set(categories) <= SEMANTIC_RULE_IDS:
            raise SemanticBenchmarkError(
                f"{expectations_path} semantic_categories contains an unknown rule"
            )
        if fixture_class == "positive" and len(categories) != 1:
            raise SemanticBenchmarkError(
                f"{expectations_path} positive fixtures require exactly one semantic category"
            )
        if fixture_class != "positive" and categories:
            raise SemanticBenchmarkError(
                f"{expectations_path} non-positive fixtures must not reserve semantic categories"
            )
        blocks_data = data.get("expected_blocks")
        if not isinstance(blocks_data, list):
            raise SemanticBenchmarkError(f"{expectations_path} expected_blocks must be a list")
        blocks = tuple(_validate_block(item, expectations_path) for item in blocks_data)
        existing_rule_ids = _string_list(data, "expected_existing_rule_ids", expectations_path)
        cases.append(
            SemanticBenchmarkCase(
                case_id=case_id,
                fixture_class=fixture_class,
                semantic_categories=tuple(sorted(categories)),
                expected_blocks=blocks,
                expected_existing_rule_ids=tuple(sorted(existing_rule_ids)),
                artifact_root=artifact_root,
            )
        )
    if not cases:
        raise SemanticBenchmarkError(f"semantic benchmark root has no cases: {root}")
    return cases


def _inventory_block_data(block: object) -> dict[str, object]:
    return {key: getattr(block, key) for key in sorted(_BLOCK_KEYS)}


def validate_semantic_benchmark_inventory(case: SemanticBenchmarkCase) -> None:
    """Assert that one case exercises exactly its source-selected inventory blocks."""

    inventory = semantic_text_inventory_repository(case.artifact_root)
    if inventory.skipped_files:
        raise SemanticBenchmarkError(f"{case.case_id} inventory unexpectedly skipped source files")
    actual_blocks = tuple(_inventory_block_data(block) for block in inventory.blocks)
    if actual_blocks != case.expected_blocks:
        raise SemanticBenchmarkError(
            f"{case.case_id} inventory blocks did not match its declared expectation"
        )
    actual_rule_ids = {finding.rule_id for finding in scan_repository(case.artifact_root).findings}
    if not set(case.expected_existing_rule_ids) <= actual_rule_ids:
        missing = sorted(set(case.expected_existing_rule_ids) - actual_rule_ids)
        raise SemanticBenchmarkError(
            f"{case.case_id} is missing expected existing static rules: {', '.join(missing)}"
        )
    unexpected_semantic = sorted(rule_id for rule_id in actual_rule_ids if rule_id.startswith("SA"))
    if unexpected_semantic:
        raise SemanticBenchmarkError(
            f"{case.case_id} emitted semantic rules through the static scanner: "
            f"{', '.join(unexpected_semantic)}"
        )


def validate_semantic_benchmark_corpus(cases: Iterable[SemanticBenchmarkCase]) -> None:
    for case in cases:
        validate_semantic_benchmark_inventory(case)


def semantic_benchmark_observations(
    cases: Iterable[SemanticBenchmarkCase],
) -> dict[str, tuple[str, ...]]:
    """Run the library-only semantic detector over every benchmark artifact."""

    return {
        case.case_id: tuple(
            finding.rule_id for finding in analyze_semantic_repository(case.artifact_root).findings
        )
        for case in cases
    }


def semantic_category_metrics(
    cases: Iterable[SemanticBenchmarkCase],
    observed_rule_ids: Mapping[str, Iterable[str]],
) -> dict[str, dict[str, float | int | None]]:
    """Calculate detector quality per reserved semantic rule ID.

    Observations are supplied separately so metric calculation remains
    independently unit-testable from the rule-pack execution harness.
    """

    case_list = list(cases)
    ids = {case.case_id for case in case_list}
    unknown_case_ids = set(observed_rule_ids) - ids
    if unknown_case_ids:
        raise SemanticBenchmarkError(
            f"observations contain unknown cases: {', '.join(sorted(unknown_case_ids))}"
        )
    observations: dict[str, set[str]] = {}
    for case_id, rule_ids in observed_rule_ids.items():
        values = set(rule_ids)
        if not values <= SEMANTIC_RULE_IDS:
            raise SemanticBenchmarkError(f"{case_id} observations contain an unknown semantic rule")
        observations[case_id] = values

    metrics: dict[str, dict[str, float | int | None]] = {}
    for rule_id in sorted(SEMANTIC_RULE_IDS):
        true_positive = false_positive = false_negative = 0
        for case in case_list:
            expected = rule_id in case.semantic_categories
            actual = rule_id in observations.get(case.case_id, set())
            if actual and expected:
                true_positive += 1
            elif actual:
                false_positive += 1
            elif expected:
                false_negative += 1
        precision_denominator = true_positive + false_positive
        recall_denominator = true_positive + false_negative
        precision = true_positive / precision_denominator if precision_denominator else None
        recall = true_positive / recall_denominator if recall_denominator else None
        f1 = (
            2 * precision * recall / (precision + recall)
            if precision is not None and recall is not None and precision + recall
            else None
        )
        metrics[rule_id] = {
            "true_positive": true_positive,
            "false_positive": false_positive,
            "false_negative": false_negative,
            "precision": precision,
            "recall": recall,
            "f1": f1,
        }
    return metrics


def validate_semantic_rule_pack(
    cases: Iterable[SemanticBenchmarkCase],
) -> dict[str, dict[str, float | int | None]]:
    """Enforce the committed corpus as the narrow SA001/SA002 quality gate."""

    case_list = list(cases)
    observations = semantic_benchmark_observations(case_list)
    for case in case_list:
        expected = set(case.semantic_categories)
        actual = set(observations[case.case_id])
        if actual != expected:
            raise SemanticBenchmarkError(
                f"{case.case_id} semantic findings did not match its labeled categories"
            )
    metrics = semantic_category_metrics(case_list, observations)
    for rule_id, values in metrics.items():
        if (
            values["false_positive"]
            or values["false_negative"]
            or values["precision"] != 1.0
            or values["recall"] != 1.0
            or values["f1"] != 1.0
        ):
            raise SemanticBenchmarkError(
                f"{rule_id} does not meet the synthetic corpus quality gate"
            )
    return metrics
