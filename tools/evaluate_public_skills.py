from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import Counter
from pathlib import Path

from skillgate import __version__
from skillgate.discovery import discover_preinstall_paths
from skillgate.models import model_to_data
from skillgate.preinstall import build_preinstall_packet
from skillgate.scan import scan_paths
from skillgate.skills import validate_skills
from skillgate.sources import SourceError, fetch_github_sparse, parse_github_repo_url, request_text

CATALOG = Path(__file__).resolve().parents[1] / "fixtures/public-skills/catalog.json"


def evaluate_sample(sample: dict) -> dict:
    """Read one pinned public artifact; never install or execute its contents."""
    url = sample["source_url"]
    repo = parse_github_repo_url(url)
    if not repo.ref or not re.fullmatch(r"[0-9a-f]{40}", repo.ref):
        raise ValueError("Public acceptance sources must use full immutable commit SHAs")
    license_record = sample["license"]
    license_url = (
        f"https://raw.githubusercontent.com/{repo.owner}/{repo.repo}/{repo.ref}/"
        f"{license_record['path']}"
    )
    license_text = request_text(license_url, max_bytes=1_048_576)
    license_sha256 = hashlib.sha256(license_text.encode("utf-8")).hexdigest()
    sparse = fetch_github_sparse(url)
    try:
        remote = scan_paths(sparse.root, map(Path, sparse.fetched_paths), format_aware=True)
        local = scan_paths(sparse.root, discover_preinstall_paths(sparse.root), format_aware=True)
        skills = validate_skills(
            sparse.root,
            root_directory_name=Path(repo.subpath).name if repo.subpath else repo.repo,
        )
        packet = build_preinstall_packet(
            {
                "kind": "github",
                "reference": url,
                "revision": sparse.manifest["resolved_commit_sha"],
                "metadata": sparse.manifest,
            },
            remote,
            skills,
        )
        files = [
            {key: value for key, value in model_to_data(item).items() if key != "file_type"}
            for item in remote.scanned_files
        ]
        skipped = [
            {"path": item["remote_path"].removeprefix(f"{repo.subpath}/"), "reason": item["reason"]}
            for item in sparse.manifest["skipped_files"]
        ]
        validation_rules = sorted({item["rule_id"] for item in skills["findings"]})
        expected = sample["expected"]
        checks = {
            "revision": sparse.manifest["resolved_commit_sha"] == repo.ref,
            "license": license_sha256 == license_record["sha256"],
            "files": files == expected["files"],
            "skipped_files": skipped == expected["skipped_files"],
            "coverage": packet["metadata"]["coverage"]["status"] == expected["coverage"],
            "validation": validation_rules == expected["validation_rule_ids"],
            "materialized_local_parity": remote == local,
            "repeat_scan": remote
            == scan_paths(sparse.root, map(Path, sparse.fetched_paths), format_aware=True),
            "evidence": all(
                any(
                    all(model_to_data(capability).get(key) == value for key, value in probe.items())
                    for capability in remote.capabilities
                )
                for probe in expected["evidence"]
            ),
        }
        return {
            "id": sample["id"],
            "source_url": url,
            "checks": checks,
            "passed": all(checks.values()),
            "scanned_files": files,
            "skipped_files": skipped,
            "coverage": packet["metadata"]["coverage"],
            "coverage_gate_expected_exit": int(
                packet["metadata"]["coverage"]["status"] != "complete"
            ),
            "finding_counts": dict(
                sorted(Counter(item.rule_id for item in remote.findings).items())
            ),
            "validation_rule_ids": validation_rules,
        }
    finally:
        sparse.cleanup()


def main() -> int:
    parser = argparse.ArgumentParser(description="Opt-in, bounded public skill acceptance checks.")
    parser.add_argument("--catalog", type=Path, default=CATALOG)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    catalog = json.loads(args.catalog.read_text(encoding="utf-8"))
    results = []
    for sample in catalog["samples"]:
        try:
            result = evaluate_sample(sample)
        except (OSError, SourceError, ValueError) as exc:
            result = {"id": sample["id"], "passed": False, "error": str(exc)}
        results.append(result)
        print(f"{sample['id']}: {'pass' if result['passed'] else 'FAIL'}", flush=True)
    payload = {
        "scanner_version": __version__,
        "catalog_sha256": hashlib.sha256(args.catalog.read_bytes()).hexdigest(),
        "method": "Pinned source, license, files, gaps, selected evidence, and local parity",
        "limitations": [
            "Ten selected skills from two publishers; no representative accuracy claim.",
            "Selected static observations; independent human adjudication is pending.",
            "Local parity uses the downloaded supported files, not a full upstream checkout.",
            "Coverage gate exits are derived from packet status; CLI tests remain separate.",
        ],
        "passed": sum(item["passed"] for item in results),
        "total": len(results),
        "results": results,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    return int(payload["passed"] != payload["total"])


if __name__ == "__main__":
    raise SystemExit(main())
