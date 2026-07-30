from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import tempfile
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlparse

from skillgate import __version__
from skillgate.discovery import REFERENCE_RE, SCRIPT_EXTENSIONS, is_excluded, is_relevant_path
from skillgate.mcp_app_assets import _asset_kind, _refs_from_text, _strip_ref_suffix
from skillgate.mcp_apps import inventory_from_json_text
from skillgate.models import SCHEMA_VERSION

GITHUB_API = "https://api.github.com"
GITHUB_RAW = "https://raw.githubusercontent.com"
GIT_SHA_RE = re.compile(r"^[0-9a-fA-F]{40}$")
GITHUB_JSON_MAX_BYTES = 10_485_760


class SourceError(RuntimeError):
    def __init__(self, message: str, manifest: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.manifest = manifest


@dataclass(frozen=True)
class GitHubRepo:
    owner: str
    repo: str
    ref: str | None = None
    subpath: str | None = None


@dataclass(frozen=True)
class GitHubTreeItem:
    path: str
    type: str


@dataclass(frozen=True)
class RemoteScanLimits:
    max_files: int = 100
    max_total_bytes: int = 5_242_880
    max_file_bytes: int = 1_048_576
    request_timeout: int = 30
    redirect_limit: int = 3

    def to_data(self) -> dict[str, int]:
        return {
            "max_files": self.max_files,
            "max_total_bytes": self.max_total_bytes,
            "max_file_bytes": self.max_file_bytes,
            "request_timeout": self.request_timeout,
            "redirect_limit": self.redirect_limit,
        }


@dataclass(frozen=True)
class ResolvedGitHubRef:
    requested_ref: str | None
    resolved_ref: str
    commit_sha: str


@dataclass
class SparseFetchResult:
    root: Path
    cleanup_path: Path
    fetched_paths: list[str]
    missing_references: list[str]
    manifest: dict[str, Any]

    def cleanup(self) -> None:
        shutil.rmtree(self.cleanup_path, ignore_errors=True)


def parse_github_repo_url(url: str) -> GitHubRepo:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or parsed.netloc.lower() != "github.com":
        raise SourceError("Expected a GitHub repository URL such as https://github.com/OWNER/REPO")
    parts = [part for part in parsed.path.strip("/").split("/") if part]
    if len(parts) < 2:
        raise SourceError("GitHub URL must include an owner and repository name")
    repo = parts[1][:-4] if parts[1].endswith(".git") else parts[1]
    if not parts[0] or not repo:
        raise SourceError("GitHub URL must include an owner and repository name")
    if len(parts) == 2:
        return GitHubRepo(owner=parts[0], repo=repo)
    if len(parts) >= 4 and parts[2] == "tree":
        tree_ref = parts[3]
        subpath = normalize_remote_path("/".join(parts[4:])) if len(parts) > 4 else None
        return GitHubRepo(owner=parts[0], repo=repo, ref=tree_ref, subpath=subpath)
    raise SourceError(
        "Expected a GitHub repository URL or tree URL such as "
        "https://github.com/OWNER/REPO/tree/BRANCH/path"
    )


def normalize_remote_path(path: str | None) -> str | None:
    if path is None:
        return None
    parts = []
    for part in path.replace("\\", "/").split("/"):
        if part in {"", "."}:
            continue
        if part == "..":
            raise SourceError("GitHub tree path must not contain '..'")
        parts.append(part)
    return "/".join(parts) or None


def path_within_subpath(path: str, subpath: str | None) -> bool:
    if subpath is None:
        return True
    return path == subpath or path.startswith(f"{subpath}/")


def strip_subpath(path: str, subpath: str | None) -> str:
    if subpath is None:
        return path
    if path == subpath:
        return Path(path).name
    return path.removeprefix(f"{subpath}/")


class LimitedRedirectHandler(urllib.request.HTTPRedirectHandler):
    def __init__(self, redirect_limit: int) -> None:
        self.redirect_limit = redirect_limit
        self.redirect_count = 0

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        self.redirect_count += 1
        if self.redirect_count > self.redirect_limit:
            raise SourceError(f"GitHub request exceeded redirect limit: {req.full_url}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def urlopen_limited(
    request: urllib.request.Request,
    *,
    timeout: int,
    redirect_limit: int,
):
    opener = urllib.request.build_opener(LimitedRedirectHandler(redirect_limit))
    return opener.open(request, timeout=timeout)


def response_content_length(response: Any) -> int | None:
    value = response.headers.get("Content-Length") if hasattr(response, "headers") else None
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def read_response_bounded(response: Any, *, max_bytes: int, description: str, url: str) -> bytes:
    length = response_content_length(response)
    if length is not None and length > max_bytes:
        raise SourceError(f"{description} exceeded maximum response size: {url}")
    data = response.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise SourceError(f"{description} exceeded maximum response size: {url}")
    return data


def request_json(
    url: str,
    timeout: int = 30,
    redirect_limit: int = 3,
) -> dict[str, object]:
    request = urllib.request.Request(url, headers={"Accept": "application/vnd.github+json"})
    try:
        with urlopen_limited(request, timeout=timeout, redirect_limit=redirect_limit) as response:
            data = read_response_bounded(
                response,
                max_bytes=GITHUB_JSON_MAX_BYTES,
                description="GitHub API response",
                url=url,
            )
            return json.loads(data.decode("utf-8"))
    except SourceError:
        raise
    except urllib.error.HTTPError as exc:
        raise SourceError(f"GitHub request failed with HTTP {exc.code}: {url}") from exc
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        raise SourceError(f"GitHub request failed: {url}") from exc


def request_text(
    url: str,
    timeout: int = 30,
    redirect_limit: int = 3,
    max_bytes: int | None = None,
) -> str:
    request = urllib.request.Request(url, headers={"Accept": "text/plain"})
    try:
        with urlopen_limited(request, timeout=timeout, redirect_limit=redirect_limit) as response:
            if max_bytes is None:
                return response.read().decode("utf-8", errors="replace")
            data = read_response_bounded(
                response,
                max_bytes=max_bytes,
                description="GitHub file response",
                url=url,
            )
            return data.decode("utf-8", errors="replace")
    except SourceError:
        raise
    except urllib.error.HTTPError as exc:
        raise SourceError(f"GitHub file fetch failed with HTTP {exc.code}: {url}") from exc
    except (urllib.error.URLError, TimeoutError) as exc:
        raise SourceError(f"GitHub file fetch failed: {url}") from exc


def default_branch(repo: GitHubRepo, limits: RemoteScanLimits | None = None) -> str:
    limits = limits or RemoteScanLimits()
    data = request_json(
        f"{GITHUB_API}/repos/{repo.owner}/{repo.repo}",
        timeout=limits.request_timeout,
        redirect_limit=limits.redirect_limit,
    )
    branch = data.get("default_branch")
    if not isinstance(branch, str) or not branch:
        raise SourceError("GitHub repository metadata did not include a default branch")
    return branch


def github_ref(
    repo: GitHubRepo, ref_kind: str, ref: str, limits: RemoteScanLimits
) -> dict[str, Any]:
    return request_json(
        f"{GITHUB_API}/repos/{repo.owner}/{repo.repo}/git/ref/"
        f"{quote(f'{ref_kind}/{ref}', safe='/')}",
        timeout=limits.request_timeout,
        redirect_limit=limits.redirect_limit,
    )


def peel_ref_object(value: object, limits: RemoteScanLimits) -> str | None:
    if not isinstance(value, dict):
        return None
    sha = value.get("sha")
    object_type = value.get("type")
    if object_type == "commit" and isinstance(sha, str):
        return sha
    url = value.get("url")
    if object_type == "tag" and isinstance(url, str):
        data = request_json(
            url,
            timeout=limits.request_timeout,
            redirect_limit=limits.redirect_limit,
        )
        nested = data.get("object") if isinstance(data, dict) else None
        return peel_ref_object(nested, limits)
    return sha if isinstance(sha, str) and GIT_SHA_RE.fullmatch(sha) else None


def resolve_github_ref(
    repo: GitHubRepo,
    requested_ref: str | None,
    limits: RemoteScanLimits | None = None,
) -> ResolvedGitHubRef:
    limits = limits or RemoteScanLimits()
    resolved_ref = requested_ref or default_branch(repo, limits)
    if GIT_SHA_RE.fullmatch(resolved_ref):
        return ResolvedGitHubRef(
            requested_ref=requested_ref,
            resolved_ref=resolved_ref,
            commit_sha=resolved_ref.lower(),
        )
    errors = []
    for ref_kind in ["heads", "tags"]:
        try:
            data = github_ref(repo, ref_kind, resolved_ref, limits)
        except SourceError as exc:
            errors.append(str(exc))
            continue
        commit_sha = peel_ref_object(data.get("object"), limits)
        if commit_sha:
            return ResolvedGitHubRef(
                requested_ref=requested_ref,
                resolved_ref=resolved_ref,
                commit_sha=commit_sha.lower(),
            )
    details = "; ".join(errors) if errors else "ref did not resolve to a commit"
    raise SourceError(f"Unable to resolve GitHub ref '{resolved_ref}' to a commit SHA: {details}")


def github_tree(
    repo: GitHubRepo, ref: str, limits: RemoteScanLimits | None = None
) -> list[GitHubTreeItem]:
    limits = limits or RemoteScanLimits()
    data = request_json(
        f"{GITHUB_API}/repos/{repo.owner}/{repo.repo}/git/trees/{quote(ref, safe='')}?recursive=1",
        timeout=limits.request_timeout,
        redirect_limit=limits.redirect_limit,
    )
    if data.get("truncated") is True:
        raise SourceError(f"GitHub tree response was truncated for ref: {ref}")
    tree = data.get("tree")
    if not isinstance(tree, list):
        raise SourceError(f"GitHub ref was not found or did not return a tree: {ref}")
    items = []
    for item in tree:
        if isinstance(item, dict) and isinstance(item.get("path"), str):
            items.append(GitHubTreeItem(path=item["path"], type=str(item.get("type", ""))))
    return sorted(items, key=lambda item: item.path)


def relevant_remote_paths(items: list[GitHubTreeItem], subpath: str | None = None) -> list[str]:
    return sorted(
        item.path
        for item in items
        if item.type == "blob"
        and path_within_subpath(item.path, subpath)
        and not is_excluded(Path(item.path))
        and is_relevant_path(Path(strip_subpath(item.path, subpath)))
    )


def referenced_script_paths(source_path: str, content: str, available_paths: set[str]) -> list[str]:
    return sorted(
        reference
        for reference in referenced_script_candidates(source_path, content)
        if reference in available_paths
    )


def referenced_script_candidates(source_path: str, content: str) -> list[str]:
    base = Path(source_path).parent
    references = []
    for match in REFERENCE_RE.finditer(content):
        raw = match.group("path").replace("\\", "/")
        if "://" in raw or raw.startswith("/"):
            continue
        normalized = (base / raw).as_posix()
        parts = []
        for part in normalized.split("/"):
            if part in {"", "."}:
                continue
            if part == "..":
                if parts:
                    parts.pop()
                continue
            else:
                parts.append(part)
        candidate = "/".join(parts)
        if Path(candidate).suffix.lower() in SCRIPT_EXTENSIONS:
            references.append(candidate)
    return sorted(set(references))


def _normalize_remote_ref(source_path: str, raw_ref: str) -> str:
    base = Path(source_path).parent
    normalized = (base / _strip_ref_suffix(raw_ref)).as_posix()
    parts = []
    for part in normalized.split("/"):
        if part in {"", "."}:
            continue
        if part == "..":
            if parts:
                parts.pop()
            else:
                parts.append("..")
        else:
            parts.append(part)
    return "/".join(parts)


def _remote_resource_uri_candidates(source_path: str, uri: str, subpath: str | None) -> list[str]:
    parsed = urlparse(uri)
    candidates: list[str] = []
    prefix = f"{subpath}/" if subpath else ""
    if parsed.scheme == "ui":
        combined = "/".join(part for part in [parsed.netloc, parsed.path.lstrip("/")] if part)
        if combined:
            candidates.append(f"{prefix}{combined}")
        if parsed.path:
            candidates.append(f"{prefix}{parsed.path.lstrip('/')}")
    elif "://" not in uri and not uri.startswith("/"):
        candidates.append(_normalize_remote_ref(source_path, uri))
        candidates.append(f"{prefix}{_strip_ref_suffix(uri)}")
    return sorted(set(candidates))


def referenced_mcp_app_asset_candidates(
    fetched_remote: dict[str, str],
    *,
    subpath: str | None,
) -> list[str]:
    candidates: set[str] = set()
    for source_path, content in sorted(fetched_remote.items()):
        app_inventory = inventory_from_json_text(content)
        for resource in app_inventory.resources:
            for candidate in _remote_resource_uri_candidates(
                source_path, resource.resource_uri, subpath
            ):
                if _asset_kind(candidate):
                    candidates.add(candidate)
        if _asset_kind(source_path):
            for raw_ref in _refs_from_text(source_path, content):
                if "://" in raw_ref or raw_ref.startswith("ui://"):
                    continue
                candidate = _normalize_remote_ref(source_path, raw_ref)
                if _asset_kind(candidate):
                    candidates.add(candidate)
    return sorted(candidates)


def raw_url(repo: GitHubRepo, ref: str, path: str) -> str:
    quoted_path = "/".join(quote(part, safe="") for part in path.split("/"))
    return f"{GITHUB_RAW}/{repo.owner}/{repo.repo}/{quote(ref, safe='')}/{quoted_path}"


def materialize_sparse_files(files: dict[str, str], prefix: str = "skillgate-github-") -> Path:
    temp_root = Path(tempfile.mkdtemp(prefix=prefix))
    scan_root = temp_root / "repo"
    scan_root.mkdir()
    for rel_path, content in sorted(files.items()):
        target = (scan_root / rel_path).resolve()
        try:
            target.relative_to(scan_root.resolve())
        except ValueError as exc:
            raise SourceError(f"Unsafe remote path rejected: {rel_path}") from exc
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8", newline="\n")
    return temp_root


def remote_manifest(
    *,
    source_url: str,
    requested_ref: str | None,
    resolved_ref: str,
    resolved_commit_sha: str,
    limits: RemoteScanLimits,
) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "tool_version": __version__,
        "source_url": source_url,
        "requested_ref": requested_ref,
        "resolved_ref": resolved_ref,
        "resolved_commit_sha": resolved_commit_sha,
        "scan_started_at": datetime.now(UTC)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z"),
        "limits": limits.to_data(),
        "downloaded_files": [],
        "skipped_files": [],
        "summary": {
            "downloaded_file_count": 0,
            "skipped_file_count": 0,
            "total_bytes": 0,
        },
    }


def add_skipped(manifest: dict[str, Any], remote_path: str, reason: str) -> None:
    manifest["skipped_files"].append({"remote_path": remote_path, "reason": reason})
    manifest["summary"]["skipped_file_count"] = len(manifest["skipped_files"])


def add_downloaded(
    manifest: dict[str, Any],
    *,
    remote_path: str,
    materialized_path: str,
    content: str,
    reason: str,
) -> None:
    data = content.encode("utf-8")
    manifest["skipped_files"] = [
        item for item in manifest["skipped_files"] if item["remote_path"] != remote_path
    ]
    manifest["downloaded_files"].append(
        {
            "remote_path": remote_path,
            "materialized_path": materialized_path,
            "sha256": hashlib.sha256(data).hexdigest(),
            "size_bytes": len(data),
            "reason": reason,
        }
    )
    manifest["summary"]["downloaded_file_count"] = len(manifest["downloaded_files"])
    manifest["summary"]["skipped_file_count"] = len(manifest["skipped_files"])
    manifest["summary"]["total_bytes"] = sum(
        item["size_bytes"] for item in manifest["downloaded_files"]
    )


def skipped_remote_paths(
    items: list[GitHubTreeItem],
    selected_paths: set[str],
    subpath: str | None,
) -> list[tuple[str, str]]:
    skipped = []
    for item in items:
        if item.type != "blob" or not path_within_subpath(item.path, subpath):
            continue
        if item.path in selected_paths:
            continue
        stripped = strip_subpath(item.path, subpath)
        if is_excluded(Path(item.path)):
            skipped.append((item.path, "excluded_path"))
        elif not is_relevant_path(Path(stripped)):
            skipped.append((item.path, "unsupported_file"))
    return skipped


def enforce_download_limits(
    manifest: dict[str, Any],
    limits: RemoteScanLimits,
    remote_path: str,
    content: str,
) -> None:
    next_file_count = len(manifest["downloaded_files"]) + 1
    data_size = len(content.encode("utf-8"))
    current_total = int(manifest["summary"]["total_bytes"])
    if next_file_count > limits.max_files:
        add_skipped(manifest, remote_path, "max_files_exceeded")
        raise SourceError("Remote scan incomplete: maximum file count exceeded", manifest)
    if data_size > limits.max_file_bytes:
        add_skipped(manifest, remote_path, "max_file_bytes_exceeded")
        raise SourceError("Remote scan incomplete: maximum individual file size exceeded", manifest)
    if current_total + data_size > limits.max_total_bytes:
        add_skipped(manifest, remote_path, "max_total_bytes_exceeded")
        raise SourceError("Remote scan incomplete: maximum total bytes exceeded", manifest)


def fetch_text_with_limits(
    repo: GitHubRepo,
    commit_sha: str,
    remote_path: str,
    manifest: dict[str, Any],
    limits: RemoteScanLimits,
) -> str:
    try:
        content = request_text(
            raw_url(repo, commit_sha, remote_path),
            timeout=limits.request_timeout,
            redirect_limit=limits.redirect_limit,
            max_bytes=limits.max_file_bytes,
        )
    except SourceError as exc:
        reason = (
            "max_file_bytes_exceeded"
            if "exceeded maximum response size" in str(exc)
            else "download_failed"
        )
        add_skipped(manifest, remote_path, reason)
        raise SourceError(
            f"Remote scan incomplete: failed to download {remote_path}: {exc}", manifest
        ) from exc
    enforce_download_limits(manifest, limits, remote_path, content)
    return content


def fetch_github_sparse(
    url: str,
    ref: str | None = None,
    limits: RemoteScanLimits | None = None,
) -> SparseFetchResult:
    limits = limits or RemoteScanLimits()
    repo = parse_github_repo_url(url)
    requested_ref = ref or repo.ref
    resolved = resolve_github_ref(repo, requested_ref, limits)
    manifest = remote_manifest(
        source_url=url,
        requested_ref=requested_ref,
        resolved_ref=resolved.resolved_ref,
        resolved_commit_sha=resolved.commit_sha,
        limits=limits,
    )
    try:
        tree = github_tree(repo, resolved.commit_sha, limits)
    except SourceError as exc:
        raise SourceError(f"Remote scan incomplete: {exc}", manifest) from exc
    available_paths = {item.path for item in tree if item.type == "blob"}
    selected_paths = set(relevant_remote_paths(tree, repo.subpath))
    for remote_path, reason in skipped_remote_paths(tree, selected_paths, repo.subpath):
        add_skipped(manifest, remote_path, reason)
    fetched_remote: dict[str, str] = {}

    for path in sorted(selected_paths):
        content = fetch_text_with_limits(repo, resolved.commit_sha, path, manifest, limits)
        fetched_remote[path] = content
        add_downloaded(
            manifest,
            remote_path=path,
            materialized_path=strip_subpath(path, repo.subpath),
            content=content,
            reason="relevant_path",
        )

    referenced_paths = set()
    missing_references = set()
    for path, content in fetched_remote.items():
        for reference in referenced_script_candidates(path, content):
            if not path_within_subpath(reference, repo.subpath):
                add_skipped(manifest, reference, "referenced_script_outside_subtree")
            elif reference not in available_paths:
                add_skipped(manifest, reference, "missing_referenced_script")
                missing_references.add(reference)
            else:
                referenced_paths.add(reference)

    if missing_references:
        raise SourceError(
            "Remote scan incomplete: missing referenced scripts: "
            f"{', '.join(sorted(missing_references))}",
            manifest,
        )
    for path in sorted(referenced_paths & available_paths):
        if path not in fetched_remote:
            content = fetch_text_with_limits(repo, resolved.commit_sha, path, manifest, limits)
            fetched_remote[path] = content
            add_downloaded(
                manifest,
                remote_path=path,
                materialized_path=strip_subpath(path, repo.subpath),
                content=content,
                reason="referenced_script",
            )

    unsupported_app_assets = set()
    for path, content in fetched_remote.items():
        app_inventory = inventory_from_json_text(content)
        for resource in app_inventory.resources:
            candidates = _remote_resource_uri_candidates(path, resource.resource_uri, repo.subpath)
            if not candidates or not any(_asset_kind(candidate) for candidate in candidates):
                unsupported_app_assets.add(resource.resource_uri)
    for resource_uri in sorted(unsupported_app_assets):
        add_skipped(manifest, resource_uri, "unsupported_mcp_app_asset")

    fetched_assets: set[str] = set()
    while True:
        next_assets = [
            path
            for path in referenced_mcp_app_asset_candidates(
                fetched_remote,
                subpath=repo.subpath,
            )
            if path not in fetched_remote and path not in fetched_assets
        ]
        if not next_assets:
            break
        for path in next_assets:
            fetched_assets.add(path)
            if path.startswith("../") or not path_within_subpath(path, repo.subpath):
                add_skipped(manifest, path, "mcp_app_asset_outside_subtree")
                continue
            if is_excluded(Path(path)):
                add_skipped(manifest, path, "excluded_path")
                continue
            if path not in available_paths:
                add_skipped(manifest, path, "missing_mcp_app_asset")
                continue
            content = fetch_text_with_limits(repo, resolved.commit_sha, path, manifest, limits)
            fetched_remote[path] = content
            add_downloaded(
                manifest,
                remote_path=path,
                materialized_path=strip_subpath(path, repo.subpath),
                content=content,
                reason="mcp_app_asset",
            )

    fetched = {
        strip_subpath(path, repo.subpath): content
        for path, content in sorted(fetched_remote.items())
    }
    cleanup_path = materialize_sparse_files(fetched)
    return SparseFetchResult(
        root=cleanup_path / "repo",
        cleanup_path=cleanup_path,
        fetched_paths=sorted(fetched),
        missing_references=[],
        manifest=manifest,
    )


def codex_home() -> Path:
    value = os.environ.get("CODEX_HOME")
    if value:
        return Path(value)
    return Path.home() / ".codex"


def installed_skill_roots() -> list[Path]:
    home = codex_home()
    roots = [home / "skills", home / "plugins" / "cache"]
    return [root for root in roots if root.exists()]
