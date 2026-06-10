from __future__ import annotations

import json
import os
import shutil
import tempfile
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote, urlparse

from skillgate.discovery import REFERENCE_RE, SCRIPT_EXTENSIONS, is_excluded, is_relevant_path

GITHUB_API = "https://api.github.com"
GITHUB_RAW = "https://raw.githubusercontent.com"


class SourceError(RuntimeError):
    pass


@dataclass(frozen=True)
class GitHubRepo:
    owner: str
    repo: str


@dataclass(frozen=True)
class GitHubTreeItem:
    path: str
    type: str


@dataclass
class SparseFetchResult:
    root: Path
    cleanup_path: Path
    fetched_paths: list[str]
    missing_references: list[str]

    def cleanup(self) -> None:
        shutil.rmtree(self.cleanup_path, ignore_errors=True)


def parse_github_repo_url(url: str) -> GitHubRepo:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or parsed.netloc.lower() != "github.com":
        raise SourceError("Expected a GitHub repository URL such as https://github.com/OWNER/REPO")
    parts = [part for part in parsed.path.strip("/").split("/") if part]
    if len(parts) < 2:
        raise SourceError("GitHub URL must include an owner and repository name")
    if len(parts) > 2:
        raise SourceError(
            "GitHub tree/subdirectory URLs are not supported yet; use the repo root URL"
        )
    repo = parts[1][:-4] if parts[1].endswith(".git") else parts[1]
    if not parts[0] or not repo:
        raise SourceError("GitHub URL must include an owner and repository name")
    return GitHubRepo(owner=parts[0], repo=repo)


def request_json(url: str) -> dict[str, object]:
    request = urllib.request.Request(url, headers={"Accept": "application/vnd.github+json"})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raise SourceError(f"GitHub request failed with HTTP {exc.code}: {url}") from exc
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        raise SourceError(f"GitHub request failed: {url}") from exc


def request_text(url: str) -> str:
    request = urllib.request.Request(url, headers={"Accept": "text/plain"})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        raise SourceError(f"GitHub file fetch failed with HTTP {exc.code}: {url}") from exc
    except (urllib.error.URLError, TimeoutError) as exc:
        raise SourceError(f"GitHub file fetch failed: {url}") from exc


def default_branch(repo: GitHubRepo) -> str:
    data = request_json(f"{GITHUB_API}/repos/{repo.owner}/{repo.repo}")
    branch = data.get("default_branch")
    if not isinstance(branch, str) or not branch:
        raise SourceError("GitHub repository metadata did not include a default branch")
    return branch


def github_tree(repo: GitHubRepo, ref: str) -> list[GitHubTreeItem]:
    data = request_json(
        f"{GITHUB_API}/repos/{repo.owner}/{repo.repo}/git/trees/{quote(ref, safe='')}?recursive=1"
    )
    tree = data.get("tree")
    if not isinstance(tree, list):
        raise SourceError(f"GitHub ref was not found or did not return a tree: {ref}")
    items = []
    for item in tree:
        if isinstance(item, dict) and isinstance(item.get("path"), str):
            items.append(GitHubTreeItem(path=item["path"], type=str(item.get("type", ""))))
    return sorted(items, key=lambda item: item.path)


def relevant_remote_paths(items: list[GitHubTreeItem]) -> list[str]:
    return sorted(
        item.path
        for item in items
        if item.type == "blob"
        and not is_excluded(Path(item.path))
        and is_relevant_path(Path(item.path))
    )


def referenced_script_paths(source_path: str, content: str, available_paths: set[str]) -> list[str]:
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
        if Path(candidate).suffix.lower() in SCRIPT_EXTENSIONS and candidate in available_paths:
            references.append(candidate)
    return sorted(set(references))


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


def fetch_github_sparse(url: str, ref: str | None = None) -> SparseFetchResult:
    repo = parse_github_repo_url(url)
    resolved_ref = ref or default_branch(repo)
    tree = github_tree(repo, resolved_ref)
    available_paths = {item.path for item in tree if item.type == "blob"}
    selected_paths = set(relevant_remote_paths(tree))
    fetched: dict[str, str] = {}

    for path in sorted(selected_paths):
        fetched[path] = request_text(raw_url(repo, resolved_ref, path))

    referenced_paths = set()
    for path, content in fetched.items():
        referenced_paths.update(referenced_script_paths(path, content, available_paths))

    missing_references = sorted(path for path in referenced_paths if path not in available_paths)
    for path in sorted(referenced_paths & available_paths):
        if path not in fetched:
            fetched[path] = request_text(raw_url(repo, resolved_ref, path))

    cleanup_path = materialize_sparse_files(fetched)
    return SparseFetchResult(
        root=cleanup_path / "repo",
        cleanup_path=cleanup_path,
        fetched_paths=sorted(fetched),
        missing_references=missing_references,
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
