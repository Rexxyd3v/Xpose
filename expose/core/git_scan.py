"""Scan Git objects, including the index, without checking out or executing code."""
import subprocess
from pathlib import Path
from expose.core.filesystem import ignored

def git(root, *args):
    result = subprocess.run(["git", "-C", str(root), *args], capture_output=True, timeout=120)
    if result.returncode:
        raise ValueError("Git operation failed; check the repository, revision, and Git installation.")
    return result.stdout

def repository_root(path):
    if not Path(path).is_dir():
        raise ValueError("Local repository folder does not exist. Enter a folder on your computer, or choose GitHub repository for a remote URL.")
    try:
        return Path(git(path, "rev-parse", "--show-toplevel").decode().strip())
    except ValueError as exc:
        raise ValueError("This folder is not an accessible Git repository. Choose its repository folder, or use Local files to scan a normal folder.") from exc

def scan_tree(scanner, root, ref, paths=None, seen_versions=None, **metadata):
    command = ("ls-files", "--stage", "-z") if ref == ":" else ("ls-tree", "-rz", "--full-tree", ref)
    for entry in git(root, *command).split(b"\0"):
        if not entry:
            continue
        info, raw_path = entry.split(b"\t", 1)
        fields = info.decode().split()
        file = raw_path.decode("utf-8", errors="replace")
        if ignored(file, scanner.ignore_patterns) or (paths is not None and file not in paths):
            continue
        if ref == ":" and fields[2] != "0":
            scanner.errors.append({"file": file, "reason": "unmerged index entry"})
            continue
        if not fields[0].startswith("100"):
            scanner.skipped.append({"file": file, "reason": "symbolic link or submodule"})
            continue
        oid = fields[1] if ref == ":" else fields[2]
        if seen_versions is not None:
            identity = (file, oid)
            if identity in seen_versions:
                continue
            seen_versions.add(identity)
        size = int(git(root, "cat-file", "-s", oid))
        if size > scanner.max_file_size:
            scanner.skipped.append({"file": file, "reason": "file size limit", **metadata})
            continue
        scanner.scan_content(git(root, "cat-file", "blob", oid), file, **metadata)

def scan_staged(scanner, root):
    root = repository_root(root)
    # Compare with HEAD, or an empty tree on an unborn branch, to avoid scanning unchanged files.
    head = subprocess.run(["git", "-C", str(root), "rev-parse", "--verify", "HEAD"], capture_output=True, timeout=30)
    args = ["diff", "--cached", "--name-only", "--diff-filter=ACMRU", "-z"]
    if head.returncode == 0:
        args.append("HEAD")
    paths = {p.decode("utf-8", errors="replace") for p in git(root, *args).split(b"\0") if p}
    scan_tree(scanner, root, ":", paths)

def scan_history(scanner, root, revision="--all", max_commits=0):
    root = repository_root(root)
    if revision.startswith("-") and revision != "--all":
        raise ValueError("Revision must be a Git revision or range.")
    args = ["rev-list", "--topo-order"]
    if max_commits:
        args.append("--max-count=" + str(max_commits))
    args.extend([revision, "--"])
    try:
        commits = git(root, *args).decode().splitlines()
    except ValueError as exc:
        raise ValueError("History could not be read. Check that the repository has commits and that the revision or range exists.") from exc
    if not commits:
        raise ValueError("No commits found for the selected history.")
    seen, seen_versions = set(), set()
    for commit in commits:
        start = len(scanner.findings)
        scan_tree(scanner, root, commit, seen_versions=seen_versions, commit=commit)
        unique = []
        for finding in scanner.findings[start:]:
            if finding["id"] not in seen:
                unique.append(finding)
                seen.add(finding["id"])
        scanner.findings[start:] = unique
    return len(commits)
