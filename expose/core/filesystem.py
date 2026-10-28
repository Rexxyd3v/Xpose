import fnmatch
import os
from pathlib import PurePosixPath

DEFAULT_IGNORES = {".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build", ".idea", ".vscode", ".xpose", "report.json", "report.html", "report.sarif", ".xpose-baseline.json"}

def ignored(relative, patterns):
    path = relative.replace("\\", "/").strip("/")
    parts = PurePosixPath(path).parts
    return any(fnmatch.fnmatchcase(path, p.rstrip("/")) or fnmatch.fnmatchcase(path, p.rstrip("/") + "/**") or
               ("/" not in p.rstrip("/") and any(fnmatch.fnmatchcase(part, p.rstrip("/")) for part in parts)) for p in patterns)

def walk_directory(path, ignore_patterns, on_error=None):
    base = os.path.abspath(path)
    for root, dirs, files in os.walk(base, onerror=on_error, followlinks=False):
        dirs[:] = sorted(d for d in dirs if not os.path.islink(os.path.join(root, d)) and not ignored(os.path.relpath(os.path.join(root, d), base), ignore_patterns))
        yield root, dirs, sorted(f for f in files if not ignored(os.path.relpath(os.path.join(root, f), base), ignore_patterns))
