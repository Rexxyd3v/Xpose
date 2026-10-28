"""Simple deterministic tree using the scanner exclusion rules."""
from pathlib import Path
from expose.cli.ui import color, safe
from expose.core.filesystem import ignored

def show_tree(path, ignore_patterns, prefix="", root=None, secret_files=None):
    base = Path(root or path)
    items = sorted(p for p in Path(path).iterdir() if not ignored(p.relative_to(base).as_posix(), ignore_patterns))
    for index, item in enumerate(items):
        last = index == len(items) - 1
        label = safe(item.name) + ("/" if item.is_dir() else "")
        if item.relative_to(base).as_posix() in (secret_files or set()):
            label = color(label, "HIGH")
        print(prefix + ("`-- " if last else "|-- ") + label)
        if item.is_dir() and not item.is_symlink():
            show_tree(item, ignore_patterns, prefix + ("    " if last else "|   "), base, secret_files)
