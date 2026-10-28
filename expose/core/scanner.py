"""Shared file/content scanner with explicit completeness accounting."""
import hashlib
import os
from pathlib import Path
from expose.core.detector import Detector
from expose.core.filesystem import DEFAULT_IGNORES, walk_directory

class Scanner:
    def __init__(self, rules, ignore_patterns=(), max_file_size=2_000_000, retain_secrets=False):
        self.detector = Detector(rules)
        self.ignore_patterns = DEFAULT_IGNORES | set(ignore_patterns)
        self.max_file_size = max_file_size
        self.findings, self.skipped, self.errors = [], [], []
        self.files_scanned = 0
        self.retain_secrets = retain_secrets
        self.revealed = {}

    def scan_content(self, content, file, **metadata):
        if len(content) > self.max_file_size:
            self.skipped.append({"file": file, "reason": "file size limit"})
            return
        if b"\0" in content:
            self.skipped.append({"file": file, "reason": "binary file"})
            return
        try:
            text = content.decode("utf-8-sig")
        except UnicodeDecodeError:
            self.errors.append({"file": file, "reason": "unsupported text encoding; use UTF-8"})
            return
        self.files_scanned += 1
        values = []
        matches = self.detector.find_secrets(text, on_secret=values.append if self.retain_secrets else None, source_path=file)
        for index, match in enumerate(matches):
            digest = match.pop("secret_hash")
            line_number = match.pop("line_offset", 0) + 1
            fingerprint = hashlib.sha256((file + "\0" + match["rule_id"] + "\0" + digest).encode("utf-8")).hexdigest()
            if self.retain_secrets:
                self.revealed[fingerprint] = values[index]
            self.findings.append({**match, "id": fingerprint, "file": file, "line": line_number, **metadata})

    def scan(self, path):
        path = Path(path).resolve()
        if not path.exists():
            raise ValueError("Scan target does not exist: " + str(path))
        self.findings, self.skipped, self.errors = [], [], []
        self.files_scanned = 0
        self.revealed.clear()
        def walk_error(error):
            self.errors.append({"file": os.path.relpath(error.filename, path), "reason": "directory could not be read"})
        if path.is_file():
            paths, base = [path], path.parent
        else:
            paths = (Path(root) / f for root, _, files in walk_directory(path, self.ignore_patterns, walk_error) for f in files)
            base = path
        for file in paths:
            relative = file.relative_to(base).as_posix()
            if file.is_symlink():
                self.skipped.append({"file": relative, "reason": "symbolic link"})
                continue
            try:
                with file.open("rb") as stream:
                    self.scan_content(stream.read(self.max_file_size + 1), relative)
            except OSError:
                self.errors.append({"file": relative, "reason": "file could not be read"})
        return self.findings
