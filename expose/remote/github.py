"""Public GitHub cloning with validated targets and bounded subprocesses."""
import re
import os
import subprocess


def parse_github_url(url):
    value = url.strip().rstrip("/")
    for prefix in ("https://github.com/", "http://github.com/", "git@github.com:"):
        if value.startswith(prefix):
            value = value[len(prefix):]
            break
    if value.endswith(".git"):
        value = value[:-4]
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9_][A-Za-z0-9_.-]*", value):
        raise ValueError("Use a GitHub owner/repo or repository URL (without credentials or branch paths).")
    return value


def clone_repo(repo_url, dest_dir, full_history=False):
    repo = parse_github_url(repo_url)
    args = ["git", "-c", "core.hooksPath=", "clone", "--no-checkout", "--no-tags"]
    if not full_history:
        args += ["--depth", "1", "--single-branch"]
    result = subprocess.run(args + ["https://github.com/" + repo + ".git", str(dest_dir)], capture_output=True, stdin=subprocess.DEVNULL,
                            env={**os.environ, "GIT_TERMINAL_PROMPT": "0", "GCM_INTERACTIVE": "never"}, timeout=300)
    if result.returncode:
        error = result.stderr.decode("utf-8", errors="replace").lower()
        if any(text in error for text in ("repository not found", "authentication failed", "could not read username")):
            raise ValueError("GitHub repository is not accessible. Check the owner/repo spelling and that the repository is public.")
        if any(text in error for text in ("could not resolve host", "failed to connect", "couldn't connect")):
            raise ValueError("Cannot connect to GitHub. Check your internet connection, proxy, or DNS settings.")
        raise ValueError("Clone failed. Check the public repository URL, network, and Git installation.")
    return str(dest_dir)
