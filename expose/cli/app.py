import argparse
import json
import shlex
import subprocess
import sys
import tempfile
import time
from collections import Counter
from pathlib import Path

from expose.cli import ui
from expose.config import load_config
from expose.core.detector import SEVERITIES, Detector
from expose.core.git_scan import git, repository_root, scan_history, scan_staged, scan_tree
from expose.core.scanner import Scanner
from expose.remote.github import clone_repo, parse_github_url
from expose.reports.formats import save_report
from expose.rules.loader import load_rules, load_ignore_patterns
from expose.state import baseline_ids, dismiss, make_baseline, now, read_json, save_run, suppressions, write_json

def parser():
    p = argparse.ArgumentParser(prog="xpose", description="Find credential exposure in files, staged changes, and Git history.", epilog="Exit codes: 0 = below threshold, 1 = findings at threshold, 2 = scan/configuration error. Use --reveal on scan commands to display credential values in the CLI.")
    p.add_argument("--version", action="version", version="Xpose 2.0.0")
    commands = p.add_subparsers(dest="command")
    commands.add_parser("help", help="Show the interactive menu guide and usage examples")
    for command, help in [("scan", "Scan a directory or file"), ("staged", "Scan changed files from the Git index"), ("history", "Scan committed snapshots, including deleted secrets"), ("remote", "Scan a public GitHub repository")]:
        sub = commands.add_parser(command, help=help)
        if command == "remote":
            sub.add_argument("url", help="GitHub owner/repo or repository URL")
            sub.add_argument("--history", action="store_true", help="Clone and scan all available branch history")
            sub.add_argument("--tree", action="store_true", help="List files containing findings")
        else:
            sub.add_argument("path", nargs="?", default=".")
        if command in {"history", "remote"}:
            sub.add_argument("--revision", default="--all", help="Revision or range (default: all refs)")
            sub.add_argument("--max-commits", type=positive_or_zero, default=0, help="Limit commits; 0 scans all selected commits")
        sub.add_argument("--config", help="Explicit .xpose.toml path")
        sub.add_argument("--exclude", action="append", default=[], help="Additional relative path glob; repeatable")
        sub.add_argument("--fail-on", type=str.upper, choices=SEVERITIES, help="Exit 1 for new findings at this severity or above")
        sub.add_argument("--min-severity", type=str.upper, choices=SEVERITIES, help="Hide lower severities in console; exit policy still checks all findings")
        sub.add_argument("--baseline", help="Reviewed baseline file")
        sub.add_argument("--output", "-o", help="Report path (default: report.json)")
        sub.add_argument("--format", choices=["json", "html", "sarif"])
        sub.add_argument("--max-file-size", type=positive, help="Maximum bytes per file")
        sub.add_argument("--limit", type=positive_or_zero, default=0, help="Maximum console findings; 0 shows all (default)")
        sub.add_argument("--reveal", action="store_true", help="Show full detected credential values in the CLI; saved reports remain masked")
        sub.add_argument("--quiet", "-q", action="store_true", help="Only print scan errors; reports and exit status remain available")
        sub.add_argument("--no-save", action="store_true", help="Do not save local scan history (the requested report is still written)")
    sub = commands.add_parser("init", help="Write a starter .xpose.toml")
    sub.add_argument("path", nargs="?", default=".")
    sub = commands.add_parser("baseline", help="Create a fingerprint-only baseline from a JSON report")
    sub.add_argument("report", nargs="?", default="report.json")
    sub.add_argument("--output", "-o", default=".xpose-baseline.json")
    sub = commands.add_parser("report", help="Display the complete saved scan report in the CLI")
    sub.add_argument("path", nargs="?", help="JSON report; defaults to the latest local scan")
    sub.add_argument("--config")
    sub.add_argument("--limit", type=positive_or_zero, default=0)
    sub = commands.add_parser("review", help="Review masked findings and record justified dismissals")
    sub.add_argument("--report", help="JSON scan report; defaults to latest local run")
    sub.add_argument("--config")
    sub.add_argument("--severity", type=str.upper, choices=SEVERITIES)
    sub.add_argument("--search", default="", help="Filter by rule or path")
    sub.add_argument("--id", help="Unique finding ID prefix to dismiss")
    sub.add_argument("--reason", help="Required with --id")
    sub.add_argument("--restore", action="store_true", help="Remove a dismissal; requires --id")
    sub = commands.add_parser("rules", help="List or validate built-in and configured rules")
    sub.add_argument("--config")
    sub.add_argument("--validate", action="store_true")
    sub = commands.add_parser("test-rule", help="Test a regex against stdin or a UTF-8 fixture; output is masked")
    sub.add_argument("--pattern", required=True, help="Regex; use (?P<secret>...) to isolate the credential")
    sub.add_argument("--file", help="Read sample text from a file instead of stdin")
    sub.add_argument("--min-entropy", type=float, default=0)
    sub = commands.add_parser("dashboard", help="Serve the read-only local dashboard")
    sub.add_argument("--config")
    sub.add_argument("--port", type=positive, default=8765)
    sub.add_argument("--open", action="store_true", help="Open the local dashboard in your default browser")
    sub = commands.add_parser("runs", help="Show recent local scan history")
    sub.add_argument("--config")
    sub = commands.add_parser("hook", help="Install a staged-secret pre-commit hook in this repository")
    sub.add_argument("--path", default=".")
    return p

def positive_or_zero(value):
    number = int(value)
    if number < 0:
        raise argparse.ArgumentTypeError("Must be zero or greater")
    return number

def positive(value):
    number = positive_or_zero(value)
    if not number:
        raise argparse.ArgumentTypeError("Must be greater than zero")
    return number

def configure(args):
    root = Path.cwd() if args.command == "remote" else Path(args.path).resolve()
    if args.command in {"history", "staged"}:
        root = repository_root(root)
    config = load_config(root, args.config)
    for key in ("fail_on", "min_severity", "max_file_size", "format"):
        if getattr(args, key) is not None:
            config[key] = getattr(args, key)
    for key in ("output", "baseline"):
        if getattr(args, key):
            config[key] = str(Path(getattr(args, key)).resolve())
    config["exclude"] = config["exclude"] + args.exclude
    # Exclude generated output/state even when users choose custom names.
    for key in ("output", "baseline", "state_dir"):
        if config[key]:
            try:
                config["exclude"].append(Path(config[key]).relative_to(root if root.is_dir() else root.parent).as_posix())
            except ValueError:
                pass
    return config

def resolve_scan_target(args):
    """Accept explicit GitHub URLs wherever a scan target is requested."""
    if args.command not in {"scan", "history", "staged"}:
        return args
    target = args.path.strip()
    if not target.startswith(("https://", "http://", "git@")):
        return args
    parse_github_url(target)
    if args.command == "staged":
        raise ValueError("Staged changes exist only in a local repository. Enter its local folder, or choose 2 (GitHub repository) / run 'xpose remote URL' to scan GitHub.")
    history = args.command == "history"
    args.command = "remote"
    args.url = target
    args.history = history
    args.tree = False
    args.revision = getattr(args, "revision", "--all")
    args.max_commits = getattr(args, "max_commits", 0)
    return args

def run_scan(args, session=None):
    started = time.monotonic()
    config = configure(args)
    rules = load_rules(custom_rules=config["rules"])
    if args.reveal and args.quiet:
        raise ValueError("--reveal cannot be combined with --quiet; remove --quiet to display credential values.")
    scanner = Scanner(rules, load_ignore_patterns() | set(config["exclude"]), config["max_file_size"], retain_secrets=args.reveal)
    known = baseline_ids(config["baseline"]) if config["baseline"] else set()
    dismissed = suppressions(config["state_dir"])
    if not args.quiet:
        ui.banner()
    commits = None
    with ui.activity("Scanning " + (args.url if args.command == "remote" else str(Path(args.path).resolve())) + " ...", args.quiet):
        if args.command == "remote":
            target = "https://github.com/" + parse_github_url(args.url)
            with tempfile.TemporaryDirectory(prefix="xpose_") as tmp:
                clone_repo(args.url, tmp, full_history=args.history)
                if args.history:
                    commits = scan_history(scanner, tmp, args.revision, args.max_commits)
                else:
                    scan_tree(scanner, tmp, "HEAD")
        elif args.command == "staged":
            target = str(repository_root(args.path))
            scan_staged(scanner, target)
        elif args.command == "history":
            target = str(repository_root(args.path))
            commits = scan_history(scanner, target, args.revision, args.max_commits)
        else:
            target = str(Path(args.path).resolve())
            scanner.scan(target)
    for f in scanner.findings:
        f["status"] = "suppressed" if f["id"] in dismissed else "baseline" if f["id"] in known else "new"
        if f["status"] == "suppressed":
            f["suppression_reason"] = dismissed[f["id"]]["reason"]
    scanner.findings.sort(key=lambda f: (-SEVERITIES[f["severity"]], f["file"], f["line"]))
    active = [f for f in scanner.findings if f["status"] == "new"]
    statuses = Counter(f["status"] for f in scanner.findings)
    report = {"version": 1, "created_at": now(), "target": target, "mode": args.command + ("-history" if args.command == "remote" and args.history else ""),
              "complete": not scanner.errors, "duration_seconds": round(time.monotonic() - started, 3),
              "scope": {"max_file_size": config["max_file_size"], "excludes": sorted(scanner.ignore_patterns), "commits_scanned": commits, "max_commits": getattr(args, "max_commits", None)},
              "summary": {"files_scanned": scanner.files_scanned, "total": len(scanner.findings), "new": statuses["new"], "baseline": statuses["baseline"], "suppressed": statuses["suppressed"],
                          "skipped": len(scanner.skipped), "errors": len(scanner.errors), "severity": {s: sum(f["severity"] == s for f in active) for s in reversed(SEVERITIES)}},
              "findings": scanner.findings, "errors": scanner.errors, "skipped": scanner.skipped}
    save_report(report, config["output"], config["format"])
    if not args.no_save:
        save_run(config["state_dir"], report)
    if session is not None:
        session.update(report=report, config=config)
    if not args.quiet:
        display = dict(report, findings=[f for f in report["findings"] if SEVERITIES[f["severity"]] >= SEVERITIES[config["min_severity"]]])
        ui.render(display, args.limit, revealed=scanner.revealed if args.reveal else None)
        if getattr(args, "tree", False):
            for file in sorted({f["file"] for f in report["findings"]}):
                print("  |-- " + ui.safe(file))
        print("  " + ui.color("Saved copy: ", "primary") + ui.safe(config["output"]))
        print("  " + ui.color("Next: xpose report  |  xpose review  |  xpose dashboard", "accent") + "\n")
    scanner.revealed.clear()
    if scanner.errors:
        if args.quiet:
            print("Xpose: incomplete scan; inspect errors in the report.", file=sys.stderr)
        return 2
    return int(any(SEVERITIES[f["severity"]] >= SEVERITIES[config["fail_on"]] for f in active))

def review(args, config, report=None):
    if args.report or report is None:
        report = read_json(args.report or Path(config["state_dir"]) / "latest.json")
    if not isinstance(report, dict) or not isinstance(report.get("findings"), list):
        raise ValueError("No JSON report available. Run a scan first.")
    findings = report["findings"]
    if args.id:
        matches = {f["id"] for f in findings if f["id"].startswith(args.id)}
        if len(matches) != 1:
            raise ValueError("ID prefix must identify exactly one finding in the report.")
        finding_id = matches.pop()
        if args.restore:
            data = suppressions(config["state_dir"])
            data.pop(finding_id, None)
            write_json(Path(config["state_dir"]) / "suppressions.json", data)
            print("Dismissal removed. Re-scan to refresh reports.")
        else:
            if not args.reason:
                raise ValueError("Use --reason to document the dismissal.")
            dismiss(config["state_dir"], finding_id, args.reason)
            print("Dismissal saved. Re-scan to refresh reports.")
        return 0
    if args.reason or args.restore:
        raise ValueError("--reason and --restore require --id.")
    dismissed = suppressions(config["state_dir"])
    ui.banner()
    shown = 0
    for f in findings:
        if args.severity and f["severity"] != args.severity:
            continue
        if args.search.lower() not in (f["file"] + " " + f["rule"]).lower():
            continue
        shown += 1
        print("\n  " + ui.color(f["severity"], f["severity"]) + " " + ui.safe(f["rule"]) + "  " + f["id"][:12])
        print("  " + ui.safe(f["file"]) + ":" + str(f["line"]))
        print("  " + ui.safe(f["context"]))
        print("  Fix: " + ui.safe(f["remediation"]))
        if f["id"] in dismissed:
            print("  Dismissed: " + ui.safe(dismissed[f["id"]]["reason"]))
        elif sys.stdin.isatty():
            reason = input("  Dismiss with reason, Enter to keep, or q to finish: ").strip()
            if reason == "q":
                break
            if reason:
                dismiss(config["state_dir"], f["id"], reason)
                dismissed[f["id"]] = {"reason": reason}
    if not shown:
        print("  " + ui.color("No findings match this review. Run a scan or change the filters.", "primary"))
    return 0

def install_hook(path):
    root = repository_root(path)
    hook = Path(git(root, "rev-parse", "--git-path", "hooks/pre-commit").decode().strip())
    if not hook.is_absolute():
        hook = root / hook
    if hook.exists():
        raise ValueError("A pre-commit hook already exists. Integrate Xpose with your existing hook instead of replacing it.")
    hook.parent.mkdir(parents=True, exist_ok=True)
    source_entry = Path(__file__).resolve().parents[2] / "xpose.py"
    invocation = [sys.executable, str(source_entry)] if source_entry.is_file() else [sys.executable, "-m", "expose"]
    command = " ".join(shlex.quote(v.replace("\\", "/")) for v in invocation)
    hook.write_text("#!/bin/sh\n# Xpose: checks the staged snapshot, not working-tree content.\nexec " + command + " staged --no-save --limit 5 --output .xpose/pre-commit.json\n", encoding="utf-8", newline="\n")
    hook.chmod(hook.stat().st_mode | 0o111)
    print("Installed pre-commit hook: " + str(hook))

def interactive():
    session = {}
    while True:
        ui.clear_screen()
        ui.banner()
        ui.menu()
        choice = ui.prompt("Choose [0-8]:").strip()
        while choice not in {"0", "1", "2", "3", "4", "5", "6", "7", "8"}:
            print("  " + ui.color("Choose a number from 0 to 8.", "highlight"))
            choice = ui.prompt("Choose [0-8]:").strip()
        if choice == "0":
            return 0
        ui.clear_screen()
        if choice in {"1", "2", "3", "4", "6"}:
            ui.banner()
        if choice == "1":
            argv = ["scan", ui.prompt("Path [.]:").strip().strip('"') or "."]
        elif choice == "2":
            argv = ["remote", ui.prompt("GitHub owner/repo:").strip()]
        elif choice in {"3", "4"}:
            label = "Local repository folder [.]:" if choice == "3" else "Repository folder or GitHub URL [.]:"
            argv = ["staged" if choice == "3" else "history", ui.prompt(label).strip().strip('"') or "."]
        elif choice == "5":
            argv = ["review"]
        elif choice == "6":
            argv = ["dashboard", "--open"]
        elif choice == "7":
            argv = ["help"]
        elif choice == "8":
            argv = ["report"]
        else:
            print("  " + ui.color("Choose a number from 0 to 8.", "highlight"))
            continue
        if choice in {"1", "2", "3", "4"}:
            if ui.prompt("Show full credential values in this terminal? [Y/n]:").strip().lower() not in {"n", "no"}:
                argv.append("--reveal")
        try:
            if choice in {"1", "2", "3", "4"}:
                ui.clear_screen()
            main(argv, session=session)
        except SystemExit as exc:
            # Invalid input in one menu action must not close the entire application.
            if exc.code:
                print("  " + ui.color("Invalid input. Check the selected action and try again.", "highlight"))
        ui.prompt("Press Enter to return to menu...")

def main(argv=None, session=None):
    p = parser()
    args = p.parse_args(argv)
    try:
        if not args.command:
            if not sys.stdin.isatty():
                p.print_help()
                return 0
            return interactive()
        if args.command in {"scan", "remote", "history", "staged"}:
            args = resolve_scan_target(args)
            return run_scan(args, session=session) if session is not None else run_scan(args)
        if args.command == "help":
            ui.banner()
            ui.help_screen()
            return 0
        if args.command == "init":
            path = Path(args.path) / ".xpose.toml"
            if path.exists():
                raise ValueError("Configuration already exists.")
            path.write_text('''# Xpose project configuration (Python 3.11+)
exclude = ["tests/fixtures/**", "*.min.js"]
fail_on = "HIGH"
min_severity = "INFO"
max_file_size = 2000000
output = "report.json"
format = "json"
state_dir = ".xpose"
# baseline = ".xpose-baseline.json"

# [[rules]]
# name = "Internal token"
# pattern = 'internal_(?P<secret>[A-Za-z0-9]{32})'
# severity = "HIGH"
# min_entropy = 3.5
''', encoding="utf-8")
            print("Created " + str(path))
            return 0
        if args.command == "baseline":
            report = read_json(args.report)
            if not isinstance(report, dict) or not report.get("complete") or not isinstance(report.get("findings"), list):
                raise ValueError("Baseline requires a complete Xpose JSON report.")
            if Path(args.output).exists():
                raise ValueError("Baseline already exists; choose a new output or remove it after review.")
            make_baseline(report, args.output)
            print("Created reviewed-baseline file " + args.output)
            return 0
        if args.command == "hook":
            install_hook(args.path)
            return 0
        if args.command == "test-rule":
            detector = Detector({"rules": [{"name": "Playground", "pattern": args.pattern, "severity": "HIGH", "min_entropy": args.min_entropy}]})
            content = Path(args.file).read_bytes() if args.file else sys.stdin.buffer.read()
            scanner = Scanner({"rules": [r for r, _, _ in detector.rules]})
            scanner.scan_content(content, "sample")
            for f in scanner.findings:
                print(f"Line {f['line']}: " + ui.safe(f["context"]) + f" (entropy {f['entropy']})")
            print(f"{len(scanner.findings)} matches; {len(scanner.skipped)} skipped; {len(scanner.errors)} errors")
            return 2 if scanner.errors else 0
        if session and "config" in session and args.command in {"report", "review", "dashboard"} and not getattr(args, "config", None):
            config = session["config"]
        else:
            config = load_config(Path.cwd(), getattr(args, "config", None))
        if args.command == "report":
            report = session["report"] if session and "report" in session and not args.path else read_json(args.path or Path(config["state_dir"]) / "latest.json")
            if not isinstance(report, dict) or not isinstance(report.get("findings"), list) or "summary" not in report:
                raise ValueError("No JSON report available. Run a scan first.")
            ui.banner()
            ui.render(report, args.limit)
            return 0
        if args.command == "review":
            return review(args, config, report=session.get("report") if session else None)
        if args.command == "rules":
            rules = load_rules(custom_rules=config["rules"])["rules"]
            for r in rules:
                print("  " + ui.color(r["severity"], r["severity"]) + "  " + ui.safe(r["name"]))
            print(f"\n{len(rules)} validated rules")
        elif args.command == "dashboard":
            if args.port > 65535:
                raise ValueError("Port must be 1–65535.")
            from expose.dashboard import serve
            serve(config["state_dir"], args.port, open_browser=args.open)
        elif args.command == "runs":
            for run in read_json(Path(config["state_dir"]) / "runs.json", [])[-20:]:
                print(ui.safe(f"{run['created_at']}  {run['mode']:<14} {run['summary']['new']:>3} new  {'complete' if run['complete'] else 'INCOMPLETE'}  {run['target']}"))
        return 0
    except KeyboardInterrupt:
        print("\nXpose stopped.", file=sys.stderr)
        return 130
    except EOFError:
        return 0
    except (ValueError, OSError, subprocess.SubprocessError) as exc:
        # Tracebacks and subprocess output can contain credentials: keep errors bounded.
        message = str(exc) if isinstance(exc, ValueError) else "Operation failed; check file access, Git, or network availability."
        print("Xpose: " + ui.safe(message), file=sys.stderr)
        return 2
