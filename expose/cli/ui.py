"""Dependency-free terminal UI; plain output when redirected or NO_COLOR is set."""
import os
import shutil
import sys
import threading
from contextlib import contextmanager

BANNER = ''' █████ █████                                    
▒▒███ ▒▒███                                     
 ▒▒███ ███   ████████   ██████   █████   ██████ 
  ▒▒█████   ▒▒███▒▒███ ███▒▒███ ███▒▒   ███▒▒███
   ███▒███   ▒███ ▒███▒███ ▒███▒▒█████ ▒███████ 
  ███ ▒▒███  ▒███ ▒███▒███ ▒███ ▒▒▒▒███▒███▒▒▒  
 █████ █████ ▒███████ ▒▒██████  ██████ ▒▒██████ 
▒▒▒▒▒ ▒▒▒▒▒  ▒███▒▒▒   ▒▒▒▒▒▒  ▒▒▒▒▒▒   ▒▒▒▒▒▒  
             ▒███                               
             █████                              
            ▒▒▒▒▒                               '''

COLORS = {"HIGH": "31", "CRITICAL": "91", "MEDIUM": "33", "LOW": "32", "INFO": "34", "green": "92"}
THEME = {"primary": ((57, 255, 20), "92"), "accent": ((0, 190, 90), "32"),
         "text": ((196, 255, 196), "97"), "highlight": ((134, 255, 70), "92"),
         "muted": ((103, 151, 108), "32")}
ENABLED = sys.stdout.isatty() and "NO_COLOR" not in os.environ and os.environ.get("TERM") != "dumb"
if os.name == "nt" and ENABLED:
    try:
        import ctypes
        handle = ctypes.windll.kernel32.GetStdHandle(-11)
        mode = ctypes.c_ulong()
        if ctypes.windll.kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            ctypes.windll.kernel32.SetConsoleMode(handle, mode.value | 4)
    except (OSError, AttributeError):
        ENABLED = False

def safe(value):
    return "".join(c if c.isprintable() else " " for c in str(value))

def clear_screen():
    """Clear interactive screens without adding control codes to redirected output."""
    if not sys.stdout.isatty():
        return
    sys.stdout.flush()
    if os.name == "nt" and os.system("cls") == 0:
        return
    sys.stdout.write("\033[2J\033[H")
    sys.stdout.flush()

def rgb_sequence(rgb, fallback):
    if os.environ.get("COLORTERM", "").lower() in {"truecolor", "24bit"} or os.name == "nt" or os.environ.get("WT_SESSION"):
        return f"38;2;{rgb[0]};{rgb[1]};{rgb[2]}"
    if "256color" in os.environ.get("TERM", ""):
        levels = [round(v / 255 * 5) for v in rgb]
        return "38;5;" + str(16 + 36 * levels[0] + 6 * levels[1] + levels[2])
    return fallback

def color(value, kind="primary"):
    text = safe(value)
    if not ENABLED:
        return text
    sequence = rgb_sequence(*THEME[kind]) if kind in THEME else COLORS.get(kind, "0")
    return "\033[" + sequence + "m" + text + "\033[0m"

def gradient(text):
    """Interpolate neon green -> matrix green -> deep green across the banner."""
    stops = [(134, 255, 70), (57, 255, 20), (0, 158, 75)]
    lines = text.splitlines()
    width = max(map(len, lines), default=1)
    output = []
    for y, line in enumerate(lines):
        row = []
        for x, char in enumerate(line):
            if not ENABLED or char == " ":
                row.append(char)
                continue
            progress = min(1, (x / max(1, width - 1)) * .8 + (y / max(1, len(lines) - 1)) * .2)
            segment = min(1, int(progress * 2))
            blend = progress * 2 - segment
            rgb = [round(a + (b - a) * blend) for a, b in zip(stops[segment], stops[segment + 1])]
            sequence = rgb_sequence(rgb, "92" if progress < .65 else "32")
            row.append("\033[" + sequence + "m" + char)
        output.append("".join(row) + ("\033[0m" if ENABLED else ""))
    return "\n".join(output)

def banner():
    if os.name == "nt" and sys.stdout.isatty() and hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    art = BANNER
    try:
        art.encode(sys.stdout.encoding or "utf-8")
    except UnicodeEncodeError:
        art = "  X P O S E"
    print("\n" + gradient(art))
    print("  " + color("Secret scanner", "primary") + color("  /  ", "muted") + color("v2.0.0", "accent"))
    print(color("  " + "-" * min(68, max(20, shutil.get_terminal_size().columns - 6)), "accent"))

def prompt(label):
    return input("  " + color(">", "accent") + " " + color(label, "primary") + " ")

def menu():
    print("\n  " + color("SCAN", "primary"))
    items = [("1", "Local files", "Scan a folder or file"),
             ("2", "GitHub repository", "Scan a public repository"),
             ("3", "Staged changes", "Check the next commit"),
             ("4", "Git history", "Find previously committed secrets")]
    for key, label, detail in items:
        print("  " + color("[" + key + "]", "primary") + "  " + color(f"{label:<20}", "text") + color(detail, "muted"))
    print("\n  " + color("EXPLORE", "accent"))
    for key, label, detail in [("5", "Review findings", "Inspect and dismiss results"),
                               ("6", "Local dashboard", "Browse scan history"),
                               ("7", "Help", "View commands and options"),
                               ("8", "Latest report", "Read the full report here")]:
        print("  " + color("[" + key + "]", "accent") + "  " + color(f"{label:<20}", "text") + color(detail, "muted"))
    print("\n  " + color("[0]", "highlight") + "  " + color("Exit", "highlight") + "\n")

def help_screen():
    print("\n  " + color("HELP / HOW TO USE XPOSE", "primary"))
    topics = [
        ("1 - Local files", "Enter a folder or a single file, such as C:\\projects\\my-app. Enter uses the current folder."),
        ("2 - GitHub repository", "Enter a public GitHub URL or owner/repo. Xpose downloads a temporary copy and scans it."),
        ("3 - Staged changes", "Enter a LOCAL Git folder. Scans changed files staged with git add; GitHub URLs cannot contain uncommitted changes."),
        ("4 - Git history", "Enter a local Git folder or GitHub URL. Scans available committed versions, including removed credentials."),
        ("5 - Review findings", "Review the last scan in this session. Enter a dismissal reason, Enter to keep a finding, or q to finish."),
        ("6 - Local dashboard", "Opens the dashboard in your browser. The CLI hosts it until Ctrl+C; then you can return to the menu."),
        ("7 - Help", "Shows this guide and waits for Enter before returning to the menu."),
        ("8 - Latest report", "Read the last scan in this session directly in the CLI. Saved reports contain masked values."),
        ("0 - Exit", "Close the interactive menu."),
    ]
    width = max(30, min(90, shutil.get_terminal_size().columns - 8))
    import textwrap
    for title, description in topics:
        print("\n  " + color(title, "accent"))
        print(textwrap.fill(description, width=width, initial_indent="    ", subsequent_indent="    "))
    print("\n  " + color("DISPLAYING CREDENTIALS", "primary"))
    print("    Choose Yes at the reveal prompt to see full detected values during a scan.")
    print("    Passwords, tokens, connection credentials, hashes, and private keys are supported.")
    print("\n  " + color("DIRECT COMMANDS", "primary"))
    for command in ("python xpose.py scan . --reveal", "python xpose.py remote owner/repo --reveal", "python xpose.py history . --max-commits 100 --reveal", "python xpose.py report", "python xpose.py rules --validate", "python xpose.py init", "python xpose.py scan --help"):
        print("    " + color(command, "text"))
    print("\n  " + color("TROUBLESHOOTING", "primary"))
    print("    No staged files? Run git add first. No commits? Create a commit before history scanning.")
    print("    Remote scan failed? Check the public URL, internet access, and that Git is installed.")
    print("    No saved report? Run a scan first. Scan errors stay visible until you press Enter.")
    print("    Exit codes: 0 = below threshold; 1 = findings; 2 = error; 130 = interrupted.\n")

@contextmanager
def activity(label, quiet=False):
    stop = threading.Event()
    def animate():
        i = 0
        while not stop.wait(0.12):
            sys.stdout.write("\r  " + color("|/-\\"[i % 4]) + " " + safe(label))
            sys.stdout.flush()
            i += 1
    thread = None
    if not quiet:
        if ENABLED:
            thread = threading.Thread(target=animate, daemon=True)
            thread.start()
        else:
            print("  " + safe(label))
    try:
        yield
    finally:
        stop.set()
        if thread:
            thread.join()
            sys.stdout.write("\r\033[2K")

def render(report, limit=0, revealed=None):
    summary = report["summary"]
    print("\n  " + color("SCAN COMPLETE" if report["complete"] else "SCAN INCOMPLETE", "green" if report["complete"] else "HIGH"))
    print("  " + safe(report["target"]) + "  /  " + report["mode"])
    if report.get("created_at"):
        print("  " + color("Scan time: " + report["created_at"], "muted"))
    print(f"\n  {summary['files_scanned']} files  |  {summary['new']} new  |  {summary['baseline']} baseline  |  {summary['suppressed']} dismissed")
    print("  " + "  ".join(color(f"{name}: {summary['severity'][name]}", name) for name in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")))
    print()
    findings = report["findings"]
    visible = findings[:limit] if limit else findings
    for i, finding in enumerate(visible, 1):
        print("  " + color(f"[{i:02}]", "accent") + " " + color(f"{finding['severity']:<8}", finding["severity"]) + " " + color(finding["rule"], "text") + "  " + color(finding["status"], "muted"))
        print("       " + color("File    ", "primary") + safe(finding["file"]) + ":" + str(finding["line"]))
        if finding.get("commit"):
            print("       " + color("Commit  ", "primary") + finding["commit"][:12])
        value = revealed.get(finding["id"], "[REDACTED]") if revealed is not None else "[REDACTED]"
        value_lines = value.splitlines() or [value]
        print("       " + color("Credential ", "accent") + color(value_lines[0], "highlight"))
        for part in value_lines[1:]:
            print("                  " + color(part, "highlight"))
        print("       " + color("Context ", "primary") + safe(finding["context"]))
        print("       " + color("Fix     ", "green") + safe(finding["remediation"]))
        print("       " + color("ID      " + finding["id"][:12], "muted"))
        print()
    if not findings:
        print("  No findings match the current display filters.")
    elif revealed is None:
        print("  " + color("Show full credential values with --reveal during a scan.", "primary"))
    if limit and len(findings) > limit:
        print(f"  ... {len(findings) - limit} more. Use --limit 0 to show every finding in the CLI.")
    for kind in ("errors", "skipped"):
        if report[kind]:
            print("\n  " + color(f"{len(report[kind])} {kind}", "HIGH" if kind == "errors" else "muted"))
            for issue in report[kind]:
                print("    " + safe(issue["file"]) + " - " + safe(issue["reason"]))
    print()
