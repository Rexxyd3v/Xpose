"""Compatibility adapter for the consolidated terminal renderer."""
from expose.cli.ui import color, safe

def print_findings_to_console(findings, target=None, base_path=None):
    print("Xpose findings" + (" / " + safe(target) if target else ""))
    for finding in findings:
        print(color(finding["severity"], finding["severity"]), safe(finding["rule"]), safe(finding["file"]), finding["line"], "[REDACTED]")
