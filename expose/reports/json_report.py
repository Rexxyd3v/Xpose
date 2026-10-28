"""JSON writer for already-sanitized Xpose reports."""
from expose.state import write_json

def save_findings_to_json(findings, output_file="report.json"):
    write_json(output_file, findings)
