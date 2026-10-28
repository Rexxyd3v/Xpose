import html
import json
from pathlib import Path
from urllib.parse import quote
from expose.state import write_json

STYLE = """body{font:15px system-ui;background:#0b1020;color:#e2e8f0;margin:0}main{max-width:1200px;margin:48px auto;padding:0 24px}h1{font-size:36px;letter-spacing:-1px}small,.muted{color:#94a3b8}.cards{display:flex;gap:16px;flex-wrap:wrap;margin:24px 0}.card{background:#151e33;border:1px solid #2d3a53;border-radius:12px;padding:20px;min-width:130px}.card strong{font-size:28px;display:block;color:#67e8f9}table{width:100%;border-collapse:collapse;background:#151e33;border-radius:12px}td,th{text-align:left;padding:14px;border-bottom:1px solid #2d3a53;vertical-align:top}th{color:#94a3b8;font-size:12px;text-transform:uppercase}code{white-space:pre-wrap;overflow-wrap:anywhere;color:#c4b5fd}input,select,button{padding:10px;background:#151e33;border:1px solid #475569;border-radius:6px;color:#e2e8f0;margin:4px}a{color:#67e8f9}.HIGH,.CRITICAL{color:#fda4af}.MEDIUM{color:#fcd34d}details{margin-top:10px} .scroll{overflow-x:auto}"""

def report_html(report):
    esc = lambda v: html.escape(str(v), quote=True)
    cards = "".join('<div class="card"><small>' + esc(k.replace("_", " ")) + '</small><strong>' + esc(v) + '</strong></div>' for k, v in report["summary"].items() if isinstance(v, int))
    rows = []
    for f in report["findings"]:
        rows.append('<tr><td class="' + esc(f["severity"]) + '">' + esc(f["severity"]) + '</td><td>' + esc(f["rule"]) + '<br><small>' + esc(f["status"]) + '</small></td><td>' + esc(f["file"]) + ':' + str(f["line"]) + '<br><small>' + esc(f.get("commit", "")[:12]) + '</small></td><td><code>' + esc(f["context"]) + '</code><details><summary>Remediation</summary>' + esc(f["remediation"]) + '</details></td></tr>')
    issues = "".join('<li>' + esc(i["file"]) + ': ' + esc(i["reason"]) + '</li>' for i in report["errors"] + report["skipped"])
    return '<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Xpose scan report</title><style>' + STYLE + '</style><main><small>XPOSE / SECRET SCANNER</small><h1>Scan report</h1><p>' + esc(report["target"]) + ' &middot; ' + esc(report["mode"]) + ' &middot; ' + esc(report["created_at"]) + '</p><p>' + ('Completed within configured scope' if report["complete"] else 'INCOMPLETE — inspect scan errors') + '</p><div class="cards">' + cards + '</div><div class="scroll"><table><thead><tr><th>Severity</th><th>Detection</th><th>Location</th><th>Masked context</th></tr></thead><tbody>' + ''.join(rows) + '</tbody></table></div><details><summary>Skipped files and errors</summary><ul>' + issues + '</ul></details></main></html>'

def sarif(report):
    rules = {}
    results = []
    for f in report["findings"]:
        rid = f["rule_id"]
        rules[rid] = {"id": rid, "shortDescription": {"text": f["rule"]}, "help": {"text": f["remediation"]}}
        result = {"ruleId": rid, "level": "error" if f["severity"] in {"HIGH", "CRITICAL"} else "warning" if f["severity"] == "MEDIUM" else "note",
                  "message": {"text": f["rule"] + ": credential redacted. " + f["remediation"]},
                  "locations": [{"physicalLocation": {"artifactLocation": {"uri": quote(f["file"], safe="/"), "uriBaseId": "%SRCROOT%"}, "region": {"startLine": f["line"]}}}],
                  "partialFingerprints": {"xpose/v1": f["id"]}, "properties": {"severity": f["severity"], "status": f["status"]}}
        if f["status"] in {"baseline", "suppressed"}:
            result["suppressions"] = [{"kind": "external", "justification": f.get("suppression_reason", "Present in reviewed baseline")}]
        results.append(result)
    return {"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "runs": [{"tool": {"driver": {"name": "Xpose", "version": "2.0.0", "rules": list(rules.values())}}, "invocations": [{"executionSuccessful": report["complete"]}], "results": results}]}

def save_report(report, output, format="json"):
    if format == "json":
        write_json(output, report)
    elif format == "sarif":
        write_json(output, sarif(report))
    else:
        path = Path(output)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(report_html(report), encoding="utf-8")
