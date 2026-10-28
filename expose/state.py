"""Local reports, justified suppressions, and raw-secret-free baselines."""
import json
import os
from datetime import datetime, timezone
from pathlib import Path

def now():
    return datetime.now(timezone.utc).isoformat()

def read_json(path, default=None):
    path = Path(path)
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding="utf-8"))

def write_json(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(data, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
    os.replace(temporary, path)

def baseline_ids(path):
    if not Path(path).is_file():
        raise ValueError("Baseline file does not exist.")
    data = read_json(path)
    if not isinstance(data, dict) or data.get("version") != 1 or not isinstance(data.get("ids"), list) or not all(isinstance(i, str) for i in data["ids"]):
        raise ValueError("Invalid baseline file.")
    return set(data["ids"])

def make_baseline(report, output):
    write_json(output, {"version": 1, "created_at": now(), "ids": sorted({f["id"] for f in report["findings"]})})

def suppressions(state_dir):
    data = read_json(Path(state_dir) / "suppressions.json", {})
    if not isinstance(data, dict) or not all(isinstance(v, dict) and isinstance(v.get("reason"), str) and v["reason"].strip() for v in data.values()):
        raise ValueError("Invalid suppression file; each entry needs a reason.")
    return data

def dismiss(state_dir, finding_id, reason):
    if not reason.strip():
        raise ValueError("A dismissal needs a reason.")
    data = suppressions(state_dir)
    data[finding_id] = {"reason": reason.strip(), "created_at": now()}
    write_json(Path(state_dir) / "suppressions.json", data)

def save_run(state_dir, report):
    state = Path(state_dir)
    history = read_json(state / "runs.json", [])
    history.append({k: report[k] for k in ("created_at", "target", "mode", "summary", "complete")})
    write_json(state / "runs.json", history[-200:])
    write_json(state / "latest.json", report)
