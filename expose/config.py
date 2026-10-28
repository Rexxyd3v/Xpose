import tomllib
from pathlib import Path
from expose.core.detector import SEVERITIES

DEFAULTS = {"exclude": [], "fail_on": "HIGH", "min_severity": "INFO", "max_file_size": 2_000_000,
            "output": "report.json", "format": "json", "baseline": None, "state_dir": ".xpose", "rules": []}

def load_config(root, explicit=None):
    root = Path(root).resolve()
    if root.is_file():
        root = root.parent
    path = Path(explicit).resolve() if explicit else root / ".xpose.toml"
    config = dict(DEFAULTS)
    if explicit and not path.is_file():
        raise ValueError("Configuration file does not exist.")
    if path.is_file():
        data = tomllib.loads(path.read_text(encoding="utf-8"))
        unknown = set(data) - set(DEFAULTS)
        if unknown:
            raise ValueError("Unknown configuration setting: " + ", ".join(sorted(unknown)))
        config.update(data)
        root = path.parent
    for key in ("fail_on", "min_severity"):
        if not isinstance(config[key], str) or config[key].upper() not in SEVERITIES:
            raise ValueError(key + " must be a supported severity.")
        config[key] = config[key].upper()
    if not isinstance(config["exclude"], list) or not all(isinstance(p, str) and p for p in config["exclude"]):
        raise ValueError("exclude must be a list of path patterns.")
    if isinstance(config["max_file_size"], bool) or not isinstance(config["max_file_size"], int) or config["max_file_size"] < 1:
        raise ValueError("max_file_size must be a positive integer.")
    if config["format"] not in {"json", "html", "sarif"}:
        raise ValueError("format must be json, html, or sarif.")
    if not isinstance(config["rules"], list):
        raise ValueError("rules must be a list of rule tables.")
    for key in ("output", "state_dir"):
        if not isinstance(config[key], str) or not config[key]:
            raise ValueError(key + " must be a nonempty path.")
    if config["baseline"] is not None and not isinstance(config["baseline"], str):
        raise ValueError("baseline must be a path.")
    for key in ("state_dir", "baseline", "output"):
        if config[key]:
            config[key] = str((root / config[key]).resolve())
    config["root"] = str(root)
    return config
