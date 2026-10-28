import json
from pathlib import Path
from expose.core.detector import validate_rule

def load_rules(rules_dir=None, custom_rules=()):
    rules_dir = Path(rules_dir) if rules_dir else Path(__file__).parent
    rules = []
    for path in sorted(rules_dir.glob("*.json")):
        if path.name != "ignore.json":
            data = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(data, list):
                raise ValueError("Rule file must contain a list: " + path.name)
            rules.extend(data)
    rules.extend(custom_rules)
    names = set()
    for rule in rules:
        validate_rule(rule)
        identity = rule.get("id", rule["name"])
        if identity in names:
            raise ValueError("Duplicate rule ID: " + identity)
        names.add(identity)
    return {"rules": rules}

def load_ignore_patterns(rules_dir=None):
    path = (Path(rules_dir) if rules_dir else Path(__file__).parent) / "ignore.json"
    return set(json.loads(path.read_text(encoding="utf-8")).get("ignore_patterns", []))
