"""Validated detection with optional transient capture for explicit CLI reveal."""
import hashlib
import re
from pathlib import PurePosixPath
from urllib.parse import urlsplit
from expose.core.entropy import entropy

SEVERITIES = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
REMEDIATION = "Rotate or revoke the credential, remove it from source, and load its replacement from an environment variable or secret manager."
CODE_EXTENSIONS = {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".py", ".rb", ".php", ".go", ".rs", ".java", ".kt", ".kts", ".c", ".h", ".cc", ".cpp", ".cs", ".swift", ".scala", ".lua"}
GUIDANCE = {
    "GitHub PAT": "Revoke this GitHub token and issue a replacement with minimal permissions. Load it from GITHUB_TOKEN or a CI secret instead of source.",
    "GitHub fine-grained PAT": "Revoke this GitHub token and issue a replacement scoped to the required repositories. Store it as a CI secret or GITHUB_TOKEN environment variable.",
    "AWS Access Key": "Rotate the AWS access key and its paired secret. Prefer workload roles; otherwise inject AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY through a secret store.",
    "OpenAI API Key": "Rotate the exposed OpenAI key. Load the replacement from OPENAI_API_KEY in the server environment or deployment secret store.",
    "Anthropic API Key": "Rotate the exposed Anthropic key. Load the replacement from ANTHROPIC_API_KEY in the server environment or deployment secret store.",
    "OpenRouter API Key": "Rotate the exposed OpenRouter key. Inject the replacement through a server environment variable or deployment secret store.",
    "Private Key": "Replace the exposed key pair and revoke associated credentials or certificates where applicable. Store private key material outside source in a protected key store.",
    "JWT": "Determine whether this JWT grants access. Revoke the session or token where supported, and remove it from source. Review signing-key rotation only if the signing key was exposed.",
}

def guidance(rule):
    if rule.get("remediation"):
        return rule["remediation"]
    if rule.get("credential_uri"):
        return "Rotate the password embedded in this connection URI. Move the connection string into an environment variable or deployment secret store and review access logs."
    return GUIDANCE.get(rule["name"], REMEDIATION)

def validate_rule(rule):
    if not isinstance(rule, dict) or not all(isinstance(rule.get(k), str) and rule[k] for k in ("name", "pattern", "severity")):
        raise ValueError("Each rule needs a name, pattern, and severity.")
    if rule["severity"].upper() not in SEVERITIES:
        raise ValueError("Invalid severity in rule " + rule["name"])
    for key in ("id", "remediation"):
        if key in rule and (not isinstance(rule[key], str) or not rule[key].strip()):
            raise ValueError(key + " must be a nonempty string in rule " + rule["name"])
    for key in ("generic", "credential_uri", "assignment", "allow_weak"):
        if key in rule and not isinstance(rule[key], bool):
            raise ValueError(key + " must be true or false in rule " + rule["name"])
    try:
        pattern = re.compile(rule["pattern"])
    except re.error as exc:
        raise ValueError("Invalid regex in rule " + rule["name"]) from exc
    group = rule.get("secret_group", "secret" if "secret" in pattern.groupindex else 0)
    if isinstance(group, bool) or not isinstance(group, (int, str)) or (isinstance(group, int) and not 0 <= group <= pattern.groups) or (isinstance(group, str) and group not in pattern.groupindex):
        raise ValueError("Invalid secret_group in rule " + rule["name"])
    threshold = rule.get("min_entropy", 0)
    if isinstance(threshold, bool) or not isinstance(threshold, (float, int)) or not 0 <= threshold <= 8:
        raise ValueError("min_entropy must be between 0 and 8 in rule " + rule["name"])
    minimum = rule.get("min_length", 0)
    if isinstance(minimum, bool) or not isinstance(minimum, int) or minimum < 0:
        raise ValueError("min_length must be a nonnegative integer in rule " + rule["name"])
    return pattern, group

def is_placeholder(value, allow_weak=False):
    value = value.strip("\"' ")
    lower = value.lower()
    if allow_weak and (lower in {"password", "changeme"} or (len(value) >= 8 and len(set(value)) <= 2)):
        return False
    return (lower in {"password", "changeme", "your_api_key", "your-secret-here", "example", "redacted", "<redacted>"}
            or lower.startswith(("your_", "your-", "example_", "example-", "replace_me", "placeholder", "${", "{{", "<your"))
            or (len(value) >= 8 and len(set(value)) <= 2))

class Detector:
    def __init__(self, rules):
        self.rules = [(r, *validate_rule(r)) for r in rules["rules"]]

    def find_secrets(self, line, on_secret=None, source_path=None):
        code_file = PurePosixPath(str(source_path or "").replace("\\", "/")).suffix.lower() in CODE_EXTENSIONS
        candidates = []
        for rule, pattern, group in self.rules:
            for match in pattern.finditer(line):
                value = match.group(group)
                quoted = bool(value and value[:1] in {"'", '"', '`'} and value[-1:] == value[:1])
                if rule.get("assignment") and code_file and not quoted and value and not re.fullmatch(r"[0-9]+(?:\.[0-9]+)?", value):
                    # In source code, a bare name/property/access expression is not a literal credential.
                    # Configuration files retain unquoted literal support (e.g. PASSWORD=abc.def).
                    continue
                if rule.get("assignment") and quoted:
                    value = value[1:-1]
                if rule.get("assignment") and quoted and match.group(group).startswith('`') and "${" in value:
                    continue
                if rule.get("assignment") and quoted and re.match(r'''^\s*['"]\s*\+''', value):
                    continue
                if rule.get("assignment") and not quoted and value and ("(" in value or value.endswith((".append", ".get", ".read", ".pop"))):
                    continue
                if rule.get("assignment") and value and (value.lstrip().startswith(("$", "{{", "<", "+")) or (not quoted and (value.lower() in {"none", "null", "true", "false", "undefined"} or value.lstrip().startswith(("os.", "process.", "getenv(", "env(", "config.", "settings."))))):
                    continue
                if not value or len(value) < rule.get("min_length", 0) or is_placeholder(value, rule.get("allow_weak", False)):
                    continue
                if rule.get("credential_uri"):
                    try:
                        parsed = urlsplit(value)
                        if not parsed.username or not parsed.password or is_placeholder(parsed.password, allow_weak=True):
                            continue
                    except ValueError:
                        continue
                score = entropy(value)
                if score < rule.get("min_entropy", 0):
                    continue
                candidates.append((rule, match, value, score))
        candidates.sort(key=lambda c: (c[0].get("generic", False), -SEVERITIES[c[0]["severity"].upper()], c[1].start()))
        selected = []
        for item in candidates:
            if not any(item[1].start() < other[1].end() and item[1].end() > other[1].start() for other in selected):
                selected.append(item)
        context = line.rstrip("\r\n")
        spans = []
        for _, match, _, _ in sorted(candidates, key=lambda c: c[1].start()):
            if spans and match.start() <= spans[-1][1]:
                spans[-1] = (spans[-1][0], max(spans[-1][1], match.end()))
            else:
                spans.append((match.start(), match.end()))
        for start, end in reversed(spans):
            context = context[:start] + "[REDACTED]" + "\n" * line[start:end].count("\n") + context[end:]
        context_lines = context.split("\n")
        ordered = sorted(selected, key=lambda c: c[1].start())
        findings = [{"rule": rule["name"], "severity": rule["severity"].upper(),
                 "rule_id": rule.get("id", rule["name"]), "match": "[REDACTED]",
                 "secret_hash": hashlib.sha256(value.encode("utf-8")).hexdigest(),
                 "entropy": round(score, 2), "start": match.start(), "end": match.end(),
                 "line_offset": line.count("\n", 0, match.start()),
                 "context": context_lines[line.count("\n", 0, match.start())].rstrip("\r")[:240], "remediation": guidance(rule)}
                for rule, match, value, score in ordered]
        if on_secret is not None:
            for _, _, value, _ in ordered:
                on_secret(value)
        return findings
