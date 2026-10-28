# Xpose — Feature Roadmap

![Actual Xpose main menu running in CMD](docs/assets/xpose-cmd-menu.png)

Future ideas for clearer findings, better control, and faster review inside the CLI.

> **The roadmap features are proposed work.** The screenshots and GIF below show the **current, working Xpose CLI in a real CMD window**, not mockups of future features. Credential values are masked.

## Actual CMD demonstration

![Actual CMD recording: Xpose menu, repository URL, remote scan, masked findings, and Help](docs/assets/xpose-cmd-demo.gif)

Recorded using the repository requested for this demonstration:

[POS and Inventory Management System](https://github.com/Rexxyd3v/POS-AND-INVENTORY-MANAGEMENT-SYSTEM..git)

```powershell
python xpose.py remote https://github.com/Rexxyd3v/POS-AND-INVENTORY-MANAGEMENT-SYSTEM..git
```

The recording uses menu option **2 — GitHub repository**, enters that exact URL, keeps credentials masked, displays the completed scan, and navigates to Help and back to the menu. Binary image/build files were excluded in the capture workspace to keep the report readable. These are captures of real terminal output, without designed overlays or simulated findings.

### Repository input

![The requested GitHub URL entered in the actual CMD prompt](docs/assets/xpose-cmd-scan-input.png)

### Actual scan report

![Actual Xpose CMD report with masked credential findings](docs/assets/xpose-cmd-report.png)

### Help page

![Actual Help output in CMD](docs/assets/xpose-cmd-help.png)

## Feature ideas

| Feature | What it would do | Why it helps |
| --- | --- | --- |
| **Explain findings** | Show the matched rule and evidence, such as a literal password assignment, recognizable token format, or credential-bearing URL. | Makes it easier to judge a result and understand false positives. |
| **Confidence levels** | Add High, Medium, or Low confidence based on documented detection evidence. | Separates how strongly the evidence supports a finding from how serious exposure would be. |
| **Rule controls** | Enable or disable individual rules from project configuration and a CLI settings page. | Lets a project tune noisy rules without editing scanner code. |
| **CLI search and filters** | Filter the current report by path, credential type, severity, confidence, and status. | Keeps large reports usable without opening a separate file. |
| **Duplicate grouping** | Group matching credentials and list every affected file and line under one entry. | Reduces repeated rows while preserving all locations. |
| **Scan comparison** | Compare compatible runs and show new, still-present, and resolved findings. | Makes remediation progress visible. |
| **Changed-line scanning** | Offer a mode that checks only added or modified lines in a staged change or commit comparison. | Focuses commit checks on newly introduced exposure. |
| **Encoded-secret detection** | Optionally decode Base64, hex, and URL-encoded text within configured limits, then run detection rules. | Extends coverage to credentials that are not stored as plain text. |

## Suggested implementation order

### Phase 1 — Clarity and control

- [ ] **Explain findings:** display evidence alongside each result in the CLI and saved reports.
- [ ] **Rule controls:** list enabled rules and support per-project enable/disable settings.
- [ ] **CLI filters:** search and narrow an existing report without re-scanning.

### Phase 2 — Efficient review

- [ ] **Confidence levels:** define evidence categories and validate them against synthetic positives and false positives.
- [ ] **Duplicate grouping:** preserve all occurrences while making reports easier to read.
- [ ] **Scan comparison:** compare compatible targets, scopes, and rule versions.

### Phase 3 — Broader scanning options

- [ ] **Changed-line scans:** preserve original line numbers and handle staged content, renamed files, and deleted lines correctly.
- [ ] **Encoded secrets:** add opt-in decoding with size and depth limits and clear origin tracking.

## Design expectations

- **Confidence is not severity.** A strong match can have a different impact from another equally strong match. Confidence labels should explain their evidence, not pretend to be calibrated probabilities.
- **Grouping preserves evidence.** A grouped result must retain every file, line, and relevant commit; do not combine unrelated credentials just because their masked display is identical.
- **Resolved needs a comparable scan.** Missing results from a failed scan or a narrower scope should not automatically count as resolved.
- **Changed-line mode has a defined scope.** Keep full-file scanning available so users can choose wider coverage.
- **Decoding remains bounded.** Track the original encoded location, limit work, and apply the same masking behavior to decoded values.
- **No local AI dependency.** These ideas can be implemented with detection rules, syntax checks, and deterministic comparison logic.

## Current foundation

Xpose already includes local and remote scanning, Git history and staged scanning, configurable rules, baseline and suppression workflows, credential reveal in the CLI, JSON/HTML/SARIF reports, and a local dashboard. The items above extend that foundation; they are future work.

## Reference implementations

- [detect-secrets: disabling detection plugins](https://github.com/Yelp/detect-secrets#disabling-plugins) — a reference for per-detector controls.
- [Gitleaks: decoding](https://github.com/gitleaks/gitleaks#decoding) — a reference for optional decoding and depth limits.

## Media

All images below are actual captures of the CMD window running Xpose:

- [CMD main menu](docs/assets/xpose-cmd-menu.png)
- [Repository URL entered in CMD](docs/assets/xpose-cmd-scan-input.png)
- [Masked scan report in CMD](docs/assets/xpose-cmd-report.png)
- [CMD Help page](docs/assets/xpose-cmd-help.png)
- [Animated CMD navigation and scan](docs/assets/xpose-cmd-demo.gif)
