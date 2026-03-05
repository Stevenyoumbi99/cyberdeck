# CyberDeck — Git Workflow & Development Guide

> Branching strategy, commit conventions, release process, and instructions for
> adding new scan modules.
> Last updated: March 2026 — reflects v1.0.0.

---

## Table of Contents

1. [Repository Overview](#1-repository-overview)
2. [Branch Strategy](#2-branch-strategy)
3. [Daily Development Workflow](#3-daily-development-workflow)
4. [Commit Message Conventions](#4-commit-message-conventions)
5. [Merging dev → main (Releases)](#5-merging-dev--main-releases)
6. [Adding a New Scan Module](#6-adding-a-new-scan-module)
7. [Team Collaboration Rules](#7-team-collaboration-rules)
8. [Useful Git Commands](#8-useful-git-commands)

---

## 1. Repository Overview

| Item              | Value                                           |
|-------------------|-------------------------------------------------|
| Remote URL (SSH)  | `git@github.com:Stevenyoumbi99/cyberdeck.git`   |
| Remote URL (HTTPS)| `https://github.com/Stevenyoumbi99/cyberdeck.git` |
| Primary dev branch| `dev`                                           |
| Stable branch     | `main`                                          |
| Current version   | v1.0.0                                          |

Clone the repository:

```bash
# SSH (requires SSH key on GitHub)
git clone git@github.com:Stevenyoumbi99/cyberdeck.git

# HTTPS (no key required)
git clone https://github.com/Stevenyoumbi99/cyberdeck.git
```

Configure your identity (first time only):

```bash
git config --global user.name "Your Name"
git config --global user.email "your@email.com"
```

---

## 2. Branch Strategy

```
main        ──────────────●────────────●────────────
                           ↑            ↑
dev         ─────●────●───┤────●────●──┤────●──────
                  ↑   ↑             ↑
feature/*   ──────┘   └─────────────┘
```

### Branch descriptions

| Branch        | Purpose                                                    | Who pushes  |
|---------------|------------------------------------------------------------|-------------|
| `main`        | Stable releases. Always deployable. Never develop here.    | Merge from dev only |
| `dev`         | Integration branch. All tested work lands here first.      | Feature branches |
| `feature/*`   | One branch per module or significant change.               | Developer   |
| `hotfix/*`    | Emergency fixes applied directly to main, then backported. | Developer   |

### Naming convention for feature branches

```bash
feature/lan-scan          # a new module
feature/dashboard-detail  # a new UI feature
feature/report-pdf        # a new output format
fix/anomaly-zscore        # a bug fix
docs/architecture-update  # documentation only
```

---

## 3. Daily Development Workflow

### 3.1 Start a new feature

```bash
# 1. Make sure you are on dev and it is up to date
git checkout dev
git pull origin dev

# 2. Create a feature branch
git checkout -b feature/your-feature-name

# 3. Do your work, make commits as you go
git add modules/your_module.py
git commit -m "feat(your_module): describe what you added"
```

### 3.2 Finish a feature — merge into dev

```bash
# 1. Make sure dev is still up to date before merging
git checkout dev
git pull origin dev

# 2. Merge your feature branch
git merge feature/your-feature-name

# 3. Push dev to GitHub
git push origin dev

# 4. (Optional) delete the feature branch now that it is merged
git branch -d feature/your-feature-name
git push origin --delete feature/your-feature-name
```

### 3.3 Pull the latest dev on an existing branch

```bash
git checkout dev
git pull origin dev
git checkout feature/your-feature-name
git merge dev        # bring dev changes into your branch
```

### 3.4 Check remote URL

If you see permission errors or pushes going to the wrong repo:

```bash
git remote -v
# Should show:
# origin  git@github.com:Stevenyoumbi99/cyberdeck.git (fetch)
# origin  git@github.com:Stevenyoumbi99/cyberdeck.git (push)
```

Update if needed:

```bash
git remote set-url origin git@github.com:Stevenyoumbi99/cyberdeck.git
# (produces no output on success — silence means it worked)
```

---

## 4. Commit Message Conventions

All commits use the **Conventional Commits** format:

```
type(scope): short description (≤ 72 characters)

Optional body: why this change was needed, what approach was taken.
Wrap at 72 characters.

Optional footer: references to issues, breaking change notes.
```

### Types

| Type       | When to use                                           |
|------------|-------------------------------------------------------|
| `feat`     | New feature or module                                 |
| `fix`      | Bug fix                                               |
| `docs`     | Documentation only                                    |
| `refactor` | Code restructuring without behavior change            |
| `test`     | Adding or fixing tests                                |
| `chore`    | Build scripts, dependency updates, repo maintenance   |
| `style`    | Formatting, whitespace (no logic change)              |

### Scopes — use the affected module or component name

| Scope            | Applies to                              |
|------------------|-----------------------------------------|
| `launcher`       | `launcher.py`                           |
| `gui`            | `ui/launcher_gui.py`                    |
| `dashboard`      | `modules/dashboard.py`                  |
| `lan_scan`       | `modules/lan_scan.py`                   |
| `passive_monitor`| `modules/passive_monitor.py`            |
| `arp_monitor`    | `modules/arp_monitor.py`                |
| `tls_audit`      | `modules/tls_audit.py`                  |
| `anomaly_detect` | `modules/anomaly_detect.py`             |
| `pentest_tools`  | `modules/pentest_tools.py`              |
| `wifi_audit`     | `modules/wifi_audit.py`                 |
| `bluetooth_recon`| `modules/bluetooth_recon.py`            |
| `osint`          | `modules/osint.py`                      |
| `report`         | `utils/report_generator.py`             |
| `config`         | `utils/config_loader.py` / `config/`    |
| `logger`         | `utils/logger.py`                       |
| `result`         | `utils/result_handler.py`               |
| `docs`           | `docs/`                                 |
| `core`           | cross-cutting (launcher, engine, utils) |
| `modules`        | multiple modules in one commit          |

### Real examples from this project

```bash
feat(modules): implement Phases 5, 6 and 7 scanning and detection modules
feat(core): implement Phase 4 core engine
feat: initial project skeleton with architecture design
feat(dashboard): add per-scan detail pages and fix result ordering
fix(dashboard): sort results by mtime for true newest-first order
docs(architecture): full rewrite for v1.0.0
docs(installation): add Pi hardware setup and verification steps
docs(user_guide): document all 8 modules and troubleshooting section
```

### What NOT to do

```bash
# Too vague
git commit -m "fix stuff"
git commit -m "update"

# Not conventional commits format
git commit -m "I added the wifi module"

# Do NOT include co-authorship lines
# (never add "Co-Authored-By: Claude" or similar to commits in this project)
```

---

## 5. Merging dev → main (Releases)

A release is a merge of `dev` into `main`. Do this when:
- All planned features for the version are complete and tested
- No known blocking bugs

### Steps

```bash
# 1. Make sure dev is up to date and pushed
git checkout dev
git pull origin dev
git push origin dev     # confirm all local commits are on GitHub

# 2. Switch to main and pull the latest
git checkout main
git pull origin main

# 3. Merge dev into main (no fast-forward — keep merge commit)
git merge dev --no-ff -m "release: merge dev into main for v1.0.0"

# 4. Push main
git push origin main
```

### Handling merge conflicts

If a conflict appears during the merge:

```bash
# Git will list conflicting files, e.g.:
# CONFLICT (content): Merge conflict in modules/anomaly_detect.py

# Option A: keep the dev version (most common — dev is the tested integration)
git checkout --ours modules/anomaly_detect.py

# Option B: keep the main version
git checkout --theirs modules/anomaly_detect.py

# Option C: open the file and manually resolve the conflict markers
# (<<<<<<< HEAD ... ======= ... >>>>>>> dev)

# After resolving all conflicts:
git add modules/anomaly_detect.py
git commit    # completes the merge commit
git push origin main
```

### After a release

Tag the release for historical reference:

```bash
git tag v1.0.0 -m "Release v1.0.0"
git push origin v1.0.0
```

---

## 6. Adding a New Scan Module

Every scan module follows the same contract. Here is the complete checklist to add
a new module named `example_scan` as a concrete reference.

### 6.1 Create the module file

Create `modules/example_scan.py`:

```python
"""
CyberDeck — Example Scan Module
================================
Brief description of what this module does and why.
"""

import logging
from datetime import datetime

logger = logging.getLogger("cyberdeck")


def run(config: dict) -> dict:
    """
    Entry point for the example_scan module.

    Args:
        config: Full config dict loaded from config/config.json

    Returns:
        Standardized result dict:
        {
            "module":    "example_scan",
            "timestamp": "<ISO 8601>",
            "status":    "success" | "error" | "partial",
            "data":      { ... module-specific results ... },
            "errors":    []
        }
    """
    timestamp = datetime.now().isoformat()
    errors = []

    try:
        # --- your scan logic here ---
        data = {}  # populate with scan results

        status = "success"

    except Exception as exc:
        logger.error("example_scan failed: %s", exc)
        errors.append(str(exc))
        data = {}
        status = "error"

    return {
        "module":    "example_scan",
        "timestamp": timestamp,
        "status":    status,
        "data":      data,
        "errors":    errors,
    }
```

The **only required interface** is `run(config) -> dict`. The launcher discovers
modules by calling `importlib.import_module(f"modules.{name}")` and then
`module.run(config)`.

### 6.2 Register in launcher.py

Open `launcher.py` and add the module name to `MODULES`:

```python
MODULES = [
    "lan_scan",
    "passive_monitor",
    "arp_monitor",
    "tls_audit",
    "anomaly_detect",
    "pentest_tools",
    "wifi_audit",
    "bluetooth_recon",
    "osint",
    "example_scan",   # ← add here
]
```

The order in this list determines the order in the GUI buttons and text menu.

### 6.3 Add a detail view in dashboard.py

Open `modules/dashboard.py` and find `_DETAIL_TEMPLATE`. Add a new `{% elif %}`
block for your module inside the `{% if module == "..." %}` chain:

```html+jinja
{% elif module == "example_scan" %}
<h2>Example Scan Results</h2>
{% if data.your_key %}
<table>
  <tr><th>Field</th><th>Value</th></tr>
  {% for item in data.your_key %}
  <tr>
    <td>{{ item.name }}</td>
    <td>{{ item.value }}</td>
  </tr>
  {% endfor %}
</table>
{% else %}
<p>No results found.</p>
{% endif %}
```

### 6.4 Add a report section in report_generator.py

Open `utils/report_generator.py` and add a rendering block for your module
inside `_render_module_section()` (or equivalent function). Follow the pattern
of existing modules — return an HTML string fragment.

### 6.5 Test the new module

```bash
# Run only your module in the text menu
sudo python3 launcher.py
# Select "example_scan" from the menu

# Check the result file was saved
ls -la results/ | grep example_scan

# Open the dashboard and verify the detail page renders
# Navigate to: http://localhost:5000
# Click the example_scan result filename link
```

### 6.6 Commit the new module

```bash
git checkout dev
git pull origin dev
git checkout -b feature/example-scan

git add modules/example_scan.py
git add launcher.py
git add modules/dashboard.py
git add utils/report_generator.py
git commit -m "feat(example_scan): add example scan module with dashboard and report support"

git checkout dev
git merge feature/example-scan
git push origin dev
```

---

## 7. Team Collaboration Rules

1. **Never develop directly on `main`** — main is for stable releases only.
   All code goes to `dev` via feature branches.

2. **Always pull before starting** — before creating a new feature branch,
   run `git pull origin dev` to avoid diverging from teammates' work.

3. **One module = one branch** — keep changes focused. A branch named
   `feature/lan-scan` should only touch `modules/lan_scan.py` and the
   places that register it (launcher.py, dashboard.py, report_generator.py).

4. **Test locally before merging** — run `sudo python3 launcher.py` and verify
   your module produces a valid result file in `results/` before opening a
   merge request.

5. **Never edit a teammate's module without telling them** — if you need to
   fix a bug in someone else's module, tell them first or open a `fix/` branch
   clearly named (e.g., `fix/wifi-audit-crash`) so the author can review.

6. **Do not commit `.claude/`** — this directory contains local AI assistant
   context and is listed in `.gitignore`. It must stay local.

7. **Do not commit secrets** — never commit `config/config.json` changes that
   contain real IP addresses, credentials, or API keys. Keep sensitive
   configuration local.

8. **Keep commit messages clean** — follow the Conventional Commits format.
   Do not include co-authorship lines for AI tools.

9. **Resolve conflicts by keeping `dev`** — when merging dev into main and
   a conflict appears, the dev version is usually correct (it is the
   integration-tested version). Use `git checkout --ours` to keep it.

10. **Tag releases** — every merge to main that corresponds to a version bump
    should be tagged (`git tag v1.x.x`) and pushed.

---

## 8. Useful Git Commands

```bash
# Show current status
git status

# Show all branches (local and remote)
git branch -a

# Show log with graph (last 10 commits)
git log --oneline --graph -10

# Show what changed in the last commit
git show HEAD --stat

# See the diff between dev and main
git diff main..dev --stat

# Undo the last commit but keep the changes staged
git reset --soft HEAD~1

# Discard all unstaged changes in a single file
git checkout -- path/to/file.py

# Check remote URL
git remote -v

# Update remote URL (silent on success)
git remote set-url origin git@github.com:Stevenyoumbi99/cyberdeck.git

# List tags
git tag

# Create and push a release tag
git tag v1.0.0 -m "Release v1.0.0"
git push origin v1.0.0
```
