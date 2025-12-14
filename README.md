# Watcher

## High-Signal Linux File Monitoring for Security-Sensitive Systems

Watcher is a lightweight Linux file monitoring tool designed for administrators who need **actionable security visibility without filesystem noise**.

Most file integrity and monitoring tools either generate excessive events, require heavy agents, or lack meaningful attribution. Watcher focuses only on **security-relevant files and behaviors**, capturing *who changed what, how, and from where* — in real time — using native Linux mechanisms.

This project is intended for environments where **clarity and forensic signal matter more than volume**.

---

## What Watcher Is Good For

Typical use cases include:

- Detecting unauthorized changes to system configuration
- Identifying persistence mechanisms after compromise
- Monitoring privileged file access on hardened servers
- Reconstructing activity during security incidents
- Lightweight monitoring where full FIM / EDR tools are impractical

Watcher is especially useful on servers, lab systems, and administrative machines where you want visibility without deploying complex infrastructure.

---

## High-Signal Monitoring (Not Full Filesystem Scanning)

Watcher intentionally monitors **only paths that indicate compromise or persistence**, dramatically reducing noise while still catching meaningful activity.

Monitored locations include:

**Core system areas:**
- `/etc`
- `/usr`
- `/var`
- `/root`

**User-level sensitive files:**
- Shell startup files (`.bashrc`, `.bash_profile`, `.profile`, `.zshrc`, `.zprofile`)
- `~/.ssh/` (keys, configs, authorized_keys, known_hosts)
- `~/.gnupg/`
- `~/.config/systemd/`
- `~/bin/`

These locations are common targets for backdoors, privilege escalation, and persistence.

---

## Events Captured

Watcher tracks security-relevant filesystem activity, including:

- File content changes (`IN_MODIFY`, `IN_CLOSE_WRITE`)
- Permission, ownership, or timestamp changes (`IN_ATTRIB`)
- File creation, deletion, and moves
- Read or open access to sensitive files

Even simple actions like `cat` or attempted copies inside protected paths are visible.

---

## Forensic-Quality Attribution

Each event includes enough context to answer **who acted, how they acted, and from where**, without correlating multiple log sources.

Captured metadata includes:

- Username and UID
- Local vs remote session
- SSH session details (when applicable)
- Process name and executable path
- PID / PPID
- Full command line
- File size
- Creation and modification timestamps

This allows rapid reconstruction of activity during incident response.

---

## Intelligent Noise Reduction

Watcher is designed to remain usable on real systems:

- Filters high-traffic but low-value paths (browser caches, temp files)
- Suppresses editor swap and temporary files
- Debounce logic to avoid repeated triggers during rapid edits
- Automatic log rotation to prevent disk growth
- Severity classification for prioritization

### Severity Levels

- **HIGH** – Modification, deletion, or permission changes to security-sensitive files
- **MEDIUM** – New or suspicious files inside protected directories
- **LOW** – Read or open access to sensitive files

---

## Logging

Events are written to console and to rotating log files located at:

```
/root/logs/security-monitor
```

Logs are structured for manual review or downstream processing.

---

## Customization & Integration

Watcher is intentionally simple and scriptable:

- Monitored paths can be tailored to specific system roles
- Severity rules can be adjusted per environment
- Output can be adapted for alerting, reporting, or SIEM ingestion
- Designed to be extended rather than replaced

This repository provides a practical foundation that can be adapted to many operational contexts.

---

## About This Project

Watcher is maintained as a focused, transparent Linux security tool rather than a full monitoring platform.

If you need this adapted, extended, or integrated into your environment — including custom rules, reporting, or deployment-specific tuning — I am available for **fixed-scope customization and tooling work**.

---

*Technical documentation and implementation details are intentionally kept separate to preserve clarity and maintainability.*
