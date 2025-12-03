#!/usr/bin/env python3
"""
Usage:
  sudo ./Watch.py --console   # foreground + logs
  sudo ./Watch.py --daemon    # silent (logs only)
  sudo ./Watch.py --dry-run   # preview watch roots and planned sensitive items

Requirements:
  sudo apt install python3-pyinotify python3-psutil
"""
from __future__ import annotations

import os
import sys
import pwd
import argparse
import logging
import logging.handlers
from datetime import datetime

try:
    import pyinotify
except Exception:
    print("pyinotify required. Install: sudo apt install python3-pyinotify", file=sys.stderr)
    raise

try:
    import psutil
except Exception:
    print("psutil required. Install: sudo apt install python3-psutil", file=sys.stderr)
    raise

# -------------------- Configuration --------------------
LOG_DIR = "/root/logs/security-monitor"
LOG_FILE = os.path.join(LOG_DIR, "watcher.log")
MAX_LOG_BYTES = 5 * 1024 * 1024
BACKUP_COUNT = 7

COLOR_LOW = "\033[94m"
COLOR_MID = "\033[93m"
COLOR_HIGH = "\033[91m"
COLOR_RESET = "\033[0m"

# Small recursive set of system dirs
RECURSIVE_SYSTEM_DIRS = [
    "/etc", "/root", "/boot",
    "/bin", "/sbin", "/usr/bin", "/usr/sbin",
    "/lib", "/lib64", "/usr/local/bin"
]

# Critical prefixes (HIGH severity on writes)
CRITICAL_PREFIXES = [
    "/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/ssh",
    "/etc/systemd", "/boot", "/root"
]

# Home coverage (FULL) - sensitive items and recursive safe subtrees
HOME_SENSITIVE_FILES = [
    ".bashrc", ".bash_profile", ".profile", ".bash_logout",
    ".zshrc", ".zprofile", ".bash_aliases", ".pam_environment", ".inputrc"
]
HOME_RECURSIVE_DIRS = [
    ".ssh", ".gnupg", "bin", ".local/bin", ".config/systemd", ".profile.d"
]
HOME_ADDITIONAL_SENSITIVE = [
    ".crontab", ".bash_history", ".ssh/authorized_keys", ".ssh/config", ".ssh/rc",
    ".ssh/known_hosts"
]
HOME_SENSITIVE_KEYWORDS = [
    "passwd", "shadow", "authorized_keys", "id_rsa", "id_ed25519", "key", "secret",
    "systemd", "service", "cron", "gpg", "gnupg"
]

# Process ignore prefixes (common noisy apps)
PROCESS_IGNORE_PREFIXES = [
    "chrome", "chromium", "firefox", "brave", "android-studio",
    "code", "vscode", "nautilus", "thunderbird", "tracker", "baloo",
    "plasma", "gvfs", "snap", "flatpak", "electron"
]

# Global ignore directories (never watch)
GLOBAL_IGNORE_DIRS = [
    "/proc", "/sys", "/dev", "/tmp", "/var/tmp", "/run/user",
    "/var/cache", "/usr/share", "/usr/local/android-studio"
]

# Masks (we include IN_OPEN & IN_ACCESS so we can selectively allow them)
WRITE_MASKS = (
    pyinotify.IN_MODIFY
    | pyinotify.IN_CLOSE_WRITE
    | pyinotify.IN_DELETE
    | pyinotify.IN_MOVED_FROM
    | pyinotify.IN_MOVED_TO
    | pyinotify.IN_MOVE_SELF
)
READ_MASKS = pyinotify.IN_OPEN | pyinotify.IN_ACCESS
ATTRIB_MASK = pyinotify.IN_ATTRIB

# Full mask we give to watchers (we filter in Python)
GLOBAL_MASK = (
    pyinotify.IN_ACCESS
    | pyinotify.IN_OPEN
    | pyinotify.IN_CLOSE_WRITE
    | pyinotify.IN_ATTRIB
    | pyinotify.IN_MODIFY
    | pyinotify.IN_CREATE
    | pyinotify.IN_DELETE
    | pyinotify.IN_MOVED_FROM
    | pyinotify.IN_MOVED_TO
    | pyinotify.IN_MOVE_SELF
)

# -------------------- Helpers --------------------
def normpath(p: str) -> str:
    try:
        return os.path.realpath(p)
    except Exception:
        return os.path.abspath(p) if p else ""

GLOBAL_IGNORE_DIRS_NORM = [normpath(x).rstrip(os.sep) + os.sep for x in GLOBAL_IGNORE_DIRS]
RECURSIVE_SYSTEM_DIRS_NORM = [normpath(x).rstrip(os.sep) + os.sep for x in RECURSIVE_SYSTEM_DIRS]
CRITICAL_PREFIXES_NORM = [normpath(x).rstrip(os.sep) for x in CRITICAL_PREFIXES]

def path_is_globally_ignored(path: str) -> bool:
    if not path:
        return True
    p = normpath(path)
    for nd in GLOBAL_IGNORE_DIRS_NORM:
        if p == nd.rstrip(os.sep) or p.startswith(nd):
            return True
    return False

def is_process_ignored(proc_path_or_name: str) -> bool:
    if not proc_path_or_name:
        return False
    pn = os.path.basename(proc_path_or_name).lower()
    for pref in PROCESS_IGNORE_PREFIXES:
        if pn.startswith(pref):
            return True
    return False

def stat_info(path: str):
    try:
        st = os.stat(path)
        size = st.st_size
        mtime = datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
        ctime = datetime.fromtimestamp(st.st_ctime).strftime("%Y-%m-%d %H:%M:%S")
        uid = st.st_uid
        return size, mtime, ctime, uid
    except Exception:
        return None, None, None, None

def pid_info(pid: int):
    try:
        p = psutil.Process(pid)
        exe = p.exe() if p.exe() else "unknown"
        cmdline = " ".join(p.cmdline()) if p.cmdline() else ""
        username = p.username() if p.username() else ""
        ppid = p.ppid()
        parent_exe = "unknown"
        try:
            parent_exe = psutil.Process(ppid).exe()
        except Exception:
            parent_exe = "unknown"
        terminal = p.terminal()
        return {
            "pid": pid,
            "exe": exe,
            "cmdline": cmdline,
            "username": username,
            "ppid": ppid,
            "parent_exe": parent_exe,
            "terminal": terminal,
        }
    except Exception:
        return None

# limited open-file scan
def find_process_opening(path: str, limit: int = 150):
    target = normpath(path)
    scanned = 0
    for proc in psutil.process_iter(['pid', 'open_files', 'name', 'username']):
        scanned += 1
        if scanned > limit:
            break
        try:
            of = proc.info.get('open_files') or []
            for f in of:
                try:
                    if not f.path:
                        continue
                    if normpath(f.path) == target:
                        return pid_info(proc.info['pid'])
                except Exception:
                    continue
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            continue
    return None

def access_method_from_proc(procinfo: dict | None) -> str:
    if not procinfo:
        return "unknown"
    try:
        pid = procinfo.get("pid")
        p = psutil.Process(pid)
        for parent in p.parents():
            try:
                name = os.path.basename(parent.exe() or "")
            except Exception:
                name = ""
            if name in ("sudo", "su"):
                return "sudo"
    except Exception:
        pass
    try:
        users = psutil.users()
        for u in users:
            if u.name == procinfo.get("username"):
                if hasattr(u, "host") and u.host:
                    return f"ssh ({u.host})"
                term = procinfo.get("terminal")
                if term is None:
                    return "gui/desktop"
                if term.startswith("tty"):
                    return "local-tty"
                if term.startswith("pts"):
                    return "local-pty"
    except Exception:
        pass
    term = procinfo.get("terminal") if procinfo else None
    if term is None:
        return "daemon"
    if term.startswith("tty"):
        return "local-tty"
    if term.startswith("pts"):
        return "local-pty"
    return "unknown"

# editor/swap heuristics
def guess_editor_from_swap(path: str):
    base = os.path.basename(path)
    if base.startswith(".") and base.endswith(".swp"):
        return ["nano", "vim"]
    if base.endswith(".swp"):
        return ["vim", "nano"]
    if base.endswith(".swo") or base.endswith(".swx"):
        return ["vim"]
    return None

def find_recent_dir_writers(parent_dir: str, limit: int = 150):
    if not parent_dir:
        return None
    parent_dir = normpath(parent_dir)
    scanned = 0
    for proc in psutil.process_iter(['pid', 'open_files', 'name', 'cmdline']):
        scanned += 1
        if scanned > limit:
            break
        try:
            of = proc.info.get('open_files') or []
            for f in of:
                try:
                    if not f.path:
                        continue
                    if normpath(os.path.dirname(f.path)) == parent_dir:
                        return pid_info(proc.info['pid'])
                except Exception:
                    continue
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            continue
    return None

# -------------------- Build sensitive lists --------------------
def build_sensitive_maps():
    """
    Build:
      - sensitive_prefixes: list of absolute prefixes for recursive sensitive dirs
      - sensitive_files_set: set of absolute file paths that are sensitive (per user)
    """
    sensitive_prefixes = set()
    sensitive_files_set = set()

    # root home and all /home/* users
    users = [u for u in pwd.getpwall() if u.pw_dir and os.path.isdir(u.pw_dir)]
    for u in users:
        home = normpath(u.pw_dir)
        # TOP-level sensitive files
        for fname in HOME_SENSITIVE_FILES + HOME_ADDITIONAL_SENSITIVE:
            sensitive_files_set.add(os.path.join(home, fname))
        # recursive sensitive directories
        for dr in HOME_RECURSIVE_DIRS:
            candidate = os.path.join(home, dr)
            # add as prefix (watch if exists)
            sensitive_prefixes.add(candidate.rstrip(os.sep))
    # also add root equivalents
    root_home = "/root"
    for fname in HOME_SENSITIVE_FILES + HOME_ADDITIONAL_SENSITIVE:
        sensitive_files_set.add(os.path.join(root_home, fname))
    for dr in HOME_RECURSIVE_DIRS:
        sensitive_prefixes.add(os.path.join(root_home, dr).rstrip(os.sep))

    # normalize
    sensitive_prefixes_norm = [normpath(x).rstrip(os.sep) for x in sensitive_prefixes]
    sensitive_files_norm = {normpath(x) for x in sensitive_files_set}
    return sensitive_prefixes_norm, sensitive_files_norm

SENSITIVE_PREFIXES, SENSITIVE_FILES = build_sensitive_maps()

# -------------------- Skip & severity rules --------------------
def path_is_sensitive(path: str) -> bool:
    """Return True if path is in SENSITIVE_FILES or under SENSITIVE_PREFIXES."""
    if not path:
        return False
    p = normpath(path)
    if p in SENSITIVE_FILES:
        return True
    for sp in SENSITIVE_PREFIXES:
        if p == sp or p.startswith(sp + os.sep):
            return True
    return False

def should_skip_event(path: str, mask: int) -> bool:
    """
    Filtering rules:
     - Skip global ignore trees
     - Skip read-only events globally EXCEPT for sensitive files (we'll allow IN_OPEN/IN_ACCESS only for sensitive)
     - For general home files (non-sensitive), skip IN_OPEN/IN_ACCESS; allow write events only for higher-level checks
     - Critical system prefixes require write events to show unless sensitive (we treat writes)
     - Filter browser/cache churn for non-writes
    """
    if not path:
        return True
    p = normpath(path).lower()

    # global ignore trees
    if path_is_globally_ignored(path):
        return True

    # If path is sensitive -> do not skip IN_OPEN/IN_ACCESS here (we'll handle below)
    is_sensitive = path_is_sensitive(path)

    # Suppress read-only masks globally except for sensitive paths
    if mask & READ_MASKS and not is_sensitive:
        return True

    # Suppress cache/browser churn for non-writes
    cache_indicators = ["/cache/", ".cache/", "/tmp/", "chromium", "chrome", "mozilla", "webstorage", "service worker"]
    if any(x in p for x in cache_indicators) and not (mask & WRITE_MASKS):
        return True

    # For critical system prefixes, suppress non-write events
    for cp in CRITICAL_PREFIXES_NORM:
        if p.startswith(cp):
            if not (mask & WRITE_MASKS or mask & ATTRIB_MASK):
                return True

    # For non-sensitive home files: if under /home and not sensitive, skip open/read and also skip metadata changes
    if p.startswith("/home/") or p.startswith("/root/"):
        if not is_sensitive:
            # allow write events for certain parent-level detection? But per Option B we only care about sensitive items
            # So skip most events
            if not (mask & WRITE_MASKS):
                return True
            # if it's a write but filename not sensitive -> skip
            if not any(kw in p for kw in HOME_SENSITIVE_KEYWORDS):
                return True

    return False

def classify_severity(mask: int, path: str) -> str:
    """Return HIGH/MEDIUM/LOW"""
    p = normpath(path)
    # attrib inside sensitive prefixes => HIGH
    if mask & ATTRIB_MASK:
        if path_is_sensitive(path):
            return "HIGH"
    # writes => high if critical prefix or sensitive system
    for f in (pyinotify.IN_DELETE, pyinotify.IN_MODIFY, pyinotify.IN_MOVED_FROM, pyinotify.IN_MOVED_TO, pyinotify.IN_MOVE_SELF):
        if mask & f:
            for cp in CRITICAL_PREFIXES_NORM:
                if p.startswith(cp):
                    return "HIGH"
            for sd in RECURSIVE_SYSTEM_DIRS_NORM:
                if p.startswith(sd):
                    return "HIGH"
            # sensitive in home => HIGH
            if path_is_sensitive(path):
                return "HIGH"
            return "MEDIUM"
    # create/close_write/attrib on system trees => medium
    if (mask & pyinotify.IN_CREATE) or (mask & pyinotify.IN_CLOSE_WRITE) or (mask & pyinotify.IN_ATTRIB):
        for sd in RECURSIVE_SYSTEM_DIRS_NORM:
            if p.startswith(sd):
                return "MEDIUM"
        if path_is_sensitive(path):
            return "MEDIUM"
        return "LOW"
    return "LOW"

# -------------------- Logging setup --------------------
logger = None
def ensure_log_dir():
    try:
        os.makedirs(LOG_DIR, exist_ok=True)
    except Exception:
        pass

def setup_logging():
    global logger
    ensure_log_dir()
    logger = logging.getLogger("watcher_v4_5")
    logger.setLevel(logging.INFO)
    handler = logging.handlers.RotatingFileHandler(LOG_FILE, maxBytes=MAX_LOG_BYTES, backupCount=BACKUP_COUNT)
    formatter = logging.Formatter('%(asctime)s %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
    handler.setFormatter(formatter)
    logger.addHandler(handler)

# -------------------- Event handler --------------------
class WatchHandler(pyinotify.ProcessEvent):
    def __init__(self, console: bool = True):
        super().__init__()
        self.console = console

    def process_default(self, event):
        path = getattr(event, "pathname", None)
        if not path:
            return
        path = normpath(path)
        mask = getattr(event, "mask", 0)
        maskname = getattr(event, "maskname", "UNKNOWN")

        # Skip quickly
        if should_skip_event(path, mask):
            return

        severity = classify_severity(mask, path)

        # Attribution pipeline
        pid = getattr(event, "pid", None)
        uid = getattr(event, "uid", None)
        procinfo = None
        if isinstance(pid, int) and pid > 0:
            procinfo = pid_info(pid)

        if not procinfo and severity in ("MEDIUM", "HIGH"):
            procinfo = find_process_opening(path, limit=200)

        # editor guess (swap) fallback
        if not procinfo:
            guesses = guess_editor_from_swap(path)
            if guesses:
                for g in guesses:
                    for p in psutil.process_iter(['pid','name','cmdline','exe']):
                        try:
                            name = (p.info.get('name') or "").lower()
                            cmd = " ".join(p.info.get('cmdline') or [])
                            exe = (p.info.get('exe') or "").lower()
                            if g in name or g in cmd or g in exe:
                                procinfo = pid_info(p.pid)
                                break
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            continue
                    if procinfo:
                        break

        # recent dir writers
        if not procinfo:
            parent = os.path.dirname(path)
            procinfo = find_recent_dir_writers(parent, limit=200)

        # metadata
        size, mtime, ctime, st_uid = stat_info(path)
        # user attribution
        user = None
        if procinfo:
            user = procinfo.get("username") or None
        if not user:
            try:
                if isinstance(uid, int):
                    user = pwd.getpwuid(uid).pw_name
                elif isinstance(st_uid, int):
                    user = pwd.getpwuid(st_uid).pw_name
                else:
                    user = "?"
            except Exception:
                user = "?"

        # drop noisy processes discovered by procinfo
        if procinfo:
            exe_path = procinfo.get("exe") or ""
            if is_process_ignored(exe_path) or is_process_ignored(procinfo.get("cmdline") or ""):
                return

        exe = procinfo.get("exe") if procinfo else "unknown"
        cmdline = procinfo.get("cmdline") if procinfo else ""
        pid_display = procinfo.get("pid") if procinfo else (pid if pid is not None else "?")
        ppid = procinfo.get("ppid") if procinfo else "?"
        parent_exe = procinfo.get("parent_exe") if procinfo else "unknown"
        access_method = access_method_from_proc(procinfo) if procinfo else "unknown"
        uid_out = st_uid if st_uid is not None else (uid if uid is not None else "?")

        # Build formatted forensic block
        header = ""
        if severity == "HIGH":
            header = "------ HIGH-RISK CHANGE ------\n"
        elif severity == "MEDIUM":
            header = "------ SUSPICIOUS CHANGE ------\n"

        size_out = f"{size} bytes" if size is not None else "Unknown"
        mtime_out = mtime or "Unknown"
        ctime_out = ctime or "Unknown"

        block_lines = [
            header if header else "",
            f"File: {path}",
            f"Action: {maskname}",
            f"Modified: {mtime_out}",
            f"Created: {ctime_out}",
            f"Changed by: {user} (UID: {uid_out})",
            f"Access Method: {access_method}",
            f"Process: {exe}",
            f"PID: {pid_display}  PPID: {ppid} ({parent_exe})",
            f"Cmdline: {cmdline}",
            f"Size: {size_out}",
            "---------------------------------",
        ]
        block = "\n".join([ln for ln in block_lines if ln is not None and ln != ""])

        color = COLOR_LOW if severity == "LOW" else (COLOR_MID if severity == "MEDIUM" else COLOR_HIGH)
        first_line = f"[{severity}] {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | {maskname} | {path}"
        if self.console:
            print(f"{color}{first_line}{COLOR_RESET}")
            print(block)

        # persist only MEDIUM/HIGH
        if severity in ("MEDIUM", "HIGH") and logger:
            logger.info(block)

# -------------------- Build watches --------------------
def build_watch_roots():
    """
    Build a small set of watch roots:
      - recursive system roots (small)
      - /home (recursive) to monitor users (we filter events in Python)
      - root (/root) included among system roots above; ensure present
    """
    roots = []
    # system roots (recursive where appropriate)
    for sd in RECURSIVE_SYSTEM_DIRS:
        if os.path.isdir(sd) and not path_is_globally_ignored(sd):
            roots.append((normpath(sd), True))

    # ALWAYS watch /home recursively to capture per-user sensitive changes
    if os.path.isdir("/home") and not path_is_globally_ignored("/home"):
        roots.append((normpath("/home"), True))

    # ensure /root is watched (already in RECURSIVE_SYSTEM_DIRS typically)
    if os.path.isdir("/root") and not path_is_globally_ignored("/root"):
        roots.append((normpath("/root"), True))

    # deduplicate
    seen = set()
    result = []
    for p, r in roots:
        if p not in seen:
            seen.add(p)
            result.append((p, r))
    return result

# -------------------- Main --------------------
def main():
    parser = argparse.ArgumentParser(description="Watcher v4.5 - Full home coverage (sensitive IN_OPEN/IN_ACCESS)")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--console", action="store_true", help="Foreground console (prints + logs)")
    group.add_argument("--daemon", action="store_true", help="Daemon mode (logs only)")
    parser.add_argument("--dry-run", action="store_true", help="List planned watches and sensitive items and exit")
    args = parser.parse_args()

    console_enabled = args.console or not args.daemon
    if os.geteuid() != 0 and console_enabled:
        print("Warning: running without root may miss events or process attribution.", file=sys.stderr)

    # Update global ignore set with log dir and common per-user caches
    GLOBAL_IGNORE_DIRS_NORM.extend([normpath(LOG_DIR).rstrip(os.sep) + os.sep])
    # Add per-user caches:
    for u in pwd.getpwall():
        h = u.pw_dir
        if h and os.path.isdir(h):
            GLOBAL_IGNORE_DIRS_NORM.append(normpath(os.path.join(h, ".cache")).rstrip(os.sep) + os.sep)
            GLOBAL_IGNORE_DIRS_NORM.append(normpath(os.path.join(h, ".local", "share", "Trash")).rstrip(os.sep) + os.sep)

    setup_logging()

    # Print planned sensitive items head-up
    if args.dry_run:
        print("Dry-run: Sensitive prefixes (recursive) (sample):")
        for sp in SENSITIVE_PREFIXES[:20]:
            print("  ", sp)
        print("\nDry-run: Sensitive files (explicit sample):")
        for sf in list(SENSITIVE_FILES)[:40]:
            print("  ", sf)
        print("\nPlanned watch roots:")
        for p, r in build_watch_roots():
            print(f"  {p}  rec={r}")
        return

    # create WatchManager and Notifier
    wm = pyinotify.WatchManager()
    mask = GLOBAL_MASK
    handler = WatchHandler(console=console_enabled)
    notifier = pyinotify.Notifier(wm, handler)

    # add roots
    added = 0
    for path, rec in build_watch_roots():
        try:
            wm.add_watch(path, mask, rec=rec, auto_add=rec)
            added += 1
        except Exception:
            continue

    if console_enabled:
        print("=== Watcher v4.5 started ===")
        print(f"Watches added (roots): {added}")
        print(f"Sensitive users/files: {len(SENSITIVE_PREFIXES)} prefixes, {len(SENSITIVE_FILES)} explicit files")
        print(f"Logging to: {LOG_FILE}")
        print("Monitoring. Press Ctrl+C to stop.\n")

    try:
        notifier.loop()
    except KeyboardInterrupt:
        if console_enabled:
            print("\nStopping monitor...")
        try:
            notifier.stop()
        except Exception:
            pass
    except Exception as e:
        print("Notifier error:", e, file=sys.stderr)
        try:
            notifier.stop()
        except Exception:
            pass

if __name__ == "__main__":
    main()
