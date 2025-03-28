import os
import json
import time
from datetime import datetime
import pyinotify
import pwd
import shutil
import psutil
import re  # For regex matching

# Define directories to watch
WATCHED_DIRECTORIES = ['/etc', '/bin', '/sbin', '/usr/bin', '/usr/sbin', '/lib', '/home']

# Hidden directory for logs and whitelist
LOG_DIR = "/dev/.wl/logs/"
LOG_FILE = os.path.join(LOG_DIR, "watcher.log")
WHITELIST_FILE = "/dev/.wl/whitelist.json"

# Initialize IGNORE_LIST with hardcoded defaults
IGNORE_LIST = [
    '/var/log/', '/etc/cron.d/', '/etc/fwupd', '/etc/sudoers', '/etc/fonts/', '/etc/xdg/',
    '/etc/sgml/', '/etc/dconf/', '/etc/udev/', '/etc/thunderbird/', '/etc/exim4/',
    '/etc/vulkan/', '/etc/dpkg/', '/etc/logcheck/', '/etc/cups/', '/etc/polkit-1/',
    '/etc/libblockdev/', '/etc/avahi/', '/etc/NetworkManager/', '/etc/alsa/',
    '/etc/pki/', '/etc/smartmontools/', '/etc/passwd', '/etc/nvidia/', '/etc/ModemManager/',
    '/etc/apparmor.d/', '/etc/X11/', '/etc/opt/chrome/'
]

# Directories to always monitor (prevent adding these to the whitelist)
CRITICAL_DIRECTORIES = [
    "/etc/ssh", "/etc/systemd", "/etc/network", "/etc/cron.d",
    "/etc/cron.weekly", "/etc/sudoers.d", "/etc/init.d", "/etc/rc0.d",
    "/etc/rc1.d", "/etc/rc2.d", "/etc/rc3.d", "/etc/rc4.d", "/etc/rc5.d", "/etc/rc6.d"
]

# Log rotation settings
MAX_LOG_SIZE = 5 * 1024 * 1024  # 5 MB
MAX_LOG_FILES = 10  # Number of rotated logs to keep

# Alternating header counter
HEADER_COUNTER = 0

# Track last event times for debounce logic and whitelisting
last_event_times = {}
last_seen_paths = {}

# Debounce and delay thresholds in seconds
DEBOUNCE_TIME = 5
WHITELIST_DELAY_TIME = 15


def ensure_directory():
    """Ensure necessary directories and files exist, and initialize whitelist."""
    if not os.path.exists(LOG_DIR):
        os.makedirs(LOG_DIR, exist_ok=True)
    if not os.path.exists(WHITELIST_FILE):
        # Populate whitelist.json with default values if it doesn't exist
        with open(WHITELIST_FILE, "w") as f:
            json.dump(IGNORE_LIST, f, indent=4)
        print("[WHITELIST] Created and initialized.")
    if not os.path.exists(LOG_FILE):
        open(LOG_FILE, "w").close()


def load_whitelist():
    """Load whitelist patterns from whitelist.json into IGNORE_LIST."""
    global IGNORE_LIST
    try:
        with open(WHITELIST_FILE, "r") as f:
            dynamic_whitelist = json.load(f)
        # Combine the hardcoded list with the dynamic whitelist
        IGNORE_LIST = list(set(IGNORE_LIST + dynamic_whitelist))
        print("[WHITELIST] Loaded and merged.")
    except FileNotFoundError:
        print("[WHITELIST] File not found. Using hardcoded ignore list.")
    except json.JSONDecodeError:
        print("[WHITELIST] Invalid JSON format. Using hardcoded ignore list.")


def add_to_whitelist(path):
    """Dynamically add paths to the whitelist after a delay."""
    now = time.time()
    if path in CRITICAL_DIRECTORIES:
        print(f"[WHITELIST] Skipping critical directory: {path}")
        return

    # Check for delay before adding to whitelist
    if path in last_seen_paths and now - last_seen_paths[path] < WHITELIST_DELAY_TIME:
        print(f"[WHITELIST] Path delay not met for: {path}")
        return

    last_seen_paths[path] = now

    # Add to whitelist if not already present
    if path not in IGNORE_LIST:
        IGNORE_LIST.append(path)
        with open(WHITELIST_FILE, "w") as f:
            json.dump(IGNORE_LIST, f, indent=4)
        print(f"[WHITELIST] Added to whitelist: {path}")


def rotate_logs():
    """Check log size and rotate if necessary."""
    if os.path.exists(LOG_FILE) and os.path.getsize(LOG_FILE) > MAX_LOG_SIZE:
        timestamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")
        rotated_log = os.path.join(LOG_DIR, f"watcher_{timestamp}.log")
        shutil.move(LOG_FILE, rotated_log)
        print(f"[LOG ROTATION] Log rotated: {rotated_log}")

        # Compress the rotated log (optional)
        shutil.make_archive(rotated_log, 'gztar', root_dir=LOG_DIR, base_dir=os.path.basename(rotated_log))
        os.remove(rotated_log)

        # Manage the number of archived logs
        cleanup_old_logs()


def cleanup_old_logs():
    """Delete old rotated logs if they exceed the limit."""
    logs = sorted([f for f in os.listdir(LOG_DIR) if f.startswith("watcher_") and f.endswith(".log.tar.gz")])
    while len(logs) > MAX_LOG_FILES:
        oldest_log = os.path.join(LOG_DIR, logs.pop(0))
        os.remove(oldest_log)
        print(f"[LOG CLEANUP] Removed old log: {oldest_log}")


def get_username_from_uid(uid):
    try:
        user_info = pwd.getpwuid(uid)
        return user_info.pw_name
    except KeyError:
        return f"UID:{uid}"


def get_process_info(file_path):
    """Identify the process accessing the file."""
    for proc in psutil.process_iter(['pid', 'name', 'username', 'open_files']):
        try:
            if any(file.path == file_path for file in proc.info['open_files'] or []):
                return f"{proc.info['name']} (PID: {proc.info['pid']}) by {proc.info['username']}"
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            continue
    return "Unknown"


def is_user_remote(user):
    """Check if the user is remote."""
    try:
        sessions = psutil.users()
        for session in sessions:
            if session.name == user:
                # Remote if accessed via SSH or has a hostname
                if session.host != "":
                    return "Remote"
                # Check if the terminal is pseudo (pts) or not
                if session.terminal and session.terminal.startswith('pts'):
                    return "Remote"
        return "Local"
    except Exception as e:
        print(f"[ERROR] Failed to determine user location: {e}")
        return "Unknown"


def should_log_event(file_path):
    """Determine if the event should be logged based on debounce time."""
    global last_event_times
    now = time.time()
    if file_path in last_event_times:
        if now - last_event_times[file_path] < DEBOUNCE_TIME:
            return False
    last_event_times[file_path] = now
    return True


def log_event_block(event):
    global HEADER_COUNTER
    rotate_logs()  # Check and rotate logs before writing
    file_path = event["file_path"]
    action = event["action"]
    user = event["user"]

    if not should_log_event(file_path):
        return  # Skip logging if debounce conditions are met

    access_method = get_process_info(file_path)
    user_type = is_user_remote(user)

    try:
        metadata = os.stat(file_path)
        size = metadata.st_size
        uid = metadata.st_uid
        mtime = datetime.fromtimestamp(metadata.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
        ctime = datetime.fromtimestamp(metadata.st_ctime).strftime('%Y-%m-%d %H:%M:%S')
    except FileNotFoundError:
        size, uid, mtime, ctime = "Unknown", "Unknown", "Unknown", "Unknown"

    header = ""
    if HEADER_COUNTER % 2 == 0:
        header = "------ NEW UPDATE DETECTED ------\n"

    log_entry = (
        f"{header}"
        f"File: {file_path}\n"
        f"Action: {action}\n"
        f"Modified: {mtime}\n"
        f"Created: {ctime}\n"
        f"Changed by: {user} ({user_type})\n"
        f"Access Method: {access_method}\n"
        f"Size: {size} bytes\n"
        f"UID: {uid}\n"
        f"---------------------------------\n"
    )

    with open(LOG_FILE, "a") as log:
        log.write(log_entry)

    print(log_entry)
    HEADER_COUNTER += 1


class MyEventHandler(pyinotify.ProcessEvent):
    def process_default(self, event):
        # Check if the event path matches any ignore pattern using regex search
        if any(re.search(pattern, event.pathname) for pattern in IGNORE_LIST):
            return

        file_path = event.pathname
        action = event.maskname.lower()

        # Dynamically add repetitive paths to the whitelist
        if file_path.startswith('/etc/') and 'in_isdir' in action:
            add_to_whitelist(file_path)

        try:
            metadata = os.stat(file_path)
            user = get_username_from_uid(metadata.st_uid)
        except FileNotFoundError:
            user = "Unknown"

        event_data = {
            "file_path": file_path,
            "action": action,
            "user": user
        }

        log_event_block(event_data)


def start_monitoring():
    ensure_directory()
    load_whitelist()

    wm = pyinotify.WatchManager()
    handler = MyEventHandler()
    mask = pyinotify.IN_MODIFY | pyinotify.IN_ATTRIB | pyinotify.IN_DELETE | pyinotify.IN_CREATE | pyinotify.IN_ACCESS

    for directory in WATCHED_DIRECTORIES:
        if os.path.isdir(directory):
            wm.add_watch(directory, mask, rec=True)

    notifier = pyinotify.Notifier(wm, handler)
    print("Monitoring file accesses in critical directories. Press Ctrl+C to stop.")
    notifier.loop()


if __name__ == "__main__":
    try:
        start_monitoring()
    except KeyboardInterrupt:
        print("Monitoring stopped.")
