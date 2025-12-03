# **Watcher – Real-Time Linux Security File Monitor (Updated 12/25)**
/
**Watcher** is a lightweight, high-signal security monitoring tool designed to detect suspicious or unauthorized activity on Linux systems.  
It provides **real-time alerts**, **process attribution**, and **forensic-quality metadata**, while avoiding the noise and overhead of full filesystem monitoring.

Watcher focuses strictly on **security-relevant files** and **intrusion indicators**, making it suitable for system administrators, security teams, and hardened administrative environments.

---

## **Features**

### **Selective High-Security Monitoring**

Watcher monitors only directories and files that matter for system integrity and compromise detection:

- Core system configuration directories:  
  - `/etc`  
  - `/usr`  
  - `/var`  
  - `/root`
- Per-user sensitive items:
  - Shell rc files (`.bashrc`, `.bash_profile`, `.profile`, `.zshrc`, `.zprofile`)
  - `~/.ssh/` (keys, configs, authorized_keys, known_hosts)
  - `~/.gnupg/`
  - `~/.config/systemd/`
  - `~/bin/`

This dramatically reduces noise while still catching attacks, persistence mechanisms, and unauthorized access.

---

### **Event Types Captured**

Watcher detects:

- **IN_MODIFY** file content changes  
- **IN_CLOSE_WRITE** editors finishing writes  
- **IN_ATTRIB** permission changes, ownership changes, timestamp tampering  
- **IN_DELETE / IN_MOVED_FROM / IN_MOVED_TO** deletions & moves  
- **IN_CREATE** creation of suspicious files  
- **IN_OPEN** *reads or file opens* (sensitive directories only)

Even a simple `cat file` or attempted copy is logged.

---

### **User & Process Attribution**

Each alert captures:

- Username  
- UID  
- Local vs remote login  
- SSH session details (if applicable)  
- Process name  
- Process path  
- PID / PPID  
- Full command line  
- File size  
- File creation & modification timestamps

This provides strong forensic signal: *who did what, when, how, and using what program*.

---

### **Intelligent Filtering & Signal Controls**

Watcher includes multiple noise-reduction features:

- Filters out harmless high-traffic locations (browser caches, temp files, etc.)
- Suppresses editor swap/temporary files
- Debounce logic to avoid repeated triggers during fast edits
- Automatic log rotation to prevent disk bloat
- Severity classification (HIGH / MEDIUM / LOW)

---

### **Severity Levels**

- **HIGH** – modification, deletion, or permission changes to security-sensitive files  
- **MEDIUM** – new files or suspicious activity inside protected directories  
- **LOW** – read/open access to sensitive files

---

### **Logging**

Watcher outputs to console and rotates log files in:
/root/logs/security-monitor
