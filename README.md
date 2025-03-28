## **Watcher – System Monitoring Script**  

**Watcher** is a real-time system monitoring script that detects and logs changes to critical system directories. It helps administrators track modifications, file accesses, and deletions, making it useful for security auditing, intrusion detection, and system troubleshooting.  

### **Features**  

- **Monitors Key System Directories**  
  - Watches critical paths such as `/etc`, `/bin`, `/usr/bin`, and `/home`.  
  - Detects file modifications, attribute changes, deletions, and access events.  

- **User & Process Tracking**  
  - Identifies the user responsible for changes.  
  - Differentiates between local and remote users.  
  - Detects the process accessing or modifying a file.  

- **Intelligent Logging & Whitelisting**  
  - Maintains a **whitelist** of frequently changing files to reduce noise.  
  - Uses **debounce logic** to prevent excessive logging of rapid changes.  
  - Implements **log rotation** to manage disk space efficiently.  

### **Usage**  

To run the script, execute:  
```bash
sudo python watcher.py
```
It must be run with **root privileges** to monitor system directories effectively.  

### **Requirements**  
- **Python 3**  
- `pyinotify`, `psutil`, and `shutil` libraries (install with `pip install pyinotify psutil`)  

This tool provides real-time insights into system changes, helping maintain security and operational awareness.
