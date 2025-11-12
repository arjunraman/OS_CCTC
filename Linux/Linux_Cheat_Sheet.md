# 🐧 Linux Command Cheat Sheet (Comprehensive)

A detailed, practical reference for Linux command-line use — from basics to advanced system and process management.

---

## 🧩 1. Basic Commands (with explanations)

| Description | Command | What it does / Example |
|--------------|----------|-------------------------|
| Print the current directory | `pwd` | Prints the full path of the current working directory. Example: `pwd` → `/home/alice/projects` |
| Print hostname of a system | `hostname` | Shows the system's network hostname. Example: `hostname` → `server1` |
| Display system information | `uname -a` | Shows kernel name, hostname, kernel release, version, and architecture. |
| Display IP address | `ifconfig` | Shows network interfaces and their IPs (`ip addr` is the modern equivalent). |
| Display network connections | `ss -ntlp` | Lists listening TCP sockets with associated processes. |
| List directories | `ls` | Lists files and directories in the current folder. |
| Change directories | `cd` | Navigates directories. Examples: `cd /var/log`, `cd ..`, `cd ~` |
| Read file contents | `cat` | Displays contents of a file. Example: `cat /etc/hosts` |
| Display command help page | `man` | Opens manual page for a command. Example: `man grep` (press `q` to exit). |

---

## ⚙️ 1.5 Useful Commands (with explanations & examples)

| Description | Command | What it does / Example |
|-------------|---------|------------------------|
| Connect over SSH | `ssh user@IP` | Securely connect to a remote host. Example: `ssh alice@203.0.113.10` |
| Search for a string in a file | `grep 'root' /etc/passwd` | Finds matching lines in a file. Add `-n` for line numbers. |
| Recursively search a directory | `grep -R 'keyword' /home/user/` | Searches all files recursively. |
| Search system for a file | `find / -name 'file.txt' 2>/dev/null` | Searches entire filesystem (ignores permission errors). |
| List hidden files with permissions | `ls -la` | Shows all files (including hidden ones) with details. |

---

## 📂 1.6 Key File Locations (what they contain)

| File Path | Purpose / Notes |
|-----------|-----------------|
| `/etc/passwd` | User accounts, UIDs, GIDs, shells, home directories. |
| `/etc/shadow` | Encrypted password hashes, readable only by root. |
| `/etc/group` | Group names and members. |
| `/etc/profile` | System-wide login configuration. |
| `/etc/hosts` | Local hostname-to-IP mapping. |

---

## ⚡ 1.7 Common One-Liners

| Purpose | Command |
|----------|----------|
| Top 10 memory-consuming processes | `ps aux --sort=-%mem | head` |
| Disk usage by directory | `du -h --max-depth=1 | sort -hr` |
| Find files over 500MB | `find / -type f -size +500M 2>/dev/null` |
| Count processes | `ps -e | wc -l` |
| Show open ports | `ss -tuln` |
| View logged-in users | `who` or `w` |
| System uptime | `uptime` |
| Follow log in real time | `tail -f /var/log/syslog` |
| Search logs for “error” | `grep -i error /var/log/syslog` |
| Restart a service | `sudo systemctl restart nginx` |
| Check which process uses a port | `sudo lsof -i :8080` |
| Delete old log files (>30 days) | `find /var/log -type f -mtime +30 -delete` |

---

## 🧩 2. Process and System Resource Management

| Description | Command | Explanation |
|--------------|----------|-------------|
| Show all running processes | `ps aux` | Displays all processes with CPU, memory, and user info. |
| Monitor live processes | `top` | Real-time process monitor. Press `q` to quit. |
| Improved interface | `htop` | Enhanced, color-coded process viewer. |
| List processes by user | `ps -u username` | Shows only processes from a specific user. |
| Find a process by name | `pgrep processname` | Returns PIDs of matching processes. |
| Kill a process by PID | `kill <PID>` | Sends a termination signal. |
| Force kill a process | `kill -9 <PID>` | Sends SIGKILL (cannot be ignored). |
| Kill by name | `pkill processname` | Terminates all instances of a named process. |
| Change process priority | `renice <PID> -n <value>` | Adjusts CPU scheduling priority (-20 to 19). |
| Run with specific priority | `nice -n 10 command` | Starts a command with lower priority. |
| CPU usage summary | `mpstat 1` | Displays CPU usage per second. |
| Memory usage overview | `free -m` | Shows total and free RAM in MB. |
| System performance stats | `vmstat 1` | Reports memory, I/O, and CPU stats. |
| Monitor disk I/O | `iotop` | Displays I/O by process (root required). |
| Show open files per process | `lsof -p <PID>` | Lists files opened by a process. |
| Display process tree | `pstree -p` | Shows parent-child process hierarchy. |

**Examples:**
```bash
ps aux --sort=-%cpu | head         # Show top CPU consumers
kill -9 $(pgrep firefox)           # Kill all Firefox processes
nice -n 5 tar -czf backup.tar.gz /home  # Run low-priority backup
```

**Tips:**
- Use `ps aux | grep nginx` to filter results  
- Use `command &` to run in background  
- `jobs`, `fg`, `bg` manage background/foreground tasks  
- Press `Ctrl+Z` to suspend a process

---

## 👥 3. User, Group, and Permission Management

| Description | Command | Explanation |
|--------------|----------|-------------|
| Add a new user | `sudo adduser alice` | Creates a new user, home directory, and shell. |
| Delete a user | `sudo deluser alice` | Removes a user account (add `--remove-home` to delete their home folder). |
| Change a user’s password | `sudo passwd alice` | Prompts to reset or set a new password. |
| Add an existing user to a group | `sudo usermod -aG sudo alice` | Adds *alice* to the *sudo* group for admin privileges. |
| Show a user’s groups | `groups alice` | Lists all groups a user belongs to. |
| Display current user info | `id` | Shows UID, GID, and groups for the current user. |
| List all users on system | `cat /etc/passwd | cut -d: -f1` | Extracts all usernames from the password file. |
| List all groups | `cut -d: -f1 /etc/group` | Displays all defined groups. |
| Create a new group | `sudo groupadd devteam` | Creates a group named *devteam*. |
| Delete a group | `sudo groupdel devteam` | Removes the group. |
| Change file ownership | `sudo chown alice:devteam file.txt` | Makes *alice* the owner and *devteam* the group. |
| Change file permissions | `chmod 755 file.txt` | Owner: read/write/execute; others: read/execute only. |
| Recursively change permissions | `chmod -R 644 /var/www/html` | Applies mode changes to all subdirectories/files. |
| View file permissions | `ls -l` | Lists files with permission strings like `-rw-r--r--`. |
| Change default file permissions mask | `umask 022` | Sets default permission template for new files. |
| Test effective permissions | `namei -l /path/to/file` | Displays file path ownership and permissions layer by layer. |

**Understanding Permissions:** Each file has **Owner**, **Group**, and **Others**.  
Example: `-rwxr-xr--` → Owner: rwx, Group: r-x, Others: r--.

---

✅ **Pro Tip:** Combine ownership and permission checks:
```bash
ls -l /var/www | grep '^d' | awk '{print $1,$3,$4,$9}'
```
Shows all directories with their permission strings, owners, and groups.
