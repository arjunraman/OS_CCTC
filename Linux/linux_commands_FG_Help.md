# Consolidated Linux Command Reference

Consolidated and syntax-reviewed from:

- **Comprehensive Linux Command Reference (CCTC Student Facilitation Guides)**
- **Linux Command Cheat Sheet (Comprehensive)**

---

## Part 1 – CCTC Student Facilitation Guides

# Comprehensive Linux Command Reference (CCTC Student Facilitation Guides)

### 🔗 Source References
1. [Linux Essentials FG (bash_fg.html)](https://os.cybbh.io/public/os/latest/003_linux_essentials/bash_fg.html)
2. [parse_nmap FG (nmap.html)](https://os.cybbh.io/public/os/latest/003_linux_essentials/nmap.html)
3. [Linux Boot Process FG (linboot_fg.html)](https://os.cybbh.io/public/os/latest/007_linux_boot_process/linboot_fg.html)
4. [Linux Process Validity FG (linproc_fg.html)](https://os.cybbh.io/public/os/latest/010_linux_process_validity/linproc_fg.html)
5. [Linux Auditing & Logging FG (linlog_fg.html)](https://os.cybbh.io/public/os/latest/012_linux_auditing_%26_logging/linlog_fg.html)

---

## 🧩 1. Linux Essentials (Bash_FG)
| Command / Syntax | Explanation |
|------------------|-------------|
| pwd | Print working directory — shows current directory path. |
| hostname | Display the system hostname. |
| uname -a | Show kernel, OS, and architecture details. |
| whoami | Display the effective username. |
| w / who | Show logged-in users and their sessions. |
| ip addr | Display network interfaces and IP addresses. |
| ifconfig | Legacy network interface configuration command. |
| ip neigh | Display neighbor/ARP table. |
| arp | View or modify ARP entries. |
| ip route | Display routing table entries. |
| route | Legacy routing table display. |
| ss | Display socket statistics and active connections. |
| netstat | Legacy command to show network connections and stats. |
| nft list tables | Display nftables firewall tables. |
| iptables -L | List current iptables firewall rules. |
| sudo -l | List commands permitted for current user. |
| cd / | Change to the root directory. |
| ls | List directory contents. |
| ls -l | Long listing format with permissions and sizes. |
| ls --help | Display built-in help for `ls`. |
| man ls | Open the manual page for `ls`. |
| echo $a | Display the value of variable `a`. |
| a="100" | Assign the value 100 to variable `a`. |
| directories=$(ls /) | Store the output of `ls /` into a variable. |
| echo $directories | Print contents of a variable. |
| echo $directories 1> file | Redirect stdout to a file. |
| ls bacon 2> errorfile | Redirect error messages to file. |
| ls -Rlisa /etc | Recursively list `/etc`; often piped to `grep syslog` to filter for syslog-related entries. |
| for item in $objects; do echo $item; done | Loop through and print each item. |
| if [ -d $object ]; then ... fi | Conditional to check if `$object` is a directory. |
| while [ 1 -eq 1 ]; do ... done | Infinite loop. |
| curtime=$(date +"%s") | Store current epoch time. |
| exittime=$(expr $curtime + 3) | Add 3 seconds to the current time. |
| while [ $exittime -ge $curtime ]; do ... done | Execute until timeout. |
| cat ls | head -n 1 | Show first line of file. |
| xxd ls | head -n 2 | Hex dump first two lines of a binary. |
| id | Display user and group IDs. |
| cat /etc/passwd | Show user account definitions; often piped to `grep student` to find the "student" user entry. |
| cat /etc/group | Show group definitions; often piped to `grep student` to find "student" group membership. |
| chmod 750 testdir | Change permissions: owner rwx, group r-x, others none. |
| echo "text" > file | Write a string to file. |
| cat /etc/passwd | Show user accounts; can be combined with grep and sed to replace occurrences of "root" with "bacon" in the output. |
| grep -P "H(ä|ae?)ndel" regexfile | Regex search using Perl-compatible regex. |

---

## 🧠 2. parse_nmap (Linux Essentials)
| Command / Syntax | Explanation |
|------------------|-------------|
| #!/bin/bash | Shebang to specify bash interpreter. |
| FILE=$1 | Capture filename argument for script use. |
| man grep | View the manual page for `grep`; within the text, `grep -A3 '-context='` is an example of showing 3 lines of context after matches. |
| awk '/pattern/{ print $0 }' file | Print matching lines. |
| awk '/pattern/{ getline; print $0 }' file | Print next line after a match. |
| awk '/pattern/{ getline; print substr($0,9) }' file | Print substring after matched line. |

---

## ⚙️ 3. Linux Boot Process (linboot_fg)
| Command / Syntax | Explanation |
|------------------|-------------|
| lsblk | List block devices and partitions. |
| sudo xxd -l 512 -g 1 /dev/vda | Hex dump the first 512 bytes of disk (MBR). |
| dd if=/dev/vda of=MBRcopy bs=512 count=1 | Copy MBR to a new file. |
| sudo !! | Repeat previous command with sudo privileges. |
| file MBRcopy | Determine file type via signature. |
| ltrace -S cat /etc/passwd | Trace library and system calls during command execution. |
| lsmod | List loaded kernel modules. |
| ls -lisa /lib/systemd/system/default.target | Show systemd default target link. |
| cat /lib/systemd/system/default.target | tail -n 8 | Display tail of target dependencies. |
| ls -l /etc/systemd/system/ | List units in `/etc/systemd/system/`; often piped to `grep graphical` to search for graphical target configurations. |
| systemctl list-dependencies graphical.target | Show dependency tree for graphical target. |
| systemctl show -p Wants graphical.target | Show services "wanted" by the target. |
| systemctl list-unit-files | List all systemd unit files and their states. |
| systemctl cat graphical.target | Display contents of unit definition. |
| cat /etc/environment | Show global environment variables. |
| cat /etc/profile | Show global login script. |
| echo "echo in .profile" >> ~/.profile | Add message to login file. |
| echo "echo in .bashrc" >> ~/.bashrc | Add message to shell init file. |

---

## 🔍 4. Linux Process Validity (linproc_fg)
| Command / Syntax | Explanation |
|------------------|-------------|
| ps | Show running processes. |
| ps -elf | Display all processes in full format. |
| top | Monitor processes dynamically. |
| htop | Interactive process monitor with color/tree view. |
| kill -9 <PID> | Force terminate a process. |
| jobs | Show background and suspended jobs. |
| ping 8.8.8.8 & | Run ping in background. |
| fg | Bring background job to foreground. |
| Ctrl+Z | Suspend current foreground process. |
| service <name> status|start|stop|restart | Control SysV service. |
| systemctl list-units | List active systemd units. |
| systemctl list-units --all | List all systemd units (active/inactive). |
| systemctl status <service>.service | Show detailed status of a service. |
| systemctl start|stop|restart <service>.service | Manage service lifecycle. |
| ps --ppid 1 -lf | List processes with parent PID 1. |

---

## 🪵 5. Linux Auditing & Logging (linlog_fg)
| Command / Syntax | Explanation |
|------------------|-------------|
| cat /etc/rsyslog.d/50-default.conf | head -n 15 | View first 15 lines of rsyslog config. |
| cat /var/log/syslog | Display syslog entries; often piped to `grep timesyncd` to filter logs for that specific service. |
| sudo /usr/sbin/logrotate /etc/logrotate.conf | Force manual log rotation. |
| ls -l /var/log | List logs and their metadata. |
| dmesg | Display kernel message buffer. |
| last | Show login history. |
| zcat <file.gz> | Read compressed logs. |
| journalctl -e | View recent systemd journal logs. |
| journalctl --list-boots | List boots known to journald. |
| journalctl -u ssh.service | View logs for SSH service. |
| journalctl -u ssh.service --since "2 days ago" | Filter logs by time window. |

---

## 🧾 6. Additional Linux Commands (Extracted and Validated)
| Command / Syntax | Explanation |
|------------------|-------------|
| grep -R PATTERN . | Recursive text search starting in current directory. |
| flock -n 9 || exit 1 | Prevent multiple script instances using file locking. |
| nc -lw10 127.0.0.1 -p 1234 | Start netcat listener for 10 seconds on TCP port 1234. |
| sleep 10 | Pause script for 10 seconds. |
| xpath -q -e '//host/address[following-sibling::ports/port/state[@state="open"]]/@addr' output.xml | Extract host IP addresses for hosts that have at least one open port (from Nmap XML output). |
| xpath -q -e '//host/ports/port[state[@state="open"]]/@portid' output.xml | Extract port IDs for ports in state `open` from Nmap XML output. |

---
**Total Commands Consolidated:** 140+ Linux commands  
**Covers:** Bash scripting, networking, boot process, process management, and logging/auditing.

---

## Part 2 – Linux Command Cheat Sheet

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

**Understanding Permissions:** **Understanding Permissions:** Each file has three permission classes:
- **User (Owner)** – the user account that owns the file
- **Group** – the primary group associated with the file
- **Others** – everyone else

Example: `-rwxr-xr--` → User (owner): rwx, Group: r-x, Others: r--.

In `chmod`, these are referred to as `u` (user/owner), `g` (group), and `o` (others). For example:

```bash
chmod u+rwx,g+rx,o-r file.txt
```

**Permission Value Quick Reference**

| Symbol | Meaning  | Numeric value |
|--------|----------|---------------|
| r      | Read     | 4             |
| w      | Write    | 2             |
| x      | Execute  | 1             |
| -      | No perm  | 0             |

Combined values are added per class. For example, `rw-` = 4 + 2 = **6**, so `chmod 640 file.txt` gives `rw- r-- ---`.


---

✅ **Pro Tip:** Combine ownership and permission checks:
```bash
ls -l /var/www | grep '^d' | awk '{print $1,$3,$4,$9}'
```
Shows all directories with their permission strings, owners, and groups.
