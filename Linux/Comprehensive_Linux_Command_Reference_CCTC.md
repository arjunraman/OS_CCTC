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
| ls -Rlisa /etc | grep syslog | Recursively list `/etc` and filter for syslog entries. |
| for item in $objects; do echo $item; done | Loop through and print each item. |
| if [ -d $object ]; then ... fi | Conditional to check if `$object` is a directory. |
| while [ 1 -eq 1 ]; do ... done | Infinite loop. |
| curtime=$(date +"%s") | Store current epoch time. |
| exittime=$(expr $curtime + 3) | Add 3 seconds to the current time. |
| while [ $exittime -ge $curtime ]; do ... done | Execute until timeout. |
| cat ls | head -n 1 | Show first line of file. |
| xxd ls | head -n 2 | Hex dump first two lines of a binary. |
| id | Display user and group IDs. |
| cat /etc/passwd | grep student | Find the "student" user entry. |
| cat /etc/group | grep student | Find "student" group membership. |
| chmod 750 testdir | Change permissions: owner rwx, group r-x, others none. |
| echo "text" > file | Write a string to file. |
| cat /etc/passwd | grep root | sed s/root/bacon/g | Replace "root" with "bacon". |
| grep -P "H(ä|ae?)ndel" regexfile | Regex search using Perl-compatible regex. |

---

## 🧠 2. parse_nmap (Linux Essentials)
| Command / Syntax | Explanation |
|------------------|-------------|
| #!/bin/bash | Shebang to specify bash interpreter. |
| FILE=$1 | Capture filename argument for script use. |
| man grep | grep -A3 '-context=' | Show help text with 3 lines after match. |
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
| ls -l /etc/systemd/system/ | grep graphical | Search for graphical target configurations. |
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
| cat /var/log/syslog | grep timesyncd | Filter logs for specific services. |
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
| xpath -q -e '//host/address[following-sibling::ports/port/state[@state="open"]]/@addr \| //host/ports/port[state[@state="open"]]/@portid' output.xml | md5sum | Extract open host IPs and ports from Nmap XML, then hash. |
| xpath -q -e '//host/address[following-sibling::ports/port/state[@state="open"]]/@addr' output.xml | Extract only host IPs with open ports. |
| xpath -q -e '//host/ports/port[state[@state="open"]]/@portid' output.xml | Extract only port IDs of open ports. |

---
**Total Commands Consolidated:** 140+ Linux commands  
**Covers:** Bash scripting, networking, boot process, process management, and logging/auditing.
