# Linux Command Cheat Sheet (Battlefield / Bibliotheca Env)

This file consolidates all processed **Linux** commands from your histories, with duplicates removed, syntax corrected where needed, and each command given a short explanation.

---

## 1. Basic Navigation & Listing

| Command | What it does |
| --- | --- |
| `ls` | List files in the current directory. |
| `ls -a` | List all files including hidden dotfiles (`.`, `..`, `.something`). |
| `ls -al` | Long listing including hidden files with permissions, owner, size. |
| `ls -lh` | Long listing with human-readable sizes (K, M, G). |
| `ls -lisa /sbin/init` | Show inode and detailed info for `/sbin/init`. |
| `ls -l /etc/rc6.d/` | Long listing of runlevel-6 (shutdown/reboot) scripts. |
| `ls -la` | Long listing including hidden files in the current directory. |
| `ls -ld /media/Bibliotheca` | Show permissions/owner for that directory itself (not contents). |
| `ls -ld /etc/*.d` | Show permissions/owner for each `/etc/*.d` directory. |
| `ls -ld` | Long listing for the current directory (same as `ls -ld .`). |
| `ls /usr/bin > bin.txt` | Save the list of `/usr/bin` commands into `bin.txt`. |
| `cd /` | Change directory to filesystem root. |
| `cd /tmp` | Change to `/tmp`. |
| `cd /home` | Go into `/home`. |
| `cd /home/garviel` | Go directly to user `garviel`'s home directory. |
| `cd Battlefield` | Enter the `Battlefield` directory. |
| `cd titan_commands` | Enter the `titan_commands` directory. |
| `cd /media/Bibliotheca` | Jump into the `Bibliotheca` mount. |
| `cd Bibliotheca_duo` | Enter that subdirectory. |
| `cd Bibliotheca_quattuor` | Enter that subdirectory. |
| `cd Bibliotheca_unus` | Enter that subdirectory. |
| `cd ..` | Go up one directory level. |
| `cd` | Go to your home directory (from anywhere). |
| `pwd` | Print the current working directory. |
| `clear` | Clear the terminal screen. |
| `exit` | Exit the current shell. |
| `history` | Show shell command history. |

---

## 2. Help & Manual Pages

| Command | What it does |
| --- | --- |
| `man ls` | View full manual page for `ls`. |
| `sudo man ls` | Same, but run via sudo (e.g., if manpath is restricted). |
| `man -k digest` | Search man page names/descriptions for the word “digest”. |
| `man -k "digest"` | Same as above, with quotes. |
| `man -w ls` | Show the location of the `ls` manpage file. |
| `man --where ls` | Same as `man -w ls`; print manpage path. |

---

## 3. Boot, Init, Runlevels & systemd

| Command | What it does |
| --- | --- |
| `cat /boot/grub/grub.cfg` | Show GRUB bootloader configuration. |
| `cat /boot/grub/grub.cfg \| grep linux` | Show only lines mentioning “linux” (kernel entries). |
| `cat /etc/inittab` | View old SysV init configuration, if present. |
| `readlink /sbin/init` | See what `/sbin/init` actually links to (e.g., `/lib/systemd/systemd`). |
| `ls -lisa /lib/systemd/system/default.target` | Show info about systemd’s default target. |
| `find / -name graphical.target 2>/dev/null` | Locate the `graphical.target` unit file; suppress permission errors. |
| `cat /lib/systemd/system/graphical.target` | Show systemd definition of the graphical target. |
| `systemctl list-units` | List active systemd units. |
| `systemctl list-units --type=service` | List active systemd services only. |
| `systemctl list-dependencies graphical.target` | Show dependency tree for graphical target. |
| `systemctl show -p Wants graphical.target` | Show what units are “wanted” by `graphical.target`. |
| `systemctl status sshd.service` | Status and recent logs for the SSH daemon. |
| `systemctl status rsyslog` | Status and recent logs for system logging daemon. |
| `systemctl cat whatischaos` | Show the unit file for `whatischaos.service`. |
| `systemctl cat vestrisecreta` | Show the unit file for `vestrisecreta.service`. |

---

## 4. Processes & `/proc`

| Command | What it does |
| --- | --- |
| `ps` | Basic snapshot of current processes. |
| `ps aux` | Detailed process list including user, CPU, memory, etc. |
| `ps -elf` | Extended full-format process list with more columns. |
| `ps -elf \| head` | Show only the first few processes from the full list. |
| `ps -eo pid,ppid,comm` | Print only PID, parent PID, and command name. |
| `ps -eo pid,ppid,comm \| awk '$2 == 1 { count++ } END { print count }'` | Count processes whose parent is PID 1. |
| `ps --ppid 1 -lf` | List children of PID 1 in long format. |
| `ps -p 2038` | Show info for process ID 2038. |
| `pgrep cron` | Show PID(s) for the cron daemon. |
| `pgrep -P 1 \| wc -l` | Count processes whose parent is PID 1. |
| `pgrep -u bombadil bash` | Show PIDs of bash shells owned by user `bombadil`. |
| `pstree` | Show processes in a tree view. |
| `pstree -p` | Process tree including PIDs. |
| `pstree -p 1` | Show only the subtree rooted at PID 1. |
| `htop` | Interactive process viewer (top-like, scrollable). |
| `ps -elf \| grep ntpd` | Check whether NTP daemon is running. |
| `ps aux \| grep ntpd` | Another way to search for NTP processes. |
| `ls -l /proc` | List `/proc` entries (PIDs and kernel pseudo-files). |
| `cd /proc/2038; ls` | Inspect pseudo-files for process 2038. |
| `ls -l /proc/1306/fd/3` | Show what file descriptor 3 of PID 1306 is pointing to. |
| `ls -l /proc/19095/fd` | List all open file descriptors for process 19095. |

---

## 5. Disks, Hex, MBR & Hashes

| Command | What it does |
| --- | --- |
| `lsblk` | List block devices and their mount points. |
| `sudo xxd -l 32 -g 1 /dev/sda` | Hex dump the first 32 bytes of disk `/dev/sda` (1 byte per group). |
| `sudo xxd -l 512 -g 1 /dev/sda` | Hex dump the first 512 bytes (MBR/boot sector) of `/dev/sda`. |
| `sudo xxd -l 512 -g 1 /dev/sda1` | Hex dump first sector of partition `/dev/sda1`. |
| `sudo cat /dev/sda \| xxd -l 512 -g 1` | Pipe raw disk into `xxd` to display first 512 bytes. |
| `xxd /home/bombadil/mbroken` | Hex dump the entire `mbroken` file (MBR copy). |
| `xxd -s 0x1BE -l 16 /home/bombadil/mbroken` | Show a 16-byte partition table entry at offset 0x1BE. |
| `xxd -s 0x180 -l 16 /home/bombadil/mbroken` | Show 16 bytes at offset 0x180. |
| `strings /home/bombadil/mbroken \| grep GRUB` | Search for “GRUB” strings inside the MBR copy. |
| `dd if=mbroken bs=1 skip=446 count=16 \| md5sum` | Hash 16 bytes starting at offset 446 (partition entry). |
| `dd if=mbroken bs=1 count=446 \| md5sum` | Hash first 446 bytes (boot code area). |
| `dd if=mbroken bs=1 count=16` | Output first 16 bytes of `mbroken`. |
| `cat mbroken \| md5sum` | Compute MD5 of entire `mbroken` file. |
| `md5sum file.txt` | MD5 checksum for `file.txt`. |
| `md5sum output.csv` | MD5 checksum for `output.csv`. |
| `echo -n 'OneWayBestWay' \| md5sum` | MD5 hash of the literal string (no trailing newline). |
| `sha512sum filtered_numbers.tmp` | SHA-512 hash of filtered number list. |
| `echo -n "OneWayBestWay" \| sha512sum` | SHA-512 hash of that exact string. |
| `echo -n 'quixos' \| sha512sum` | SHA-512 hash of `quixos`. |

---

## 6. Files, Search & Text Processing

### 6.1 `cat` and Basic File Viewing

| Command | What it does |
| --- | --- |
| `cat Battlefield` | Show contents of the `Battlefield` instruction file. |
| `cat titan_commands` | Show contents of the `titan_commands` file. |
| `cat minefield_map` | Show the minefield puzzle map. |
| `cat Inquisition_Targets` | View the Inquisition targets list. |
| `cat /etc/passwd` | Display all user entries. |
| `cat /etc/group` | Display all group entries. |
| `sudo cat /etc/shadow` | View hashed passwords (root-only) for users. |
| `sudo cat /media/Bibliotheca/Bibliotheca_quattuor/.Secrets_of_the_Immeterium` | View hidden dotfile containing “secrets”. |
| `cat /media/Bibliotheca/Bibliotheca_duo/.warp2/.warp5/warp5/.warp3/warp2/.secrets` | View nested hidden secrets file inside multiple dot directories. |
| `cat /media/Bibliotheca/Bibliotheca_duo/.Secrets_of_the_Immaterium` | View hidden “Immaterium” secrets file. |
| `nano file.txt` | Open `file.txt` in the nano editor (create if missing). |
| `cat README` | View a README file in the current directory. |

### 6.2 `find`: Locating Files and Directories

| Command | What it does |
| --- | --- |
| `find / -type d -name "Bibliotheca"` | Find any directory named `Bibliotheca`. |
| `find / -type d -name "Battlefield"` | Find `Battlefield` directories. |
| `find / -type f -name "Battlefield"` | Find files named `Battlefield`. |
| `find /home -type f -exec wc -l {} + 2>/dev/null > file_counts.txt` | Count lines of all files under `/home`, ignoring errors, save results. |
| `find . -type f -exec wc -l {} + \| sort -rn \| sed -n '2p'` | Show the 2nd largest file by line count in the current tree. |
| `find ~ -type f -print0 \| xargs -0 wc -l \| sort -rn \| sed -n '2p'` | Same idea but scanning the entire home directory. |
| `find /media/Bibliotheca -type f -user Quixos` | Files in Bibliotheca owned by user `Quixos`. |
| `find /media/Bibliotheca -type f -user Quixos -perm 600` | Files owned by `Quixos` with `600` permissions. |
| `find /media/Bibliotheca -type f` | List all files in Bibliotheca. |
| `find . -name ".*"` | Find hidden files/directories (names starting with `.`) under current directory. |
| `find /media/Bibliotheca -name ".*"` | Find hidden files/directories under Bibliotheca. |
| `find /media/Bibliotheca -type f \( -perm -g=r -a ! -perm -u=r -o -perm -g=w -a ! -perm -u=w -o -perm -g=x -a ! -perm -u=x \)` | Find files where the group has at least one permission (r/w/x) that the user does not. |

### 6.3 `grep`, `sort`, `comm`, `wc`

| Command | What it does |
| --- | --- |
| `grep /bin/sh /etc/passwd` | Show accounts using `/bin/sh` shell. |
| `grep /bin/sync /etc/passwd` | Show accounts using `/bin/sync` shell. |
| `grep -r "whatischaos" /lib` | Recursively search `/lib` for the string `whatischaos`. |
| `grep -r 'lp 443' /lib` | Look for references to `lp 443` (likely malicious binary). |
| `grep -r '443' /lib` | Search for literal `443` in `/lib`. |
| `grep -E -r 'apache' /lib` | Recursively search for “apache” using extended regex. |
| `grep -r --include='*.txt' 'PATTERN' /lib` | Search recursively for `PATTERN` but only in `.txt` files under `/lib`. |
| `sort Inquisition_Targets > sortinqui.txt` | Sort the target list alphabetically. |
| `comm -12 memsofguards.txt sortinqui.txt` | Show lines common to both files (intersection). |
| `wc -l numbers` | Count lines in `numbers`. |
| `wc -l connections` | Count lines in `connections`. |
| `wc -l numbers && wc -l connections` | Show line counts of both files sequentially. |

### 6.4 `awk` for CSV and passwd Processing

| Command | What it does |
| --- | --- |
| `awk -F: '{print $5}' /etc/passwd` | Print GECOS/comment/full-name field for each user. |
| `awk -F: '{print $7}' /etc/passwd \| sort \| uniq -c` | Count how many users use each login shell. |
| `awk -F: 'NR == FNR {shells[$0]; next} $NF in shells' /etc/shells /etc/passwd` | Show passwd entries whose shell is listed in `/etc/shells`. |
| `grep -Ff /etc/shells /etc/passwd` | Match lines in `/etc/passwd` whose shell field appears in `/etc/shells`. |
| `awk -F, '{OFS=","; print $1,$2,$3,$4,$5,$6}' /home/garviel/connections.csv > /home/garviel/output.csv` | Normalize first 6 CSV columns and save. |
| `awk '{OFS=","; print $1,$2,$3,$4,$5,$6}' /home/garviel/connections > /home/garviel/new_file.csv` | Convert whitespace-separated data to CSV with 6 columns. |
| `awk '{OFS=","; print $1,$2,$3,$4,$5,$6}' /home/garviel/original_file.txt > /media/Bibliotheca/new_file.csv` | Same idea, exporting CSV to Bibliotheca. |
| `awk -F'\t' '{OFS=","; print $1,$2,$3,$4,$5,$6}' /home/garviel/new_file.csv > /home/garviel/output.csv` | Convert tab-separated data to CSV. |
| `awk -F'\t' '{OFS=","; print $1,$2,$3,$4,$5,$6}' /home/garviel/connections > /home/garviel/output.csv` | Convert tab-separated `connections` file to CSV. |
| `awk '$1 >= 420 && $1 <= 1337' /home/garviel/numbers > filtered_numbers.tmp` | Filter lines whose first field is between 420 and 1337. |
| `awk '$1 >= 420 && $1 <= 1337' /home/garviel/numbers \| sha512sum \| awk '{print $1}'` | Hash the filtered lines and print only the hash. |
| `awk 'NR >= 420 && NR <= 1337' numbers \| sha512sum` | Use line numbers (NR) rather than first field to select 420–1337. |

### 6.5 Filtering by User in Listings

| Command | What it does |
| --- | --- |
| `ls -l \| grep sejanus` | Show only `ls -l` entries that mention `sejanus` (owner, group, etc.). |

---

## 7. Numbers, IP and MAC Regexes

| Command | What it does |
| --- | --- |
| `grep -Eo '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' numbers` | Extract IPv4-looking strings from `numbers`. |
| `grep -Eo '\b((25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})\.){3}(25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})\b' numbers` | Extract valid IPv4 addresses from `numbers`. |
| `grep -Eo '\b((25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})\.){3}(25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})\b' file.txt` | Same valid IPv4 pattern, but searching `file.txt`. |
| `grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}|\b([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}\b' numbers` | Extract IPv4 **or** IPv6 addresses from `numbers`. |
| `grep -c -E '\b((25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})\.){3}(25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})\b' numbers` | Count valid IPv4 addresses. |
| `grep -cE '([[:xdigit:]]{2}[:-]){5}[[:xdigit:]]{2}' numbers` | Count MAC-like addresses (`aa:bb:cc:dd:ee:ff`) in `numbers`. |
| `grep -Eic '\b[0-9a-f](0|4|8|c)[0-9a-f:-]{10,15}[0-9a-f]\b' numbers` | Count MACs with certain bit patterns (e.g., globally vs locally administered). |
| `grep -Eic '\b[0-9a-f](2|6|a|e)[0-9a-f:-]{10,15}[0-9a-f]\b' numbers` | Count MACs with alternate bit patterns. |
| `grep -Eic '\b[0-9a-f]([02468ace])[0-9a-f:-]{10,15}[0-9a-f]\b' numbers` | Count MACs whose second nibble is even. |

---

## 8. Networking, Ports & Services

| Command | What it does |
| --- | --- |
| `netstat -tulpn` | Show listening TCP/UDP sockets with process IDs and names. |
| `netstat --all` | Show all sockets: listening and established. |
| `netstat --all --program \| grep '9999'` | Find which process is using port 9999. |
| `lsof -i -P` | List all network connections with numeric ports. |
| `lsof -i :9999` | Show process(es) using TCP/UDP port 9999. |
| `sudo lsof -i :9999` | Same as above, but with root access to see everything. |
| `lsof -i :22` | Show processes using SSH port 22. |
| `sudo lsof -i :22` | Root view of processes using SSH port 22. |
| `sudo lsof -i :123` | Show processes using NTP port 123. |
| `fuser 9999/tcp` | Show PIDs using TCP port 9999. |
| `ps aux \| grep ssh` | Find SSH-related processes. |
| `/bin/apache3 -lp 443 < /dev/urandom` | (Malicious example) Run a custom binary `apache3` on port 443 sending random data. |
| `netcat -lp 3389 < /tmp/NMAP_all_hosts.txt` | Use netcat to listen on 3389 and serve `NMAP_all_hosts.txt` content. |

---

## 9. Cron & Scheduled Jobs

| Command | What it does |
| --- | --- |
| `crontab -l` | Show current user’s cron jobs. |
| `sudo crontab -l` | Show root’s cron jobs. |
| `cd /etc; cat crontab` | View system-wide `/etc/crontab`. |
| `cd /etc/init.d; ls` | List SysV init scripts. |
| `cd /etc/init.d; cat cron` | Show cron’s SysV init script. |
| `service cron start` | Start the cron service (correct form). |

---

## 10. Permissions, ACLs & Hidden Directories

| Command | What it does |
| --- | --- |
| `ls -l /media/Bibliotheca` | List contents with permissions and owners. |
| `ls -lisa /media/Bibliotheca` | Detailed listing including inode numbers. |
| `getfacl /media/Bibliotheca` | Show extended Access Control Lists for that directory. |
| `ls -l` (inside each Bibliotheca_* directory) | Inspect file sizes/owners/perms per shelf. |
| `id sejanus` | Show UID, GID and group membership for user `sejanus`. |
| `ls -a /media/Bibliotheca` | Show all files, including hidden `.Secrets_...` files. |

---

## 11. Encryption, Compression & the `Encrypted` File

| Command | What it does |
| --- | --- |
| `file Encrypted` | Identify the file type of `Encrypted`. |
| `ent Encrypted` | Measure entropy; high entropy suggests compression or encryption. |
| `gpg --decrypt --output Encrypted.txt Encrypted.gpg` | Decrypt `Encrypted.gpg` into `Encrypted.txt`. |
| `openssl enc -help` | Show options for `openssl enc` subcommand. |
| `openssl enc -ciphers` | List available symmetric ciphers. |
| `openssl enc -d -in Encrypted -out encrypted.txt` | Attempt to decrypt `Encrypted` with default/known cipher parameters. |
| `openssl enc -d -aes256 -in Encrypted -out encrypted.txt` | Decrypt using AES-256 (if correct cipher/key). |
| `openssl enc -d -aes-128-cbc -in cipher -out encrypted2.txt` | Decrypt `cipher` as AES-128-CBC. |
| `unzip Encrypted` | Treat `Encrypted` as a zip archive and extract it. |
| `rm encrypted.txt` | Remove decrypted plaintext once done. |

---

## 12. PATH, Commands & the Mystery `binary`

| Command | What it does |
| --- | --- |
| `echo $PATH` | Show current PATH search list. |
| `cat $HOME/paths` | Inspect the puzzle file listing “paths”. |
| `which ls` | Show full path to the `ls` binary. |
| `which -a gimp` | Show all locations where `gimp` is found in PATH. |
| `realpath ~/.bash_logout` | Show absolute path of `.bash_logout`. |
| `ls /usr/bin > bin.txt` | Capture `/usr/bin` listing into a file. |
| `diff -r /home/garviel/paths /usr/bin` | Compare puzzle `paths` list with real `/usr/bin`. |
| `compgen -c \| sort \| uniq` | List all available commands in PATH (unique, sorted). |
| `comm -12 /tmp/paths_names <(compgen -c \| sort \| uniq)` | Show intersection between puzzle paths and actual commands. |

---

## 13. Misc / Puzzle-Specific Commands

| Command | What it does |
| --- | --- |
| `./minefield_map` | Execute the `minefield_map` binary/script. |
| `./minefield_map arg1 arg2` | Run `minefield_map` with two arguments (puzzle variant). |
| `get-history` | Environment-specific helper to dump shell history (not a standard Linux command). |

---

_End of consolidated Linux commands cheat sheet._


---

## 14. Additional 

These are additional commands that appeared in the newer history files and were **not** already covered above. They follow the same pattern: cleaned syntax and a short description.

| Command | What it does |
| --- | --- |
| `cd tmp` | Change into the `tmp` subdirectory relative to the current directory (e.g., from `/` this is equivalent to `cd /tmp`). |
| `sudo lsof -c cron` | List open files and network sockets for processes whose command name matches `cron`. |
| `sudo su` | Start a root shell (if permitted), switching your effective user to `root`. |
| `sudo xxd -l 512 -g 1 /dev/vda` | Hex dump the first 512 bytes of `/dev/vda` (often the primary disk in virtualized/KVM environments). |
| `xxd -s 0x1BE -l 32 /home/bombadil/mbroken` | Dump 32 bytes starting at offset `0x1BE` (a full MBR partition entry) from the `mbroken` file. |
| `xxd -s 0x1BE -l 8 /home/bombadil/mbroken` | Dump only the first 8 bytes of the MBR partition entry at offset `0x1BE` in `mbroken`. |
| `xxd -s 0x180 -l 16 /home/bombadil/mbroken > file.txt` | Dump 16 bytes at offset `0x180` from `mbroken` and redirect the hex output into `file.txt`. |
