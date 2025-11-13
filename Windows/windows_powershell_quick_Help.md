# 🧩 PowerShell Cheat Sheet — Detailed Notes

## 🔹 BASIC COMMANDS

### `Get-Service`
**Description:** Displays all running and stopped services on the system.  
**Usage:**
```powershell
Get-Service
```
**Example:**
```powershell
Get-Service | Where-Object {$_.Status -eq "Running"}
```
Shows only services currently running.

---

### `Get-Process`
**Description:** Lists active processes similar to Task Manager.  
**Usage:**
```powershell
Get-Process
```
**Example:**
```powershell
Get-Process | Sort-Object CPU -Descending
```
Sorts by CPU usage to find heavy processes.

---

### `Get-Host`
**Description:** Displays information about the current PowerShell session (version, culture, etc.).  
**Usage:**
```powershell
Get-Host
```

---

### `ipconfig`
**Description:** Command-line utility to show IP configuration.  
**Usage:**
```powershell
ipconfig /all
```
**Note:** Native Windows command (not a PowerShell cmdlet).

---

### `netstat -ano`
**Description:** Displays network connections, listening ports, and associated process IDs.  
**Usage:**
```powershell
netstat -ano
```

---

### `Get-ChildItem` or `ls`
**Description:** Lists directories and files (like `dir` in CMD).  
**Usage:**
```powershell
Get-ChildItem
```
**Example:**
```powershell
Get-ChildItem -Recurse -Force
```
Lists all files including hidden ones, recursively.

---

### `Set-Location` or `cd`
**Description:** Changes the current working directory.  
**Usage:**
```powershell
Set-Location "C:\Windows"
```

---

### `Get-Content` or `cat`
**Description:** Reads and outputs file contents.  
**Usage:**
```powershell
Get-Content .\file.txt
```
**Example:**
```powershell
Get-Content .\log.txt | Select-String "Error"
```
Searches for “Error” in a log file.

---

### `Get-Help`
**Description:** Displays help information about cmdlets.  
**Usage:**
```powershell
Get-Help Get-Process
```
**Tip:** Add `-Online` to open full help docs in browser.

---

## 🔹 USEFUL COMMANDS

### SSH Connection
**Command:**
```powershell
ssh username@destinationIP
```
**Description:** Connects to a remote system via SSH (requires OpenSSH client).

---

### Search for a String
**Command:**
```powershell
findstr /i "string"
```
**Description:** Case-insensitive search for text in files or output.

---

### Compare Two Files
**Command:**
```powershell
Compare-Object (cat file1) (cat file2)
```
**Description:** Compares the content of two files line by line.

---

### Recursive String Search
**Command:**
```powershell
Get-ChildItem "C:\Directory" -R | Select-String -Pattern "String"
```
**Description:** Recursively searches files in a directory for a string pattern.

---

### Search for a File by Name
**Command:**
```powershell
Get-ChildItem -Path C:\ -Filter "*file*" -R
```
**Description:** Recursively searches for files containing “file” in the name.

---

### List Hidden Directories
**Command:**
```powershell
Get-ChildItem -Hidden
```
**Description:** Displays hidden files and directories.

---

## 🔹 KEY FILE LOCATIONS

| Scope | Description | Path |
|-------|--------------|------|
| **All Users, All Hosts** | Global PowerShell profile | `$PsHome\Profile.ps1` |
| **All Users, Current Host** | Host-specific profile for all users | `$PsHome\Microsoft.PowerShell_profile.ps1` |
| **Current User, All Hosts** | User-specific profile across all hosts | `$HOME\Documents\WindowsPowerShell\Profile.ps1` |
| **Current User, Current Host** | User- and host-specific profile | `$HOME\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1` |

### System and Application Paths
- **System Files:** `C:\Windows\System32`  
- **Application Files:** `C:\Program Files`

---

## 🧠 Additional Notes
- Use `Get-Command` to discover available cmdlets.  
- Use `|` (the pipeline) to pass output between commands.  
- `Select-Object`, `Sort-Object`, and `Where-Object` are key filtering tools.  
- Add `-Verbose` or `-ErrorAction` to manage detailed output and error handling.  


---

## 🔹 COMMON PIPELINE EXAMPLES

### Filter Running Services
```powershell
Get-Service | Where-Object {$_.Status -eq "Running"}
```
Shows only running services.

### Sort Processes by Memory Usage
```powershell
Get-Process | Sort-Object WorkingSet -Descending | Select-Object -First 10
```
Lists top 10 processes by memory usage.

### Export Processes to CSV
```powershell
Get-Process | Select-Object Name, CPU, Id | Export-Csv -Path processes.csv -NoTypeInformation
```
Exports selected process data to a CSV file.

### Find Specific Files and Export Results
```powershell
Get-ChildItem -Recurse -Filter "*.log" | Select-Object FullName, Length | Export-Csv logs.csv -NoTypeInformation
```
Searches recursively for `.log` files and exports names and sizes.

### Count Matching Lines in Files
```powershell
Get-ChildItem -Recurse -Filter "*.txt" | Select-String "Error" | Measure-Object
```
Counts all “Error” occurrences across text files.

### Display Event Logs Matching Keyword
```powershell
Get-EventLog -LogName System | Where-Object {$_.Message -like "*network*"} | Select-Object -First 5
```
Shows first 5 system log entries containing “network”.

---


---

## 🔹 ADMINISTRATIVE & SYSTEM MANAGEMENT COMMANDS

### Manage Services (Start/Stop/Restart)
```powershell
Start-Service -Name "Spooler"
Stop-Service -Name "Spooler"
Restart-Service -Name "Spooler"
```
Controls Windows services directly from PowerShell.

### Manage User Accounts
```powershell
Get-LocalUser
New-LocalUser -Name "NewUser" -NoPassword
Add-LocalGroupMember -Group "Administrators" -Member "NewUser"
```
Displays, creates, and assigns local users to groups.

### Manage Scheduled Tasks
```powershell
Get-ScheduledTask
Register-ScheduledTask -TaskName "Backup" -Action (New-ScheduledTaskAction -Execute "notepad.exe")
```
Lists or creates Windows scheduled tasks.

### Modify the Registry
```powershell
Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
Set-ItemProperty "HKCU:\Software\MyApp" "Setting" "Enabled"
```
Reads and modifies registry keys or values.

### System Information and Performance
```powershell
Get-ComputerInfo
Get-WmiObject Win32_OperatingSystem | Select-Object CSName, Caption, OSArchitecture
```
Displays detailed system information.

### Manage Windows Updates (Requires Admin)
```powershell
Get-WindowsUpdate
Install-WindowsUpdate -AcceptAll -AutoReboot
```
Checks and installs Windows Updates (requires module `PSWindowsUpdate`).

### Disk and Storage Management
```powershell
Get-Volume
Get-Disk
Get-Partition
```
Displays disks, partitions, and storage volume details.

### Reboot or Shutdown System
```powershell
Restart-Computer -Force
Stop-Computer -Force
```
Performs system reboot or shutdown operations.


---

## 🔹 SECURITY, PERMISSIONS & EVENT LOG MANAGEMENT

### View Current User and Groups
```powershell
whoami
Get-LocalGroupMember "Administrators"
```
Displays the current logged-in user and members of the Administrators group.

### Manage File/Folder Permissions (ACLs)
```powershell
Get-Acl "C:\FolderName"
Set-Acl "C:\FolderName" (Get-Acl "C:\TemplateFolder")
```
Views and applies Access Control Lists (ACLs) to secure files and folders.

### Check Execution Policy
```powershell
Get-ExecutionPolicy
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
```
Controls script execution restrictions for PowerShell sessions.

### Audit and Monitor Security Events
```powershell
Get-EventLog -LogName Security -Newest 10
Get-WinEvent -LogName Security | Where-Object {$_.Id -eq 4625}
```
Retrieves recent security log events such as failed logon attempts (Event ID 4625).

### View Firewall Configuration
```powershell
Get-NetFirewallRule | Select-Object Name, Enabled, Direction, Action
```
Lists all active firewall rules and their actions.

### Manage Firewall Rules
```powershell
New-NetFirewallRule -DisplayName "AllowSSH" -Direction Inbound -Protocol TCP -LocalPort 22 -Action Allow
Remove-NetFirewallRule -DisplayName "AllowSSH"
```
Adds or removes specific firewall rules.

### Manage User Privileges and Accounts
```powershell
Get-LocalUser
Disable-LocalUser -Name "Guest"
Enable-LocalUser -Name "Administrator"
```
Enables or disables local user accounts.

### Encrypt and Decrypt Files
```powershell
cipher /e "C:\SensitiveData"
cipher /d "C:\SensitiveData"
```
Encrypts or decrypts folders/files using EFS (Encrypting File System).

### Monitor PowerShell Transcripts for Auditing
```powershell
Start-Transcript -Path "C:\Logs\session_log.txt"
Stop-Transcript
```
Records all PowerShell commands executed in a session for audit trails.


---

## 🔹 ALTERNATE DATA STREAMS (ADS) & HIDDEN FILES

Windows NTFS supports **Alternate Data Streams (ADS)** that can store hidden metadata or content attached to a file without changing its visible size. Hidden files can also be concealed via **attributes** (Hidden/System).

### Why it matters
- ADS can hide scripts, notes, or malware payloads.
- Downloaded files often include a `Zone.Identifier` ADS that marks the origin (Internet, Intranet, etc.).
- Hidden/System attributes can make files vanish from normal directory listings.

### Inspect ADS (PowerShell)
List all streams on a file:
```powershell
Get-Item -Path .\example.txt -Stream *
```
Show the content of a specific stream (e.g., Zone.Identifier):
```powershell
Get-Content -Path .\example.txt -Stream Zone.Identifier
```
Create or overwrite a custom stream:
```powershell
Set-Content -Path .\example.txt -Stream notes -Value "Secret note in ADS"
```
Append to a stream:
```powershell
Add-Content -Path .\example.txt -Stream notes -Value " (appended)"
```
Remove a stream:
```powershell
Remove-Item -Path .\example.txt -Stream notes
```

### Inspect ADS (CMD interop)
Quickly list streams with the legacy `dir` flag:
```powershell
cmd /c "dir /r .\example.txt"
```
> Tip: `dir /r` shows stream names and sizes; good for a fast check.

### Unblock downloaded files (remove Zone.Identifier)
```powershell
Unblock-File -Path .\installer.ps1
# or view before removing:
Get-Content -Path .\installer.ps1 -Stream Zone.Identifier
```
> Use when a trusted file was downloaded but is being blocked due to its zone.

### Copying and archiving with ADS
- `Copy-Item` may **not** preserve non-default streams.
- Prefer `robocopy` for full fidelity:
```powershell
robocopy . . example.txt /COPYALL /R:0 /W:0
```
- Zipping with modern tools often strips ADS unless specifically preserved.

### Enumerate hidden & system files
Show hidden items in a folder:
```powershell
Get-ChildItem -Force
```
Find Hidden or System recursively:
```powershell
Get-ChildItem -Recurse -Force | Where-Object { $_.Attributes -match 'Hidden|System' }
```
Only hidden (not system):
```powershell
Get-ChildItem -Attributes Hidden -Force -Recurse
```

### Set or clear Hidden/System attributes
Using `attrib` (works in PowerShell too):
```powershell
attrib +h +s "C:\path\to\file.txt"     # hide and mark as system
attrib -h -s "C:\path\to\file.txt"     # unhide and clear system
```
PowerShell object approach (toggle Hidden flag):
```powershell
$item = Get-Item "C:\path\to\file.txt"
$item.Attributes = $item.Attributes -bor [IO.FileAttributes]::Hidden    # add
$item.Attributes = $item.Attributes -band (-bnot [IO.FileAttributes]::Hidden)  # remove
```

### Dotfiles vs attributes
Files starting with a dot (e.g., `.env`) are **not** automatically hidden on Windows. Use `-Force` to see them and set the `Hidden` attribute if you want them concealed:
```powershell
Get-ChildItem -Force
attrib +h ".\.env"
```

### Quick triage one-liners
```powershell
# List files that contain any ADS (excluding default unnamed stream)
Get-ChildItem -Recurse -File | ForEach-Object {
  $s = Get-Item -LiteralPath $_.FullName -Stream * 2>$null
  if ($s.Count -gt 1) { $_.FullName }
}

# Dump Zone.Identifier for all downloaded PS1 files in Downloads
Get-ChildItem "$env:USERPROFILE\Downloads" -Filter *.ps1 | ForEach-Object {
  if (Get-Item $_ -Stream Zone.Identifier -ErrorAction SilentlyContinue) {
    "{0}`n{1}`n" -f $_.FullName, (Get-Content $_ -Stream Zone.Identifier -ErrorAction SilentlyContinue -Raw)
  }
}
```


---

## 🔹 FORENSIC CHECKLIST — ADS & HIDDEN FILES

This section provides a **practical triage workflow** for forensic analysis of alternate data streams, hidden/system files, and potential persistence mechanisms.

### 1. Enumerate Alternate Data Streams (ADS)
List all ADS on system drives and export to file:
```powershell
Get-ChildItem -Path C:\ -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object {
  $streams = Get-Item -LiteralPath $_.FullName -Stream * -ErrorAction SilentlyContinue
  if ($streams.Count -gt 1) {
    [PSCustomObject]@{File=$_.FullName; Streams=$streams.Stream}
  }
} | Export-Csv C:\Forensic\ADS_Report.csv -NoTypeInformation
```

### 2. Identify Hidden or System Files
```powershell
Get-ChildItem -Path C:\ -Force -Recurse -ErrorAction SilentlyContinue |
Where-Object { $_.Attributes -match 'Hidden|System' } |
Select-Object FullName, Attributes |
Export-Csv C:\Forensic\HiddenFiles.csv -NoTypeInformation
```

### 3. Collect File Hashes for Evidence Integrity
Generate SHA256 hashes for files of interest:
```powershell
Get-ChildItem -Path "C:\Forensic\Samples" -File -Recurse |
Get-FileHash -Algorithm SHA256 |
Export-Csv "C:\Forensic\Hashes.csv" -NoTypeInformation
```

### 4. Preserve Metadata and Streams in Archive
Copy and preserve files with all NTFS metadata:
```powershell
robocopy "C:\Evidence" "D:\Archive" /COPYALL /E /R:0 /W:0 /LOG:"C:\Forensic\robocopy.log"
```
> `/COPYALL` preserves data, attributes, timestamps, ACLs, owner info, and ADS.

### 5. Examine Zone.Identifier Markers
Check files for Internet-origin markers:
```powershell
Get-ChildItem -Recurse -Filter *.exe | ForEach-Object {
  if (Get-Item $_ -Stream Zone.Identifier -ErrorAction SilentlyContinue) {
    "$($_.FullName) contains Zone.Identifier"
  }
}
```

### 6. Extract Metadata for Timeline Analysis
Use PowerShell to pull timestamps:
```powershell
Get-ChildItem -Recurse -File |
Select-Object FullName, CreationTime, LastWriteTime, LastAccessTime |
Export-Csv "C:\Forensic\Timeline.csv" -NoTypeInformation
```

### 7. Document Everything
Always include in your forensic notes:
- Full file paths examined  
- Hash values (SHA256 preferred)  
- Original timestamps  
- ADS evidence or flags  
- Copy logs (from robocopy or PowerShell)

---
