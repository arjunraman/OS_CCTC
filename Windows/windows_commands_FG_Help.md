# 🧭 CYBBH Operating Systems Command Reference (Consolidated Master Sheet)

> **Source files consolidated:**  
> – `CYBBH_Master_Command_Reference.md`  
> – `PowerShell_Notes.md`  

---

## 📚 Table of Contents

- [Reference Sources](#reference-sources)
- [2. Windows PowerShell Basics — Pattern Search & ACL Auditing](#powershell-basics)
- [3. Windows Registry and ADS](#windows-registry-ads)
- [9. Active Directory Enumeration](#active-directory-enum)
- [10. PowerShell Cheat Sheet — Detailed Notes](#powershell-cheatsheet)
  - [10.1 Basic Commands](#basic-commands)
  - [10.2 Useful Commands & Search Patterns](#useful-commands)
  - [10.3 Key File Locations](#key-file-locations)
  - [10.4 Pipeline & Filtering Examples](#pipeline-filtering)
  - [10.5 Administrative & System Management](#admin-system)
  - [10.6 Security, Permissions & Event Logs](#security-permissions)
  - [10.7 Alternate Data Streams (ADS) & Hidden Files](#ads-hidden-files)
  - [10.8 Forensic Checklist — ADS & Hidden Files](#forensic-checklist)

---

<a id="reference-sources"></a>
## 🔗 Reference Sources

- Linux Essentials FG + Primer — https://os.cybbh.io/public/os/latest/003_linux_essentials/bash_fg.html  
- Linux Nmap FG — https://os.cybbh.io/public/os/latest/003_linux_essentials/nmap.html  
- Linux Boot Process FG + Primer — https://os.cybbh.io/public/os/latest/007_linux_boot_process/linboot_fg.html  
- Linux Process Validity FG + Primer — https://os.cybbh.io/public/os/latest/010_linux_process_validity/linproc_fg.html  
- Linux Auditing & Logging FG + Primer — https://os.cybbh.io/public/os/latest/012_linux_auditing_%26_logging/linlog_fg.html  
- Windows PowerShell FG + Primer — https://os.cybbh.io/public/os/latest/002_powershell/pwsh_fg.html  
- Windows Registry FG + Primer — https://os.cybbh.io/public/os/latest/004_windows_registry/reg_fg.html  
- Windows ADS FG + Primer — https://os.cybbh.io/public/os/latest/005_windows_ads/ads_fg.html  
- Windows Boot Process FG + Primer — https://os.cybbh.io/public/os/latest/006_windows_boot_process/winboot_fg.html  
- Windows Process Validity FG + Primer — https://os.cybbh.io/public/os/latest/008_windows_process_validity/winproc_fg.html  
- Windows UAC Bypass FG — https://os.cybbh.io/public/os/latest/009_windows_uac/uac_fg.html  
- Windows Auditing & Logging FG + Primer — https://os.cybbh.io/public/os/latest/011_windows_auditing_%26_logging/artifacts_fg.html  
- Memory Analysis FG + Primer — https://os.cybbh.io/public/os/latest/013_memory_analysis/mem_fg.html  
- Active Directory Enumeration FG + Primer — https://os.cybbh.io/public/os/latest/014_windows_active_directory_enumeration/active_fg.html  
- Sysinternals FG — https://os.cybbh.io/public/os/latest/015_windows_sysinternals/sysint_fg.html  

---

<a id="powershell-basics"></a>
## 🪟 2. Windows PowerShell Basics — Pattern Search & ACL Auditing

### 2.1 Count Regex Pattern Matches in a File

```powershell
(Get-Content -Path $path1 -Raw | Select-String -Pattern "aa[a-g]" -AllMatches).Matches.Count
```

Counts all instances of the regex pattern `aa[a-g]` within a file. Useful for pattern detection, content validation, or spotting specific character sequences.

---

### 2.2 Enumerate File Permissions for “ReadAndExecute” Rights

```powershell
Get-Acl C:\Windows\System32\drivers\etc\hosts |
  ForEach-Object {
      $_.Access | Where-Object { $_.FileSystemRights -like "*ReadAndExecute*" }
  } |
  Select-Object IdentityReference, FileSystemRights
```

Retrieves ACL entries on the `hosts` file and shows which identities have **Read & Execute** rights — a quick permissions audit for a key system file.

---

### 2.3 Sort and Display the First 21 Lines of a File (Descending)

```powershell
Get-Content -Path "C:\Users\CTF\Desktop\CTF\words.txt" |
    Sort-Object |
    Sort-Object -Descending |
    Select-Object -First 21
```

Reads a text file, sorts the lines, then outputs the **top 21** in descending order. Handy to view “top-ranked” or last-sorted entries.

*(You could simplify to a single `Sort-Object -Descending`, but this syntax is still valid.)*

---

### 2.4 Compare Two Text Files Line by Line

```powershell
Compare-Object -ReferenceObject (Get-Content new.txt) -DifferenceObject (Get-Content old.txt)
```

Compares two text files and highlights differences. Shows which lines are unique to `new.txt` or `old.txt`, useful for config drift or log comparison.

---

<a id="windows-registry-ads"></a>
## 🧱 3. Windows Registry and ADS

### 3.1 View Startup Keys

```powershell
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
```

Queries common **startup locations** in the registry to enumerate programs configured to launch at boot/login.

---

### 3.2 Create or Modify Registry Entries (PowerShell)

```powershell
Set-ItemProperty -Path HKCU:\Software\Classes\ms-settings\shell\open\command -Name "(Default)" -Value "cmd.exe"
```

Sets or modifies the `(Default)` value of the specified registry key. Frequently used in **UAC bypass** or persistence scenarios; must be handled carefully.

---

### 3.3 Export Registry Key

```powershell
reg export HKLM\SOFTWARE\Key backup.reg
```

Exports a registry subtree to `backup.reg` for backup, offline analysis, or migration.

---

### 3.4 Show Alternate Data Streams (ADS) via CMD

```powershell
dir /r
more < file.txt:secret
```

- `dir /r` displays NTFS **alternate data streams** on files.  
- `more < file.txt:secret` reads content from the `secret` ADS attached to `file.txt`.

---

### 3.5 Enumerate Saved Network Profiles

```powershell
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles" |
    ForEach-Object { (Get-ItemProperty $_.PSPath).ProfileName }
```

Lists network profiles (Wi-Fi/Ethernet) saved on the system. Helps reconstruct **network history** and potential lateral movement paths.

---

### 3.6 Enumerate Connected USB Devices

```powershell
reg query "HKLM\SYSTEM\CurrentControlSet\Enum\USB"
```

Displays registry entries corresponding to USB devices, which is useful in **forensic investigations** to identify removable media usage.

---

<a id="active-directory-enum"></a>
## 🔐 9. Active Directory Enumeration

### 9.1 Enumerate All Fine-Grained Password Policies (FGPP)

```powershell
Get-ADFineGrainedPasswordPolicy -Filter { name -like "*" }
```

Lists all **Fine-Grained Password Policies** defined in the domain, revealing specialized password rules applied to particular users or groups.

---

<a id="powershell-cheatsheet"></a>
## 🔟 PowerShell Cheat Sheet — Detailed Notes (Consolidated)

<a id="basic-commands"></a>
### 10.1 Basic Commands

#### `Get-Service`

```powershell
Get-Service
Get-Service | Where-Object {$_.Status -eq "Running"}
```

Displays all services on the system and can be filtered (e.g., to show only running services).

---

#### `Get-Process`

```powershell
Get-Process
Get-Process | Sort-Object CPU -Descending
```

Lists active processes, similar to Task Manager. Sorting by CPU highlights high-usage processes.

---

#### `Get-Host`

```powershell
Get-Host
```

Shows details of the current PowerShell host/session (version, culture, etc.).

---

#### `ipconfig`

```powershell
ipconfig /all
```

Native Windows networking command (not a cmdlet) to display detailed IP configuration for all adapters.

---

#### `netstat -ano`

```powershell
netstat -ano
```

Displays network connections, listening ports, and associated process IDs — useful for quick network triage.

---

#### `Get-ChildItem` / `ls`

```powershell
Get-ChildItem
Get-ChildItem -Recurse -Force
```

Lists files and directories. With `-Recurse` and `-Force`, it traverses subdirectories and includes hidden items.

---

#### `Set-Location` / `cd`

```powershell
Set-Location "C:\Windows"
```

Changes the current working directory.

---

#### `Get-Content` / `cat`

```powershell
Get-Content .\file.txt
Get-Content .\log.txt | Select-String "Error"
```

Reads file contents; piping to `Select-String` lets you grep-like search for patterns.

---

#### `Get-Help`

```powershell
Get-Help Get-Process
Get-Help Get-Process -Online
```

Displays help for cmdlets; `-Online` opens the full documentation in a browser.

---

<a id="useful-commands"></a>
### 10.2 Useful Commands & Search Patterns

#### SSH Connection

```powershell
ssh username@destinationIP
```

Uses the OpenSSH client to connect to a remote system via SSH.

---

#### Search for a String (CMD)

```powershell
findstr /i "string"
```

Performs a case-insensitive search for text in files or piped output.

---

#### Compare Two Files

```powershell
Compare-Object (cat file1) (cat file2)
```

Compares the content of two files line by line, showing differences.

---

#### Recursive String Search

```powershell
Get-ChildItem "C:\Directory" -Recurse | Select-String -Pattern "String"
```

Recursively searches through files in a directory for a pattern.

---

#### Search for a File by Name

```powershell
Get-ChildItem -Path C:\ -Filter "*file*" -Recurse
```

Finds files whose names match a wildcard pattern.

---

#### List Hidden Directories

```powershell
Get-ChildItem -Hidden
```

Shows files and directories marked as `Hidden`.

---

<a id="key-file-locations"></a>
### 10.3 Key File Locations

| Scope                      | Description                          | Path                                                      |
|---------------------------|--------------------------------------|-----------------------------------------------------------|
| All Users, All Hosts      | Global PowerShell profile            | `$PsHome\Profile.ps1`                                    |
| All Users, Current Host   | Host-specific profile for all users  | `$PsHome\Microsoft.PowerShell_profile.ps1`               |
| Current User, All Hosts   | User profile across all hosts        | `$HOME\Documents\WindowsPowerShell\Profile.ps1`          |
| Current User, Current Host| User+host-specific profile           | `$HOME\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1` |

**Common system paths:**

- System files: `C:\Windows\System32`  
- Application files: `C:\Program Files`  

---

<a id="pipeline-filtering"></a>
### 10.4 Pipeline & Filtering Examples

#### Filter Running Services

```powershell
Get-Service | Where-Object {$_.Status -eq "Running"}
```

Shows only running services.

---

#### Sort Processes by Memory Usage

```powershell
Get-Process |
  Sort-Object WorkingSet -Descending |
  Select-Object -First 10
```

Lists the top 10 processes by memory consumption.

---

#### Export Processes to CSV

```powershell
Get-Process |
  Select-Object Name, CPU, Id |
  Export-Csv -Path processes.csv -NoTypeInformation
```

Exports essential process metrics to CSV for later analysis.

---

#### Find Specific Files and Export Results

```powershell
Get-ChildItem -Recurse -Filter "*.log" |
  Select-Object FullName, Length |
  Export-Csv logs.csv -NoTypeInformation
```

Finds all `.log` files and exports paths and sizes.

---

#### Count Matching Lines in Files

```powershell
Get-ChildItem -Recurse -Filter "*.txt" |
  Select-String "Error" |
  Measure-Object
```

Counts all lines containing “Error” across text files.

---

#### Display Event Logs Matching Keyword

```powershell
Get-EventLog -LogName System |
  Where-Object {$_.Message -like "*network*"} |
  Select-Object -First 5
```

Shows the first five System events that reference “network”.

---

<a id="admin-system"></a>
### 10.5 Administrative & System Management

#### Manage Services

```powershell
Start-Service -Name "Spooler"
Stop-Service -Name "Spooler"
Restart-Service -Name "Spooler"
```

Starts, stops, or restarts Windows services.

---

#### Manage Local User Accounts

```powershell
Get-LocalUser
New-LocalUser -Name "NewUser" -NoPassword
Add-LocalGroupMember -Group "Administrators" -Member "NewUser"
```

Enumerates, creates, and grants group membership to local users.

---

#### Manage Scheduled Tasks

```powershell
Get-ScheduledTask

Register-ScheduledTask -TaskName "Backup" `
  -Action (New-ScheduledTaskAction -Execute "notepad.exe")
```

Displays existing scheduled tasks or registers a new one with a specified action.

---

#### Modify the Registry (PowerShell)

```powershell
Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
Set-ItemProperty "HKCU:\Software\MyApp" "Setting" "Enabled"
```

Reads and sets registry values using PowerShell’s registry provider.

---

#### System Information and Performance

```powershell
Get-ComputerInfo

Get-WmiObject Win32_OperatingSystem |
  Select-Object CSName, Caption, OSArchitecture
```

Retrieves detailed OS information, including machine name and architecture.

---

#### Manage Windows Updates (Requires `PSWindowsUpdate`)

```powershell
Get-WindowsUpdate
Install-WindowsUpdate -AcceptAll -AutoReboot
```

Checks for and installs Windows Updates via PowerShell.

---

#### Disk and Storage Management

```powershell
Get-Volume
Get-Disk
Get-Partition
```

Displays volumes, physical disks, and partition information.

---

#### Reboot or Shutdown System

```powershell
Restart-Computer -Force
Stop-Computer -Force
```

Forces a reboot or shutdown of the local machine (remote use requires permissions and parameters).

---

<a id="security-permissions"></a>
### 10.6 Security, Permissions & Event Logs

#### View Current User and Admin Group Members

```powershell
whoami
Get-LocalGroupMember "Administrators"
```

Shows the logged-in user and which accounts are in the local `Administrators` group.

---

#### Manage File/Folder Permissions (ACLs)

```powershell
Get-Acl "C:\FolderName"

Set-Acl "C:\FolderName" (Get-Acl "C:\TemplateFolder")
```

Reads and applies NTFS ACLs from a “template” folder to another location.

---

#### Check and Set Execution Policy

```powershell
Get-ExecutionPolicy
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
```

Controls script execution restrictions for the current user.

---

#### Audit and Monitor Security Events

```powershell
Get-EventLog -LogName Security -Newest 10

Get-WinEvent -LogName Security |
  Where-Object {$_.Id -eq 4625}
```

Fetches recent security events and filters for failed logon attempts (`Event ID 4625`).

---

#### View Firewall Configuration

```powershell
Get-NetFirewallRule |
  Select-Object Name, Enabled, Direction, Action
```

Lists firewall rules and their state, direction, and action.

---

#### Manage Firewall Rules

```powershell
New-NetFirewallRule -DisplayName "AllowSSH" -Direction Inbound -Protocol TCP -LocalPort 22 -Action Allow
Remove-NetFirewallRule -DisplayName "AllowSSH"
```

Adds or removes firewall rules, such as allowing SSH inbound on port 22.

---

#### Manage User Privileges and Accounts

```powershell
Get-LocalUser
Disable-LocalUser -Name "Guest"
Enable-LocalUser -Name "Administrator"
```

Enables or disables local accounts for security hardening.

---

#### Encrypt and Decrypt Files (CMD interop)

```powershell
cipher /e "C:\SensitiveData"
cipher /d "C:\SensitiveData"
```

Encrypts and decrypts folders/files using EFS (Encrypting File System).

---

#### Monitor PowerShell Transcripts

```powershell
Start-Transcript -Path "C:\Logs\session_log.txt"
Stop-Transcript
```

Captures all commands and output in a session for auditing or training.

---

<a id="ads-hidden-files"></a>
### 10.7 Alternate Data Streams (ADS) & Hidden Files

> **Context:** NTFS supports hidden **Alternate Data Streams**, and files can also be hidden via **attributes**. Attackers and tools can abuse both.

#### Inspect ADS (PowerShell)

List all streams on a file:

```powershell
Get-Item -Path .\example.txt -Stream *
```

Show a specific stream:

```powershell
Get-Content -Path .\example.txt -Stream Zone.Identifier
```

Create or overwrite a custom stream:

```powershell
Set-Content -Path .\example.txt -Stream notes -Value "Secret note in ADS"
```

Append data:

```powershell
Add-Content -Path .\example.txt -Stream notes -Value " (appended)"
```

Remove a stream:

```powershell
Remove-Item -Path .\example.txt -Stream notes
```

---

#### Inspect ADS (CMD interop)

```powershell
cmd /c "dir /r .\example.txt"
```

`dir /r` lists ADS names and sizes on the file.

---

#### Unblock Downloaded Files (Zone.Identifier)

```powershell
Get-Content -Path .\installer.ps1 -Stream Zone.Identifier
Unblock-File -Path .\installer.ps1
```

Views and removes the zone marker that can cause SmartScreen or other protections to warn/block.

---

#### Copying and Archiving with ADS

```powershell
robocopy . . example.txt /COPYALL /R:0 /W:0
```

Uses `robocopy` to preserve data, attributes, ACLs, owner info, timestamps, and ADS.

---

#### Enumerate Hidden & System Files

```powershell
Get-ChildItem -Force

Get-ChildItem -Recurse -Force |
  Where-Object { $_.Attributes -match 'Hidden|System' }

Get-ChildItem -Attributes Hidden -Force -Recurse
```

Shows hidden/system files, either broadly or filtered.

---

#### Set or Clear Hidden/System Attributes

```powershell
attrib +h +s "C:\path\to\file.txt"
attrib -h -s "C:\path\to\file.txt"
```

CMD-style attribute manipulation (works in PowerShell).

PowerShell object method:

```powershell
$item = Get-Item "C:\path\to\file.txt"
$item.Attributes = $item.Attributes -bor [IO.FileAttributes]::Hidden
$item.Attributes = $item.Attributes -band (-bnot [IO.FileAttributes]::Hidden)
```

---

#### Dotfiles vs Attributes on Windows

```powershell
Get-ChildItem -Force
attrib +h ".\.env"
```

Dotfiles (`.env`) are not automatically hidden; you must use attributes and `-Force` to see them.

---

<a id="forensic-checklist"></a>
### 10.8 Forensic Checklist — ADS & Hidden Files

#### 1. Enumerate Alternate Data Streams (ADS)

```powershell
Get-ChildItem -Path C:\ -Recurse -File -ErrorAction SilentlyContinue |
  ForEach-Object {
    $streams = Get-Item -LiteralPath $_.FullName -Stream * -ErrorAction SilentlyContinue
    if ($streams.Count -gt 1) {
      [PSCustomObject]@{
        File    = $_.FullName
        Streams = $streams.Stream
      }
    }
  } |
  Export-Csv C:\Forensic\ADS_Report.csv -NoTypeInformation
```

Finds files that have one or more non-default streams and exports a report.

---

#### 2. Identify Hidden or System Files

```powershell
Get-ChildItem -Path C:\ -Force -Recurse -ErrorAction SilentlyContinue |
  Where-Object { $_.Attributes -match 'Hidden|System' } |
  Select-Object FullName, Attributes |
  Export-Csv C:\Forensic\HiddenFiles.csv -NoTypeInformation
```

Exports a list of hidden/system files for review.

---

#### 3. Collect File Hashes

```powershell
Get-ChildItem -Path "C:\Forensic\Samples" -File -Recurse |
  Get-FileHash -Algorithm SHA256 |
  Export-Csv "C:\Forensic\Hashes.csv" -NoTypeInformation
```

Generates SHA256 hashes to maintain chain-of-custody integrity.

---

#### 4. Preserve Metadata and Streams in Archive

```powershell
robocopy "C:\Evidence" "D:\Archive" /COPYALL /E /R:0 /W:0 /LOG:"C:\Forensic\robocopy.log"
```

Copies evidence while preserving attributes, ACLs, timestamps, owners, and ADS.

---

#### 5. Examine Zone.Identifier Markers

```powershell
Get-ChildItem -Recurse -Filter *.exe |
  ForEach-Object {
    if (Get-Item $_ -Stream Zone.Identifier -ErrorAction SilentlyContinue) {
      "$($_.FullName) contains Zone.Identifier"
    }
  }
```

Identifies executables tagged as downloaded from the Internet.

---

#### 6. Extract Metadata for Timeline Analysis

```powershell
Get-ChildItem -Recurse -File |
  Select-Object FullName, CreationTime, LastWriteTime, LastAccessTime |
  Export-Csv "C:\Forensic\Timeline.csv" -NoTypeInformation
```

Creates a CSV for timeline reconstruction.

---

#### 7. Documentation Checklist

When performing forensic triage, always note:

- Full file paths  
- Hash values (preferably SHA256)  
- Original timestamps  
- Presence of ADS or unusual attributes  
- Logs from copy/collection tools (e.g., `robocopy`)  
