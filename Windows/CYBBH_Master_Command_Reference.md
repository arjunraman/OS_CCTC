# 🧭 CYBBH Operating Systems Command Reference (Consolidated Master Sheet)

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

## 🪟 2. Windows PowerShell Basics — Pattern Search & ACL Auditing

### 1️⃣ Count Regex Pattern Matches in a File
```powershell
(Get-Content -Path $path1 -Raw | Select-String -Pattern "aa[a-g]" -AllMatches).Matches.Count
```
Counts all instances of the regex pattern `aa[a-g]` within a file. Useful for pattern detection or text analysis.

---

### 2️⃣ Enumerate File Permissions for “ReadAndExecute” Rights
```powershell
Get-Acl C:\Windows\System32\drivers\etc\hosts |
  ForEach-Object {
      $_.Access | Where-Object { $_.FileSystemRights -like "*ReadAndExecute*" }
  } |
  Select-Object IdentityReference, FileSystemRights
```
Retrieves ACL entries on the hosts file and shows which identities have Read/Execute rights. A quick permissions audit.

---

### 3️⃣ Sort and Display the First 21 Lines of a File (Descending)
```powershell
Get-Content -Path "C:\Users\CTF\Desktop\CTF\words.txt" |
    Sort-Object |
    Sort-Object -Descending |
    Select-Object -First 21
```
Reads, sorts, and outputs the first 21 descending lines of a text file — a basic way to preview or rank contents.

---

### 4️⃣ Compare Two Text Files Line by Line
```powershell
Compare-Object -ReferenceObject (Get-Content new.txt) -DifferenceObject (Get-Content old.txt)
```
Compares two files (`new.txt` vs. `old.txt`) and highlights differences. Shows which lines exist only in one file.

---

## 🧱 3. Windows Registry and ADS

### 1️⃣ View Startup Keys
```powershell
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
```

### 2️⃣ Create or Modify Registry Entries
```powershell
Set-ItemProperty -Path HKCU:\Software\Classes\ms-settings\shell\open\command -Name "(Default)" -Value "cmd.exe"
```

### 3️⃣ Export Registry Key
```powershell
reg export HKLM\SOFTWARE\Key backup.reg
```

### 4️⃣ Show Alternate Data Streams (ADS)
```powershell
dir /r
more < file.txt:secret
```

### 5️⃣ Enumerate Saved Network Profiles
```powershell
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles" |
    ForEach-Object { (Get-ItemProperty $_.PSPath).ProfileName }
```
Lists network profiles (Wi-Fi/Ethernet) saved on the system — useful for network history and forensics.

### 6️⃣ Enumerate Connected USB Devices
```powershell
reg query "HKLM\SYSTEM\CurrentControlSet\Enum\USB"
```
Displays all connected USB device registry entries. Useful for tracking hardware history or forensic USB usage.

---

## 🔐 9. Active Directory Enumeration

### 1️⃣ Enumerate All Fine-Grained Password Policies (FGPP)
```powershell
Get-ADFineGrainedPasswordPolicy -Filter { name -like "*" }
```
Lists every Fine-Grained Password Policy defined in the domain, revealing password settings for different users/groups.

---
