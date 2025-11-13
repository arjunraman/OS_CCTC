# Windows / PowerShell Command Reference (Consolidated)

Cleaned, de-duplicated commands with corrected syntax and short explanations.  
Commands derived from **CCTC OS Notes – Registry** are clearly marked as examples.

---

## Table of Contents

- [1. Basic shell & navigation](#1-basic-shell--navigation)
- [2. Core PowerShell cmdlets & aliases](#2-core-powershell-cmdlets--aliases)
- [3. Files & content operations](#3-files--content-operations)
- [4. Text & regex searching in files](#4-text--regex-searching-in-files)
- [5. Directory & file search / counts](#5-directory--file-search--counts)
- [6. Alternate data streams & hidden files](#6-alternate-data-streams--hidden-files)
- [7. Hosts file, ACLs & hashes](#7-hosts-file-acls--hashes)
- [8. Registry & autoruns](#8-registry--autoruns)
- [9. USB devices & network profiles](#9-usb-devices--network-profiles)
- [10. Active Directory – discovery & filters](#10-active-directory--discovery--filters)
- [11. Domain information, groups & SIDs](#11-domain-information-groups--sids)
- [12. Local accounts, net help & network shares](#12-local-accounts-net-help--network-shares)
- [13. Processes, members & counts](#13-processes-members--counts)
- [14. Sysinternals & service/process inspection](#14-sysinternals--serviceprocess-inspection)
- [15. Archives & ZIP handling](#15-archives--zip-handling)
- [16. Windows boot troubleshooting](#16-windows-boot-troubleshooting)
- [17. UAC & policies](#17-uac--policies)
- [18. Windows services](#18-windows-services)
- [19. Memory forensics (Volatility)](#19-memory-forensics-volatility)
- [20. Forensic artifacts: recent docs, prefetch, Recycle Bin, Jump Lists, logs](#20-forensic-artifacts-recent-docs-prefetch-recycle-bin-jump-lists-logs)
- [21. Network & firewall inspection](#21-network--firewall-inspection)

---

## 1. Basic shell & navigation

```powershell
dir
ls
Get-ChildItem
```
List files and folders in the current directory.

```powershell
cd ..
Set-Location ..
```
Move up one directory.

```powershell
cd CTF
cd Desktop
cd Documents
cd Music
cd WWW
cd C:\Users\CTF
cd C:\Windows\PLA\not_anihc
```
Change to the specified directory.

```powershell
clear
Clear-Host
```
Clear the console screen.

---

## 2. Core PowerShell cmdlets & aliases

A quick reference of core cmdlets and their common aliases.

| Cmdlet           | Common Aliases                | Description |
|------------------|-------------------------------|-------------|
| Set-Location     | `cd`, `chdir`, `sl`          | Sets the current working location to a specified location. |
| Get-Content      | `cat`, `gc`, `type`          | Gets the content of the item at the specified location. |
| Add-Content      | `ac`                         | Appends content to the specified items (e.g., add text to a file). |
| Set-Content      | `sc`                         | Writes or replaces the content in an item with new content. |
| Copy-Item        | `copy`, `cp`, `cpi`          | Copies an item from one location to another. |
| Remove-Item      | `del`, `erase`, `rd`, `ri`, `rm`, `rmdir` | Deletes the specified items. |
| Move-Item        | `mi`, `move`, `mv`           | Moves an item from one location to another. |
| Set-Item         | `si`                         | Changes the value of an item to the value specified in the command. |
| New-Item         | `ni`                         | Creates a new item (for example, a file or folder). |
| Start-Job        | `sajb`                       | Starts a PowerShell background job. |
| Compare-Object   | `compare`, `dif`             | Compares two sets of objects. |
| Group-Object     | `group`                      | Groups objects that contain the same value for specified properties. |
| Invoke-WebRequest| `curl`, `iwr`, `wget`        | Gets content from a web page on the Internet. |
| Measure-Object   | `measure`                    | Calculates numeric properties of objects or counts lines/words/chars. |
| Resolve-Path     | `rvpa`                       | Resolves wildcard characters in a path and displays the resolved paths. |
| Resume-Job       | `rujb`                       | Restarts a suspended job. |
| Set-Variable     | `set`, `sv`                  | Sets the value of a variable, creating it if it does not exist. |
| Show-Command     | `shcm`                       | Opens a GUI window to help build PowerShell commands. |
| Sort-Object      | `sort`                       | Sorts objects by property values. |
| Start-Service    | `sasv`                       | Starts one or more stopped services. |
| Start-Process    | `saps`, `start`              | Starts one or more processes on the local computer. |
| Suspend-Job      | `sujb`                       | Temporarily stops (suspends) workflow jobs. |
| Wait-Job         | `wjb`                        | Waits for one or all PowerShell background jobs to complete. |
| Where-Object     | `?`, `where`                 | Filters objects in the pipeline based on property values. |
| Write-Output     | `echo`, `write`              | Sends objects to the next command in the pipeline or to the console. |

---

## 3. Files & content operations

```powershell
Get-Content -Path "C:\Users\CTF\Desktop\CTF\words.txt"
cat words.txt
```
Display the contents of a file.

```powershell
(Get-Content -Path "C:\Users\CTF\Desktop\CTF\words.txt")[20]
```
Show the 21st line of the file (0-based index).

```powershell
Get-Content -Path "C:\Users\CTF\Desktop\CTF\words.txt" -TotalCount 22
```
Read only the first 22 lines of the file.

```powershell
(Get-Content -Path "C:\Users\CTF\Desktop\CTF\words.txt" -TotalCount 22 |
  Sort-Object -Descending)[20]
```
Sort the first 22 lines in descending order and get the 21st item from that sorted list.

```powershell
(Get-Content -Path "C:\Users\CTF\Desktop\CTF\words.txt").Count
```
Count the number of lines in the file.

```powershell
$new_content = Get-Content -Path "C:\Users\CTF\Downloads\new.txt"
$old_content = Get-Content -Path "C:\Users\CTF\Downloads\old.txt"
Compare-Object -ReferenceObject $old_content -DifferenceObject $new_content
```
Load two text files and display the differences between them.

```powershell
Get-Content -Path "C:\Users\CTF\Desktop\CTF\words.txt" -TotalCount 22 |
  Sort-Object -Descending |
  Select-Object -First 1
```
Get the “largest” (lexicographically last) of the first 22 lines.

*(The following is an example from CCTC registry notes)*:

```powershell
Get-ChildItem -Path C:\Users\CTF -Filter 'readme*' -Recurse
```
Recursively search the CTF user’s home directory for files starting with `readme`. *(Example – CCTC Registry Notes)*

---

## 4. Text & regex searching in files

```powershell
(Get-Content -Path "C:\Users\CTF\Desktop\CTF\words.txt" |
  Select-String -Pattern "gaab" -CaseSensitive:$false -AllMatches).Matches.Count
```
Count all (case-insensitive) matches of the string `gaab` in the file.

```powershell
$path1   = "C:\Users\CTF\Desktop\CTF\words.txt"
$pattern = "aa[a-g]"

(Get-Content -Path $path1 -Raw |
  Select-String -Pattern $pattern -AllMatches).Matches.Count
```
Count how many matches exist for the regex `aa` followed by a letter in the range a–g.

```powershell
(Get-Content -Path "C:\Users\CTF\Desktop\CTF\words.txt" -Raw) -split '\s+' |
  Where-Object { $_ -match '[a-z]' } |
  Measure-Object |
  Select-Object -ExpandProperty Count
```
Split the file into tokens and count how many contain at least one letter a–z.

*(Examples from CCTC registry notes)*:

```powershell
Get-ChildItem -Force -Path "C:\Users\CTF\" -Recurse | Select-String -Pattern "fortune"
```
Scan all files (including hidden) under the CTF profile for the string `fortune` to locate “fortune cookie” hints. *(Example – CCTC Registry Notes)*

```powershell
Get-ChildItem -Force -Recurse | Select-String -Pattern "phi5h"
```
Search all files (including hidden) for the obfuscated string `phi5h` to locate phishing-related artifacts. *(Example – CCTC Registry Notes)*

---

## 5. Directory & file search / counts

```powershell
(Get-ChildItem -Path "C:\Users\CTF\Music" -Directory).Count
```
Count how many subdirectories are under `Music`.

```powershell
Get-ChildItem -Path C:\ -Recurse -File -ErrorAction SilentlyContinue |
  Where-Object { $_.Name -eq "readme" }
```
Recursively search the C: drive for files named exactly `readme`.

```powershell
Get-ChildItem -Path "C:\" -Recurse -ErrorAction SilentlyContinue -Filter '*fortune*'
```
Recursively search for files with names containing `fortune`.

```powershell
Get-ChildItem -Path "C:\" -Recurse -File -ErrorAction SilentlyContinue -Filter '*phish*'
```
Search for files whose names contain `phish`.

*(Examples from CCTC registry notes)*:

```powershell
Get-ChildItem -Recurse | ForEach-Object { Get-Item $_.FullName -Stream * } |
  Where-Object Stream -ne ':$DATA'
```
Enumerate alternate data streams for all files and filter out the default `:$DATA` stream. *(Example – CCTC Registry Notes)*

```powershell
Get-ChildItem -Path 'C:\Windows\Prefetch\'
```
List prefetch files, which record recently executed programs. *(Example – CCTC Registry Notes)*

```powershell
Get-ChildItem 'C:\$Recycle.Bin\' -Recurse -Force | Select-Object FullName
```
Enumerate all Recycle Bin containers and their deleted files. *(Example – CCTC Registry Notes)*

```powershell
Get-ChildItem 'C:\Users\student\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\'
```
List Jump List automatic-destination files for the `student` user. *(Example – CCTC Registry Notes)*

---

## 6. Alternate data streams & hidden files

```cmd
dir /R
dir /R C:\Windows\PLA\not_anihc
dir /R .\bit_free
```
Use `dir /R` to show files and their alternate data streams (ADS).

```powershell
Get-Item .\bit_free -Stream *
Get-Item .\completely_blank -Stream *
Get-Item .\empty_file -Stream *
Get-Item .\nothing_here -Stream *
```
List all streams (including ADS) for a file.

```powershell
Get-Content .\nothing_here -Stream secret.info
Get-Content .\nothing_here -Stream hidden
```
Read data stored in alternate streams `secret.info` or `hidden`.

*(Examples from CCTC registry notes)*:

```powershell
Get-Item '.\The Fortune Cookie' -Stream *
Get-Content '.\The Fortune Cookie' -Stream none
```
Inspect ADS for `The Fortune Cookie` file and read from the non-default `none` stream to reveal a hidden password. *(Example – CCTC Registry Notes)*

---

## 7. Hosts file, ACLs & hashes

```powershell
Get-Item "C:\Windows\System32\drivers\etc\hosts"
```
Get the hosts file object.

```powershell
(Get-Acl C:\Windows\System32\drivers\etc\hosts).Access
```
List ACEs (who has which rights) on the hosts file.

```powershell
Get-FileHash C:\Windows\System32\drivers\etc\hosts -Algorithm MD5
```
Compute an MD5 hash for the hosts file.

*(Examples from CCTC registry notes)*:

```powershell
Get-Acl -Path C:\Windows\System32\drivers\etc\hosts | Select-Object -ExpandProperty Access
```
Display detailed ACEs on the hosts file, including group rights such as `BUILTIN\Users`. *(Example – CCTC Registry Notes)*

```cmd
certutil -hashfile C:\Windows\System32\drivers\etc\hosts md5
```
Use `certutil` to compute the MD5 hash of the hosts file, often used for tamper checks. *(Example – CCTC Registry Notes)*

```powershell
Get-ChildItem C:\Windows\System32\drivers\etc\hosts | Select-Object Name, LastAccessTime
```
Show last access time for the hosts file for timeline/audit questions. *(Example – CCTC Registry Notes)*

---

## 8. Registry & autoruns

*(Examples from CCTC registry notes)*:

```powershell
Get-ChildItem
```
When used in the **Registry provider**, list all subkeys and their contents under the current registry path. *(Example – CCTC Registry Notes)*

```powershell
Get-Item
```
When used in the **Registry provider**, return a specific registry key (and its values) instead of listing child keys. *(Example – CCTC Registry Notes)*

```cmd
reg query HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run
```
Query the `Run` key containing programs that run at every boot. *(Example – CCTC Registry Notes)*

```powershell
Get-LocalUser <Username> | Select-Object -ExpandProperty SID
```
Get the SID for a local user so you can pivot into their hive under `HKEY_USERS\<SID>`. *(Example – CCTC Registry Notes)*

```cmd
reg query HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
```
Query the `RunOnce` key that executes entries a single time at next boot. *(Example – CCTC Registry Notes)*

```cmd
reg query "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
```
Query the current user’s `RunOnce` key for per-user one-shot autoruns.

---

## 9. USB devices & network profiles

*(Examples from CCTC registry notes)*:

```cmd
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR
```
Enumerate USB storage device history, including manufacturer info (e.g., `SanDisk`). *(Example – CCTC Registry Notes)*

```cmd
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles"
```
List stored network profiles to examine SSIDs and network names the system has connected to. *(Example – CCTC Registry Notes)*

---

## 10. Active Directory – discovery & filters

```powershell
Get-Command -Module ActiveDirectory
```
List all cmdlets in the `ActiveDirectory` module.

```powershell
Get-Help Search-ADAccount
```
Show help for `Search-ADAccount`.

```powershell
Get-ADUser -Filter 'Enabled -eq $False' -Properties Name,Enabled
```
List disabled AD users, showing name and enabled status.

```powershell
Get-ADUser -Filter 'Enabled -eq $True'
```
List enabled AD users.

```powershell
Search-ADAccount -LockedOut
Search-ADAccount -PasswordNeverExpires
```
Find accounts that are locked out or whose passwords never expire.

```powershell
Get-ADUser -Filter 'Enabled -eq $True' -Properties AccountExpirationDate |
  Where-Object { $_.AccountExpirationDate -lt (Get-Date) -and $_.AccountExpirationDate -ne $null }
```
Find enabled users whose account expiration date is in the past.

```powershell
Get-ADUser -Filter * -Properties Name,PasswordNeverExpires |
  Where-Object { $_.PasswordNeverExpires -eq $true } |
  Select-Object SamAccountName,Name,PasswordNeverExpires
```
List users whose password never expires.

```powershell
Get-ADUser -Filter 'PasswordNeverExpires -eq $True -and SamAccountName -ne "andy.dwyer"' `
  -Properties PasswordNeverExpires |
  Select-Object SamAccountName,Name,PasswordNeverExpires
```
Same as above but excluding a specific account.

```powershell
Get-ADUser -Filter 'Name -like "*"' -Properties *
```
Dump all user objects with full properties.

```powershell
Get-ADUser -Filter 'telephoneNumber -like "*6754*"' | Select-Object Name
```
Find users whose phone number contains `6754`.

```powershell
Get-ADUser -Filter 'Description -like "*"' | Select-Object Name
Get-ADUser -Filter 'Description -notlike "*SOLDIER*"' -Properties * |
  Select-Object Name,Description
```
List users with any description / users whose description does **not** contain `SOLDIER`.

```powershell
Get-ADObject -Filter 'Name -like "*"' -Properties *
```
Dump all AD objects with all properties.

```powershell
Get-ADObject -Filter 'userAccountControl -band 128' -Properties userAccountControl
```
List objects where the “disabled” bit is set in `userAccountControl`.

```powershell
Get-ADObject -Filter 'pwdLastSet -notlike "0"' -Properties *
```
Find accounts that have actually set a password.

```powershell
Get-ADUser -LDAPFilter '(&(objectCategory=Person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=128))' `
  -Properties userAccountControl |
  Select-Object Name,SamAccountName,userAccountControl
```
Find disabled user accounts using an LDAP filter.

---

## 11. Domain information, groups & SIDs

```powershell
(Get-CimInstance Win32_ComputerSystem).Domain
```
Show the AD domain of the current machine.

```powershell
Get-ADForest
Get-ADDomain
```
Display forest and domain information.

```powershell
Get-ADUser -Identity krbtgt -Properties SID | Select-Object -ExpandProperty SID
```
Display the SID of the `krbtgt` account.

```powershell
(Get-ADGroupMember -Identity 'Domain Admins' -Recursive |
  Where-Object { $_.objectClass -eq 'user' }).Count
```
Count how many user accounts are (directly or indirectly) members of `Domain Admins`.

```powershell
Get-ADGroupMember -Identity 'Domain Admins' -Recursive |
  Where-Object { $_.objectClass -eq 'user' }
```
List user accounts that are members of `Domain Admins`.

---

## 12. Local accounts, net help & network shares

```powershell
net user
```
List local user accounts.

```powershell
net user *
```
Prompt to display details for specific accounts interactively.

```powershell
net user Alice.Brandywine
```
Show information about the local account `Alice.Brandywine`.

```powershell
NET HELPMSG 2221
```
Explain error code 2221 from `net` commands (e.g., “user name could not be found”).

```powershell
$WarriorShare = "\\file-server\warrior share"
net use * $WarriorShare
```
Map a network share path to an available drive letter.

```powershell
Get-ChildItem -Path $WarriorShare -Filter "file" -Recurse -File -ErrorAction SilentlyContinue
```
Search the share for files whose names contain `file`.

```powershell
dir $WarriorShare
dir "$WarriorShare\1st Battalion"
dir $WarriorShare /b /a-d
dir $WarriorShare -Recurse
```
List contents of the share and specific subfolders using different view styles.

```powershell
$WarriorShare_BHQ_S6 = "\\file-server\warrior share\Brigade HQ\S-6"
net use * $WarriorShare_BHQ_S6
Get-Content -Path "$WarriorShare_BHQ_S6\lulz.pdf"
```
Map the S-6 subfolder of the share and read a file from it.

---

## 13. Processes, members & counts

```powershell
Get-Process
```
List running processes.

```powershell
(Get-Process).Count
```
Count how many processes are running.

```powershell
Get-Process | Get-Member -MemberType Property
```
Show properties available on process objects.

```powershell
(Get-Process | Get-Member -MemberType Property).Count
```
Count how many properties process objects expose.

```powershell
(Get-Process | Get-Member).Count
(Get-Process | Get-Member -MemberType Method).Count
```
Count all members / method members on process objects.

---

## 14. Sysinternals & service/process inspection

```powershell
.\accesschk.exe
.\accesschk.exe -p spoolsv.exe
```
Run **AccessChk** to inspect process permissions (e.g., for `spoolsv.exe`).

```powershell
.\handle.exe
.\handle.exe spoolsv.exe
```
Run **Handle** to list open handles globally and handles associated with `spoolsv.exe`.

```powershell
.\listdlls.exe /?
```
Show usage help for **ListDLLs**.

```powershell
Get-Process winlogon | ForEach-Object { $_.Modules } | More
Get-Process chrome   | ForEach-Object { $_.Modules } | More
```
List loaded modules for `winlogon` and `chrome`, paged through `more`.

*(Examples from CCTC registry notes)*:

```text
autoruns.exe
```
Sysinternals **Autoruns** GUI to enumerate startup and persistence locations. *(Example – CCTC Registry Notes)*

```text
procexp.exe
```
Sysinternals **Process Explorer** (advanced Task Manager). *(Example – CCTC Registry Notes)*

```text
tcpview.exe
```
Sysinternals **TCPView** to view live network connections. *(Example – CCTC Registry Notes)*

```text
loadorder.exe
```
Sysinternals **LoadOrder** to inspect service/driver load order. *(Example – CCTC Registry Notes)*

```powershell
Get-Process spoolsv | Select-Object Name, Id, Path
icacls "C:\Windows\System32\spoolsv.exe"
```
Find the spooler process and inspect ACLs on its executable. *(Example – CCTC Registry Notes)*

```powershell
.\handle.exe SPOOLSV
```
Use **Handle** to list resources held by `spoolsv.exe`. *(Example – CCTC Registry Notes)*

```powershell
.\PsService.exe query mpssvc
```
Use **PsService** to query the Windows Defender Firewall service. *(Example – CCTC Registry Notes)*

```powershell
.\Listdlls.exe winlogon.exe
```
List DLLs loaded into `winlogon.exe` for injection detection. *(Example – CCTC Registry Notes)*

```text
sigcheck.exe
```
Sysinternals **Sigcheck**, used here to inspect file signatures and requested execution level for UAC. *(Example – CCTC Registry Notes)*

---

## 15. Archives & ZIP handling

```powershell
Copy-Item -Path C:\Users\CTF\Documents\Omega1000.zip -Destination C:\Users\CTF\Desktop
```
Copy the ZIP file to the desktop.

```powershell
while ($zips = Get-ChildItem -Recurse -Filter *.zip) {
  foreach ($zip in $zips) {
    Expand-Archive -Verbose -Path $zip.FullName -DestinationPath $zip.DirectoryName -ErrorAction SilentlyContinue
  }
}
```
Recursively find all ZIP files and extract them to their containing directory.

```powershell
Expand-Archive -Path .\Omega1.zip -DestinationPath C:\Users\CTF\Documents\Omega1
```
Extract `Omega1.zip` to the specified folder.

```powershell
tar -xf .\Omega1.zip
```
Extract the ZIP archive using `tar` if available.

---

## 16. Windows boot troubleshooting

*(Examples from CCTC registry notes)*:

```cmd
bcdedit
```
Display Boot Configuration Data (BCD) settings to investigate misconfigurations. *(Example – CCTC Registry Notes)*

```cmd
bcdedit /deletevalue {current} safeboot
```
Remove the `safeboot` flag from the current boot entry to stop forced Safe Mode. *(Example – CCTC Registry Notes)*

```cmd
shutdown /a
```
Abort a pending shutdown or restart. *(Example – CCTC Registry Notes)*

```cmd
dir /S system.management.automation.dll
```
Search the system for `System.Management.Automation.dll`, useful when PowerShell is broken. *(Example – CCTC Registry Notes)*

```powershell
Test-Path $PROFILE*
```
Check which PowerShell profile scripts exist (per-user and all-users). *(Example – CCTC Registry Notes)*

```powershell
Get-Content $PROFILE
Start-Process "C:\Path\To\Suspicious.pdf"
```
Review an existing profile script and launch the referenced PDF for deeper analysis. *(Example – CCTC Registry Notes)*

---

## 17. UAC & policies

*(Examples from CCTC registry notes)*:

```powershell
Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name EnableLUA
```
Read the `EnableLUA` value to determine whether UAC is enabled. *(Example – CCTC Registry Notes)*

```powershell
Get-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System"
```
Retrieve the UAC policy key to inspect other UAC-related settings. *(Example – CCTC Registry Notes)*

---

## 18. Windows services

*(Examples from CCTC registry notes)*:

```cmd
sc query
```
Show service information from `cmd.exe`. *(Example – CCTC Registry Notes)*

```cmd
sc query state= all
```
List all services, running and stopped. *(Example – CCTC Registry Notes)*

```powershell
Get-Service
```
List services from PowerShell. *(Example – CCTC Registry Notes)*

```powershell
Get-Service -DisplayName "Totally-Legit"
```
Find a service by its display name. *(Example – CCTC Registry Notes)*

```powershell
Get-Service legit
```
Find a service by its service name. *(Example – CCTC Registry Notes)*

---

## 19. Memory forensics (Volatility)

```powershell
cd .\andy.dwyer\Desktop\Memory_Analysis\
.\volatility_2.6_win64_standalone.exe -h
```
Change into the memory analysis directory and show Volatility help.

```powershell
.\volatility_2.6_win64_standalone.exe -f ".\0zapftis.vmem" imageinfo
```
Infer OS profile information for `0zapftis.vmem`.

```powershell
.\volatility_2.6_win64_standalone.exe -f ".\0zapftis.vmem" cmdscan
.\volatility_2.6_win64_standalone.exe -f ".\0zapftis.vmem" driverscan
```
List command-line history and scan for drivers within the memory image.

```powershell
.\volatility_2.6_win64_standalone.exe -f ".\0zapftis.vmem" --profile=WinXPSP2x86 procdump -p 544 -D .
```
Dump process ID 544 to the current directory.

```powershell
.\volatility_2.6_win64_standalone.exe -f ".\cridex.vmem" --profile=WinXPSP2x86 procdump -p 1640 -D .
```
Dump process ID 1640 from `cridex.vmem`.

```powershell
.\volatility_2.6_win64_standalone.exe -f ".\0zapftis.vmem" --profile=WinXPSP2x86 connections
.\volatility_2.6_win64_standalone.exe -f ".\0zapftis.vmem" --profile=WinXPSP2x86 connscan
.\volatility_2.6_win64_standalone.exe -f ".\0zapftis.vmem" --profile=WinXPSP2x86 conscan
```
Enumerate network connections from the memory image.

```powershell
Set-MpPreference -ExclusionPath 'C:\Users\andy.dwyer\Desktop\Memory_Analysis\'
```
Add the memory analysis folder as an exclusion in Windows Defender.

```powershell
Get-FileHash -Algorithm MD5 -Path .\executable.544.exe
```
Compute an MD5 hash of the dumped executable for signature comparison.

---

## 20. Forensic artifacts: recent docs, prefetch, Recycle Bin, Jump Lists, logs

*(Examples from CCTC registry notes)*:

```powershell
Get-Item "REGISTRY::HKEY_USERS\*\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\.txt" |
  Select-Object -ExpandProperty Property |
  ForEach-Object {
    [System.Text.Encoding]::Default.GetString(
      (Get-ItemProperty -Path "REGISTRY::HKEY_USERS\*\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\.txt" -Name $_).$_
    )
  }
```
Walk RecentDocs entries for `.txt` files, decode the binary values, and recover names of recently opened text documents. *(Example – CCTC Registry Notes)*

```powershell
Get-ChildItem -Path 'C:\Windows\Prefetch\'
```
List prefetch files for program execution history. *(Example – CCTC Registry Notes)*

```powershell
Get-ChildItem 'C:\$Recycle.Bin\' -Recurse -Force | Select-Object FullName
```
Enumerate all Recycle Bin entries for deleted file recovery. *(Example – CCTC Registry Notes)*

```powershell
Get-ChildItem 'C:\Users\student\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\'
```
List Jump List automatic-destination files containing recent paths and executables. *(Example – CCTC Registry Notes)*

```powershell
Get-EventLog -LogName System |
  Where-Object { $_.Message -match "flag" } |
  Format-Table -Wrap
```
Search the System event log for messages containing `flag` and show full message text. *(Example – CCTC Registry Notes)*

---

## 21. Network & firewall inspection

```powershell
Get-NetFirewallProfile -Name Public | Format-List LogAllowedConnections
```
Display whether the Public firewall profile logs allowed connections.

*(Example from CCTC registry notes)*:

```powershell
Get-NetFirewallProfile -Profile Public
```
Retrieve Public profile firewall settings (including logging flags). *(Example – CCTC Registry Notes)*
