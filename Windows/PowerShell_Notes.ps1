# PowerShell Cheat Sheet — Quick Reference
# ----------------------------------------
# Each section below includes example commands with inline comments.

# BASIC COMMANDS

# Display running services
Get-Service

# Display running processes
Get-Process

# Display system information
Get-Host

# Display IP configuration (CMD utility)
ipconfig /all

# Display network connections and PIDs
netstat -ano

# List directories (alias: ls)
Get-ChildItem

# Change directories (alias: cd)
Set-Location "C:\Windows"

# Read file contents (alias: cat)
Get-Content .\file.txt

# Get cmdlet help information
Get-Help Get-Process

# USEFUL COMMANDS

# Connect to remote system via SSH
ssh username@destinationIP

# Search for a string (case-insensitive)
findstr /i "string"

# Compare two files
Compare-Object (cat file1) (cat file2)

# Recursively search a directory for a string
Get-ChildItem "C:\Directory" -R | Select-String -Pattern "String"

# Search the system for a file name pattern
Get-ChildItem -Path C:\ -Filter "*file*" -R

# List hidden directories
Get-ChildItem -Hidden

# KEY FILE LOCATIONS

# PowerShell profiles
# All Users, All Hosts
$PsHome\Profile.ps1

# All Users, Current Host
$PsHome\Microsoft.PowerShell_profile.ps1

# Current User, All Hosts
$HOME\Documents\WindowsPowerShell\Profile.ps1

# Current User, Current Host
$HOME\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1

# System and Application Paths
# System Files: C:\Windows\System32
# Application Files: C:\Program Files


# COMMON PIPELINE EXAMPLES

# Filter running services
Get-Service | Where-Object {$_.Status -eq "Running"}

# Sort processes by memory usage (top 10)
Get-Process | Sort-Object WorkingSet -Descending | Select-Object -First 10

# Export process list to CSV
Get-Process | Select-Object Name, CPU, Id | Export-Csv -Path processes.csv -NoTypeInformation

# Search recursively for .log files and export results
Get-ChildItem -Recurse -Filter "*.log" | Select-Object FullName, Length | Export-Csv logs.csv -NoTypeInformation

# Count lines with "Error" across text files
Get-ChildItem -Recurse -Filter "*.txt" | Select-String "Error" | Measure-Object

# Display event logs with "network" keyword
Get-EventLog -LogName System | Where-Object {$_.Message -like "*network*"} | Select-Object -First 5


# ADMINISTRATIVE & SYSTEM MANAGEMENT COMMANDS

# Manage services
Start-Service -Name "Spooler"
Stop-Service -Name "Spooler"
Restart-Service -Name "Spooler"

# Manage user accounts
Get-LocalUser
New-LocalUser -Name "NewUser" -NoPassword
Add-LocalGroupMember -Group "Administrators" -Member "NewUser"

# Manage scheduled tasks
Get-ScheduledTask
Register-ScheduledTask -TaskName "Backup" -Action (New-ScheduledTaskAction -Execute "notepad.exe")

# Modify registry entries
Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
Set-ItemProperty "HKCU:\Software\MyApp" "Setting" "Enabled"

# System information
Get-ComputerInfo
Get-WmiObject Win32_OperatingSystem | Select-Object CSName, Caption, OSArchitecture

# Manage Windows Updates (requires PSWindowsUpdate)
Get-WindowsUpdate
Install-WindowsUpdate -AcceptAll -AutoReboot

# Disk and storage management
Get-Volume
Get-Disk
Get-Partition

# Reboot or shutdown system
Restart-Computer -Force
Stop-Computer -Force


# SECURITY, PERMISSIONS & EVENT LOG MANAGEMENT

# View current user and admin group members
whoami
Get-LocalGroupMember "Administrators"

# Manage file/folder permissions (ACLs)
Get-Acl "C:\FolderName"
Set-Acl "C:\FolderName" (Get-Acl "C:\TemplateFolder")

# Check or change execution policy
Get-ExecutionPolicy
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser

# Audit and monitor security logs
Get-EventLog -LogName Security -Newest 10
Get-WinEvent -LogName Security | Where-Object {$_.Id -eq 4625}

# View and manage firewall rules
Get-NetFirewallRule | Select-Object Name, Enabled, Direction, Action
New-NetFirewallRule -DisplayName "AllowSSH" -Direction Inbound -Protocol TCP -LocalPort 22 -Action Allow
Remove-NetFirewallRule -DisplayName "AllowSSH"

# Manage user privileges and accounts
Get-LocalUser
Disable-LocalUser -Name "Guest"
Enable-LocalUser -Name "Administrator"

# Encrypt and decrypt files
cipher /e "C:\SensitiveData"
cipher /d "C:\SensitiveData"

# Monitor PowerShell session logs
Start-Transcript -Path "C:\Logs\session_log.txt"
Stop-Transcript


# ALTERNATE DATA STREAMS (ADS) & HIDDEN FILES

# List all streams on a file
Get-Item -Path .\example.txt -Stream *

# Show content of Zone.Identifier
Get-Content -Path .\example.txt -Stream Zone.Identifier

# Create/append/remove a custom ADS
Set-Content -Path .\example.txt -Stream notes -Value "Secret note in ADS"
Add-Content -Path .\example.txt -Stream notes -Value " (appended)"
Remove-Item -Path .\example.txt -Stream notes

# Quickly list streams via CMD
cmd /c "dir /r .\example.txt"

# Unblock downloaded file (remove Zone.Identifier)
Unblock-File -Path .\installer.ps1

# Copy preserving metadata (ADS preservation recommended via robocopy)
robocopy . . example.txt /COPYALL /R:0 /W:0

# Show hidden items and find hidden/system recursively
Get-ChildItem -Force
Get-ChildItem -Recurse -Force | Where-Object { $_.Attributes -match 'Hidden|System' }

# Only hidden
Get-ChildItem -Attributes Hidden -Force -Recurse

# Set/Clear Hidden and System flags
attrib +h +s "C:\path\to\file.txt"
attrib -h -s "C:\path\to\file.txt"

# Toggle Hidden attribute via .NET flags
$item = Get-Item "C:\path\to\file.txt"
$item.Attributes = $item.Attributes -bor [IO.FileAttributes]::Hidden
$item.Attributes = $item.Attributes -band (-bnot [IO.FileAttributes]::Hidden)

# Quick triage for files having ADS (more than default stream)
Get-ChildItem -Recurse -File | ForEach-Object {
  $s = Get-Item -LiteralPath $_.FullName -Stream * 2>$null
  if ($s.Count > 1) { $_.FullName }
}

# Dump Zone.Identifier for downloaded PS1 files
Get-ChildItem "$env:USERPROFILE\Downloads" -Filter *.ps1 | ForEach-Object {
  if (Get-Item $_ -Stream Zone.Identifier -ErrorAction SilentlyContinue) {
    "{0}`n{1}`n" -f $_.FullName, (Get-Content $_ -Stream Zone.Identifier -ErrorAction SilentlyContinue -Raw)
  }
}


# FORENSIC CHECKLIST — ADS & HIDDEN FILES

# Enumerate all Alternate Data Streams and export
Get-ChildItem -Path C:\ -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object {
  $streams = Get-Item -LiteralPath $_.FullName -Stream * -ErrorAction SilentlyContinue
  if ($streams.Count -gt 1) {
    [PSCustomObject]@{File=$_.FullName; Streams=$streams.Stream}
  }
} | Export-Csv C:\Forensic\ADS_Report.csv -NoTypeInformation

# Identify Hidden or System files
Get-ChildItem -Path C:\ -Force -Recurse -ErrorAction SilentlyContinue |
Where-Object { $_.Attributes -match 'Hidden|System' } |
Select-Object FullName, Attributes |
Export-Csv C:\Forensic\HiddenFiles.csv -NoTypeInformation

# Collect file hashes for integrity
Get-ChildItem -Path "C:\Forensic\Samples" -File -Recurse |
Get-FileHash -Algorithm SHA256 |
Export-Csv "C:\Forensic\Hashes.csv" -NoTypeInformation

# Preserve NTFS metadata and streams with robocopy
robocopy "C:\Evidence" "D:\Archive" /COPYALL /E /R:0 /W:0 /LOG:"C:\Forensic\robocopy.log"

# Check Zone.Identifier ADS tags
Get-ChildItem -Recurse -Filter *.exe | ForEach-Object {
  if (Get-Item $_ -Stream Zone.Identifier -ErrorAction SilentlyContinue) {
    "$($_.FullName) contains Zone.Identifier"
  }
}

# Extract file metadata for timeline analysis
Get-ChildItem -Recurse -File |
Select-Object FullName, CreationTime, LastWriteTime, LastAccessTime |
Export-Csv "C:\Forensic\Timeline.csv" -NoTypeInformation
