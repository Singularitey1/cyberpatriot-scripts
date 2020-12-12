@echo off
color 0A
:-------------------------------------
:: Check for permissions
>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"

:: If error flag set, we do not have admin.
if '%errorlevel%' NEQ '0' (
    echo Requesting administrative privileges...
    goto UACPrompt
) else ( goto gotAdmin )

:UACPrompt
    echo Set UAC = CreateObject^("Shell.Application"^) > "%temp%\getadmin.vbs"
    set params = %*:"=""
    echo UAC.ShellExecute "cmd.exe", "/c %~s0 %params%", "", "runas", 1 >> "%temp%\getadmin.vbs"

    "%temp%\getadmin.vbs"
    del "%temp%\getadmin.vbs"
    exit /B

:gotAdmin
    pushd "%CD%"
    CD /D "%~dp0"
:--------------------------------------

:: ---------------------------------------------------------Windows 10---------------------------------------------------------

:: -------------------------------------------------Local Security Policy-------------------------------------------------

:: --------------------Password and Logon Policy--------------------

echo Updating Password Policy

net accounts /uniquepw:5
net accounts /minpwlen:14
net accounts /maxpwage:90
net accounts /minpwage:10

echo Exporting and updating Password Security Policy settings...

echo Password Complexity
secedit.exe /export /cfg C:\secconfig.cfg
powershell -ExecutionPolicy Bypass -Command "(gc C:\secconfig.cfg) -replace 'PasswordComplexity = 0', 'PasswordComplexity = 1' | Out-File -encoding ASCII C:\secconfigupdated.cfg"
echo Importing Updated Password Security Policy Settings, Will be Deleted...
secedit.exe /configure /db %windir%\securitynew.sdb /cfg C:\secconfigupdated.cfg /areas SECURITYPOLICY
echo Import successful...
del c:\secconfig.cfg
del c:\secconfigupdated.cfg

echo Password Stored Using Reversible Encryption
secedit.exe /export /cfg C:\secconfig.cfg
powershell -ExecutionPolicy Bypass -Command "(gc C:\secconfig.cfg) -replace 'ClearTextPassword = 1', 'ClearTextPassword = 0' | Out-File -encoding ASCII C:\secconfigupdated.cfg"
echo Importing Updated Password Security Policy Settings, Will be Deleted...
secedit.exe /configure /db %windir%\securitynew.sdb /cfg C:\secconfigupdated.cfg /areas SECURITYPOLICY
echo Import successful...
del c:\secconfig.cfg
del c:\secconfigupdated.cfg

echo Don't Display Last Username
secedit.exe /export /cfg C:\secconfig.cfg
powershell -ExecutionPolicy Bypass -Command "(gc C:\secconfig.cfg) -replace 'DontDisplayLastUserName=4,0', 'DontDisplayLastUserName=4,1' | Out-File -encoding ASCII C:\secconfigupdated.cfg"
echo Importing Updated Password Security Policy Settings, Will be Deleted...
secedit.exe /configure /db %windir%\securitynew.sdb /cfg C:\secconfigupdated.cfg /areas SECURITYPOLICY
echo Import successful...
del c:\secconfig.cfg
del c:\secconfigupdated.cfg

echo Limit Blank Password Use to Console Only
secedit.exe /export /cfg C:\secconfig.cfg
powershell -ExecutionPolicy Bypass -Command "(gc C:\secconfig.cfg) -replace 'LimitBlankPasswordUse=4,0', 'LimitBlankPasswordUse=4,1' | Out-File -encoding ASCII C:\secconfigupdated.cfg"
echo Importing Updated Password Security Policy Settings, Will be Deleted...
secedit.exe /configure /db %windir%\securitynew.sdb /cfg C:\secconfigupdated.cfg /areas SECURITYPOLICY
echo Import successful...
del c:\secconfig.cfg
del c:\secconfigupdated.cfg

echo Password Security Policy updates completed...

:: --------------------Lockout Policy--------------------

echo Updating Account Lockout Policy
net accounts /lockoutduration:30
net accounts /lockoutthreshold:5
net accounts /lockoutwindow:30

:: --------------------Audit Policy--------------------

echo Updating Audit Policies...
Auditpol /set /category:"Account Logon" /success:enable /failure:enable
Auditpol /set /category:"Account Management" /success:enable /failure:enable
Auditpol /set /category:"Detailed Tracking" /success:enable /failure:enable
Auditpol /set /category:"DS Access" /success:enable /failure:enable
Auditpol /set /category:"Logon/Logoff" /Success:enable /failure:enable
Auditpol /set /category:"Object Access" /success:enable /failure:enable
Auditpol /set /category:"Policy Change" /success:enable /failure:enable
Auditpol /set /category:"Privilege Use" /success:enable /failure:enable
Auditpol /set /category:"System" /success:enable /failure:enable

:: --------------------Firewall Policy--------------------

echo Configuring Firewall
netsh advfirewall set allprofiles state on

::--------------------Security Policy--------------------

Rem echo Disabling Interactive Logon: Do not require ctrl+alt+delete
Rem reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DisableCAD /t REG_DWORD /d 0 /f

:: -------------------------------------------------lusrmgr Settings-------------------------------------------------

:: --------------------Default Accounts--------------------

echo Updating Default Accounts
net user guest /active:no
wmic useraccount where name='Guest' rename 'TestTwo'
net user Administrator /active:no
wmic useraccount where name='Administrator' rename 'TestOne'

:: --------------------User Settings--------------------

choice /m "Change All User Passwords?"
if Errorlevel 2 goto NoChangePassword1
if Errorlevel 1 goto YesChangePassword1
:NoChangePassword1
goto EndChangePassword1
:YesChangePassword1
FOR /F %%F IN ('wmic useraccount get name') DO (Echo "%%F" | FIND /I "Name" 1>NUL) || (Echo "%%F" | FIND /I "DefaultAccount" 1>NUL) || (NET USER %%F T3amH@ck3r0ne!!)
echo Changed all passwords to "T3amH@ck3r0ne!!". Write it down.
:EndChangePassword1

choice /m "Do you want to delete a user?"
if Errorlevel 2 goto NoDeleteUser
if Errorlevel 1 goto YesDeleteUser
:YesDeleteUser
wmic useraccount get name
echo Below the word Name are all the users on the computer.
echo Type all the users you want to delete, and check which users to delete by comparing it with the readme. 
echo Type the usernames exactly as they appear in the list.
echo Check the forensics questions or anything else to make sure they did not have anything you needed.
goto :userCode
:YesDeleteAnotherUser
wmic useraccount get name
echo Below the word Name is an updated list of the users.
:userCode
set /p User=Enter Username:
net user %User% /delete
choice /m "Do you want to delete another user?"
if Errorlevel 2 goto NoDeleteAnotherUser
if Errorlevel 1 goto YesDeleteAnotherUser
:NoDeleteAnotherUser
:NoDeleteUser

:: -------------------------------------------------Services-------------------------------------------------

echo Updating Services

choice /m "Start Sense service (computer most likely doesn't have it)?"
if Errorlevel 2 goto NoStartSense
if Errorlevel 1 goto YesStartSense
:YesStartSense
sc config Sense start=auto
sc start Sense
:NoStartSense

choice /m "Disable Telnet service (if Telnet isn't installed then the computer doesn't have this service)?"
if Errorlevel 2 goto NoDisableTelnetService
if Errorlevel 1 goto YesDisableTelnetService
:YesDisableTelnetService
sc config tlntsvr start=disabled
net stop tlntsvr
:NoDisableTelnetService

sc config eventlog start=auto
net start eventlog

net stop TermService
sc config "TermService" start=disabled

net stop RemoteRegistry
sc config "RemoteRegistry" start=disabled

sc stop UmRdpService
sc config "UmRdpService" start= disabled

sc config WinDefend start=auto
net start WinDefend

reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v AUOptions /t REG_DWORD /d 0 /f
sc config wuauserv start=auto
net start wuauserv

:: -------------------------------------------------Other Settings-------------------------------------------------

REM echo Deleting Certain Media Files
REM echo It gives you the folder path and name of the file.
REM echo Do not delete them if you need them for something else, like a forensics question.
REM echo Do not delete anything that looks like it is part of the system.
REM echo You need to disable controlled folder access if you have it for this to work, but then reenable it after.
REM del "C:\Users\*.mp3" /s /p /a:-s
REM del "C:\Users\*.mp4" /s /p /a:-s
REM del "C:\Users\*.mov" /s /p /a:-s
REM del "C:\Users\*.txt" /s /p /a:-s
REM del "C:\Users\*.exe" /s /p /a:-s

echo Disable Sharing
net share C:\ /delete

echo Cleaning Host File
copy %WinDir%\System32\drivers\etc\hosts %WinDir%\System32\drivers\etc\hosts.old
break > %WinDir%\System32\drivers\etc\hosts

echo Disabling Certain Features
echo Disabling Telnet Client
DISM /online /disable-feature /featurename:TelnetClient
echo Disabling TFTP
DISM /online /disable-feature /featurename:TFTP
echo Disabling SMBv1
powershell -ExecutionPolicy Bypass -Command "Disable-WindowsOptionalFeature -Online -FeatureName smb1protocol"

choice /m "Disable SNMP feature (might not be there)?"
if Errorlevel 2 goto NoDisableSNMP
if Errorlevel 1 goto YesDisableSNMP
:YesDisableSNMP
echo Disabling SNMP
DISM /online /disable-feature /featurename:SNMP
:NoDisableSNMP

echo Blocking All Microsoft Accounts
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v NoConnectedUser /t REG_DWORD /d 3 /f

echo Disabling Remote Assistance
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Remote Assistance" /v fAllowToGetHelp /t REG_DWORD /d 0 /f
netsh advfirewall firewall set rule group="Remote Assistance" new enable=no

choice /m "Enable DEP for everything, you would need to restart (Recommended)?"
if Errorlevel 2 goto NoDEP
if Errorlevel 1 goto YesDEP
:YesDEP
echo Enabling DEP Protection
bcdedit.exe /set {current} nx AlwaysOn
goto EndDEP
:NoDEP
bcdedit.exe /set {current} nx optin
:EndDEP

Rem echo Enabling User Account Control
Rem C:\Windows\System32\cmd.exe /k %windir%\System32\reg.exe ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 1 /f

echo Obtaining DNS Server Address Automatically Enabled
netsh interface ipv4 set dnsservers name="Ethernet" source=dhcp













:: -------------------------------------------------Windows Settings-------------------------------------------------

choice /m "Update Windows?"
if Errorlevel 2 goto NoUpdateWindows
if Errorlevel 1 goto YesUpdateWindows
:NoUpdateWindows
goto EndUpdateWindows
:YesUpdateWindows
start ms-settings:
:EndUpdateWindows

:: ---------------------------------------------------------End of Batch Script---------------------------------------------------------

echo Script has finished. Restart may be necesary to see all changes. Check settings because the script isn't perfect.

pause
