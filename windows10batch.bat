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

choice /m "Check secpol settings (go thru checklist)? Check to see what is enabled and disabled before you change anything"
if Errorlevel 2 goto NoSecpol
if Errorlevel 1 goto YesSecpol
:NoSecpol
goto EndSecpol
:YesSecpol
secpol.msc
:EndSecpol

:: -------------------------------------------------lusrmgr Settings-------------------------------------------------

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
echo Below the word Name are all the users on the computer. Don't delete administrator or guest
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

FOR /F %%F IN ('wmic useraccount get name') DO (Echo "%%F" | FIND /I "Name" 1>NUL) || (Echo "%%F" | FIND /I "DefaultAccount" 1>NUL) || (net user %%F /PasswordChg:Yes)
FOR /F %%F IN ('wmic useraccount get name') DO (Echo "%%F" | FIND /I "Name" 1>NUL) || (Echo "%%F" | FIND /I "DefaultAccount" 1>NUL) || (WMIC USERACCOUNT WHERE Name='%%F' SET PasswordExpires=TRUE)
FOR /F %%F IN ('wmic useraccount get name') DO (Echo "%%F" | FIND /I "Name" 1>NUL) || (Echo "%%F" | FIND /I "DefaultAccount" 1>NUL) || (Echo "%%F" | FIND /I "Administrator" 1>NUL) || (Echo "%%F" | FIND /I "Guest" 1>NUL) || (Net user %%F /active:yes)

choice /m "Finish sorting users into groups? Read the readme to check which users are administrators and users"
if Errorlevel 2 goto NoLusrmgr
if Errorlevel 1 goto YesLusrmgr
:NoLusrmgr
goto EndLusrmgr
:YesLusrmgr
lusrmgr.msc
:EndLusrmgr

:: --------------------Default Accounts--------------------

echo Updating Default Accounts
net user guest /active:no
wmic useraccount where name='Guest' rename 'TestTwo'
net user Administrator /active:no
wmic useraccount where name='Administrator' rename 'TestOne'

:: -------------------------------------------------Services-------------------------------------------------

echo Updating Services

sc config Sense start=auto
sc start Sense
sc config tlntsvr start=disabled
net stop tlntsvr
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
sc stop BTAGService
sc stop bthserv
sc config BTAGService start= disabled
sc config bthserv start= disabled
sc stop MapsBroker
sc config MapsBroker start= disabled
sc stop lfsvc
sc config lfsvc start= disabled
sc stop IISADMIN
sc config IISADMIN start= disabled
sc stop irmon
sc config irmon start= disabled
sc stop SharedAccess
sc config "SharedAccess" start= disabled
sc stop lltdsvc
sc config lltdsvc start= disabled
sc stop LxssManager
sc config LxssManager start= disabled
sc stop FTPSVC
sc config FTPSVC start= disabled
sc stop MSiSCSI
sc config MSiSCSI start= disabled
sc stop InstallService
sc config InstallService start= disabled
sc stop sshd
sc config sshd start= disabled
sc stop PNRPsvc
sc config PNRPsvc start= disabled
sc stop p2psvc
sc config p2psvc start= disabled
sc stop p2pimsvc
sc config p2pimsvc start= disabled
sc stop PNRPAutoReg
sc config PNRPAutoReg start= disabled
sc stop wercplsupport
sc config wercplsupport start= disabled
sc stop RasAuto
sc config RasAuto start= disabled
sc stop SessionEnv
sc config SessionEnv start= disabled
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1 /f
sc stop RpcLocator
sc config RpcLocator start= disabled
sc stop RemoteAccess
sc config RemoteAccess start= disabled
sc stop LanmanServer
sc config LanmanServer start= disabled
sc stop simptcp
sc config simptcp start= disabled
sc stop SNMP
sc config SNMP start= disabled
sc stop SSDPSRV
sc config "SSDPSRV" start= disabled
sc stop upnphost
sc config "upnphost" start= disabled
sc stop WMSvc
sc config WMSvc start= disabled
sc stop WerSvc
sc config WerSvc start= disabled
sc stop Wecsvc
sc config Wecsvc start= disabled
sc stop WMPNetworkSvc
sc config WMPNetworkSvc start= disabled
sc stop icssvc
sc config icssvc start= disabled
sc stop WpnService
sc config WpnService start= disabled
sc stop PushToInstall
sc config PushToInstall start= disabled
sc stop WinRM
sc config WinRM start= disabled
sc stop XboxGipSvc
sc config XboxGipSvc start= disabled
sc stop XblAuthManager
sc config XblAuthManager start= disabled
sc stop XblGameSave
sc config XblGameSave start= disabled
sc stop XboxNetApiSvc
sc config XboxNetApiSvc start= disabled
sc stop Spooler
sc config Spooler start= disabled
sc stop NetTcpPortSharing
sc config NetTcpPortSharing start= disabled
sc stop WebClient
sc config WebClient start= disabled

:: -------------------------------------------------Other Settings-------------------------------------------------

echo Look for media files or suspicious files, make sure they aren't required for forensics or readme (search these in c: drive: *.exe, *.mp3, *.mp4, *.mov, *.txt, *.csv, *.zip, *.png, *.jpg, *.jpeg, *.pdf, *.bat, *.ps1)
pause

echo Disable Sharing
net share C:\ /delete
choice /m "Finish looking at shares? Check each share and make sure it's good if you don't want to remove it. If you don't know then remove it"
if Errorlevel 2 goto NoShares
if Errorlevel 1 goto YesShares
:NoShares
goto EndShares
:YesShares
compmgmt.msc
:EndShares

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
echo Disabling SNMP
DISM /online /disable-feature /featurename:SNMP

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

echo Enabling User Account Control
C:\Windows\System32\cmd.exe /k %windir%\System32\reg.exe ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 1 /f

echo Obtaining DNS Server Address Automatically Enabled
netsh interface ipv4 set dnsservers name="Ethernet" source=dhcp

:: -------------------------------------------------Windows Settings-------------------------------------------------

choice /m "Update Windows (Recommend doing it early)?"
if Errorlevel 2 goto NoUpdateWindows
if Errorlevel 1 goto YesUpdateWindows
:NoUpdateWindows
goto EndUpdateWindows
:YesUpdateWindows
ms-settings:windowsupdate
start ms-settings:
:EndUpdateWindows

:: ---------------------------------------------------------End of Batch Script---------------------------------------------------------

echo Script has finished. Restart may be necesary to see all changes. Check settings because the script isn't perfect.

pause
