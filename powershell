Set-MpPreference -EnableControlledFolderAccess Enabled
Set-MpPreference -DisableRealtimeMonitoring $false


# Silent Install MalwareBytes
# Download URL: https://www.malwarebytes.com/mwb-download/thankyou/

# Path for the workdir
$workdir = "c:\installer\"

# Check if work directory exists if not create it

If (Test-Path -Path $workdir -PathType Container)
{ Write-Host "$workdir already exists" -ForegroundColor Red}
ELSE
{ New-Item -Path $workdir  -ItemType directory }

# Download the installer

$source = "https://downloads.malwarebytes.com/file/mb3"
$destination = "$workdir\mbam.exe"
Invoke-WebRequest $source -OutFile $destination

# Start the installation

Start-Process -FilePath "$workdir\mbam.exe" -ArgumentList "/NOCANCEL /NORESTART /VERYSILENT /SUPPRESSMSGBOXES"

# Wait XX Seconds for the installation to finish

Start-Sleep -s 35

# Remove the installer

rm -Force $workdir\mbam*
