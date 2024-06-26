# Start as an administrator
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "Copying script to temp folder and running..."
    if (!(Test-Path -Path "$($env:TEMP)\psScripts.tmp\")) { New-Item "$($env:TEMP)\psScripts.tmp\" -Type Directory }
    $ScriptName = Split-Path -Path $PSCommandPath -Leaf
    Copy-Item -Path $PSCommandPath -Destination "$($env:TEMP)\psScripts.tmp\$($ScriptName)" -Force
    Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$($env:TEMP)\psScripts.tmp\$($ScriptName)`"" -Verb RunAs; exit
}
Clear-Host
Write-Host ""
Write-Host "Matt's OOBE Script - AtlasOS Edition" -ForegroundColor Blue
Write-Host "====================" -ForegroundColor Blue
Write-Host ""

Write-Host "Installing VirtIO guest utils..."
# find virtio.exe in either the D: or E: drive.
$virtioPath = Get-ChildItem -Path D:\ -Recurse -Filter "virtio-win-guest-tools.exe" -ErrorAction SilentlyContinue
if ($null -eq $virtioPath) {
    $virtioPath = Get-ChildItem -Path E:\ -Recurse -Filter "virtio-win-guest-tools.exe" -ErrorAction SilentlyContinue
}
if ($null -eq $virtioPath) {
    Write-Host "VirtIO ISO not found. Please install manually." -ForegroundColor Red
} else {
    Start-Process -FilePath $virtioPath.FullName -ArgumentList "/quiet /norestart" -Wait
}

Write-Host "Enabling Remote Desktop connections..."
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -Value 0
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"

Write-Host "Disabling sleep..."
Powercfg /Change monitor-timeout-ac 0
Powercfg /Change monitor-timeout-dc 0
Powercfg /Change standby-timeout-ac 0
Powercfg /Change standby-timeout-dc 0

Write-Host "Setting the VNC resolution to 1920x1080..."
Install-PackageProvider -Name NuGet -Force -MinimumVersion 2.8.5.201 | Out-Null
Set-PSRepository -Name PSGallery -InstallationPolicy Trusted | Out-Null
Install-Module -Name ChangeScreenResolution -Scope CurrentUser -Force | Out-Null
Import-Module ChangeScreenResolution
Set-ScreenResolution -Width 1920 -Height 1080

Write-Host "Removing OneDrive and Edge..."
Start-Process "$env:windir\System32\OneDriveSetup.exe" "/uninstall" -ErrorAction SilentlyContinue
(New-Object System.Net.WebClient).DownloadFile("https://github.com/ShadowWhisperer/Remove-MS-Edge/blob/main/Remove-EdgeOnly.exe?raw=true", "$env:TEMP\Remove-EdgeOnly.exe")
Start-Process -FilePath "$env:TEMP\Remove-EdgeOnly.exe" -Wait
Remove-Item -Path "$env:appdata\Microsoft\Windows\Start Menu\Programs\Microsoft Edge.lnk" -Force -ErrorAction SilentlyContinue

Write-Host "Removing some more bloat..."
Get-AppxPackage -AllUsers *zune* | Remove-AppxPackage -AllUsers
Get-AppxPackage -AllUsers *assist* | Remove-AppxPackage -AllUsers
Get-AppxPackage -AllUsers *YourPhone* | Remove-AppxPackage -AllUsers

Write-Host "Grabbing the Microsoft Activation Script and activating..."
& ([ScriptBlock]::Create((Invoke-RestMethod https://get.activated.win))) /HWID

Write-Host "Upgrading winget and fixing package sources..."
Add-AppPackage -path "https://cdn.winget.microsoft.com/cache/source.msix."
winget source reset --force
winget upgrade winget --silent --accept-source-agreements --accept-package-agreements --force

Write-Host "Setting winget to use the wininet downloader..."
$jsonContent = @"
{
    "network": {
        "downloader": "wininet"
    }
}
"@
$jsonContent | Set-Content -Path "$env:LOCALAPPDATA\Packages\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe\LocalState\settings.json" -Force

Write-Host "Installing default programs with winget..."
winget install LibreWolf.LibreWolf VideoLAN.VLC 9PF4KZ2VN4W9 --silent --accept-source-agreements --accept-package-agreements --force

Write-Host "Setting LibreWolf as the default browser..."
Start-Process "$env:programfiles\LibreWolf\librewolf.exe" "-setDefaultBrowser"

Write-Host "Opening TranslucentTB for auto-start..."
$familyName = (Get-AppxPackage *TranslucentTB*).PackageFamilyName
Start-Process explorer.exe "shell:appsFolder\$familyName!TranslucentTB"

Write-Host "Completed automatic setup." -ForegroundColor Green
Write-Host ""
Write-Host "====================" -ForegroundColor Yellow
Write-Host "User Configuration" -ForegroundColor Yellow
Write-Host "====================" -ForegroundColor Yellow
Write-Host ""
$computerName = Read-Host -Prompt "What should the computer name be?"
Write-Host "Renaming computer to $computerName..."
Rename-Computer -NewName $computerName -Force | Out-Null
Write-Host "Done."

$autologinyn = Read-Host -Prompt "Should I permanently enable auto-login for you? (y/n)"
if ($autologinyn -eq "y") {
    Write-Host "Enabling auto-login..."
    $username = Read-Host -Prompt "What is the username?"
    $password = Read-Host -Prompt "What is the password?" -AsSecureString
    $password = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($password))
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name AutoAdminLogon -Value 1
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name DefaultUserName -Value $username
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name DefaultPassword -Value $password
    Write-Host "Done."
}

$novaconnectyn = Read-Host -Prompt "Should I map Nova to N: for you? (y/n)"
if ($novaconnectyn -eq "y") {
    net use N: \\nova.box\Storage /user:nova nova /persistent:yes
    Write-Host "Done."
}

Write-Host ""
Write-Host "====================" -ForegroundColor Yellow
Write-Host "Initialise for AtlasOS Install" -ForegroundColor Yellow
Write-Host "====================" -ForegroundColor Yellow
Write-Host ""
Write-Host ""

Write-Host "Removing Powershell NuGet provider and DisplaySettings module..."
(Get-PackageProvider NuGet).ProviderPath | Remove-Item -Force -ErrorAction SilentlyContinue
Remove-Item -Path "$env:ProgramFiles\PackageManagement\ProviderAssemblies\nuget\*" -Force -Recurse -ErrorAction SilentlyContinue
Set-PSRepository -Name PSGallery -InstallationPolicy Untrusted
Remove-Module ChangeScreenResolution -Force
Remove-Item -Path "$env:USERPROFILE\Documents\WindowsPowerShell" -Force -Recurse -ErrorAction SilentlyContinue

Write-Host "Removing temporary files..."
Remove-Item -Path "$env:TEMP\*" -Force -Recurse -ErrorAction SilentlyContinue

Write-Host "Removing default scheduled task..."
Get-ScheduledTask -TaskName MattOOBE | Unregister-ScheduledTask -Confirm:$false

Write-Host "Cleaning both public and user desktops..."
Remove-Item -Path "$env:public\Desktop\*" -Force -Recurse
Remove-Item -Path "$env:USERPROFILE\Desktop\*" -Force -Recurse

Write-Host "Rebooting..." -ForegroundColor Red
Start-Sleep -Seconds 5
Restart-Computer -Force
