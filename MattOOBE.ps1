# Start as an administrator
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "Copying script to temp folder and running..."
    if (!(Test-Path -Path "$($env:TEMP)\psScripts.tmp\")) { New-Item "$($env:TEMP)\psScripts.tmp\" -Type Directory }
    $ScriptName = Split-Path -Path $PSCommandPath -Leaf
    Copy-Item -Path $PSCommandPath -Destination "$($env:TEMP)\psScripts.tmp\$($ScriptName)" -Force
    Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$($env:TEMP)\psScripts.tmp\$($ScriptName)`"" -Verb RunAs; exit
}

Write-Host "MATT'S OOBE SCRIPT" -ForegroundColor Blue
Write-Host "====================" -ForegroundColor Blue
Write-Host ""

Write-Host "Installing VirtIO guest utils..."
# find virtio.exe in either the D: or E: drive.
$virtioPath = Get-ChildItem -Path D:\ -Recurse -Filter "virtio-win-guest-tools.exe" -ErrorAction SilentlyContinue
if ($null -eq $virtioPath) {
    $virtioPath = Get-ChildItem -Path E:\ -Recurse -Filter "virtio-win-guest-tools.exe" -ErrorAction SilentlyContinue
}
if ($null -eq $virtioPath) {
    Write-Host "VirtIO ISO not found. Please install manually."
} else {
    Start-Process -FilePath $virtioPath.FullName -ArgumentList "/quiet /norestart" -Wait
}

Write-Host "Done." -ForegroundColor Green
Write-Host ""

Write-Host "Setting the VNC resolution to 1920x1080..."
Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
Install-Module -Name DisplaySettings -Scope CurrentUser -Force
Import-Module DisplaySettings
Set-DisplayResolution -Width 1920 -Height 1080

Write-Host "Grabbing the Microsoft Activation Script and activating..."
& ([ScriptBlock]::Create((Invoke-RestMethod https://massgrave.dev/get))) /HWID

Write-Host "Removing OneDrive and Edge..."
Start-Process "$env:windir\System32\OneDriveSetup.exe" "/uninstall"
$WebFile = "https://github.com/ShadowWhisperer/Remove-MS-Edge/blob/main/Remove-EdgeOnly.exe?raw=true"
(New-Object System.Net.WebClient).DownloadFile($WebFile, "$env:TEMP\Remove.EdgeOnly.exe")
Start-Process -FilePath "$env:temp\Remove-EdgeOnly.exe" -Wait

Write-Host "Installing default programs..."
winget install LibreWolf.LibreWolf 7zip.7zip VideoLAN.VLC 9PF4KZ2VN4W9 9MSMLRH6LZF3 --silent --accept-source-agreements --accept-package-agreements --force

Write-Host "Setting LibreWolf as the default browser..."
Start-Process "$env:programfiles\LibreWolf\librewolf.exe" "-setDefaultBrowser"

Write-Host "Completed automatic setup." -ForegroundColor Green
Write-Host ""
Write-Host "====================" -ForegroundColor Yellow
Write-Host "CONFIGURATION" -ForegroundColor Yellow
Write-Host "====================" -ForegroundColor Yellow
Write-Host ""
$computerName = Read-Host -Prompt "What should the computer name be?"
Write-Host "Renaming computer to $computerName..."
Rename-Computer -NewName $computerName -Force
Write-Host "Done."

$autologinyn = Read-Host -Prompt "Should I enable autologon for you? (y/n)"
if ($autologinyn -eq "y") {
    Write-Host "Enabling autologon..."
    $username = Read-Host -Prompt "What is the username?"
    $password = Read-Host -Prompt "What is the password?" -AsSecureString
    $password = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($password))
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name AutoAdminLogon -Value 1
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name DefaultUserName -Value $username
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name DefaultPassword -Value $password
    Write-Host "Done."
}

Write-Host "Cleaning both public and user desktops..."
Remove-Item -Path "$env:public\Desktop\*" -Force -Recurse
Remove-Item -Path "$env:USERPROFILE\Desktop\*" -Force -Recurse
Write-Host "Done."

Write-Host "Rebooting..." -ForegroundColor Red
Start-Sleep -Seconds 3
Restart-Computer -Force
