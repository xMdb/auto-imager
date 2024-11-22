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
Write-Host "Matt's OOBE Script for Windows 11 Enterprise IoT LTSC" -ForegroundColor Blue
Write-Host "====================" -ForegroundColor Blue
Write-Host ""

Write-Host "Installing all VirtIO w11 drivers..."
# find virtio.exe in either the D: or E: drive.
$virtioPath = Get-ChildItem -Path D:\ -Recurse -Filter "virtio-win-gt-x64.msi" -ErrorAction SilentlyContinue
if ($null -eq $virtioPath) {
    $virtioPath = Get-ChildItem -Path E:\ -Recurse -Filter "virtio-win-gt-x64.msi" -ErrorAction SilentlyContinue
}
if ($null -eq $virtioPath) {
    Write-Host "VirtIO ISO not found. Please install manually." -ForegroundColor Red
} else {
    Start-Process -FilePath msiexec.exe -ArgumentList "/i $($virtioPath.FullName) /quiet /norestart" -Wait
}

Write-Host "Installing VirtIO guest utils..."
# find virtio.exe in either the D: or E: drive.
$virtioGPath = Get-ChildItem -Path D:\ -Recurse -Filter "virtio-win-guest-tools.exe" -ErrorAction SilentlyContinue
if ($null -eq $virtioGPath) {
    $virtioGPath = Get-ChildItem -Path E:\ -Recurse -Filter "virtio-win-guest-tools.exe" -ErrorAction SilentlyContinue
}
if ($null -eq $virtioGPath) {
    Write-Host "VirtIO ISO not found. Please install manually." -ForegroundColor Red
} else {
    Start-Process -FilePath $virtioGPath.FullName -ArgumentList "/quiet /norestart" -Wait
}

Write-Host "Grabbing the Microsoft Activation Script and activating..."
& ([ScriptBlock]::Create((Invoke-RestMethod https://get.activated.win))) /HWID

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
(New-Object System.Net.WebClient).DownloadFile("https://github.com/ShadowWhisperer/Remove-MS-Edge/blob/main/Remove-Edge.exe?raw=true", "$env:TEMP\Remove-EdgeOnly.exe")
Start-Process -FilePath "$env:TEMP\Remove-EdgeOnly.exe" -Wait
Remove-Item -Path "$env:appdata\Microsoft\Windows\Start Menu\Programs\Microsoft Edge.lnk" -Force -ErrorAction SilentlyContinue

Write-Host "Setting up the Microsoft Store..."
wsreset -i

Write-Host "Installing the latest version of winget and its dependencies..."
$ProgressPreference = 'SilentlyContinue'
# thanks https://github.com/ChrisTitusTech/winutil/
$versionVCLibs = "14.00"
$fileVCLibs = "https://aka.ms/Microsoft.VCLibs.x64.${versionVCLibs}.Desktop.appx"
$versionUIXamlMinor = "2.8"
$versionUIXamlPatch = "2.8.6"
$fileUIXaml = "https://github.com/microsoft/microsoft-ui-xaml/releases/download/v${versionUIXamlPatch}/Microsoft.UI.Xaml.${versionUIXamlMinor}.x64.appx"
Invoke-WebRequest -Uri $fileVCLibs -OutFile $ENV:TEMP\Microsoft.VCLibs.x64.Desktop.appx
Invoke-WebRequest -Uri $fileUIXaml -OutFile $ENV:TEMP\Microsoft.UI.Xaml.x64.appx
$response = Invoke-RestMethod -Uri "https://api.github.com/repos/microsoft/Winget-cli/releases/latest" -Method Get -ErrorAction Stop
$latestVersion = $response.tag_name #Stores version number of latest release.
$licenseWingetUrl = $response.assets.browser_download_url | Where-Object {$_ -like "*License1.xml"} #Index value for License file.
$assetUrl = $response.assets.browser_download_url | Where-Object {$_ -like "*Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle"}
Invoke-WebRequest -Uri $licenseWingetUrl -OutFile $ENV:TEMP\License1.xml
# The only pain is that the msixbundle for winget-cli is 246MB. In some situations this can take a bit, with slower connections.
Invoke-WebRequest -Uri $assetUrl -OutFile $ENV:TEMP\Microsoft.DesktopAppInstaller.msixbundle
Add-AppxProvisionedPackage -Online -PackagePath $ENV:TEMP\Microsoft.DesktopAppInstaller.msixbundle -DependencyPackagePath $ENV:TEMP\Microsoft.VCLibs.x64.Desktop.appx, $ENV:TEMP\Microsoft.UI.Xaml.x64.appx -LicensePath $ENV:TEMP\License1.xml
Add-AppxPackage -Path https://cdn.winget.microsoft.com/cache/source.msix
$ProgressPreference = 'Continue'

Write-Host "Refreshing environment variables..."
$ENV:PATH = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")

Write-Host "Setting winget to use the faster wininet downloader..."
$jsonContent = @"
{
    "network": {
        "downloader": "wininet"
    }
}
"@
$jsonContent | Set-Content -Path "$env:LOCALAPPDATA\Packages\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe\LocalState\settings.json" -Force

Write-Host "Installing default programs with winget..."
# translucenttb 9PF4KZ2VN4W9
# new notepad 9MSMLRH6LZF3
winget install LibreWolf.LibreWolf M2Team.NanaZip VideoLAN.VLC Notepad++.Notepad++ 9PF4KZ2VN4W9 9MSMLRH6LZF3 --silent --accept-source-agreements --accept-package-agreements --force

Write-Host "Setting LibreWolf as the default browser..."
Start-Process "$env:programfiles\LibreWolf\librewolf.exe" "-setDefaultBrowser"

Write-Host "Opening TranslucentTB for auto-start..."
$familyName = (Get-AppxPackage *TranslucentTB*).PackageFamilyName
Start-Process explorer.exe "shell:appsFolder\$familyName!TranslucentTB"

Write-Host "Completed automatic setup." -ForegroundColor Green
Write-Host ""
Write-Host "====================" -ForegroundColor Yellow
Write-Host "CONFIGURATION" -ForegroundColor Yellow
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
    # $novaUsr = Read-Host -Prompt "What is the username?"
    # $novaPwd = Read-Host -Prompt "What is the password?" -AsSecureString
    # $novaC = New-Object System.Management.Automation.PSCredential ($novaUsr, $novaPwd)
    # New-PSDrive -Name 'N' -PSProvider 'FileSystem' -Root '\\NOVA\Storage' -Scope 'Global' -Persist -Credential $novaC | Out-Null
    # above is broken...

    # yes, the password is hard coded. yes, it is intentional. and no, it isn't publically accessible.
    net use N: \\nova.box\Storage /user:nova nova /persistent:yes
    Write-Host "Done."
    $wallpaperyn = Read-Host -Prompt "Should I open the wallpapers folder for you? (y/n)"
    if ($wallpaperyn -eq "y") {
        Start-Process "N:\Files\(4) All About Matty\wallpapers"
        Write-Host "Pausing... Continue to open the lock screen settings."
        Pause
        Start-Process "ms-settings:lockscreen"
        Write-Host "Pausing..."
        Pause
    }
}

Write-Host ""
Write-Host "====================" -ForegroundColor Yellow
Write-Host "CLEAN UP" -ForegroundColor Yellow
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

Write-Host "Removing MattOOBE scheduled task..."
Get-ScheduledTask -TaskName MattOOBE | Unregister-ScheduledTask -Confirm:$false -ErrorAction SilentlyContinue

Write-Host "Cleaning both public and user desktops..."
Remove-Item -Path "$env:public\Desktop\*" -Force -Recurse
Remove-Item -Path "$env:USERPROFILE\Desktop\*" -Force -Recurse

Write-Host "Reconfiguring UAC..."
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableLUA -Value 1
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name ConsentPromptBehaviorAdmin -Value 5
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name PromptOnSecureDesktop -Value 1
Write-Host "Done."

Write-Host "Rebooting." -ForegroundColor Red
Start-Sleep -Seconds 5
Restart-Computer -Force
