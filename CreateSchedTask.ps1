$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-ExecutionPolicy Bypass -Command "powershell -ExecutionPolicy Bypass -File $env:USERPROFILE\Desktop\AtlasPreInit.ps1"'
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(2)
Register-ScheduledTask -Action $action -Trigger $trigger -TaskName "AtlasPreInit" -Description "Run AtlasPreInit after logon" -Force
