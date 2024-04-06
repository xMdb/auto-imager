$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-ExecutionPolicy Bypass -Command "powershell -ExecutionPolicy Bypass -File $env:USERPROFILE\Desktop\MattOOBE.ps1"'
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(2)
Register-ScheduledTask -Action $action -Trigger $trigger -TaskName "MattOOBE" -Description "Run MattOOBE after logon" -Force
