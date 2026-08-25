<#
Registers a Windows Scheduled Task that starts the gil-sec monitor +
dashboard (`pnpm run monitor`) whenever you log on.

Run once, from an ordinary (non-admin) PowerShell prompt:
    powershell -ExecutionPolicy Bypass -File .\scripts\register-startup-task.ps1

To remove it later, run scripts\unregister-startup-task.ps1.
#>

$ErrorActionPreference = 'Stop'

$taskName    = 'gil-sec-security-monitor'
$projectDir  = Split-Path -Parent $PSScriptRoot
$pnpmCmd     = (Get-Command pnpm -ErrorAction Stop).Source

if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
    Write-Host "Task '$taskName' already exists. Run unregister-startup-task.ps1 first if you want to recreate it."
    exit 0
}

$action   = New-ScheduledTaskAction -Execute $pnpmCmd -Argument 'run monitor' -WorkingDirectory $projectDir
$trigger  = New-ScheduledTaskTrigger -AtLogOn
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable

Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $settings `
    -Description 'Starts the gil-sec security monitor + dashboard on user logon' | Out-Null

Write-Host "Registered scheduled task '$taskName' (runs 'pnpm run monitor' in $projectDir at logon)."
Write-Host "It will start next time you log on. To start it immediately: Start-ScheduledTask -TaskName '$taskName'"
