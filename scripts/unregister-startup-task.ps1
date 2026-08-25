<#
Removes the scheduled task created by register-startup-task.ps1.
#>

$taskName = 'gil-sec-security-monitor'

if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
    Write-Host "Removed scheduled task '$taskName'."
} else {
    Write-Host "No scheduled task named '$taskName' found."
}
