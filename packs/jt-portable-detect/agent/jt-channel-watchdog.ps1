# jt-channel-watchdog.ps1 - part of the jt-portable-detect pack (jt-wazuh-mgr)
#
# The Wazuh agent subscribes to each Windows event channel once, when it
# starts, and never subscribes again. Microsoft Defender deletes and
# re-creates its channel (Microsoft-Windows-Windows Defender/Operational)
# every time its engine process starts: at boot, a few seconds after the
# agent, and at every platform update. After that the agent has either logged
#     Could not EvtSubscribe() for (...) which returned (15007)
# or holds a subscription that never delivers another event, and nothing on
# the manager says so. Sysmon does the same when it is reinstalled or upgraded.
#
# Run this every 15 minutes and at startup, as SYSTEM. When one of those
# processes started after the agent, or less than a minute before it, it
# restarts the agent once and records that in the Application log, which the
# agent collects (rule 906190). The comparison is between start times, so a
# restart that itself races a platform update is caught on the next run.

param(
    [string[]]$Owners = @('MsMpEng.exe', 'Sysmon64.exe', 'Sysmon.exe'),
    [int]$MarginSeconds = 60
)

$ErrorActionPreference = 'Stop'

# Not "Select-Object -First 1": stopping the CIM pipeline early makes
# PowerShell log a 4100 "System error" warning on every run.
function Get-StartTime([string]$Name) {
    $found = @(Get-CimInstance Win32_Process -Filter "Name='$Name'" | Sort-Object CreationDate)
    if ($found.Count) { $found[0].CreationDate }
}

function Write-Record([string]$Type, [int]$Id, [string]$Text) {
    eventcreate /L APPLICATION /T $Type /SO jt-channel-watchdog /ID $Id /D $Text | Out-Null
}

$agent = Get-StartTime 'wazuh-agent.exe'
if (-not $agent) { exit 0 }    # not running: that is the service manager's job

foreach ($name in $Owners) {
    $started = Get-StartTime $name
    if (-not $started -or $agent -ge $started.AddSeconds($MarginSeconds)) { continue }

    $text = ('{0} started at {1:yyyy-MM-dd HH:mm:ss}, the agent at {2:yyyy-MM-dd HH:mm:ss}; ' -f $name, $started, $agent) +
            'restarted the agent to renew its event channel subscriptions.'
    try {
        Restart-Service -Name WazuhSvc -Force
    } catch {
        Write-Record ERROR 101 ('Restart-Service WazuhSvc failed: ' + $_.Exception.Message)
        exit 1
    }
    # Written after the restart, once the new agent has subscribed to the
    # Application channel; an event written before it would be skipped.
    Start-Sleep -Seconds 20
    Write-Record WARNING 100 $text
    exit 0
}
