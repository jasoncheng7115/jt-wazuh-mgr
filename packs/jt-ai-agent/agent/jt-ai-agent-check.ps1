# jt-ai-agent-check.ps1 - BETA - what jt-ai-agent sees on this Windows host, for a test report
# Part of the jt-ai-agent rule pack (jt-wazuh-mgr).  AGPL-3.0-or-later, Jason Tools Co., Ltd.
#
#   powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\jt-ai-agent-check.ps1 [-Lines 20] [-ShowPrompts]
# Prints the installed files, the GitHub Copilot policy file, the scheduled task, the prompt setting,
# a count of the audit lines by agent and event, and the last audit lines (commands and paths, which can
# be sensitive: read the output before sending it). Prompt text is shown only with -ShowPrompts.
# Run it as administrator to read the logs (users can only append to them).

param([int]$Lines = 20, [switch]$ShowPrompts, [string]$TestRoot = '')

$PF = [Environment]::GetFolderPath('ProgramFiles'); $PD = [Environment]::GetFolderPath('CommonApplicationData')
if ($TestRoot) { $PF = Join-Path $TestRoot 'ProgramFiles'; $PD = Join-Path $TestRoot 'ProgramData' }
$Hook = Join-Path $PF 'jt-ai-agent\jt-ai-agent-hook.ps1'
$LogDir = Join-Path $PD 'jt-ai-agent'
$Log = Join-Path $LogDir 'actions.log'
$PromptLog = Join-Path $LogDir 'prompts.log'

function Show([string]$label, $value) { Write-Host ('{0,-28} {1}' -f $label, $value) }

Write-Host "== jt-ai-agent check on $env:COMPUTERNAME ($(Get-Date -Format 's'))"
Show 'Windows' ([Environment]::OSVersion.VersionString)
Show 'PowerShell' $PSVersionTable.PSVersion
Show 'hook installed' (Test-Path -LiteralPath $Hook)
if (Test-Path -LiteralPath $Hook) {
    Show 'hook SHA256' ((Get-FileHash -LiteralPath $Hook -Algorithm SHA256).Hash.Substring(0, 16).ToLower())
}
$code = Get-Command code -ErrorAction SilentlyContinue
if ($code) { try { Show 'VS Code' ((& $code.Source --version 2>$null | Select-Object -First 1)) } catch { } }

Write-Host '== GitHub Copilot policy hooks'
$pd = Join-Path $PD 'GitHub\Copilot\policy.d'
if (Test-Path -LiteralPath $pd) {
    foreach ($f in Get-ChildItem -LiteralPath $pd -Filter '*.json') {
        try {
            $o = [IO.File]::ReadAllText($f.FullName) | ConvertFrom-Json
            Show $f.Name ('events: ' + (@($o.hooks.PSObject.Properties.Name) -join ', '))
        } catch { Show $f.Name ('NOT VALID JSON: ' + $_.Exception.Message) }
    }
} else { Write-Host "   no $pd" }
foreach ($u in @("$env:USERPROFILE\.copilot\settings.json", (Join-Path (Get-Location) '.github\copilot\settings.json'))) {
    if (Test-Path -LiteralPath $u) {
        $t = [IO.File]::ReadAllText($u)
        Show ('user/workspace setting') ("$u disableAllHooks=" + ($t -match '"disableAllHooks"\s*:\s*true'))
    }
}

Write-Host '== prompt setting'
$cfg = Join-Path $LogDir 'config'
if (Test-Path -LiteralPath $cfg) { Show 'config' ((Get-Content -LiteralPath $cfg | Where-Object { $_ -match '^\s*prompts\s*=' }) -join ' ') } else { Show 'config' 'none (prompts off)' }
$task = Get-ScheduledTask -TaskName 'jt-ai-agent-config' -ErrorAction SilentlyContinue
if ($task) { Show 'scheduled task' ($task.State.ToString() + ', last result ' + (Get-ScheduledTaskInfo -TaskName 'jt-ai-agent-config').LastTaskResult) } else { Show 'scheduled task' 'missing' }

Write-Host '== log permissions'
foreach ($f in @($Log, $PromptLog)) {
    if (Test-Path -LiteralPath $f) { Show (Split-Path -Leaf $f) ((& icacls.exe $f | Select-Object -First 3) -join ' | ') } else { Show (Split-Path -Leaf $f) 'missing' }
}

Write-Host '== audit lines by agent / event'
if (Test-Path -LiteralPath $Log) {
    $rows = @()
    foreach ($l in [IO.File]::ReadAllLines($Log)) {
        try { $rows += ($l | ConvertFrom-Json).jt_ai } catch { }
    }
    Show 'lines' $rows.Count
    $rows | Group-Object agent, event | Sort-Object Name | ForEach-Object { Show ('  ' + $_.Name) $_.Count }
    Write-Host "== last $Lines audit lines"
    foreach ($r in ($rows | Select-Object -Last $Lines)) {
        $what = if ($r.cmd) { 'cmd: ' + $r.cmd } elseif ($r.path) { 'path: ' + $r.path } elseif ($r.prompt_len) { "prompt: $($r.prompt_len) chars, sha $($r.prompt_sha)" + $(if ($r.prompt_redacted) { ', secret removed' } else { '' }) } else { '' }
        if ($what.Length -gt 160) { $what = $what.Substring(0, 160) + '...' }
        Write-Host ('{0} {1,-12} {2,-12} {3,-18} {4,-10} {5}' -f $r.ts, $r.user, $r.agent, $r.event, $r.tool, $what)
    }
} else { Write-Host "   no $Log" }

Write-Host '== prompts.log'
if (Test-Path -LiteralPath $PromptLog) {
    $pl = [IO.File]::ReadAllLines($PromptLog)
    Show 'prompts stored' $pl.Count
    if ($ShowPrompts) { $pl | Select-Object -Last 5 | ForEach-Object { Write-Host "   $_" } }
} else { Write-Host '   none' }
