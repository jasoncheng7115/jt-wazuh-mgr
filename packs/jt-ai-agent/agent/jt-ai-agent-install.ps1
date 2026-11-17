# jt-ai-agent-install.ps1 - BETA - set up the jt-ai-agent audit on a Windows host
# Part of the jt-ai-agent rule pack (jt-wazuh-mgr).  AGPL-3.0-or-later, Jason Tools Co., Ltd.
#
# Run in an elevated Windows PowerShell on a host in the agent group "ai-agent", which delivers this
# script and jt-ai-agent-hook.ps1 to the Wazuh agent's shared directory:
#   powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\Program Files (x86)\ossec-agent\shared\jt-ai-agent-install.ps1"
# It can be run again (updates the hook, keeps the agents' other settings).
#
#  1. copies the hook to C:\Program Files\jt-ai-agent (administrators only can change it)
#  2. creates C:\ProgramData\jt-ai-agent\actions.log and prompts.log, which users may only append to
#  3. adds the hook to the system-wide configuration of Claude Code, Codex, Gemini CLI, Cursor and
#     GitHub Copilot, merging into existing files (backups next to them, *.jt-bak-<time>)
#  4. registers the scheduled task "jt-ai-agent-config" (SYSTEM, at start-up and every 5 minutes) that
#     copies the server's setting for prompts to C:\ProgramData\jt-ai-agent\config
#
# BETA: tested with Windows PowerShell 5.1; the agents' Windows hook support follows their
# documentation and has not been run against every agent on Windows yet.

# -TestRoot <dir>: write everything under <dir>\ProgramFiles and <dir>\ProgramData instead, and do not register
# the scheduled task (to try the script out without touching the host's agents).
param([string]$Source = '', [string]$TestRoot = '')

$ErrorActionPreference = 'Stop'
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host 'Run this in an elevated PowerShell (as administrator).'; exit 1
}
if (-not $Source) { $Source = $PSScriptRoot }
$stamp = Get-Date -Format 'yyyyMMddHHmmss'
$PF = $env:ProgramFiles; $PD = $env:ProgramData
if ($TestRoot) {
    $PF = Join-Path $TestRoot 'ProgramFiles'; $PD = Join-Path $TestRoot 'ProgramData'
    # the hook and the self-test write to the test directory, too
    $env:JT_AI_AGENT_LOG = Join-Path $PD 'jt-ai-agent\actions.log'
    $env:JT_AI_AGENT_PROMPT_LOG = Join-Path $PD 'jt-ai-agent\prompts.log'
    $env:JT_AI_AGENT_CONFIG = Join-Path $PD 'jt-ai-agent\config'
}
$HookDir = Join-Path $PF 'jt-ai-agent'
$Hook = Join-Path $HookDir 'jt-ai-agent-hook.ps1'
$LogDir = Join-Path $PD 'jt-ai-agent'
$Utf8 = New-Object Text.UTF8Encoding($false)

function Cmd([string]$agent, [string]$event = '') {
    $c = 'powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + $Hook + '" -Agent ' + $agent
    if ($event) { $c += ' -Event ' + $event }
    return $c
}

function ConvertTo-Hash($o) {
    # Windows PowerShell 5.1 has no ConvertFrom-Json -AsHashtable
    if ($null -eq $o) { return $null }
    if ($o -is [Management.Automation.PSCustomObject]) {
        $h = [ordered]@{}
        foreach ($p in $o.PSObject.Properties) { $h[$p.Name] = ConvertTo-Hash $p.Value }
        return $h
    }
    if ($o -is [array]) { return ,@($o | ForEach-Object { ConvertTo-Hash $_ }) }
    return $o
}

function Read-Json([string]$path) {
    if (-not (Test-Path -LiteralPath $path)) { return [ordered]@{} }
    $text = [IO.File]::ReadAllText($path)
    if (-not $text.Trim()) { return [ordered]@{} }
    try { return ConvertTo-Hash ($text | ConvertFrom-Json) }
    catch { Write-Host "   WARNING: $path is not plain JSON; add the jt-ai-agent hooks to it by hand"; return $null }
}

function Save-File([string]$path, [string]$text, [string]$what) {
    $dir = Split-Path -Parent $path
    if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    if (Test-Path -LiteralPath $path) {
        if ([IO.File]::ReadAllText($path) -eq $text) { Write-Host "   ${what}: already up to date"; return }
        Copy-Item -LiteralPath $path -Destination "$path.jt-bak-$stamp"
    }
    [IO.File]::WriteAllText($path, $text, $Utf8)
    Write-Host "   ${what}: written ($path)"
}

function Add-Hook($hooks, [string]$event, $entry, [string]$command, [string]$matcher = '') {
    if (-not $hooks.Contains($event)) { $hooks[$event] = @() }
    $list = @($hooks[$event])
    foreach ($e in $list) {
        foreach ($h in @($e['hooks'])) { if ($h -and $h['command'] -eq $command) { return } }
        if ($e['command'] -eq $command) { return }
    }
    if ($matcher) {
        # an ordered dictionary cannot be added to another one: copy with the matcher first
        $m = [ordered]@{ matcher = $matcher }
        foreach ($k in $entry.Keys) { $m[$k] = $entry[$k] }
        $entry = $m
    }
    $hooks[$event] = $list + @($entry)
}

Write-Host "== $env:COMPUTERNAME : hook and logs (jt-ai-agent, BETA on Windows)"
if (-not (Test-Path -LiteralPath (Join-Path $Source 'jt-ai-agent-hook.ps1'))) {
    Write-Host "jt-ai-agent-hook.ps1 is not in $Source; is this host in the agent group ai-agent?"; exit 1
}
New-Item -ItemType Directory -Path $HookDir -Force | Out-Null
Copy-Item -LiteralPath (Join-Path $Source 'jt-ai-agent-hook.ps1') -Destination $Hook -Force
New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
# the directory: users may list and read the copied setting; the logs: users may only append
& icacls.exe $LogDir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-32-545:(RX)' | Out-Null
foreach ($name in @('actions.log', 'prompts.log')) {
    $f = Join-Path $LogDir $name
    if (-not (Test-Path -LiteralPath $f)) { [IO.File]::WriteAllText($f, '', $Utf8) }
    & icacls.exe $f /inheritance:r /grant:r '*S-1-5-18:F' '*S-1-5-32-544:F' '*S-1-5-32-545:(AD,S,RA)' | Out-Null
}

Write-Host '== Claude Code: C:\Program Files\ClaudeCode\managed-settings.json'
$p = Join-Path $PF 'ClaudeCode\managed-settings.json'
$d = Read-Json $p
if ($null -ne $d) {
    if (-not $d.Contains('hooks')) { $d['hooks'] = [ordered]@{} }
    $c = Cmd 'claude-code'
    foreach ($ev in @(@('PreToolUse', '*'), @('SessionStart', ''), @('PermissionRequest', '*'), @('PostToolUseFailure', '*'),
                      @('SubagentStart', ''), @('SessionEnd', ''), @('UserPromptSubmit', ''))) {
        Add-Hook $d['hooks'] $ev[0] ([ordered]@{ hooks = @([ordered]@{ type = 'command'; command = $c; timeout = 10 }) }) $c $ev[1]
    }
    Save-File $p ($d | ConvertTo-Json -Depth 20) 'claude-code'
}

Write-Host '== Codex: C:\ProgramData\OpenAI\Codex\requirements.toml'
$p = Join-Path $PD 'OpenAI\Codex\requirements.toml'
$c = (Cmd 'codex').Replace("'", "''")
$lines = @('# >>> jt-ai-agent managed hooks (every Codex user on this host; users cannot turn these off)',
           '[features]', 'hooks = true', '', '[hooks]', "windows_managed_dir = '$HookDir'")
foreach ($ev in @('PreToolUse', 'SessionStart', 'PermissionRequest', 'PostToolUse', 'SubagentStart', 'SessionEnd', 'UserPromptSubmit')) {
    $lines += @('', "[[hooks.$ev]]")
    if (@('PreToolUse', 'PermissionRequest', 'PostToolUse') -contains $ev) { $lines += 'matcher = ".*"' }
    $lines += @("[[hooks.$ev.hooks]]", 'type = "command"', "command = '$c'", "command_windows = '$c'", 'timeout = 10')
}
$lines += '# <<< jt-ai-agent'
$block = ($lines -join "`r`n") + "`r`n"
$old = if (Test-Path -LiteralPath $p) { [IO.File]::ReadAllText($p) } else { '' }
if ($old -match '(?s)# >>> jt-ai-agent.*?# <<< jt-ai-agent\r?\n?') {
    Save-File $p ([regex]::Replace($old, '(?s)# >>> jt-ai-agent.*?# <<< jt-ai-agent\r?\n?', [Text.RegularExpressions.MatchEvaluator] { param($m) $block })) 'codex'
} elseif (-not $old.Trim()) {
    Save-File $p $block 'codex'
} elseif ($old -match '(?m)^\s*\[(features|hooks)\]') {
    Write-Host "   WARNING: $p already has [features] or [hooks]; add the jt-ai-agent hooks by hand"
} else {
    Save-File $p ($old.TrimEnd() + "`r`n`r`n" + $block) 'codex'
}

Write-Host '== Gemini CLI: C:\ProgramData\gemini-cli\settings.json'
$p = Join-Path $PD 'gemini-cli\settings.json'
$d = Read-Json $p
if ($null -ne $d) {
    if (-not $d.Contains('hooksConfig')) { $d['hooksConfig'] = [ordered]@{} }
    $d['hooksConfig']['enabled'] = $true
    if ($d['hooksConfig'].Contains('disabled')) { $d['hooksConfig']['disabled'] = @(@($d['hooksConfig']['disabled']) | Where-Object { $_ -ne 'jt-ai-agent' }) }
    if (-not $d.Contains('hooks')) { $d['hooks'] = [ordered]@{} }
    $c = Cmd 'gemini'
    foreach ($ev in @(@('BeforeTool', '*'), @('AfterTool', '*'), @('SessionStart', ''), @('SessionEnd', ''), @('Notification', ''), @('BeforeAgent', ''))) {
        Add-Hook $d['hooks'] $ev[0] ([ordered]@{ hooks = @([ordered]@{ name = 'jt-ai-agent'; type = 'command'; command = $c; timeout = 10000 }) }) $c $ev[1]
    }
    Save-File $p ($d | ConvertTo-Json -Depth 20) 'gemini'
}

Write-Host '== Cursor: C:\ProgramData\Cursor\hooks.json (after-the-fact events only: its before-hooks can block)'
$p = Join-Path $PD 'Cursor\hooks.json'
$d = Read-Json $p
if ($null -ne $d) {
    if (-not $d.Contains('version')) { $d['version'] = 1 }
    if (-not $d.Contains('hooks')) { $d['hooks'] = [ordered]@{} }
    $c = Cmd 'cursor'
    foreach ($ev in @('sessionStart', 'sessionEnd', 'postToolUse', 'postToolUseFailure')) {
        Add-Hook $d['hooks'] $ev ([ordered]@{ command = $c; timeout = 10 }) $c
    }
    Save-File $p ($d | ConvertTo-Json -Depth 20) 'cursor'
}

Write-Host '== GitHub Copilot: C:\ProgramData\GitHub\Copilot\policy.d\jt-ai-agent.json'
$p = Join-Path $PD 'GitHub\Copilot\policy.d\jt-ai-agent.json'
$hooks = [ordered]@{}
foreach ($ev in @('sessionStart', 'sessionEnd', 'preToolUse', 'postToolUseFailure', 'subagentStart', 'permissionRequest', 'userPromptSubmitted')) {
    # exit 0 matters: Copilot denies a preToolUse call when a hook fails
    $hooks[$ev] = @([ordered]@{ type = 'command'; timeoutSec = 10; powershell = ((Cmd 'copilot' $ev) + '; exit 0') })
}
Save-File $p ([ordered]@{ version = 1; hooks = $hooks } | ConvertTo-Json -Depth 20) 'copilot'

Write-Host '== scheduled task jt-ai-agent-config (SYSTEM): the server setting for prompts, every 5 minutes'
if ($TestRoot) { Write-Host '   skipped (-TestRoot)' } else {
$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + $Hook + '" -SyncConfig')
$triggers = @((New-ScheduledTaskTrigger -AtStartup),
              (New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 5)))
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Minutes 2)
Register-ScheduledTask -TaskName 'jt-ai-agent-config' -Action $action -Trigger $triggers -Settings $settings `
    -User 'SYSTEM' -RunLevel Highest -Force | Out-Null
Start-ScheduledTask -TaskName 'jt-ai-agent-config'
}

Write-Host '== self-test'
'{"hook_event_name":"SessionStart","session_id":"jt-install-test","cwd":"C:\\","source":"startup"}' |
    & powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $Hook -Agent claude-code
Get-Content -LiteralPath (Join-Path $LogDir 'actions.log') -Tail 1
Write-Host "== $env:COMPUTERNAME done (BETA). New Claude Code / Codex / Gemini CLI / Cursor / Copilot sessions are audited (restart running ones)."
exit 0
