# jt-ai-agent-uninstall.ps1 - BETA - remove the jt-ai-agent audit from a Windows host
# Part of the jt-ai-agent rule pack (jt-wazuh-mgr).  AGPL-3.0-or-later, Jason Tools Co., Ltd.
#
# Run in an elevated Windows PowerShell:
#   powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\jt-ai-agent-uninstall.ps1 [-RemoveLogs]
# Takes the jt-ai-agent hook out of the system-wide settings of Claude Code, Codex, Gemini CLI, Cursor
# and GitHub Copilot (other hooks and settings are kept; a backup *.jt-bak-<time> is left next to each
# file it changes), deletes the scheduled task and C:\Program Files\jt-ai-agent. The logs in
# C:\ProgramData\jt-ai-agent stay unless -RemoveLogs (they are audit records).
# -TestRoot <dir>: work on what jt-ai-agent-install.ps1 -TestRoot <dir> wrote.

param([string]$TestRoot = '', [switch]$RemoveLogs)

$ErrorActionPreference = 'Stop'
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host 'Run this in an elevated PowerShell (as administrator).'; exit 1
}
$stamp = Get-Date -Format 'yyyyMMddHHmmss'
$PF = [Environment]::GetFolderPath('ProgramFiles'); $PD = [Environment]::GetFolderPath('CommonApplicationData')
if ($TestRoot) { $PF = Join-Path $TestRoot 'ProgramFiles'; $PD = Join-Path $TestRoot 'ProgramData' }
$HookDir = Join-Path $PF 'jt-ai-agent'
$LogDir = Join-Path $PD 'jt-ai-agent'
$Utf8 = New-Object Text.UTF8Encoding($false)

function Save-Changed([string]$path, [string]$text, [string]$what) {
    Copy-Item -LiteralPath $path -Destination "$path.jt-bak-$stamp"
    [IO.File]::WriteAllText($path, $text, $Utf8)
    Write-Host "   ${what}: hook removed ($path)"
}

function Remove-FromJson([string]$path, [string]$what) {
    if (-not (Test-Path -LiteralPath $path)) { Write-Host "   ${what}: not set up"; return }
    $text = [IO.File]::ReadAllText($path)
    try { $o = $text | ConvertFrom-Json } catch { Write-Host "   ${what}: $path is not plain JSON; remove the jt-ai-agent hooks by hand"; return }
    $hooks = $o.hooks
    if ($null -eq $hooks) { Write-Host "   ${what}: no hooks"; return }
    $changed = $false
    foreach ($ev in @($hooks.PSObject.Properties)) {
        $keep = @()
        foreach ($entry in @($ev.Value)) {
            $mine = ($entry | ConvertTo-Json -Depth 20 -Compress) -match 'jt-ai-agent-hook\.ps1'
            if ($mine) { $changed = $true } else { $keep += $entry }
        }
        if ($keep.Count) { $hooks.($ev.Name) = $keep } else { $hooks.PSObject.Properties.Remove($ev.Name) }
    }
    if ($changed) { Save-Changed $path ($o | ConvertTo-Json -Depth 20) $what } else { Write-Host "   ${what}: not set up" }
}

Write-Host "== $env:COMPUTERNAME : removing jt-ai-agent (BETA on Windows)"
Write-Host '== Claude Code'; Remove-FromJson (Join-Path $PF 'ClaudeCode\managed-settings.json') 'claude-code'
Write-Host '== Gemini CLI'; Remove-FromJson (Join-Path $PD 'gemini-cli\settings.json') 'gemini'
Write-Host '== Cursor'; Remove-FromJson (Join-Path $PD 'Cursor\hooks.json') 'cursor'

Write-Host '== Codex'
$p = Join-Path $PD 'OpenAI\Codex\requirements.toml'
if (Test-Path -LiteralPath $p) {
    $old = [IO.File]::ReadAllText($p)
    $new = [regex]::Replace($old, '(?s)# >>> jt-ai-agent.*?# <<< jt-ai-agent\r?\n?', '')
    if ($new -ne $old) {
        if ($new.Trim()) { Save-Changed $p $new 'codex' }
        else { Copy-Item -LiteralPath $p -Destination "$p.jt-bak-$stamp"; Remove-Item -LiteralPath $p; Write-Host "   codex: removed $p (it held only the jt-ai-agent hooks)" }
    } else { Write-Host '   codex: not set up' }
} else { Write-Host '   codex: not set up' }

Write-Host '== GitHub Copilot'
$p = Join-Path $PD 'GitHub\Copilot\policy.d\jt-ai-agent.json'
if (Test-Path -LiteralPath $p) { Remove-Item -LiteralPath $p; Write-Host "   copilot: removed $p" } else { Write-Host '   copilot: not set up' }

Write-Host '== scheduled task jt-ai-agent-config'
if (-not $TestRoot) {
    if (Get-ScheduledTask -TaskName 'jt-ai-agent-config' -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName 'jt-ai-agent-config' -Confirm:$false; Write-Host '   removed'
    } else { Write-Host '   not present' }
} else { Write-Host '   skipped (-TestRoot)' }

Write-Host '== hook'
if (Test-Path -LiteralPath $HookDir) { Remove-Item -LiteralPath $HookDir -Recurse -Force; Write-Host "   removed $HookDir" } else { Write-Host '   not present' }
if ($RemoveLogs) {
    if (Test-Path -LiteralPath $LogDir) { Remove-Item -LiteralPath $LogDir -Recurse -Force; Write-Host "   removed $LogDir" }
} else {
    Write-Host "   kept the logs in $LogDir (-RemoveLogs deletes them)"
}
Write-Host "== $env:COMPUTERNAME done. Restart running agent sessions."
exit 0
