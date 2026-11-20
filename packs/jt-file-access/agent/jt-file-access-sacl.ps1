<#
.SYNOPSIS
  jt-file-access: turn on access auditing for a confidential folder (Windows).

.DESCRIPTION
  1. Enables the "File System" audit subcategory (success and failure) with auditpol,
     by GUID so it works on any display language.
  2. Adds an audit rule (SACL) to the folder for Everyone (S-1-1-0): read, write, append,
     delete, change permissions, take ownership; inherited by everything under it.
  3. Checks the Wazuh agent's ossec.conf: events 4663 / 4656 / 4907 must not be excluded
     from the Security channel (the Wazuh default excludes 4656 and 4663).

  Run as Administrator. -Remove takes the folder's jt-file-access audit rule away again
  (the audit subcategory is left as it is). Nothing is changed with -WhatIf.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File jt-file-access-sacl.ps1 -Path 'D:\Confidential'
.EXAMPLE
  powershell -ExecutionPolicy Bypass -File jt-file-access-sacl.ps1 -Path 'D:\Confidential' -Remove
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true)][string]$Path,
    [switch]$Remove,
    [string]$AgentConfig = ''
)
$ErrorActionPreference = 'Stop'

$FileSystemSubcategory = '{0CCE921D-69AE-11D9-BED3-505054503030}'
$Everyone = New-Object System.Security.Principal.SecurityIdentifier('S-1-1-0')
$Rights = [System.Security.AccessControl.FileSystemRights]'ReadData, WriteData, AppendData, Delete, ChangePermissions, TakeOwnership'
$Inherit = [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
$Propagate = [System.Security.AccessControl.PropagationFlags]::None
$Flags = [System.Security.AccessControl.AuditFlags]'Success, Failure'

if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
    throw "Not a folder: $Path"
}
$full = (Resolve-Path -LiteralPath $Path).ProviderPath

$rule = New-Object System.Security.AccessControl.FileSystemAuditRule($Everyone, $Rights, $Inherit, $Propagate, $Flags)
$acl = Get-Acl -LiteralPath $full -Audit

if ($Remove) {
    if ($PSCmdlet.ShouldProcess($full, 'remove the jt-file-access audit rule')) {
        [void]$acl.RemoveAuditRuleSpecific($rule)
        Set-Acl -LiteralPath $full -AclObject $acl
        Write-Output "Removed the audit rule from $full"
    }
    return
}

if ($PSCmdlet.ShouldProcess('File System audit subcategory', 'enable success and failure')) {
    & auditpol.exe /set /subcategory:$FileSystemSubcategory /success:enable /failure:enable | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "auditpol failed with exit code $LASTEXITCODE" }
}
if ($PSCmdlet.ShouldProcess($full, 'add the jt-file-access audit rule')) {
    $acl.AddAuditRule($rule)
    Set-Acl -LiteralPath $full -AclObject $acl
}

Write-Output ''
Write-Output "Audit subcategory File System:"
& auditpol.exe /get /subcategory:$FileSystemSubcategory | Where-Object { $_.Trim() } | Select-Object -Last 1
Write-Output ''
Write-Output "Audit rules on ${full}:"
(Get-Acl -LiteralPath $full -Audit).Audit | ForEach-Object {
    '  {0}  {1}  {2}' -f $_.IdentityReference, $_.FileSystemRights, $_.AuditFlags
}

# The agent's Security channel query: 4663 / 4656 / 4907 must not be excluded.
if (-not $AgentConfig) {
    $x86 = [Environment]::GetFolderPath('ProgramFilesX86')
    $AgentConfig = Join-Path $x86 'ossec-agent\ossec.conf'
}
Write-Output ''
if (Test-Path -LiteralPath $AgentConfig) {
    $text = [System.IO.File]::ReadAllText($AgentConfig)
    $blocks = [regex]::Matches($text, '(?s)<localfile>(?:(?!</localfile>).)*?<location>\s*Security\s*</location>.*?</localfile>')
    if ($blocks.Count -eq 0) {
        Write-Output "Agent: no Security channel in $AgentConfig (the agent group's configuration decides)."
    }
    foreach ($b in $blocks) {
        $excluded = @('4663', '4656', '4907') | Where-Object { $b.Value -match ('EventID\s*!=\s*' + $_ + '\b') }
        if ($excluded) {
            Write-Output ("WARNING: the agent's Security query excludes event(s) {0}. Remove them from the <query> in {1} and restart the agent, or the manager never sees file access." -f ($excluded -join ', '), $AgentConfig)
        } else {
            Write-Output "Agent: the Security channel in $AgentConfig passes 4663, 4656 and 4907."
        }
    }
} else {
    Write-Output "Agent configuration not found at $AgentConfig (use -AgentConfig)."
}
