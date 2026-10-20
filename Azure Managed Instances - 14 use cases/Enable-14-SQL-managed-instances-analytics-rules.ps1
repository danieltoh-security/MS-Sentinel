#requires -Version 7.2
<#
.SYNOPSIS
Enables the fourteen rules imported from 14-SQL-managed-instances-analytics-rules.json.
.DESCRIPTION
Run in Azure Cloud Shell PowerShell after importing the template. Requires
Microsoft Sentinel Contributor, or equivalent alertRules read/write permissions.
Checks that all fourteen Scheduled rules exist before making any changes.
Preserves each rule's current configuration and verifies its final enabled state.
Includes the SQL Database-only loginmanager/dbmanager rule.
The operation is sequential, not atomic. A failure can leave some rules enabled;
errors are reported and rerunning the script safely skips already-enabled rules.
.EXAMPLE
.\Enable-14-SQL-managed-instances-analytics-rules.ps1 -SubscriptionId "00000000-0000-0000-0000-000000000000" -ResourceGroupName "sentinel-rg" -WorkspaceName "sentinel-workspace" -WhatIf
.EXAMPLE
.\Enable-14-SQL-managed-instances-analytics-rules.ps1 -SubscriptionId "00000000-0000-0000-0000-000000000000" -ResourceGroupName "sentinel-rg" -WorkspaceName "sentinel-workspace"
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)]
    [guid]$SubscriptionId,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$ResourceGroupName,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$WorkspaceName
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Get-Command Get-AzContext, Set-AzContext, Invoke-AzRestMethod -ErrorAction Stop | Out-Null
if (-not (Get-AzContext)) {
    throw 'No Azure session. Open Azure Cloud Shell PowerShell, or run Connect-AzAccount first.'
}
$context = Set-AzContext -SubscriptionId $SubscriptionId.ToString() -Scope Process -ErrorAction Stop
$apiVersion = '2024-03-01'
$group = [uri]::EscapeDataString($ResourceGroupName)
$workspace = [uri]::EscapeDataString($WorkspaceName)
$basePath = "/subscriptions/$SubscriptionId/resourceGroups/$group/providers/Microsoft.OperationalInsights/workspaces/$workspace/providers/Microsoft.SecurityInsights/alertRules"
$ruleIds = @(
    '739531a9-91b8-4b87-a169-000000000001'
    '739531a9-91b8-4b87-a169-000000000002'
    '739531a9-91b8-4b87-a169-000000000003'
    '739531a9-91b8-4b87-a169-000000000004'
    '739531a9-91b8-4b87-a169-000000000005'
    '739531a9-91b8-4b87-a169-000000000006'
    '739531a9-91b8-4b87-a169-000000000007'
    '739531a9-91b8-4b87-a169-000000000008'
    '739531a9-91b8-4b87-a169-000000000009'
    '739531a9-91b8-4b87-a169-000000000010'
    '739531a9-91b8-4b87-a169-000000000011'
    '739531a9-91b8-4b87-a169-000000000012'
    '739531a9-91b8-4b87-a169-000000000013'
    '739531a9-91b8-4b87-a169-000000000014'
)

function Get-ImportedRule {
    param([Parameter(Mandatory)][string]$RuleId)

    $response = Invoke-AzRestMethod -Method GET -Path "$basePath/${RuleId}?api-version=$apiVersion" -DefaultProfile $context -ErrorAction Stop
    if ([int]$response.StatusCode -ne 200) {
        throw "Cannot read rule $RuleId (HTTP $($response.StatusCode)). Check the import, target workspace, and permissions. $($response.Content)"
    }
    $rule = $response.Content | ConvertFrom-Json -AsHashtable
    if ($rule.kind -ne 'Scheduled' -or $rule.properties.enabled -isnot [bool]) {
        throw "Rule $RuleId is not a Scheduled rule with a valid enabled property. No update will be sent for it."
    }
    return $rule
}

Write-Host "Checking all 14 imported rules in workspace '$WorkspaceName'..."
foreach ($ruleId in $ruleIds) {
    Get-ImportedRule -RuleId $ruleId | Out-Null
}
Write-Warning 'All 14 rules are targeted, including the Azure SQL Database-only loginmanager/dbmanager rule. Enabling rules does not enable the underlying SQL audit action groups.'

$failures = [System.Collections.Generic.List[string]]::new()
$skipped = [System.Collections.Generic.HashSet[string]]::new()
foreach ($ruleId in $ruleIds) {
    try {
        # Read again immediately before updating so the preflight snapshot is not written back.
        $rule = Get-ImportedRule -RuleId $ruleId
        if ($rule.properties.enabled) {
            Write-Host "Already enabled: $($rule.properties.displayName)"
            continue
        }
        if (-not $PSCmdlet.ShouldProcess("$WorkspaceName / $($rule.properties.displayName)", 'Enable Sentinel analytics rule')) {
            [void]$skipped.Add($ruleId)
            continue
        }
        $rule.properties.enabled = $true
        [void]$rule.properties.Remove('lastModifiedUtc')
        $body = @{
            kind = $rule.kind
            properties = $rule.properties
        }
        if ($rule.ContainsKey('etag')) {
            $body.etag = $rule.etag
        }
        $response = Invoke-AzRestMethod -Method PUT -Path "$basePath/${ruleId}?api-version=$apiVersion" `
            -Payload ($body | ConvertTo-Json -Depth 100 -Compress) -DefaultProfile $context -ErrorAction Stop
        if ([int]$response.StatusCode -notin @(200, 201)) {
            throw "HTTP $($response.StatusCode): $($response.Content)"
        }
        Write-Host "Update accepted: $($rule.properties.displayName)"
    }
    catch {
        $message = "Enable failed for ${ruleId}: $($_.Exception.Message)"
        $failures.Add($message)
        Write-Warning $message
    }
}

$results = foreach ($ruleId in $ruleIds) {
    try {
        $rule = Get-ImportedRule -RuleId $ruleId
        if (-not $rule.properties.enabled -and -not $skipped.Contains($ruleId)) {
            $message = "Verification failed: $ruleId is still disabled."
            $failures.Add($message)
            Write-Warning $message
        }
        [pscustomobject]@{
            RuleId = $ruleId
            RuleName = $rule.properties.displayName
            Enabled = $rule.properties.enabled
            Result = $(if ($skipped.Contains($ruleId)) { 'Skipped (WhatIf/confirmation)' } elseif ($rule.properties.enabled) { 'Verified enabled' } else { 'Still disabled' })
        }
    }
    catch {
        $message = "Verification failed for ${ruleId}: $($_.Exception.Message)"
        $failures.Add($message)
        Write-Warning $message
        [pscustomobject]@{ RuleId = $ruleId; RuleName = '(unavailable)'; Enabled = $null; Result = 'Verification error' }
    }
}
$results

if ($failures.Count -gt 0) {
    throw "One or more enablement/verification operations failed. Review the warnings and results above. This is not an atomic operation; some rules may already be enabled. Fix the cause and rerun."
}
if ($skipped.Count -gt 0) {
    Write-Host "$($skipped.Count) update(s) skipped by WhatIf/confirmation. No all-enabled success is claimed."
}
else {
    Write-Host 'Verified: all 14 imported analytics rules are enabled.'
}
