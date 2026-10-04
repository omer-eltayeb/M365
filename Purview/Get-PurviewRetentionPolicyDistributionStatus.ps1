<#
.SYNOPSIS
    Reports the distribution status of Purview retention policies (optionally DLP and label policies) and can retry failed ones.
.DESCRIPTION
    Connects to Security & Compliance PowerShell and reads every retention policy with Get-RetentionCompliancePolicy
    -DistributionDetail. Each DistributionResults entry (JSON or "Key:Value" text, depending on the workload) is parsed
    into one row with Policy, Workload, Location, Status and a message truncated to 300 characters; policies without
    per-location results still produce one row with their overall DistributionStatus. -IncludeDlpAndLabels adds DLP
    policies (Get-DlpCompliancePolicy -DistributionDetail) and sensitivity label policies (Get-LabelPolicy). With
    -Retry, policies whose DistributionStatus is Error are re-submitted with the matching *-RetryDistribution cmdlet.
    Writes a CSV and prints a summary by policy type and status.
.PARAMETER IncludeDlpAndLabels
    Also report DLP policies and sensitivity label policies, which share the same distribution pipeline.
.PARAMETER Retry
    Run Set-RetentionCompliancePolicy / Set-DlpCompliancePolicy / Set-LabelPolicy -RetryDistribution for every policy in
    Error status. Supports -WhatIf and -Confirm. Without this switch the script is read-only.
.PARAMETER OutputPath
    Path of the CSV report. Defaults to .\Reports\PurviewPolicyDistribution_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emit the distribution rows to the pipeline.
.EXAMPLE
    PS> .\Get-PurviewRetentionPolicyDistributionStatus.ps1
    Reports the distribution status of all retention policies to .\Reports\PurviewPolicyDistribution_<timestamp>.csv.
.EXAMPLE
    PS> .\Get-PurviewRetentionPolicyDistributionStatus.ps1 -IncludeDlpAndLabels -PassThru | Where-Object { $_.Status -eq 'Error' } | Format-Table Policy, Workload, Location, Message
    Shows every failed location across retention, DLP and label policies.
.EXAMPLE
    PS> .\Get-PurviewRetentionPolicyDistributionStatus.ps1 -Retry -WhatIf
    Lists the policies in Error status that would be re-submitted for distribution, without changing anything.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, ExchangeOnlineManagement 3.x
    Permissions : View-Only Retention Management (report) or Retention Management / DLP Compliance Management /
                  Sensitivity Label Administrator (with -Retry) in Security & Compliance PowerShell
    Category    : Retention & records management
    Changes     : Optional (-Retry)
    Notes       : Opens a Security & Compliance PowerShell session (Connect-IPPSSession). Distribution can legitimately show
                  Pending for up to 24 hours after a policy change; only retry policies that stay in Error. Entries that
                  cannot be parsed are kept verbatim in the Message column. Policies pending deletion are never retried.
.LINK
    https://learn.microsoft.com/powershell/module/exchangepowershell/get-retentioncompliancepolicy
.LINK
    https://learn.microsoft.com/powershell/module/exchangepowershell/set-retentioncompliancepolicy
#>
#Requires -Version 5.1
#Requires -Modules ExchangeOnlineManagement

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter()]
    [switch]$IncludeDlpAndLabels,

    [Parameter()]
    [switch]$Retry,

    [Parameter()]
    [string]$OutputPath,

    [Parameter()]
    [switch]$PassThru
)

$ErrorActionPreference = 'Stop'

#region Helpers
function Connect-ExchangeIfNeeded {
    <# Connects to Exchange Online (or Security & Compliance PowerShell) only when no live session exists. #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [switch]$Compliance
    )
    $connections = @(Get-ConnectionInformation -ErrorAction SilentlyContinue)
    if ($Compliance) {
        $active = @($connections | Where-Object { $_.ConnectionUri -like '*compliance*' -and $_.State -eq 'Connected' })
        if ($active.Count -eq 0) {
            Write-Verbose 'Connecting to Security & Compliance PowerShell.'
            Connect-IPPSSession -ErrorAction Stop
        }
    }
    else {
        $active = @($connections | Where-Object { $_.ConnectionUri -notlike '*compliance*' -and $_.State -eq 'Connected' })
        if ($active.Count -eq 0) {
            Write-Verbose 'Connecting to Exchange Online.'
            Connect-ExchangeOnline -ShowBanner:$false -ErrorAction Stop
        }
    }
}

function ConvertFrom-DistributionResult {
    <# Parses one DistributionResults entry (JSON or "Key:Value" text) into Workload, Location, Status and Message. #>
    [CmdletBinding()]
    param([Parameter()][AllowNull()]$Entry)
    $text = ([string]$Entry).Trim()
    $result = @{ Workload = $null; Location = $null; Status = $null; Message = $text }
    if ($text.StartsWith('{')) {
        try {
            $json = $text | ConvertFrom-Json -ErrorAction Stop
            foreach ($name in 'Endpoint', 'Workload') { if ($null -ne $json.PSObject.Properties[$name]) { $result.Workload = [string]$json.$name } }
            foreach ($name in 'Location', 'Status', 'Message') { if ($null -ne $json.PSObject.Properties[$name]) { $result[$name] = [string]$json.$name } }
            return $result
        }
        catch { Write-Verbose "Distribution entry is not valid JSON, parsing as text: $text" }
    }
    if ($text -match '(?i)\b(?:Endpoint|Workload)\s*[:=]\s*([^,;|]+)') { $result.Workload = $Matches[1].Trim() }
    if ($text -match '(?i)\bLocation\s*[:=]\s*([^,;|\s]+)') { $result.Location = $Matches[1].Trim() }
    if ($text -match '(?i)\bStatus\s*[:=]\s*([^,;|\s]+)') { $result.Status = $Matches[1].Trim() }
    if ($text -match '(?i)\bMessage\s*[:=]\s*(.+)$') { $result.Message = $Matches[1].Trim() }
    return $result
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('PurviewPolicyDistribution_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}

try { Connect-ExchangeIfNeeded -Compliance }
catch { throw "Unable to connect to Security & Compliance PowerShell: $($_.Exception.Message)" }

# Each entry pairs a policy type with the cmdlets that read it and retry its distribution.
$sources = New-Object -TypeName System.Collections.Generic.List[object]
$sources.Add([PSCustomObject]@{
        Type  = 'Retention'
        Get   = { Get-RetentionCompliancePolicy -DistributionDetail -ErrorAction Stop }
        Retry = { param($Name) Set-RetentionCompliancePolicy -Identity $Name -RetryDistribution -ErrorAction Stop }
    })
if ($IncludeDlpAndLabels) {
    $sources.Add([PSCustomObject]@{
            Type  = 'DLP'
            Get   = { Get-DlpCompliancePolicy -DistributionDetail -ErrorAction Stop }
            Retry = { param($Name) Set-DlpCompliancePolicy -Identity $Name -RetryDistribution -ErrorAction Stop }
        })
    $sources.Add([PSCustomObject]@{
            Type  = 'Label'
            Get   = { Get-LabelPolicy -ErrorAction Stop }
            Retry = { param($Name) Set-LabelPolicy -Identity $Name -RetryDistribution -ErrorAction Stop }
        })
}

$rows = New-Object -TypeName System.Collections.Generic.List[object]
$retried = 0
$retryFailed = 0
foreach ($source in $sources) {
    Write-Verbose "Retrieving $($source.Type) policies with distribution detail."
    try { $policies = @(& $source.Get) }
    catch {
        Write-Warning "Failed to retrieve $($source.Type) policies: $($_.Exception.Message)"
        continue
    }
    foreach ($policy in ($policies | Sort-Object -Property Name)) {
        $status = [string]$policy.DistributionStatus
        $retryRequested = $false
        if ($Retry -and $status -eq 'Error' -and [string]$policy.Mode -ne 'PendingDeletion') {
            if ($PSCmdlet.ShouldProcess("$($source.Type) policy '$($policy.Name)'", 'Retry policy distribution')) {
                try {
                    & $source.Retry $policy.Name
                    $retryRequested = $true
                    $retried++
                }
                catch {
                    $retryFailed++
                    Write-Warning "Retry failed for $($source.Type) policy '$($policy.Name)': $($_.Exception.Message)"
                }
            }
        }

        $entries = @($policy.DistributionResults | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
        $parsed = @(foreach ($entry in $entries) { ConvertFrom-DistributionResult -Entry $entry })
        if ($parsed.Count -eq 0) { $parsed = @(@{ Workload = $null; Location = $null; Status = $status; Message = $null }) }
        foreach ($item in $parsed) {
            $message = [string]$item.Message
            if ($message.Length -gt 300) { $message = $message.Substring(0, 300) + '...' }
            $rows.Add([PSCustomObject]@{
                    Policy             = [string]$policy.Name
                    PolicyType         = $source.Type
                    PolicyGuid         = [string]$policy.Guid
                    Enabled            = [bool]$policy.Enabled
                    Mode               = [string]$policy.Mode
                    DistributionStatus = $status
                    Workload           = $item.Workload
                    Location           = $item.Location
                    Status             = $(if ([string]::IsNullOrWhiteSpace([string]$item.Status)) { $status } else { [string]$item.Status })
                    Message            = $message
                    RetryRequested     = $retryRequested
                    WhenChanged        = $policy.WhenChanged
                })
        }
    }
}

if ($rows.Count -gt 0) { $rows | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 }

Write-Host "`nPolicy distribution summary" -ForegroundColor Cyan
foreach ($group in ($rows | Group-Object -Property PolicyType)) {
    $policyNames = @($group.Group | Select-Object -ExpandProperty Policy -Unique)
    $errorPolicies = @($group.Group | Where-Object { $_.DistributionStatus -eq 'Error' } | Select-Object -ExpandProperty Policy -Unique).Count
    $pendingPolicies = @($group.Group | Where-Object { $_.DistributionStatus -eq 'Pending' } | Select-Object -ExpandProperty Policy -Unique).Count
    $colour = if ($errorPolicies -gt 0) { 'Red' } elseif ($pendingPolicies -gt 0) { 'Yellow' } else { 'Green' }
    Write-Host ('  {0,-10}: {1} policies, {2} in error, {3} pending, {4} location rows' -f $group.Name, $policyNames.Count, $errorPolicies, $pendingPolicies, $group.Count) -ForegroundColor $colour
}
if ($Retry) { Write-Host ('  Retry requested for {0} policies ({1} retry calls failed)' -f $retried, $retryFailed) }
Write-Host ('  Report: {0}' -f $OutputPath)

if ($PassThru) {
    $rows
}
#endregion Main
