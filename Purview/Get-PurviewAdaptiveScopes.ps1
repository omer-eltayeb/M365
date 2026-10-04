<#
.SYNOPSIS
    Reports Microsoft Purview adaptive scopes, their queries and the retention policies that use them.
.DESCRIPTION
    Connects to Security & Compliance PowerShell, reads every adaptive scope (Get-AdaptiveScope) with its location
    type (User, Site or Group), simple filter conditions and advanced OPATH/KQL query, then scans the retention
    policies (Get-RetentionCompliancePolicy and, where available, Get-AppRetentionCompliancePolicy) to list which
    policies reference each scope through AdaptiveScopeLocation. Writes a CSV, optionally the raw scope objects as
    JSON, flags scopes that no policy uses and prints a summary. The script is read-only.
.PARAMETER ExportJson
    Also write the raw adaptive scope objects (full FilterConditions structure) to a .json file next to the CSV.
.PARAMETER OutputPath
    Path of the CSV report. Defaults to .\Reports\PurviewAdaptiveScopes_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emit the scope objects to the pipeline.
.EXAMPLE
    PS> .\Get-PurviewAdaptiveScopes.ps1
    Exports all adaptive scopes with their policy usage to .\Reports\PurviewAdaptiveScopes_<timestamp>.csv.
.EXAMPLE
    PS> .\Get-PurviewAdaptiveScopes.ps1 -ExportJson -PassThru | Where-Object { $_.Unused } | Select-Object Name, LocationType, WhenCreated
    Writes CSV and JSON and lists the scopes that no retention policy references (candidates for clean-up).
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, ExchangeOnlineManagement 3.x
    Permissions : Retention Management or View-Only Retention Management role (Compliance Administrator, Records Management
                  or Global Reader role groups) in Security & Compliance PowerShell
    Category    : Retention & records management
    Changes     : No
    Notes       : Opens a Security & Compliance PowerShell session (Connect-IPPSSession). Adaptive scopes require
                  Microsoft 365 E5 / E5 Compliance (or equivalent) licensing. The scope membership preview ("Scope
                  details") is only available in the Purview portal - PowerShell exposes the query, not the evaluated
                  members. Scopes used only by Teams private channel, Viva Engage or Copilot policies are matched through
                  Get-AppRetentionCompliancePolicy; if that cmdlet is unavailable a warning is shown and those scopes may
                  appear unused.
.LINK
    https://learn.microsoft.com/powershell/module/exchangepowershell/get-adaptivescope
.LINK
    https://learn.microsoft.com/purview/purview-adaptive-scopes
#>
#Requires -Version 5.1
#Requires -Modules ExchangeOnlineManagement

[CmdletBinding()]
param(
    [Parameter()]
    [switch]$ExportJson,

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

function Get-LocationIdentifier {
    <# Returns every name/identity string found on a policy location entry so scopes can be matched by name or GUID. #>
    [CmdletBinding()]
    param([Parameter()][AllowNull()]$Location)
    foreach ($item in @($Location)) {
        if ($null -eq $item) { continue }
        foreach ($propertyName in 'Name', 'DisplayName', 'ImmutableIdentity') {
            if ($null -ne $item.PSObject.Properties[$propertyName] -and -not [string]::IsNullOrWhiteSpace([string]$item.$propertyName)) { [string]$item.$propertyName }
        }
        [string]$item
    }
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('PurviewAdaptiveScopes_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}

try { Connect-ExchangeIfNeeded -Compliance }
catch { throw "Unable to connect to Security & Compliance PowerShell: $($_.Exception.Message)" }

try { $scopes = @(Get-AdaptiveScope -ErrorAction Stop) }
catch { throw "Failed to retrieve adaptive scopes: $($_.Exception.Message)" }
try { $policies = @(Get-RetentionCompliancePolicy -ErrorAction Stop) }
catch { throw "Failed to retrieve retention policies: $($_.Exception.Message)" }
try { $policies += @(Get-AppRetentionCompliancePolicy -ErrorAction Stop) }
catch { Write-Warning "Could not read app retention policies (Teams private channels, Viva Engage, Copilot): $($_.Exception.Message)" }

# Map every identifier a policy uses for a scope (name, display name or GUID) to the policy names that reference it.
$policiesByScopeId = @{}
foreach ($policy in $policies) {
    foreach ($identifier in @(Get-LocationIdentifier -Location $policy.AdaptiveScopeLocation | Sort-Object -Unique)) {
        if (-not $policiesByScopeId.ContainsKey($identifier)) { $policiesByScopeId[$identifier] = New-Object -TypeName System.Collections.Generic.List[string] }
        if (-not $policiesByScopeId[$identifier].Contains([string]$policy.Name)) { $policiesByScopeId[$identifier].Add([string]$policy.Name) }
    }
}

$rows = New-Object -TypeName System.Collections.Generic.List[object]
foreach ($scope in ($scopes | Sort-Object -Property Name)) {
    $usedBy = New-Object -TypeName System.Collections.Generic.List[string]
    foreach ($key in @([string]$scope.Name, [string]$scope.Guid)) {
        if (-not [string]::IsNullOrWhiteSpace($key) -and $policiesByScopeId.ContainsKey($key)) {
            foreach ($policyName in $policiesByScopeId[$key]) { if (-not $usedBy.Contains($policyName)) { $usedBy.Add($policyName) } }
        }
    }
    # FilterConditions is a nested object for simple-query scopes; serialise it so the CSV cell stays readable.
    $filter = $scope.FilterConditions
    if ($null -ne $filter -and $filter -isnot [string]) {
        try { $filter = ConvertTo-Json -InputObject $filter -Compress -Depth 10 }
        catch { $filter = [string]$filter }
    }
    $rows.Add([PSCustomObject]@{
            Name             = [string]$scope.Name
            Guid             = [string]$scope.Guid
            LocationType     = [string]$scope.LocationType
            FilterConditions = [string]$filter
            RawQuery         = [string]$scope.RawQuery
            Comment          = [string]$scope.Comment
            Mode             = [string]$scope.Mode
            CreatedBy        = [string]$scope.CreatedBy
            LastModifiedBy   = [string]$scope.LastModifiedBy
            WhenCreated      = $scope.WhenCreated
            WhenChanged      = $scope.WhenChanged
            PolicyCount      = $usedBy.Count
            UsedByPolicies   = (($usedBy | Sort-Object) -join ';')
            Unused           = ($usedBy.Count -eq 0)
        })
}

if ($rows.Count -gt 0) { $rows | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 }
$jsonPath = $null
if ($ExportJson) {
    $jsonPath = [System.IO.Path]::ChangeExtension($OutputPath, '.json')
    try {
        $json = ConvertTo-Json -InputObject @($scopes) -Depth 10
        [System.IO.File]::WriteAllText($jsonPath, $json, (New-Object -TypeName System.Text.UTF8Encoding -ArgumentList $false))
    }
    catch { Write-Warning "The CSV was written but the JSON export failed: $($_.Exception.Message)" }
}

$unusedCount = @($rows | Where-Object { $_.Unused }).Count
Write-Host "`nAdaptive scope summary" -ForegroundColor Cyan
Write-Host ('  Adaptive scopes        : {0}' -f $rows.Count)
foreach ($group in ($rows | Group-Object -Property LocationType | Sort-Object -Property Name)) {
    Write-Host ('    {0,-20} : {1}' -f $group.Name, $group.Count)
}
Write-Host ('  Policies evaluated     : {0} ({1} adaptive)' -f $policies.Count, @($policies | Where-Object { @($_.AdaptiveScopeLocation).Count -gt 0 }).Count)
Write-Host ('  Scopes used by no policy: {0}' -f $unusedCount) -ForegroundColor $(if ($unusedCount -gt 0) { 'Yellow' } else { 'Green' })
Write-Host ('  Report                 : {0}' -f $OutputPath)
if ($jsonPath) { Write-Host ('  JSON                   : {0}' -f $jsonPath) }
Write-Host '  Membership preview of a scope is only available in the Purview portal (Adaptive scopes > Scope details).' -ForegroundColor Gray

if ($PassThru) {
    $rows
}
#endregion Main
