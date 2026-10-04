<#
.SYNOPSIS
    Reports every eDiscovery case hold with its locations, rule query and distribution status, flagging holds that need attention.
.DESCRIPTION
    Loops through the eDiscovery (Standard) and eDiscovery (Premium) cases you can see (or those matching -CaseName), reads the
    case hold policies with Get-CaseHoldPolicy -Case and the hold rule with Get-CaseHoldRule -Policy, and writes one row per hold:
    locations (Exchange, SharePoint, public folders), enabled state, query, distribution status and timestamps. Flags mark holds on
    closed cases, distribution errors, query-based and disabled holds. -PerLocation adds <base>_Locations.csv (one row per location).
.PARAMETER CaseName
    Case name or wildcard pattern, for example 'Legal*'. Default: every case.
.PARAMETER DistributionDetail
    Pass -DistributionDetail to Get-CaseHoldPolicy to refresh the per-location distribution results (slower).
.PARAMETER PerLocation
    Also write <base>_Locations.csv with the columns Case, Hold, LocationType, Location.
.PARAMETER OutputPath
    Path of the holds CSV. Defaults to .\Reports\PurviewCaseHolds_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emit the hold objects to the pipeline.
.EXAMPLE
    PS> .\Get-PurviewCaseHolds.ps1
    Exports every case hold you can see, with flags for closed cases, distribution errors and query-based holds.
.EXAMPLE
    PS> .\Get-PurviewCaseHolds.ps1 -CaseName 'Legal*' -DistributionDetail -PerLocation -Verbose
    Exports the holds of the Legal cases with fresh distribution results and a second CSV listing every held mailbox and site.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, ExchangeOnlineManagement 3.x
    Permissions : eDiscovery Manager role group (only cases you are a member of) or eDiscovery Administrator (all cases)
    Category    : eDiscovery & content search
    Changes     : No
    Notes       : Closing a case turns its holds off, so an enabled hold on a closed case usually means the release is still pending
                  or failed - check DistributionResults. Locations are requested with -IncludeBindings; older module versions
                  without that switch fall back to the default output, where location lists can be empty.
.LINK
    https://learn.microsoft.com/powershell/module/exchange/get-caseholdpolicy
.LINK
    https://learn.microsoft.com/powershell/module/exchange/get-caseholdrule
#>
#Requires -Version 5.1
#Requires -Modules ExchangeOnlineManagement

[CmdletBinding()]
param(
    [Parameter()]
    [string]$CaseName,

    [Parameter()]
    [switch]$DistributionDetail,

    [Parameter()]
    [switch]$PerLocation,

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

function Get-LocationName {
    <# Flattens a policy location collection to strings; entries are objects with a Name property or plain strings such as 'All'. #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [AllowNull()]
        $Locations
    )
    $names = @()
    foreach ($item in @($Locations)) {
        if ($null -eq $item) { continue }
        $name = $null
        if ($null -ne $item.PSObject.Properties['Name']) { $name = [string]$item.Name }
        if ([string]::IsNullOrWhiteSpace($name)) { $name = [string]$item }
        if (-not [string]::IsNullOrWhiteSpace($name)) { $names += $name }
    }
    return $names
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('PurviewCaseHolds_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}
$locationsPath = ($OutputPath -replace '\.[^.\\/]+$', '') + '_Locations.csv'

try { Connect-ExchangeIfNeeded -Compliance } catch { throw "Unable to connect to Security & Compliance PowerShell: $($_.Exception.Message)" }

$cases = New-Object -TypeName System.Collections.Generic.List[object]
foreach ($caseType in 'eDiscovery', 'AdvancedEdiscovery') {
    try { foreach ($case in @(Get-ComplianceCase -CaseType $caseType -ErrorAction Stop)) { $cases.Add($case) } }
    catch { Write-Warning ('Could not list {0} cases: {1}' -f $caseType, $_.Exception.Message) }
}
if ($CaseName) { $cases = @($cases | Where-Object { $_.Name -like $CaseName }) }
$cases = @($cases)
if ($cases.Count -eq 0) { Write-Warning 'No eDiscovery cases matched.' }

$holds = New-Object -TypeName System.Collections.Generic.List[object]
$locationRows = New-Object -TypeName System.Collections.Generic.List[object]
$index = 0
foreach ($case in $cases) {
    $index++
    Write-Progress -Activity 'Reading case holds' -Status ('{0} of {1}: {2}' -f $index, $cases.Count, $case.Name) -PercentComplete ([int](($index / $cases.Count) * 100))
    $holdParams = @{ Case = $case.Identity; IncludeBindings = $true; DistributionDetail = $DistributionDetail.IsPresent; ErrorAction = 'Stop' }
    try { $policies = @(Get-CaseHoldPolicy @holdParams) }
    catch [System.Management.Automation.ParameterBindingException] {
        # Older module versions do not know -IncludeBindings; retry without it.
        $holdParams.Remove('IncludeBindings')
        try { $policies = @(Get-CaseHoldPolicy @holdParams) } catch { Write-Warning ("Could not read the holds of case '{0}': {1}" -f $case.Name, $_.Exception.Message); continue }
    }
    catch { Write-Warning ("Could not read the holds of case '{0}': {1}" -f $case.Name, $_.Exception.Message); continue }

    foreach ($policy in $policies) {
        $policyId = [string]$policy.Guid
        if ([string]::IsNullOrWhiteSpace($policyId)) { $policyId = [string]$policy.Name }
        $rule = $null
        try { $rule = @(Get-CaseHoldRule -Policy $policyId -ErrorAction Stop) | Select-Object -First 1 }
        catch { Write-Warning ("Could not read the rule of hold '{0}' (case '{1}'): {2}" -f $policy.Name, $case.Name, $_.Exception.Message) }

        $exchange = @(Get-LocationName -Locations $policy.ExchangeLocation)
        $sharePoint = @(Get-LocationName -Locations $policy.SharePointLocation)
        $publicFolder = @(Get-LocationName -Locations $policy.PublicFolderLocation)
        $query = [string]$rule.ContentMatchQuery
        if ($query.Length -gt 300) { $query = $query.Substring(0, 300) + '...' }
        $distribution = (@($policy.DistributionResults) | ForEach-Object { [string]$_ }) -join ' | '
        if ($distribution.Length -gt 300) { $distribution = $distribution.Substring(0, 300) + '...' }
        $ruleDisabled = ($null -ne $rule -and $rule.Disabled -eq $true)

        $flags = @()
        if ([string]$case.Status -eq 'Closed') { $flags += 'HoldOnClosedCase' }
        if ([string]$policy.DistributionStatus -like '*Error*' -or [string]$policy.DistributionStatus -like '*Fail*') { $flags += 'DistributionError' }
        if (-not [string]::IsNullOrWhiteSpace($query)) { $flags += 'QueryBased' }
        if ($policy.Enabled -ne $true -or $ruleDisabled) { $flags += 'Disabled' }
        if (($exchange.Count + $sharePoint.Count + $publicFolder.Count) -eq 0) { $flags += 'NoLocations' }

        $holds.Add([PSCustomObject]@{
                Case                 = [string]$case.Name
                CaseType             = [string]$case.CaseType
                CaseStatus           = [string]$case.Status
                Hold                 = [string]$policy.Name
                HoldGuid             = $policyId
                Enabled              = ($policy.Enabled -eq $true)
                RuleDisabled         = $ruleDisabled
                QueryBased           = (-not [string]::IsNullOrWhiteSpace($query))
                ContentMatchQuery    = $query
                ExchangeLocation     = ($exchange -join '; ')
                ExchangeCount        = $exchange.Count
                SharePointLocation   = ($sharePoint -join '; ')
                SharePointCount      = $sharePoint.Count
                PublicFolderLocation = ($publicFolder -join '; ')
                DistributionStatus   = [string]$policy.DistributionStatus
                DistributionResults  = $distribution
                WhenCreated          = $policy.WhenCreated
                WhenChanged          = $policy.WhenChanged
                Flags                = ($flags -join '; ')
            })
        if ($PerLocation) {
            $sets = @{ Exchange = $exchange; SharePoint = $sharePoint; PublicFolder = $publicFolder }
            foreach ($type in 'Exchange', 'SharePoint', 'PublicFolder') {
                foreach ($location in $sets[$type]) { $locationRows.Add([PSCustomObject]@{ Case = [string]$case.Name; Hold = [string]$policy.Name; LocationType = $type; Location = $location }) }
            }
        }
    }
}
Write-Progress -Activity 'Reading case holds' -Completed

$holds = @($holds | Sort-Object -Property Case, Hold)
if ($holds.Count -gt 0) { $holds | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 }
if ($locationRows.Count -gt 0) { $locationRows | Export-Csv -Path $locationsPath -NoTypeInformation -Encoding UTF8 }

Write-Host "`nCase hold summary" -ForegroundColor Cyan
Write-Host ('  Cases checked        : {0}' -f $cases.Count)
Write-Host ('  Holds                : {0} ({1} enabled)' -f $holds.Count, @($holds | Where-Object { $_.Enabled }).Count)
foreach ($flag in 'HoldOnClosedCase', 'DistributionError', 'QueryBased', 'Disabled', 'NoLocations') {
    $count = @($holds | Where-Object { $_.Flags -like ('*' + $flag + '*') }).Count
    Write-Host ('    {0,-19}: {1}' -f $flag, $count) -ForegroundColor $(if ($count -gt 0 -and $flag -ne 'QueryBased') { 'Yellow' } else { 'Gray' })
}
if ($holds.Count -gt 0) { Write-Host ('  Report               : {0}' -f $OutputPath) }
if ($locationRows.Count -gt 0) { Write-Host ('  Location rows        : {0} -> {1}' -f $locationRows.Count, $locationsPath) }

if ($PassThru) {
    $holds
}
#endregion Main
