<#
.SYNOPSIS
    Reports eDiscovery (Premium) cases through Microsoft Graph, optionally with custodians, legal holds, searches and review sets.
.DESCRIPTION
    Reads GET /security/cases/ediscoveryCases (v1.0) and writes one row per case: name, status, description, external ID,
    created, modified and closed timestamps and who closed it. With -IncludeCustodians, -IncludeHolds, -IncludeSearches and
    -IncludeReviewSets it also reads the child collections (/custodians, /legalHolds, /searches, /reviewSets) of every case,
    adds the counts to the case rows and writes the details to <base>_Custodians.csv, <base>_Holds.csv, <base>_Searches.csv
    and <base>_ReviewSets.csv. The script is read-only.
.PARAMETER IncludeCustodians
    Also export the custodians of each case (email, display name, status, hold status, acknowledged and released dates).
.PARAMETER IncludeHolds
    Also export the legal holds of each case (display name, enabled, status, content query).
.PARAMETER IncludeSearches
    Also export the searches (collections) of each case.
.PARAMETER IncludeReviewSets
    Also export the review sets of each case.
.PARAMETER OutputPath
    Path of the cases CSV. Defaults to .\Reports\PurviewEDiscoveryCasesGraph_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emit the case objects to the pipeline.
.EXAMPLE
    PS> .\Get-PurviewEDiscoveryCasesViaGraph.ps1
    Exports every eDiscovery (Premium) case the signed-in user can access.
.EXAMPLE
    PS> .\Get-PurviewEDiscoveryCasesViaGraph.ps1 -IncludeCustodians -IncludeHolds -Verbose
    Exports the cases plus a custodian list and a hold list as separate CSV files next to the case report.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : Delegated eDiscovery.Read.All; the signed-in user must be an eDiscovery Manager (own cases) or eDiscovery
                  Administrator (all cases) in Microsoft Purview.
    Category    : eDiscovery & content search
    Changes     : No
    Notes       : The Graph eDiscovery API covers eDiscovery (Premium) cases only (Microsoft 365 E5 / E5 Compliance licensing);
                  eDiscovery (Standard) cases and content searches are not returned - use Get-PurviewEDiscoveryCases.ps1 for those.
                  Child collections are read per case, so large tenants with many cases take a while and may be throttled.
.LINK
    https://learn.microsoft.com/graph/api/security-casesroot-list-ediscoverycases
.LINK
    https://learn.microsoft.com/graph/api/security-ediscoverycase-list-custodians
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [Parameter()]
    [switch]$IncludeCustodians,

    [Parameter()]
    [switch]$IncludeHolds,

    [Parameter()]
    [switch]$IncludeSearches,

    [Parameter()]
    [switch]$IncludeReviewSets,

    [Parameter()]
    [string]$OutputPath,

    [Parameter()]
    [switch]$PassThru
)

$ErrorActionPreference = 'Stop'

#region Helpers
function Connect-GraphIfNeeded {
    <# Connects to Microsoft Graph only when there is no usable session for the required scopes. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Scopes
    )
    $context = Get-MgContext
    $missingScopes = @()
    if ($null -ne $context) {
        $missingScopes = @($Scopes | Where-Object { $context.Scopes -notcontains $_ })
    }
    if ($null -eq $context -or $missingScopes.Count -gt 0) {
        Write-Verbose "Connecting to Microsoft Graph with scopes: $($Scopes -join ', ')"
        Connect-MgGraph -Scopes $Scopes -NoWelcome -ErrorAction Stop | Out-Null
    }
    else {
        Write-Verbose "Reusing existing Microsoft Graph session for $($context.Account)."
    }
}

function Invoke-GraphPaged {
    <# GET helper that follows @odata.nextLink and returns every item in 'value'. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Uri,

        [Parameter()]
        [hashtable]$Headers
    )
    $results = New-Object -TypeName System.Collections.Generic.List[object]
    $nextLink = $Uri
    while (-not [string]::IsNullOrEmpty($nextLink)) {
        $requestParams = @{ Method = 'GET'; Uri = $nextLink; OutputType = 'PSObject'; ErrorAction = 'Stop' }
        if ($null -ne $Headers) { $requestParams['Headers'] = $Headers }
        $response = Invoke-MgGraphRequest @requestParams
        if ($null -ne $response.PSObject.Properties['value']) {
            foreach ($item in $response.value) { $results.Add($item) }
        }
        elseif ($null -ne $response) {
            $results.Add($response)
        }
        $nextLink = $response.'@odata.nextLink'
    }
    return $results
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('PurviewEDiscoveryCasesGraph_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}
$basePath = $OutputPath -replace '\.[^.\\/]+$', ''

try { Connect-GraphIfNeeded -Scopes @('eDiscovery.Read.All') } catch { throw "Failed to connect to Microsoft Graph: $($_.Exception.Message)" }

$baseUri = 'https://graph.microsoft.com/v1.0/security/cases/ediscoveryCases'
$caseSelect = 'id,displayName,status,description,externalId,createdDateTime,lastModifiedDateTime,closedDateTime,closedBy'
try { $cases = @(Invoke-GraphPaged -Uri ('{0}?$select={1}' -f $baseUri, $caseSelect)) }
catch { throw "Failed to list eDiscovery (Premium) cases (requires eDiscovery.Read.All and eDiscovery (Premium) licensing): $($_.Exception.Message)" }
if ($cases.Count -eq 0) { Write-Warning 'No eDiscovery (Premium) cases were returned for this account.' }

# Child collections share one generic reader: the $select list doubles as the CSV column list (PascalCased).
$children = [ordered]@{
    Custodians = @{ Enabled = $IncludeCustodians.IsPresent; Path = 'custodians'; Select = 'email,displayName,status,holdStatus,acknowledgedDateTime,createdDateTime,releasedDateTime' }
    Holds      = @{ Enabled = $IncludeHolds.IsPresent; Path = 'legalHolds'; Select = 'displayName,isEnabled,status,contentQuery,createdDateTime,lastModifiedDateTime' }
    Searches   = @{ Enabled = $IncludeSearches.IsPresent; Path = 'searches'; Select = 'displayName,description,contentQuery,createdDateTime,lastModifiedDateTime' }
    ReviewSets = @{ Enabled = $IncludeReviewSets.IsPresent; Path = 'reviewSets'; Select = 'displayName,createdDateTime' }
}
$childRows = @{}
foreach ($key in $children.Keys) { $childRows[$key] = New-Object -TypeName System.Collections.Generic.List[object] }

$results = New-Object -TypeName System.Collections.Generic.List[object]
$index = 0
foreach ($case in $cases) {
    $index++
    Write-Progress -Activity 'Reading eDiscovery (Premium) cases' -Status ('{0} of {1}: {2}' -f $index, $cases.Count, $case.displayName) -PercentComplete ([int](($index / $cases.Count) * 100))
    $counts = @{}
    foreach ($key in $children.Keys) {
        $counts[$key] = $null
        if (-not $children[$key].Enabled) { continue }
        $uri = '{0}/{1}/{2}?$select=id,{3}' -f $baseUri, $case.id, $children[$key].Path, $children[$key].Select
        try { $items = @(Invoke-GraphPaged -Uri $uri) }
        catch { Write-Warning ("Could not read {0} of case '{1}': {2}" -f $key, $case.displayName, $_.Exception.Message); continue }
        $counts[$key] = $items.Count
        foreach ($item in $items) {
            $row = [ordered]@{ Case = [string]$case.displayName; CaseId = [string]$case.id; Id = [string]$item.id }
            foreach ($field in $children[$key].Select.Split(',')) {
                $value = $item.$field
                if ($field -like '*DateTime' -and -not [string]::IsNullOrEmpty([string]$value)) { $value = [datetime]$value }
                $row[$field.Substring(0, 1).ToUpper() + $field.Substring(1)] = $value
            }
            $childRows[$key].Add([PSCustomObject]$row)
        }
        Start-Sleep -Milliseconds 200
    }

    $closedBy = $null
    if ($null -ne $case.closedBy) {
        if ($null -ne $case.closedBy.user) { $closedBy = [string]$case.closedBy.user.displayName }
        elseif ($null -ne $case.closedBy.application) { $closedBy = [string]$case.closedBy.application.displayName }
    }
    $results.Add([PSCustomObject]@{
            Id                   = [string]$case.id
            DisplayName          = [string]$case.displayName
            Status               = [string]$case.status
            Description          = [string]$case.description
            ExternalId           = [string]$case.externalId
            CreatedDateTime      = $(if ($case.createdDateTime) { [datetime]$case.createdDateTime } else { $null })
            LastModifiedDateTime = $(if ($case.lastModifiedDateTime) { [datetime]$case.lastModifiedDateTime } else { $null })
            ClosedDateTime       = $(if ($case.closedDateTime) { [datetime]$case.closedDateTime } else { $null })
            ClosedBy             = $closedBy
            CustodianCount       = $counts['Custodians']
            HoldCount            = $counts['Holds']
            SearchCount          = $counts['Searches']
            ReviewSetCount       = $counts['ReviewSets']
        })
}
Write-Progress -Activity 'Reading eDiscovery (Premium) cases' -Completed

$results = @($results | Sort-Object -Property Status, DisplayName)
if ($results.Count -gt 0) { $results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 }
foreach ($key in $children.Keys) {
    if ($childRows[$key].Count -gt 0) { $childRows[$key] | Export-Csv -Path ('{0}_{1}.csv' -f $basePath, $key) -NoTypeInformation -Encoding UTF8 }
}

Write-Host "`neDiscovery (Premium) case summary" -ForegroundColor Cyan
Write-Host ('  Cases       : {0}' -f $results.Count)
foreach ($group in ($results | Group-Object -Property Status | Sort-Object -Property Name)) {
    Write-Host ('    {0,5}  {1}' -f $group.Count, $group.Name)
}
foreach ($key in $children.Keys) {
    if ($children[$key].Enabled) { Write-Host ('  {0,-12}: {1} -> {2}_{0}.csv' -f $key, $childRows[$key].Count, $basePath) }
}
if ($results.Count -gt 0) { Write-Host ('  Report      : {0}' -f $OutputPath) }

if ($PassThru) {
    $results
}
#endregion Main
