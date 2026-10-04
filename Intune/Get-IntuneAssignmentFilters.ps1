<#
.SYNOPSIS
    Reports Intune assignment filters with their rules and which policies and apps use them in include or exclude mode.
.DESCRIPTION
    Reads the beta collection /deviceManagement/assignmentFilters (name, platform, rule, management type, last modified)
    and scans the assignments of device configuration profiles, compliance policies (v1.0), settings catalog policies (beta)
    and optionally apps for target.deviceAndAppManagementAssignmentFilterId. Each filter row shows UsedByCount and UsedBy
    (policy type, name and include/exclude mode), making unused filters and filter sprawl easy to spot. -ExportJsonFolder
    additionally saves every filter definition as a JSON file. Writes a CSV and optionally emits the rows.
.PARAMETER IncludeApps
    Also scan app assignments (/deviceAppManagement/mobileApps); requires DeviceManagementApps.Read.All.
.PARAMETER ExportJsonFolder
    Folder that receives one <FilterName>_<id>.json file per filter (rule included); created when missing.
.PARAMETER OutputPath
    CSV path. Defaults to .\Reports\IntuneAssignmentFilters_yyyyMMdd-HHmm.csv; the folder is created when missing.
.PARAMETER PassThru
    Also emit the report objects to the pipeline.
.EXAMPLE
    PS> .\Get-IntuneAssignmentFilters.ps1
    Lists every assignment filter with its rule and the configuration and compliance policies that reference it.
.EXAMPLE
    PS> .\Get-IntuneAssignmentFilters.ps1 -IncludeApps -ExportJsonFolder .\FilterBackup -PassThru | Where-Object { $_.UsedByCount -eq 0 }
    Includes app assignments, backs up all filter rules to .\FilterBackup and shows the filters nothing uses.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : DeviceManagementConfiguration.Read.All (delegated); DeviceManagementApps.Read.All with -IncludeApps
    Category    : Compliance, configuration & RBAC
    Changes     : No
    Notes       : Assignment filters and settings catalog policies are only exposed on the beta endpoint, which Microsoft may
                  change without notice. Assignments are read with $expand=assignments (one call per policy type), so the scan
                  is fast even in large tenants. Administrative templates, scripts and enrollment profiles are not scanned, so a
                  filter reported with UsedByCount 0 may still be referenced by one of those object types.
.LINK
    https://learn.microsoft.com/graph/api/intune-policyset-deviceandappmanagementassignmentfilter-list?view=graph-rest-beta
.LINK
    https://learn.microsoft.com/mem/intune/fundamentals/filters
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [Parameter()]
    [switch]$IncludeApps,

    [Parameter()]
    [string]$ExportJsonFolder,

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
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('IntuneAssignmentFilters_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}
if (-not [string]::IsNullOrWhiteSpace($ExportJsonFolder) -and -not (Test-Path -LiteralPath $ExportJsonFolder)) {
    New-Item -Path $ExportJsonFolder -ItemType Directory -Force | Out-Null
}

$scopes = @('DeviceManagementConfiguration.Read.All')
if ($IncludeApps) { $scopes += 'DeviceManagementApps.Read.All' }
try { Connect-GraphIfNeeded -Scopes $scopes } catch { throw "Failed to connect to Microsoft Graph: $($_.Exception.Message)" }

$graphV1 = 'https://graph.microsoft.com/v1.0'
$graphBeta = 'https://graph.microsoft.com/beta'   # beta: assignment filters and settings catalog policies are not exposed in v1.0
try {
    $filters = @(Invoke-GraphPaged -Uri ('{0}/deviceManagement/assignmentFilters?$select=id,displayName,description,platform,rule,assignmentFilterManagementType,lastModifiedDateTime' -f $graphBeta))
}
catch {
    throw "Failed to list assignment filters: $($_.Exception.Message)"
}
Write-Verbose ('{0} assignment filters found.' -f $filters.Count)

$sources = @(
    [PSCustomObject]@{ PolicyType = 'DeviceConfiguration'; Uri = ('{0}/deviceManagement/deviceConfigurations?$select=id,displayName&$expand=assignments' -f $graphV1); NameProperty = 'displayName' }
    [PSCustomObject]@{ PolicyType = 'SettingsCatalog'; Uri = ('{0}/deviceManagement/configurationPolicies?$select=id,name&$expand=assignments' -f $graphBeta); NameProperty = 'name' }
    [PSCustomObject]@{ PolicyType = 'Compliance'; Uri = ('{0}/deviceManagement/deviceCompliancePolicies?$select=id,displayName&$expand=assignments' -f $graphV1); NameProperty = 'displayName' }
)
if ($IncludeApps) {
    $appUri = '{0}/deviceAppManagement/mobileApps?$filter=isAssigned eq true&$select=id,displayName&$expand=assignments' -f $graphV1
    $sources += [PSCustomObject]@{ PolicyType = 'App'; Uri = $appUri; NameProperty = 'displayName' }
}

# filterId -> list of "PolicyType: Name (include|exclude)" strings
$usage = @{}
$emptyGuid = '00000000-0000-0000-0000-000000000000'
$index = 0
foreach ($source in $sources) {
    $index++
    Write-Progress -Activity 'Scanning assignments for filter usage' -Status $source.PolicyType -PercentComplete ([int](($index / $sources.Count) * 100))
    try {
        $policies = @(Invoke-GraphPaged -Uri $source.Uri)
    }
    catch {
        Write-Warning ('Could not read {0} assignments; usage counts exclude this type: {1}' -f $source.PolicyType, $_.Exception.Message)
        continue
    }
    foreach ($policy in $policies) {
        foreach ($assignment in @($policy.assignments)) {
            $filterId = [string]$assignment.target.deviceAndAppManagementAssignmentFilterId
            if ([string]::IsNullOrEmpty($filterId) -or $filterId -eq $emptyGuid) { continue }
            if (-not $usage.ContainsKey($filterId)) { $usage[$filterId] = New-Object -TypeName System.Collections.Generic.List[object] }
            $entry = '{0}: {1} ({2})' -f $source.PolicyType, $policy.($source.NameProperty), $assignment.target.deviceAndAppManagementAssignmentFilterType
            if ($usage[$filterId] -notcontains $entry) { $usage[$filterId].Add($entry) }
        }
    }
}
Write-Progress -Activity 'Scanning assignments for filter usage' -Completed

$results = New-Object -TypeName System.Collections.Generic.List[object]
foreach ($filter in $filters) {
    $usedBy = @()
    if ($usage.ContainsKey([string]$filter.id)) { $usedBy = @($usage[[string]$filter.id]) }
    $lastModified = $null; if (-not [string]::IsNullOrEmpty($filter.lastModifiedDateTime)) { $lastModified = [datetime]$filter.lastModifiedDateTime }
    $results.Add([PSCustomObject]@{ FilterId = $filter.id; DisplayName = $filter.displayName; Description = $filter.description; Platform = $filter.platform
            ManagementType = $filter.assignmentFilterManagementType; Rule = $filter.rule; LastModified = $lastModified
            UsedByCount = $usedBy.Count; UsedBy = ($usedBy -join '; ') })
    if (-not [string]::IsNullOrWhiteSpace($ExportJsonFolder)) {
        try {
            $safeName = (([string]$filter.displayName) -replace '[\\/:*?"<>|\x00-\x1F]', '_').Trim()
            if ([string]::IsNullOrWhiteSpace($safeName)) { $safeName = 'Unnamed' }
            $jsonPath = Join-Path -Path $ExportJsonFolder -ChildPath ('{0}_{1}.json' -f $safeName, ([string]$filter.id).Substring(0, 8))
            $filter | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $jsonPath -Encoding UTF8
        }
        catch {
            Write-Warning ("Could not export filter '{0}' to JSON: {1}" -f $filter.displayName, $_.Exception.Message)
        }
    }
}
foreach ($orphanId in @($usage.Keys | Where-Object { @($filters.id) -notcontains $_ })) {
    Write-Warning ('Filter {0} is referenced by {1} assignment(s) but no longer exists: {2}' -f $orphanId, $usage[$orphanId].Count, ($usage[$orphanId] -join '; '))
}

$results | Sort-Object -Property DisplayName | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
$unused = @($results | Where-Object { $_.UsedByCount -eq 0 }).Count
Write-Host ("`nAssignment filters : {0}" -f $results.Count) -ForegroundColor Cyan
Write-Host ('  In use           : {0}' -f ($results.Count - $unused)) -ForegroundColor Green
$unusedColour = 'Green'; if ($unused -gt 0) { $unusedColour = 'Yellow' }
Write-Host ('  Unused           : {0}' -f $unused) -ForegroundColor $unusedColour
foreach ($group in ($results | Group-Object -Property Platform | Sort-Object -Property Name)) {
    Write-Host ('  {0,-34} {1,4}' -f $group.Name, $group.Count) -ForegroundColor Gray
}
Write-Host ('Report saved to {0}' -f $OutputPath) -ForegroundColor Cyan
if (-not [string]::IsNullOrWhiteSpace($ExportJsonFolder)) { Write-Host ('Filter rules exported to {0}' -f $ExportJsonFolder) -ForegroundColor Cyan }
if ($PassThru) { $results }
#endregion Main
