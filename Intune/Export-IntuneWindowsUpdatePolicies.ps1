<#
.SYNOPSIS
    Exports Windows update rings, feature update, expedited quality update and driver update profiles with their assignments to JSON and a summary CSV.
.DESCRIPTION
    Reads update rings from Microsoft Graph v1.0 (/deviceManagement/deviceConfigurations?$expand=assignments, filtered to
    windowsUpdateForBusinessConfiguration) and the feature, quality and driver update profiles from the beta endpoint
    (/windowsFeatureUpdateProfiles, /windowsQualityUpdateProfiles, /windowsDriverUpdateProfiles with $expand=assignments).
    Every policy is written as JSON into <OutputFolder>\<Kind>\ and summarised in WindowsUpdatePolicies.csv with its key
    settings (deferrals, deadlines, pause state, feature version, approval type) and assignment targets.
.PARAMETER OutputFolder
    Root folder for the export. Defaults to .\IntuneUpdatePoliciesExport_yyyyMMdd-HHmm and is created when missing.
.PARAMETER PassThru
    Also emit the CSV summary rows to the pipeline.
.EXAMPLE
    PS> .\Export-IntuneWindowsUpdatePolicies.ps1
    Exports every update ring and update profile to .\IntuneUpdatePoliciesExport_<timestamp>\<Kind>\ and writes the summary CSV.
.EXAMPLE
    PS> .\Export-IntuneWindowsUpdatePolicies.ps1 -OutputFolder D:\Backups\WindowsUpdate -PassThru | Where-Object { $_.AssignedGroups -eq '' }
    Exports to D:\Backups\WindowsUpdate and lists the policies that are not assigned to anything.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : DeviceManagementConfiguration.Read.All (delegated) plus an Intune RBAC role such as Read Only Operator
    Category    : Updates & remediations
    Changes     : No
    Notes       : Feature, quality (expedite) and driver update profiles exist only on the beta endpoint, which Microsoft may
                  change without notice; they require Windows Enterprise E3/E5, Education A3/A5 or Windows 365 licensing.
                  AssignedGroups shows group IDs (Group:<id>, Exclude:<id>) because no Group.Read.All scope is requested; use
                  Get-IntunePolicyAssignments.ps1 for names. Windows PowerShell 5.1 writes JSON dates as "\/Date(...)\/".
.LINK
    https://learn.microsoft.com/graph/api/intune-deviceconfig-windowsupdateforbusinessconfiguration-list
.LINK
    https://learn.microsoft.com/graph/api/intune-softwareupdate-windowsfeatureupdateprofile-list?view=graph-rest-beta
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputFolder,

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

function Get-SafeFileName {
    <# Builds a file-system safe, length-limited file name with a short id suffix so duplicate policy names cannot collide. #>
    param([string]$Name, [string]$Id)
    $clean = ([string]$Name -replace '[\\/:*?"<>|\x00-\x1F]', '_').Trim()
    if ([string]::IsNullOrWhiteSpace($clean)) { $clean = 'Unnamed' }
    if ($clean.Length -gt 100) { $clean = $clean.Substring(0, 100).TrimEnd() }
    return ('{0}_{1}' -f $clean, $Id.Substring(0, [Math]::Min(8, $Id.Length)))
}

function ConvertTo-KeySettings {
    <# Flattens the listed policy properties into 'name=value; name=value'; nested objects become compact JSON. #>
    param([object]$Policy, [string[]]$Properties)
    $parts = New-Object -TypeName System.Collections.Generic.List[string]
    foreach ($name in $Properties) {
        $property = $Policy.PSObject.Properties[$name]
        if ($null -eq $property -or $null -eq $property.Value) { continue }
        $text = [string]$property.Value
        if (-not ($property.Value -is [string] -or $property.Value -is [System.ValueType])) { $text = $property.Value | ConvertTo-Json -Compress -Depth 5 }
        $parts.Add(('{0}={1}' -f $name, $text))
    }
    return ($parts -join '; ')
}

function ConvertTo-AssignmentLabel {
    <# Describes an assignment target as 'All devices', 'All users', 'Group:<id>' or 'Exclude:<id>' plus the assignment filter mode. #>
    param([object]$Assignment)
    $target = $Assignment.target
    switch ([string]$target.'@odata.type') {
        '#microsoft.graph.allDevicesAssignmentTarget' { $label = 'All devices' }
        '#microsoft.graph.allLicensedUsersAssignmentTarget' { $label = 'All users' }
        '#microsoft.graph.exclusionGroupAssignmentTarget' { $label = 'Exclude:{0}' -f $target.groupId }
        '#microsoft.graph.groupAssignmentTarget' { $label = 'Group:{0}' -f $target.groupId }
        default { $label = ([string]$target.'@odata.type') -replace '^#microsoft\.graph\.', '' }
    }
    $filterType = [string]$target.deviceAndAppManagementAssignmentFilterType
    if (-not [string]::IsNullOrEmpty($filterType) -and $filterType -ne 'none') { $label += ' [filter: {0}]' -f $filterType }
    return $label
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputFolder)) {
    $OutputFolder = Join-Path -Path (Get-Location).Path -ChildPath ('IntuneUpdatePoliciesExport_{0}' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
if (-not (Test-Path -LiteralPath $OutputFolder)) { New-Item -Path $OutputFolder -ItemType Directory -Force | Out-Null }

try { Connect-GraphIfNeeded -Scopes @('DeviceManagementConfiguration.Read.All') } catch { throw "Failed to connect to Microsoft Graph: $($_.Exception.Message)" }

$graphV1 = 'https://graph.microsoft.com/v1.0/deviceManagement'
$graphBeta = 'https://graph.microsoft.com/beta/deviceManagement'   # beta: feature, quality and driver update profiles are not exposed in v1.0
$catalog = @(
    [PSCustomObject]@{ Kind = 'UpdateRing'; Uri = $graphV1 + '/deviceConfigurations?$expand=assignments'; TypeFilter = '#microsoft.graph.windowsUpdateForBusinessConfiguration'
        KeyProperties = @('qualityUpdatesDeferralPeriodInDays', 'featureUpdatesDeferralPeriodInDays', 'deadlineForQualityUpdatesInDays', 'deadlineForFeatureUpdatesInDays', 'deadlineGracePeriodInDays',
            'automaticUpdateMode', 'businessReadyUpdatesOnly', 'driversExcluded', 'allowWindows11Upgrade', 'installationSchedule', 'userPauseAccess', 'qualityUpdatesPaused', 'featureUpdatesPaused') }
    [PSCustomObject]@{ Kind = 'FeatureUpdateProfile'; Uri = $graphBeta + '/windowsFeatureUpdateProfiles?$expand=assignments'; TypeFilter = $null
        KeyProperties = @('featureUpdateVersion', 'rolloutSettings', 'installLatestWindows10OnWindows11IneligibleDevice', 'installFeatureUpdatesOptional') }
    [PSCustomObject]@{ Kind = 'QualityUpdateProfile'; Uri = $graphBeta + '/windowsQualityUpdateProfiles?$expand=assignments'; TypeFilter = $null; KeyProperties = @('expeditedUpdateSettings') }
    [PSCustomObject]@{ Kind = 'DriverUpdateProfile'; Uri = $graphBeta + '/windowsDriverUpdateProfiles?$expand=assignments'; TypeFilter = $null
        KeyProperties = @('approvalType', 'deviceReporting', 'newUpdates', 'deploymentDeferralInDays', 'inventorySyncStatus') }
)

$rows = New-Object -TypeName System.Collections.Generic.List[object]; $summary = New-Object -TypeName System.Collections.Generic.List[object]
foreach ($entry in $catalog) {
    Write-Verbose ('Listing {0} policies from {1}' -f $entry.Kind, $entry.Uri)
    try { $policies = @(Invoke-GraphPaged -Uri $entry.Uri) }
    catch {
        Write-Warning ('Could not list {0} policies: {1}' -f $entry.Kind, $_.Exception.Message)
        $summary.Add([PSCustomObject]@{ Kind = $entry.Kind; Found = 0; Exported = 0; Failed = 0 })
        continue
    }
    # deviceConfigurations returns every profile type; only Windows Update for Business rings are wanted here.
    if ($null -ne $entry.TypeFilter) { $policies = @($policies | Where-Object { $_.'@odata.type' -eq $entry.TypeFilter }) }
    $kindFolder = Join-Path -Path $OutputFolder -ChildPath $entry.Kind
    if (-not (Test-Path -LiteralPath $kindFolder)) { New-Item -Path $kindFolder -ItemType Directory -Force | Out-Null }
    $exported = 0; $failed = 0; $index = 0
    foreach ($policy in $policies) {
        $index++
        $policyName = [string]$policy.displayName
        Write-Progress -Activity ('Exporting {0}' -f $entry.Kind) -Status ('{0} of {1}: {2}' -f $index, $policies.Count, $policyName) -PercentComplete ([int](($index / $policies.Count) * 100))
        try {
            $jsonPath = Join-Path -Path $kindFolder -ChildPath ('{0}.json' -f (Get-SafeFileName -Name $policyName -Id ([string]$policy.id)))
            # -LiteralPath: policy names may legitimately contain [ ] which -Path would treat as wildcards.
            $policy | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $jsonPath -Encoding UTF8
            $labels = @($policy.assignments | Where-Object { $null -ne $_ } | ForEach-Object { ConvertTo-AssignmentLabel -Assignment $_ })
            $rows.Add([PSCustomObject]@{
                    Kind           = $entry.Kind
                    Name           = $policyName
                    KeySettings    = ConvertTo-KeySettings -Policy $policy -Properties $entry.KeyProperties
                    AssignedGroups = ($labels -join '; ')
                    Id             = $policy.id
                    JsonFile       = $jsonPath
                })
            $exported++
        }
        catch {
            $failed++; Write-Warning ("Failed to export {0} '{1}' ({2}): {3}" -f $entry.Kind, $policyName, $policy.id, $_.Exception.Message)
        }
    }
    Write-Progress -Activity ('Exporting {0}' -f $entry.Kind) -Completed
    $summary.Add([PSCustomObject]@{ Kind = $entry.Kind; Found = $policies.Count; Exported = $exported; Failed = $failed })
}

if ($rows.Count -gt 0) { $rows | Export-Csv -Path (Join-Path -Path $OutputFolder -ChildPath 'WindowsUpdatePolicies.csv') -NoTypeInformation -Encoding UTF8 }
else { Write-Warning 'No Windows update policies were found; the summary CSV was not written.' }

Write-Host ('Export folder : {0}' -f $OutputFolder) -ForegroundColor Cyan
Write-Host ('{0,-22} {1,6} {2,9} {3,7}' -f 'Kind', 'Found', 'Exported', 'Failed') -ForegroundColor Cyan
foreach ($row in $summary) {
    $colour = 'Green'; if ($row.Failed -gt 0) { $colour = 'Yellow' }
    Write-Host ('{0,-22} {1,6} {2,9} {3,7}' -f $row.Kind, $row.Found, $row.Exported, $row.Failed) -ForegroundColor $colour
}
$unassigned = @($rows | Where-Object { [string]::IsNullOrEmpty($_.AssignedGroups) }).Count
if ($unassigned -gt 0) { Write-Host ('Policies without any assignment: {0}' -f $unassigned) -ForegroundColor Yellow }

if ($PassThru) { $rows }
#endregion Main
