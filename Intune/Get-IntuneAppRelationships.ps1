<#
.SYNOPSIS
    Reports Win32 app dependencies and supersedence relationships and flags superseded apps that are still assigned.
.DESCRIPTION
    Lists every Win32 app (beta /deviceAppManagement/mobileApps filtered to #microsoft.graph.win32LobApp) and reads
    /deviceAppManagement/mobileApps/{id}/relationships for each one. Dependencies (dependencyType autoInstall or detect) and
    supersedence links (supersedenceType update or replace) are flattened into one row per app and target. Direction is derived
    from targetType: child means the app depends on / supersedes the target (DependsOn, Supersedes); parent means the target
    depends on / supersedes the app (RequiredBy, SupersededBy). Rows where a superseded app is still assigned are flagged so
    stale assignments can be cleaned up.
.PARAMETER AppName
    Wildcard pattern applied to the Win32 app display name, for example '7-Zip*'. Default: all Win32 apps.
.PARAMETER IncludeAppsWithoutRelationships
    Also emit a row (RelationshipType 'None') for Win32 apps that have no dependency or supersedence links.
.PARAMETER OutputPath
    CSV file to create. Defaults to .\Reports\IntuneAppRelationships_yyyyMMdd-HHmm.csv; the folder is created when missing.
.PARAMETER PassThru
    Also emit the report objects to the pipeline.
.EXAMPLE
    PS> .\Get-IntuneAppRelationships.ps1
    Exports all Win32 dependency and supersedence links and prints how many superseded apps are still assigned.
.EXAMPLE
    PS> .\Get-IntuneAppRelationships.ps1 -AppName 'Adobe*' -PassThru | Where-Object { $_.Flag } | Format-Table App, Direction, Target, TargetVersion
    Shows the superseded Adobe apps that still carry assignments and which newer app replaces them.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : DeviceManagementApps.Read.All (delegated) plus an Intune RBAC role with "Mobile apps" read permission.
    Category    : Apps & app protection
    Changes     : No
    Notes       : The relationships navigation exists only on the beta endpoint and may change without notice. One Graph call is
                  made per Win32 app (with a 200 ms pause), so large catalogues take a few minutes. Each link is reported from both
                  apps' perspectives; filter on Direction DependsOn/Supersedes for a de-duplicated list. Only Win32 apps support
                  dependencies and supersedence in Intune.
.LINK
    https://learn.microsoft.com/graph/api/intune-apps-mobileapprelationship-list?view=graph-rest-beta
.LINK
    https://learn.microsoft.com/mem/intune/apps/apps-win32-supersedence
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [Parameter()]
    [string]$AppName,

    [Parameter()]
    [switch]$IncludeAppsWithoutRelationships,

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
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('IntuneAppRelationships_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}

try { Connect-GraphIfNeeded -Scopes @('DeviceManagementApps.Read.All') }
catch { throw "Failed to connect to Microsoft Graph: $($_.Exception.Message)" }

# beta: the relationships navigation and the isof() type filter are not available on v1.0.
$appsUri = 'https://graph.microsoft.com/beta/deviceAppManagement/mobileApps'
$select = '$select=id,displayName,displayVersion,isAssigned'
try { $apps = @(Invoke-GraphPaged -Uri ("{0}?`$filter=isof('microsoft.graph.win32LobApp')&{1}" -f $appsUri, $select)) }
catch {
    # Some tenants reject the server-side type filter; fall back to a client-side filter on @odata.type.
    Write-Verbose ('Server-side type filter failed ({0}); filtering client-side.' -f $_.Exception.Message)
    try { $apps = @(Invoke-GraphPaged -Uri ('{0}?{1}' -f $appsUri, $select) | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.win32LobApp' }) }
    catch { throw "Failed to list Win32 apps: $($_.Exception.Message)" }
}
if (-not [string]::IsNullOrWhiteSpace($AppName)) { $apps = @($apps | Where-Object { $_.displayName -like $AppName }) }
Write-Verbose ('{0} Win32 apps selected.' -f $apps.Count)

# From the queried app's point of view: a 'child' target is what it depends on / supersedes, a 'parent' target depends on / supersedes it.
$directionMap = @{
    'mobileAppDependency|child'    = 'DependsOn'
    'mobileAppDependency|parent'   = 'RequiredBy'
    'mobileAppSupersedence|child'  = 'Supersedes'
    'mobileAppSupersedence|parent' = 'SupersededBy'
}
$rows = New-Object -TypeName System.Collections.Generic.List[object]
$failed = 0
$index = 0
foreach ($app in $apps) {
    $index++
    Write-Progress -Activity 'Reading Win32 app relationships' -Status ('{0} of {1}: {2}' -f $index, $apps.Count, $app.displayName) -PercentComplete ([int](($index / $apps.Count) * 100))
    try { $relationships = @(Invoke-GraphPaged -Uri ('{0}/{1}/relationships' -f $appsUri, $app.id)) }
    catch {
        $failed++
        Write-Warning ("Failed to read relationships of '{0}' ({1}): {2}" -f $app.displayName, $app.id, $_.Exception.Message)
        continue
    }
    Start-Sleep -Milliseconds 200

    if ($relationships.Count -eq 0) {
        if ($IncludeAppsWithoutRelationships) {
            $rows.Add([PSCustomObject]@{ App = $app.displayName; AppVersion = $app.displayVersion; AppAssigned = [bool]$app.isAssigned; RelationshipType = 'None'
                    Direction = $null; Target = $null; TargetVersion = $null; Type = $null; Flag = $null; AppId = $app.id; TargetId = $null })
        }
        continue
    }
    foreach ($relationship in $relationships) {
        $typeName = ([string]$relationship.'@odata.type') -replace '^#microsoft\.graph\.', ''
        $direction = $directionMap[('{0}|{1}' -f $typeName, [string]$relationship.targetType)]
        if (-not $direction) { $direction = '{0}:{1}' -f $typeName, $relationship.targetType }
        $linkType = $relationship.dependencyType
        if ($typeName -eq 'mobileAppSupersedence') { $linkType = $relationship.supersedenceType }
        $flag = $null
        if ($direction -eq 'SupersededBy' -and [bool]$app.isAssigned) { $flag = 'Superseded app is still assigned' }
        $rows.Add([PSCustomObject]@{
                App              = $app.displayName
                AppVersion       = $app.displayVersion
                AppAssigned      = [bool]$app.isAssigned
                RelationshipType = ($typeName -replace '^mobileApp', '')
                Direction        = $direction
                Target           = $relationship.targetDisplayName
                TargetVersion    = $relationship.targetDisplayVersion
                Type             = $linkType
                Flag             = $flag
                AppId            = $app.id
                TargetId         = $relationship.targetId
            })
    }
}
Write-Progress -Activity 'Reading Win32 app relationships' -Completed

if ($rows.Count -gt 0) {
    $rows | Sort-Object -Property App, RelationshipType, Direction, Target | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
    Write-Host ('Report written to {0}' -f $OutputPath) -ForegroundColor Green
}
else { Write-Warning 'No dependency or supersedence relationships were found for the selected Win32 apps.' }

$flagged = @($rows | Where-Object { $_.Flag } | Select-Object -ExpandProperty AppId -Unique).Count
$flaggedColour = 'Green'; if ($flagged -gt 0) { $flaggedColour = 'Red' }
$failedColour = 'Green'; if ($failed -gt 0) { $failedColour = 'Yellow' }
Write-Host ("`nWin32 apps scanned            : {0}" -f $apps.Count) -ForegroundColor Cyan
Write-Host ('Apps with relationships       : {0}' -f @($rows | Where-Object { $_.RelationshipType -ne 'None' } | Select-Object -ExpandProperty AppId -Unique).Count) -ForegroundColor Cyan
Write-Host ('Superseded but still assigned : {0}' -f $flagged) -ForegroundColor $flaggedColour
Write-Host ('Apps failed to read           : {0}' -f $failed) -ForegroundColor $failedColour
foreach ($group in ($rows | Where-Object { $_.Direction } | Group-Object -Property Direction | Sort-Object -Property Name)) { Write-Host ('  {0,-14} {1,6}' -f $group.Name, $group.Count) }

if ($PassThru) { $rows }
#endregion Main
