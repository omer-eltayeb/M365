<#
.SYNOPSIS
    Exports every Intune app with its assignments to one JSON file per app plus an Apps.csv inventory index.
.DESCRIPTION
    Reads all mobile apps from Microsoft Graph (beta /deviceAppManagement/mobileApps?$expand=assignments),
    optionally filtered by app type, display name or assignment state, and writes each app including its
    assignments to <OutputFolder>\<AppType>\<AppName>_<id>.json. The Apps.csv index lists name, type,
    publisher, version, created/modified dates, assignment count, package size and - for Win32 apps -
    the install/uninstall command lines and the number of detection rules. Use it as a documentation
    backup before clean-ups or tenant migrations and to audit which apps are actually assigned.
.PARAMETER OutputFolder
    Root folder for the export. Defaults to .\IntuneAppsExport_yyyyMMdd-HHmm and is created when missing.
.PARAMETER AppType
    One or more app types to include, matched with wildcards against the Graph type name without the
    #microsoft.graph. prefix, for example 'win32LobApp', 'winGetApp' or 'macOS*'. Default: all types.
.PARAMETER AppName
    Wildcard pattern applied to the app display name, for example 'Adobe*'.
.PARAMETER AssignedOnly
    Export only apps with at least one assignment (server-side filter isAssigned eq true).
.PARAMETER PassThru
    Also emit the Apps.csv index rows to the pipeline.
.EXAMPLE
    PS> .\Export-IntuneApps.ps1
    Exports every app to .\IntuneAppsExport_<timestamp>\<AppType>\ and writes Apps.csv next to the type folders.
.EXAMPLE
    PS> .\Export-IntuneApps.ps1 -AppType win32LobApp -AssignedOnly -OutputFolder D:\Backups\IntuneApps -Verbose
    Exports only assigned Win32 apps; the index includes their install/uninstall commands and detection rule counts.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : DeviceManagementApps.Read.All (delegated) plus an Intune RBAC role such as Read Only Operator
    Category    : Apps & app protection
    Changes     : No
    Notes       : beta is used because it returns newer app types and properties (for example Win32 dependency and
                  supersedence counts) ahead of v1.0 and may change without notice. The list also contains the Microsoft
                  pre-populated managed store apps; use -AssignedOnly to limit the export to apps you deployed. App content
                  (.intunewin, .pkg) cannot be downloaded through Graph, so this is a configuration backup, not a restore
                  tool. On Windows PowerShell 5.1 ConvertTo-Json writes dates as "\/Date(...)\/"; PowerShell 7 writes ISO 8601.
.LINK
    https://learn.microsoft.com/graph/api/intune-apps-mobileapp-list?view=graph-rest-beta
.LINK
    https://learn.microsoft.com/graph/api/resources/intune-apps-win32lobapp?view=graph-rest-beta
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputFolder,

    [Parameter()]
    [string[]]$AppType = @(),

    [Parameter()]
    [string]$AppName,

    [Parameter()]
    [switch]$AssignedOnly,

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

function ConvertTo-UtcDateTime {
    <# Normalises a Graph date value (string or DateTime) to a UTC [datetime]; returns $null for empty or 0001-01-01 placeholders. #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [object]$Value
    )
    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) { return $null }
    try { $parsed = [datetime]$Value } catch { return $null }
    if ($parsed.Year -le 1) { return $null }
    return $parsed.ToUniversalTime()
}

function Get-SafeFileName {
    <# Builds a file-system safe, length-limited file name and appends a short id suffix so duplicate app names cannot collide. #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [string]$Id
    )
    $clean = ([string]$Name -replace '[\\/:*?"<>|\x00-\x1F]', '_').Trim()
    if ([string]::IsNullOrWhiteSpace($clean)) { $clean = 'Unnamed' }
    if ($clean.Length -gt 100) { $clean = $clean.Substring(0, 100).TrimEnd() }
    return ('{0}_{1}' -f $clean, $Id.Substring(0, [math]::Min(8, $Id.Length)))
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputFolder)) {
    $OutputFolder = Join-Path -Path (Get-Location).Path -ChildPath ('IntuneAppsExport_{0}' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
if (-not (Test-Path -LiteralPath $OutputFolder)) {
    New-Item -Path $OutputFolder -ItemType Directory -Force | Out-Null
}
# .NET file APIs ignore the PowerShell current location, so work with an absolute provider path.
$OutputFolder = (Resolve-Path -LiteralPath $OutputFolder).ProviderPath

try {
    Connect-GraphIfNeeded -Scopes @('DeviceManagementApps.Read.All')
}
catch {
    throw "Failed to connect to Microsoft Graph: $($_.Exception.Message)"
}

# beta: returns newer app types and properties (for example Win32 dependency and supersedence counts) that v1.0 does not expose yet.
$uri = 'https://graph.microsoft.com/beta/deviceAppManagement/mobileApps?$expand=assignments'
if ($AssignedOnly) { $uri += '&$filter=isAssigned eq true' }
try {
    $apps = @(Invoke-GraphPaged -Uri $uri)
}
catch {
    throw "Failed to list Intune apps: $($_.Exception.Message)"
}
if (-not [string]::IsNullOrWhiteSpace($AppName)) {
    $apps = @($apps | Where-Object { $_.displayName -like $AppName })
}

# Each app type stores its version under a different property; the first populated one wins.
$versionProperties = @('displayVersion', 'versionName', 'versionNumber', 'primaryBundleVersion', 'productVersion', 'identityVersion')
$index = New-Object -TypeName System.Collections.Generic.List[object]
$failed = 0
$position = 0
foreach ($app in $apps) {
    $position++
    Write-Progress -Activity 'Exporting Intune apps' -Status ('{0} of {1}: {2}' -f $position, $apps.Count, $app.displayName) -PercentComplete ([int](($position / $apps.Count) * 100))
    $typeName = ([string]$app.'@odata.type') -replace '^#microsoft\.graph\.', ''
    if ($AppType.Count -gt 0 -and @($AppType | Where-Object { $typeName -like $_ }).Count -eq 0) { continue }

    $version = $null
    foreach ($propertyName in $versionProperties) {
        $property = $app.PSObject.Properties[$propertyName]
        if ($null -ne $property -and -not [string]::IsNullOrWhiteSpace([string]$property.Value)) { $version = [string]$property.Value; break }
    }
    $isWin32 = ($typeName -eq 'win32LobApp')
    $detectionRuleCount = $null
    if ($isWin32) {
        # Older Win32 apps expose detectionRules; newer ones only carry detection rules inside the unified rules collection.
        $detectionRuleCount = @($app.detectionRules).Count
        if ($detectionRuleCount -eq 0) { $detectionRuleCount = @($app.rules | Where-Object { $_.ruleType -eq 'detection' }).Count }
    }
    $sizeMB = $null
    if ($null -ne $app.size -and [int64]$app.size -gt 0) { $sizeMB = [math]::Round([int64]$app.size / 1MB, 2) }

    $typeFolder = Join-Path -Path $OutputFolder -ChildPath $typeName
    if (-not (Test-Path -LiteralPath $typeFolder)) { New-Item -Path $typeFolder -ItemType Directory -Force | Out-Null }
    $jsonPath = Join-Path -Path $typeFolder -ChildPath ((Get-SafeFileName -Name $app.displayName -Id $app.id) + '.json')
    try {
        # -LiteralPath: app names may legitimately contain [ ] which -Path would treat as wildcards.
        $app | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $jsonPath -Encoding UTF8
    }
    catch {
        $failed++
        $jsonPath = $null
        Write-Warning ("Failed to write '{0}' ({1}): {2}" -f $app.displayName, $app.id, $_.Exception.Message)
    }

    $installCommand = $null
    $uninstallCommand = $null
    if ($isWin32) {
        $installCommand = $app.installCommandLine
        $uninstallCommand = $app.uninstallCommandLine
    }
    $index.Add([PSCustomObject]@{
            Name               = $app.displayName
            AppType            = $typeName
            Publisher          = $app.publisher
            Version            = $version
            Created            = ConvertTo-UtcDateTime -Value $app.createdDateTime
            Modified           = ConvertTo-UtcDateTime -Value $app.lastModifiedDateTime
            IsAssigned         = [bool]$app.isAssigned
            AssignmentCount    = @($app.assignments).Count
            InstallCommand     = $installCommand
            UninstallCommand   = $uninstallCommand
            DetectionRuleCount = $detectionRuleCount
            SizeMB             = $sizeMB
            AppId              = $app.id
            ExportFile         = $jsonPath
        })
}
Write-Progress -Activity 'Exporting Intune apps' -Completed

if ($index.Count -gt 0) {
    $indexPath = Join-Path -Path $OutputFolder -ChildPath 'Apps.csv'
    $index | Sort-Object -Property AppType, Name | Export-Csv -Path $indexPath -NoTypeInformation -Encoding UTF8
    Write-Host ('Index written to {0}' -f $indexPath) -ForegroundColor Green
}
else {
    Write-Warning 'No apps matched the specified criteria; nothing was exported.'
}

$failedColour = 'Green'
if ($failed -gt 0) { $failedColour = 'Yellow' }
Write-Host ''
Write-Host ('Export folder : {0}' -f $OutputFolder) -ForegroundColor Cyan
Write-Host ('Apps exported : {0}' -f ($index.Count - $failed)) -ForegroundColor Cyan
Write-Host ('Apps failed   : {0}' -f $failed) -ForegroundColor $failedColour
Write-Host 'By app type:' -ForegroundColor Cyan
foreach ($group in ($index | Group-Object -Property AppType | Sort-Object -Property Count -Descending)) {
    Write-Host ('  {0,-36} {1,6}' -f $group.Name, $group.Count)
}

if ($PassThru) {
    $index
}
#endregion Main
