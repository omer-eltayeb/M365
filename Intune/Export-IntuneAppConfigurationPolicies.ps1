<#
.SYNOPSIS
    Exports every Intune app configuration policy (managed devices and managed apps) to JSON plus a flattened CSV index.
.DESCRIPTION
    Reads both app configuration policy collections from Microsoft Graph beta: /deviceAppManagement/mobileAppConfigurations (managed
    devices - iOS/iPadOS and Android Enterprise, with assignments) and /deviceAppManagement/targetedManagedAppConfigurations (managed apps,
    with apps and assignments). Each policy is written as <OutputFolder>\<Kind>\<Name>_<id>.json; iOS policies built from an XML property
    list also get the decoded encodedSettingXml as a sibling .xml. The CSV index lists kind, name, platform, targeted apps, a key=value
    settings summary (truncated to 300 characters) and assignments.
.PARAMETER OutputFolder
    Root folder for the export. Defaults to .\IntuneAppConfigExport_yyyyMMdd-HHmm and is created when missing.
.PARAMETER PassThru
    Also emit the index rows to the pipeline.
.EXAMPLE
    PS> .\Export-IntuneAppConfigurationPolicies.ps1
    Exports all app configuration policies to .\IntuneAppConfigExport_<timestamp> and writes the CSV index next to the kind folders.
.EXAMPLE
    PS> .\Export-IntuneAppConfigurationPolicies.ps1 -OutputFolder D:\Backups\AppConfig -PassThru | Where-Object { -not $_.Assignments }
    Backs up the policies and lists those that are not assigned to any group.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : DeviceManagementApps.Read.All and Group.Read.All (delegated) plus an Intune RBAC role with "Mobile apps" read permission.
    Category    : Apps & app protection
    Changes     : No
    Notes       : beta is used because v1.0 lacks the managed-app (targeted) configurations and the Android Enterprise payload properties;
                  beta may change without notice. Android payloadJson is base64 and is decoded for the summary. Documentation backup only.
.LINK
    https://learn.microsoft.com/graph/api/intune-mam-targetedmanagedappconfiguration-list?view=graph-rest-beta
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

$script:nameCache = @{}
function Get-CachedDisplayName {
    <# Resolves a group or mobile app id to its display name once; deleted objects return '<deleted>', other failures return the id. #>
    param([string]$Uri, [string]$Id)
    if (-not $script:nameCache.ContainsKey($Id)) {
        try { $script:nameCache[$Id] = [string](Invoke-MgGraphRequest -Method GET -Uri ($Uri -f $Id) -OutputType PSObject -ErrorAction Stop).displayName }
        catch {
            if ($_.Exception.Message -match 'Request_ResourceNotFound|does not exist|not found') { $script:nameCache[$Id] = '<deleted>' }
            else { $script:nameCache[$Id] = $Id; Write-Warning ('Could not resolve {0}: {1}' -f $Id, $_.Exception.Message) }
        }
        Start-Sleep -Milliseconds 200
    }
    return $script:nameCache[$Id]
}

function Get-AssignmentText {
    <# Turns an assignments collection into 'Group; Exclude: Group; All users' text. Exclusion also matches '*groupAssignmentTarget', hence the breaks. #>
    param([object[]]$Assignments)
    $parts = @(foreach ($assignment in @($Assignments)) {
            $target = $assignment.target
            switch -Wildcard ([string]$target.'@odata.type') {
                '*exclusionGroupAssignmentTarget' { 'Exclude: {0}' -f (Get-CachedDisplayName -Uri $groupUri -Id $target.groupId); break }
                '*groupAssignmentTarget' { Get-CachedDisplayName -Uri $groupUri -Id $target.groupId; break }
                '*allLicensedUsersAssignmentTarget' { 'All users'; break }
                '*allDevicesAssignmentTarget' { 'All devices'; break }
                default { [string]$target.'@odata.type' -replace '^#microsoft\.graph\.', '' }
            }
        })
    return ($parts -join '; ')
}

function ConvertFrom-Base64Text {
    <# Decodes a base64 string to UTF-8 text; returns $null when empty or not valid base64. #>
    param([object]$Value)
    if ([string]::IsNullOrWhiteSpace([string]$Value)) { return $null }
    try { return [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String([string]$Value)) } catch { return $null }
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputFolder)) {
    $OutputFolder = Join-Path -Path (Get-Location).Path -ChildPath ('IntuneAppConfigExport_{0}' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
if (-not (Test-Path -LiteralPath $OutputFolder)) { New-Item -Path $OutputFolder -ItemType Directory -Force | Out-Null }
$OutputFolder = (Resolve-Path -LiteralPath $OutputFolder).ProviderPath

try { Connect-GraphIfNeeded -Scopes @('DeviceManagementApps.Read.All', 'Group.Read.All') }
catch { throw "Failed to connect to Microsoft Graph: $($_.Exception.Message)" }

# beta: targeted (managed app) configurations and the Android Enterprise payload properties are not exposed on v1.0.
$sources = @(
    [PSCustomObject]@{ Kind = 'ManagedDevices'; Uri = 'https://graph.microsoft.com/beta/deviceAppManagement/mobileAppConfigurations?$expand=assignments' }
    [PSCustomObject]@{ Kind = 'ManagedApps'; Uri = 'https://graph.microsoft.com/beta/deviceAppManagement/targetedManagedAppConfigurations?$expand=apps,assignments' }
)
$groupUri = 'https://graph.microsoft.com/v1.0/groups/{0}?$select=displayName'; $appUri = 'https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/{0}?$select=displayName'
$index = New-Object -TypeName System.Collections.Generic.List[object]; $failed = 0
foreach ($source in $sources) {
    try { $policies = @(Invoke-GraphPaged -Uri $source.Uri) }
    catch { Write-Warning ('Failed to read {0} app configuration policies: {1}' -f $source.Kind, $_.Exception.Message); continue }
    $kindFolder = Join-Path -Path $OutputFolder -ChildPath $source.Kind
    if ($policies.Count -gt 0 -and -not (Test-Path -LiteralPath $kindFolder)) { New-Item -Path $kindFolder -ItemType Directory -Force | Out-Null }
    $position = 0
    foreach ($policy in $policies) {
        $position++
        Write-Progress -Activity ('Exporting {0} policies' -f $source.Kind) -Status ('{0} of {1}' -f $position, $policies.Count) -PercentComplete ([int](($position / $policies.Count) * 100))
        $typeName = ([string]$policy.'@odata.type') -replace '^#microsoft\.graph\.', ''
        $safeName = (([string]$policy.displayName) -replace '[\\/:*?"<>|\x00-\x1F]', '_').Trim()
        if ($safeName.Length -gt 80) { $safeName = $safeName.Substring(0, 80).TrimEnd() }
        $baseName = '{0}_{1}' -f $safeName, $policy.id.Substring(0, 8)
        $jsonPath = Join-Path -Path $kindFolder -ChildPath ($baseName + '.json')
        try { $policy | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $jsonPath -Encoding UTF8 }
        catch { $failed++; $jsonPath = $null; Write-Warning ("Failed to write '{0}': {1}" -f $policy.displayName, $_.Exception.Message) }
        $settings = @(); $platform = 'Managed apps'; $targetedApps = @()
        if ($source.Kind -eq 'ManagedDevices') {
            if ($typeName -like 'ios*') { $platform = 'iOS/iPadOS' } elseif ($typeName -like 'android*') { $platform = 'Android Enterprise' } else { $platform = $typeName }
            $targetedApps = @(foreach ($appId in @($policy.targetedMobileApps)) { Get-CachedDisplayName -Uri $appUri -Id ([string]$appId) })
            $settings = @(foreach ($setting in @($policy.settings)) { '{0}={1}' -f $setting.appConfigKey, $setting.appConfigKeyValue })
            $xml = ConvertFrom-Base64Text -Value $policy.encodedSettingXml
            if ($null -ne $xml -and $null -ne $jsonPath) {
                try { $xml | Set-Content -LiteralPath (Join-Path -Path $kindFolder -ChildPath ($baseName + '.xml')) -Encoding UTF8; if ($settings.Count -eq 0) { $settings = @('<see sibling .xml>') } }
                catch { Write-Warning ("Failed to write the XML for '{0}': {1}" -f $policy.displayName, $_.Exception.Message) }
            }
            $payload = ConvertFrom-Base64Text -Value $policy.payloadJson; if ($null -ne $payload) { $settings += ($payload -replace '\s+', ' ') }
        }
        else {
            $targetedApps = @(foreach ($app in @($policy.apps)) {
                    $identifier = $app.mobileAppIdentifier
                    if ($null -ne $identifier) { @($identifier.bundleId, $identifier.packageId, $identifier.windowsAppId) | Where-Object { $_ } | Select-Object -First 1 }
                })
            $settings = @(foreach ($setting in @($policy.customSettings)) { '{0}={1}' -f $setting.name, $setting.value })
        }
        $summary = ($settings -join '; ')
        if ($summary.Length -gt 300) { $summary = $summary.Substring(0, 297) + '...' }
        $index.Add([PSCustomObject]@{
                Kind            = $source.Kind
                Name            = $policy.displayName
                Platform        = $platform
                TargetedApps    = ($targetedApps -join '; ')
                SettingsSummary = $summary
                Assignments     = Get-AssignmentText -Assignments $policy.assignments
                PolicyId        = $policy.id
                ExportFile      = $jsonPath
            })
    }
    Write-Progress -Activity ('Exporting {0} policies' -f $source.Kind) -Completed
}

if ($index.Count -gt 0) {
    $indexPath = Join-Path -Path $OutputFolder -ChildPath 'AppConfigurationPolicies.csv'
    $index | Sort-Object -Property Kind, Name | Export-Csv -Path $indexPath -NoTypeInformation -Encoding UTF8
    Write-Host ('Index written to {0}' -f $indexPath) -ForegroundColor Green
}
else { Write-Warning 'No app configuration policies were found; nothing was exported.' }

$failedColour = 'Green'; if ($failed -gt 0) { $failedColour = 'Yellow' }
Write-Host ("`nExport folder     : {0}" -f $OutputFolder) -ForegroundColor Cyan
Write-Host ('Policies exported : {0}' -f ($index.Count - $failed)) -ForegroundColor Cyan
Write-Host ('Policies failed   : {0}' -f $failed) -ForegroundColor $failedColour
foreach ($group in ($index | Group-Object -Property Kind | Sort-Object -Property Name)) { Write-Host ('  {0,-16} {1,6}' -f $group.Name, $group.Count) }

if ($PassThru) { $index }
#endregion Main
