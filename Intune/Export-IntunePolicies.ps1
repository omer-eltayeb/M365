<#
.SYNOPSIS
    Exports Intune configuration, compliance, administrative template and platform script policies to JSON for backup and documentation.
.DESCRIPTION
    Downloads device configuration profiles (v1.0 /deviceManagement/deviceConfigurations), settings
    catalog policies (beta /configurationPolicies including their settings), compliance policies
    (v1.0 /deviceCompliancePolicies with scheduled actions), administrative templates (beta
    /groupPolicyConfigurations including definition values) and Windows platform scripts (beta
    /deviceManagementScripts, decoded to a sibling .ps1 file) and writes one JSON file per policy
    into <OutputFolder>\<PolicyType>\. Every file embeds the policy's assignments.
.PARAMETER OutputFolder
    Root folder for the export. Defaults to .\IntuneBackup_yyyyMMdd-HHmm and is created when missing.
.PARAMETER PolicyType
    One or more policy types to export: All, DeviceConfiguration, SettingsCatalog, Compliance,
    AdministrativeTemplate or PlatformScript. Default: All.
.EXAMPLE
    PS> .\Export-IntunePolicies.ps1
    Exports every supported policy type to .\IntuneBackup_<timestamp>\<PolicyType>\<PolicyName>_<id>.json.
.EXAMPLE
    PS> .\Export-IntunePolicies.ps1 -PolicyType SettingsCatalog, Compliance -OutputFolder D:\Backups\Intune -Verbose
    Exports only settings catalog and compliance policies (with assignments) into D:\Backups\Intune.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-03
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : DeviceManagementConfiguration.Read.All (delegated) plus an Intune RBAC role such as Read Only Operator
    Category    : Compliance, configuration & RBAC
    Changes     : No
    Notes       : Settings catalog policies, administrative templates and platform scripts are only exposed on the
                  beta endpoint, which Microsoft may change without notice. This is a point-in-time documentation
                  backup, not a restore tool. Each policy costs 2-3 Graph calls (details, settings, assignments);
                  a 200 ms pause between policies keeps large tenants under the throttling limits. On Windows
                  PowerShell 5.1 ConvertTo-Json writes date values as "\/Date(...)\/"; PowerShell 7 writes ISO 8601.
.LINK
    https://learn.microsoft.com/graph/api/intune-deviceconfig-deviceconfiguration-list
.LINK
    https://learn.microsoft.com/graph/api/intune-deviceconfigv2-devicemanagementconfigurationpolicy-list?view=graph-rest-beta
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputFolder,

    [Parameter()]
    [ValidateSet('All', 'DeviceConfiguration', 'SettingsCatalog', 'Compliance', 'AdministrativeTemplate', 'PlatformScript')]
    [string[]]$PolicyType = @('All')
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
    <# Builds a file-system safe, length-limited file name and appends a short id suffix so duplicate policy names cannot collide. #>
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
    $suffix = $Id
    if ($Id.Length -gt 8) { $suffix = $Id.Substring(0, 8) }
    return ('{0}_{1}' -f $clean, $suffix)
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputFolder)) {
    $OutputFolder = Join-Path -Path (Get-Location).Path -ChildPath ('IntuneBackup_{0}' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
if (-not (Test-Path -LiteralPath $OutputFolder)) {
    New-Item -Path $OutputFolder -ItemType Directory -Force | Out-Null
}
# .NET file APIs ignore the PowerShell current location, so work with an absolute provider path.
$OutputFolder = (Resolve-Path -LiteralPath $OutputFolder).ProviderPath

try {
    Connect-GraphIfNeeded -Scopes @('DeviceManagementConfiguration.Read.All')
}
catch {
    throw "Failed to connect to Microsoft Graph: $($_.Exception.Message)"
}

$graphV1 = 'https://graph.microsoft.com/v1.0/deviceManagement'
$graphBeta = 'https://graph.microsoft.com/beta/deviceManagement'   # beta: settings catalog, administrative templates and platform scripts are not available in v1.0
$catalog = @(
    [PSCustomObject]@{ Type = 'DeviceConfiguration'; BaseUri = "$graphV1/deviceConfigurations"; ListQuery = ''; NameProperty = 'displayName' }
    [PSCustomObject]@{ Type = 'SettingsCatalog'; BaseUri = "$graphBeta/configurationPolicies"; ListQuery = ''; NameProperty = 'name' }
    [PSCustomObject]@{ Type = 'Compliance'; BaseUri = "$graphV1/deviceCompliancePolicies"; ListQuery = '?$expand=scheduledActionsForRule($expand=scheduledActionConfigurations)'; NameProperty = 'displayName' }
    [PSCustomObject]@{ Type = 'AdministrativeTemplate'; BaseUri = "$graphBeta/groupPolicyConfigurations"; ListQuery = ''; NameProperty = 'displayName' }
    [PSCustomObject]@{ Type = 'PlatformScript'; BaseUri = "$graphBeta/deviceManagementScripts"; ListQuery = ''; NameProperty = 'displayName' }
)
$selectedTypes = $catalog
if ($PolicyType -notcontains 'All') {
    $selectedTypes = @($catalog | Where-Object { $PolicyType -contains $_.Type })
}

$summary = New-Object -TypeName System.Collections.Generic.List[object]
foreach ($entry in $selectedTypes) {
    $typeFolder = Join-Path -Path $OutputFolder -ChildPath $entry.Type
    if (-not (Test-Path -Path $typeFolder)) {
        New-Item -Path $typeFolder -ItemType Directory -Force | Out-Null
    }

    Write-Verbose ('Listing {0} policies from {1}' -f $entry.Type, $entry.BaseUri)
    try {
        $policies = @(Invoke-GraphPaged -Uri ($entry.BaseUri + $entry.ListQuery))
    }
    catch {
        Write-Warning ('Could not list {0} policies: {1}' -f $entry.Type, $_.Exception.Message)
        $summary.Add([PSCustomObject]@{ PolicyType = $entry.Type; Found = 0; Exported = 0; Failed = 0 })
        continue
    }

    $nameProperty = $entry.NameProperty
    $exported = 0
    $failed = 0
    $index = 0
    foreach ($policy in $policies) {
        $index++
        $policyName = [string]$policy.$nameProperty
        Write-Progress -Activity ('Exporting {0}' -f $entry.Type) -Status ('{0} of {1}: {2}' -f $index, $policies.Count, $policyName) -PercentComplete ([int](($index / $policies.Count) * 100))
        $itemUri = '{0}/{1}' -f $entry.BaseUri, $policy.id
        $fileBase = Join-Path -Path $typeFolder -ChildPath (Get-SafeFileName -Name $policyName -Id $policy.id)

        try {
            $export = $policy
            switch ($entry.Type) {
                'SettingsCatalog' {
                    # The policy object only carries metadata; the configured settings live in a child collection.
                    $settings = @(Invoke-GraphPaged -Uri ('{0}/settings' -f $itemUri))
                    $export | Add-Member -NotePropertyName 'settings' -NotePropertyValue $settings -Force
                }
                'AdministrativeTemplate' {
                    # Definition values hold the enabled/disabled state and presentation values of each ADMX setting.
                    $definitionValues = @(Invoke-GraphPaged -Uri ($itemUri + '/definitionValues?$expand=definition,presentationValues($expand=presentation)'))
                    $export | Add-Member -NotePropertyName 'definitionValues' -NotePropertyValue $definitionValues -Force
                }
                'PlatformScript' {
                    # scriptContent (base64) is only returned by the single-item GET, not by the list call.
                    $export = Invoke-MgGraphRequest -Method GET -Uri $itemUri -OutputType PSObject -ErrorAction Stop
                    if (-not [string]::IsNullOrEmpty($export.scriptContent)) {
                        [System.IO.File]::WriteAllBytes(('{0}.ps1' -f $fileBase), [Convert]::FromBase64String($export.scriptContent))
                    }
                }
            }

            $assignments = @(Invoke-GraphPaged -Uri ('{0}/assignments' -f $itemUri))
            $export | Add-Member -NotePropertyName 'assignments' -NotePropertyValue $assignments -Force
            # -LiteralPath: policy names may legitimately contain [ ] which -Path would treat as wildcards.
            $export | ConvertTo-Json -Depth 50 | Set-Content -LiteralPath ('{0}.json' -f $fileBase) -Encoding UTF8
            $exported++
        }
        catch {
            $failed++
            Write-Warning ("Failed to export {0} '{1}' ({2}): {3}" -f $entry.Type, $policyName, $policy.id, $_.Exception.Message)
        }
        Start-Sleep -Milliseconds 200
    }
    Write-Progress -Activity ('Exporting {0}' -f $entry.Type) -Completed
    $summary.Add([PSCustomObject]@{ PolicyType = $entry.Type; Found = $policies.Count; Exported = $exported; Failed = $failed })
}

Write-Host ''
Write-Host ('Export folder : {0}' -f $OutputFolder) -ForegroundColor Cyan
Write-Host ('{0,-24} {1,6} {2,9} {3,7}' -f 'PolicyType', 'Found', 'Exported', 'Failed') -ForegroundColor Cyan
foreach ($row in $summary) {
    $colour = 'Green'
    if ($row.Failed -gt 0) { $colour = 'Yellow' }
    Write-Host ('{0,-24} {1,6} {2,9} {3,7}' -f $row.PolicyType, $row.Found, $row.Exported, $row.Failed) -ForegroundColor $colour
}
#endregion Main
