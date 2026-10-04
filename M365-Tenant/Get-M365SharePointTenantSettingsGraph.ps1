<#
.SYNOPSIS
    Reports the SharePoint Online tenant settings exposed by Microsoft Graph with a security recommendation per risky setting.
.DESCRIPTION
    Reads GET /admin/sharepoint/settings (Microsoft Graph v1.0) and flattens every property into Setting / Value /
    Severity / Recommendation rows: external sharing capability and domain restrictions, resharing by external users,
    legacy authentication protocols, idle session sign-out, OneDrive sync restrictions, site creation, storage limits,
    retention of deleted users' OneDrive and more. Recommendations are attached where a value is risky (legacy
    authentication enabled is High, Anyone links and external resharing are Medium, idle sign-out disabled is Low).
    No SharePoint Online Management Shell is needed; the script runs on PowerShell 7 and non-Windows platforms too.
.PARAMETER OutputPath
    Path of the CSV report. Defaults to .\Reports\M365SharePointTenantSettings_yyyyMMdd-HHmm.csv.
.PARAMETER Json
    Also saves the raw settings object as returned by Graph to <OutputPath base>.json.
.PARAMETER PassThru
    Also emits the Setting / Value / Severity / Recommendation objects to the pipeline.
.EXAMPLE
    PS> .\Get-M365SharePointTenantSettingsGraph.ps1
    Exports every tenant setting to .\Reports\ and prints the settings that have a recommendation.
.EXAMPLE
    PS> .\Get-M365SharePointTenantSettingsGraph.ps1 -Json -OutputPath C:\Temp\SpoSettings.csv -PassThru | Where-Object Severity -eq 'High'
    Also writes C:\Temp\SpoSettings.json and shows only the High severity findings.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : SharePointTenantSettings.Read.All (delegated); the signed-in user needs the SharePoint Administrator
                  or Global Reader role.
    Category    : Tenant configuration & health
    Changes     : No
    Notes       : The Graph settings resource covers the most important tenant settings but not everything Set-SPOTenant
                  exposes (for example anonymous link expiration or default link type). Idle session values are seconds.
                  Use Set-M365SharePointSharingLevel.ps1 from this folder to change the sharing-related settings.
.LINK
    https://learn.microsoft.com/graph/api/sharepointsettings-get
.LINK
    https://learn.microsoft.com/graph/api/resources/sharepointsettings
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputPath,

    [Parameter()]
    [switch]$Json,

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
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('M365SharePointTenantSettings_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}
$jsonPath = [System.IO.Path]::Combine([string]$outputFolder, ('{0}.json' -f [System.IO.Path]::GetFileNameWithoutExtension($OutputPath)))

try {
    Connect-GraphIfNeeded -Scopes @('SharePointTenantSettings.Read.All')
}
catch {
    throw "Failed to connect to Microsoft Graph: $($_.Exception.Message)"
}

$settingsUri = 'https://graph.microsoft.com/v1.0/admin/sharepoint/settings'
try {
    $settings = @(Invoke-GraphPaged -Uri $settingsUri)[0]
    # The raw JSON text is saved exactly as Graph returns it, so property names and values are not reformatted.
    if ($Json) { Invoke-MgGraphRequest -Method GET -Uri $settingsUri -OutputType Json -ErrorAction Stop | Set-Content -Path $jsonPath -Encoding UTF8 }
}
catch {
    throw "Failed to read the SharePoint tenant settings (SharePoint Administrator or Global Reader role required): $($_.Exception.Message)"
}
if ($null -eq $settings) { throw 'Graph returned no SharePoint settings object.' }

# Each check receives the setting value; the first matching check supplies Severity and Recommendation.
$checks = @(
    @{ Setting = 'isLegacyAuthProtocolsEnabled'; Severity = 'High'; Test = { param($v) $v -eq $true }
        Recommendation = 'Legacy authentication protocols bypass MFA and Conditional Access; set to false once no app depends on them.' }
    @{ Setting = 'sharingCapability'; Severity = 'Medium'; Test = { param($v) $v -eq 'externalUserAndGuestSharing' }
        Recommendation = 'Anyone links are allowed tenant-wide; prefer externalUserSharingOnly (authenticated guests) and set link expiration.' }
    @{ Setting = 'sharingCapability'; Severity = 'Info'; Test = { param($v) $v -eq 'disabled' }
        Recommendation = 'External sharing is off for the whole tenant; confirm this is intended (guest access to Teams-connected sites is blocked too).' }
    @{ Setting = 'sharingDomainRestrictionMode'; Severity = 'Low'; Test = { param($v) $v -eq 'none' -and $settings.sharingCapability -ne 'disabled' }
        Recommendation = 'No domain allow or block list; consider limiting external sharing to known partner domains.' }
    @{ Setting = 'isResharingByExternalUsersEnabled'; Severity = 'Medium'; Test = { param($v) $v -eq $true }
        Recommendation = 'External users can re-share content they received; disable unless partners must forward invitations.' }
    @{ Setting = 'isRequireAcceptingUserToMatchInvitedUserEnabled'; Severity = 'Medium'; Test = { param($v) $v -eq $false }
        Recommendation = 'Invitations can be redeemed with any account; enable so only the invited address can accept.' }
    @{ Setting = 'idleSessionSignOut.isEnabled'; Severity = 'Low'; Test = { param($v) $v -eq $false }
        Recommendation = 'Idle session sign-out is off; consider enabling it to protect browser sessions on shared or unmanaged devices.' }
    @{ Setting = 'isUnmanagedSyncAppForTenantRestricted'; Severity = 'Low'; Test = { param($v) $v -eq $false }
        Recommendation = 'OneDrive sync is allowed from devices outside the tenant domains; restrict it when only managed devices should sync.' }
    @{ Setting = 'deletedUserPersonalSiteRetentionPeriodInDays'; Severity = 'Low'; Test = { param($v) $null -ne $v -and [int]$v -lt 90 }
        Recommendation = 'OneDrive content of deleted users is kept for less than 90 days; raise the retention if HR or legal need longer access.' }
    @{ Setting = 'isSiteCreationEnabled'; Severity = 'Info'; Test = { param($v) $v -eq $true }
        Recommendation = 'Users can create SharePoint sites themselves; keep for self-service, otherwise disable or restrict Microsoft 365 group creation.' }
)

$rows = New-Object -TypeName System.Collections.Generic.List[object]
foreach ($property in @($settings.PSObject.Properties | Where-Object { $_.Name -notlike '@odata*' } | Sort-Object -Property Name)) {
    $leaves = @(@{ Name = $property.Name; Value = $property.Value })
    if ($property.Value -is [System.Management.Automation.PSCustomObject]) {
        $leaves = @($property.Value.PSObject.Properties | ForEach-Object { @{ Name = ('{0}.{1}' -f $property.Name, $_.Name); Value = $_.Value } })
    }
    foreach ($leaf in $leaves) {
        $value = $leaf.Value
        if ($value -is [System.Collections.IEnumerable] -and $value -isnot [string]) { $value = (@($value) -join '; ') }
        $hit = $checks | Where-Object { $_.Setting -eq $leaf.Name -and (& $_.Test $leaf.Value) } | Select-Object -First 1
        $rows.Add([PSCustomObject]@{
                Setting        = $leaf.Name
                Value          = $value
                Severity       = $hit.Severity
                Recommendation = $hit.Recommendation
            })
    }
}

$rows | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
$findings = @($rows | Where-Object { -not [string]::IsNullOrWhiteSpace($_.Severity) })
$severityColors = @{ High = 'Red'; Medium = 'Yellow'; Low = 'Yellow'; Info = 'Gray' }
Write-Host ''
Write-Host 'SharePoint tenant settings summary' -ForegroundColor Cyan
Write-Host ('  Settings exported : {0}' -f $rows.Count)
Write-Host ('  Sharing           : {0} / domain restriction {1}' -f $settings.sharingCapability, $settings.sharingDomainRestrictionMode)
Write-Host ('  Recommendations   : {0}' -f $findings.Count)
foreach ($finding in ($findings | Sort-Object -Property @{ Expression = { @('High', 'Medium', 'Low', 'Info').IndexOf([string]$_.Severity) } })) {
    Write-Host ('    [{0,-6}] {1,-48} = {2}' -f $finding.Severity, $finding.Setting, $finding.Value) -ForegroundColor $severityColors[$finding.Severity]
    Write-Host ('             {0}' -f $finding.Recommendation)
}
Write-Host ('  Report            : {0}' -f $OutputPath)
if ($Json) { Write-Host ('  JSON              : {0}' -f $jsonPath) }

if ($PassThru) { $rows }
#endregion Main
