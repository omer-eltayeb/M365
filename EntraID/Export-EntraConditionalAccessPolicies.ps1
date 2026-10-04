<#
.SYNOPSIS
    Backs up every Conditional Access policy to JSON and builds a human-readable CSV summary.
.DESCRIPTION
    Downloads all Conditional Access policies (GET /identity/conditionalAccess/policies) and named locations
    (GET /identity/conditionalAccess/namedLocations) through Microsoft Graph. Each policy is saved as the raw JSON
    returned by Graph (one file per policy) so it can be diffed or restored later, named locations are saved to
    NamedLocations.json, and ConditionalAccessSummary.csv lists every policy with its assignments, conditions,
    grant controls and session controls. By default the GUIDs of users, groups, roles, applications and named
    locations are resolved to display names; ids that no longer exist are kept as GUID with the suffix " (not found)".
.PARAMETER OutputFolder
    Folder that receives the JSON files and the summary CSV. Defaults to .\CABackup_yyyyMMdd-HHmm and is created if missing.
.PARAMETER ResolveNames
    Resolves object ids to display names (default). Use -ResolveNames:$false for a faster export that keeps the GUIDs.
.PARAMETER PassThru
    Also emits the summary objects to the pipeline.
.EXAMPLE
    PS> .\Export-EntraConditionalAccessPolicies.ps1
    Creates .\CABackup_<timestamp>\ with one JSON file per policy, NamedLocations.json and ConditionalAccessSummary.csv.
.EXAMPLE
    PS> .\Export-EntraConditionalAccessPolicies.ps1 -OutputFolder C:\Backups\CA -ResolveNames:$false -Verbose
    Exports to the given folder without resolving GUIDs (fastest option, no extra Graph calls).
.EXAMPLE
    PS> .\Export-EntraConditionalAccessPolicies.ps1 -PassThru | Where-Object { $_.State -eq 'enabledForReportingButNotEnforced' }
    Exports everything and shows the policies that are still in report-only mode.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-03
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : Policy.Read.All, Directory.Read.All, Application.Read.All (delegated), for example as Security Reader,
                  Global Reader or Conditional Access Administrator.
    Category    : Roles, governance & tenant policy
    Changes     : No
    Notes       : JSON files are written exactly as returned by Graph. To restore a policy, remove the read-only
                  properties (id, createdDateTime, modifiedDateTime, templateId) and POST the body to
                  /identity/conditionalAccess/policies. Name resolution issues one Graph call per unique id,
                  so policies with large exclusion lists increase the run time.
.LINK
    https://learn.microsoft.com/graph/api/conditionalaccessroot-list-policies
.LINK
    https://learn.microsoft.com/graph/api/conditionalaccessroot-list-namedlocations
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputFolder,

    [Parameter()]
    [switch]$ResolveNames = $true,

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
    <# Normalises a Graph date value (ISO 8601 string or [datetime]) to a UTC [datetime]; returns $null when empty. #>
    param(
        [Parameter()]
        [object]$Value
    )
    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) { return $null }
    if ($Value -is [datetime]) { return $Value.ToUniversalTime() }
    $styles = [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal
    return [datetime]::Parse([string]$Value, [System.Globalization.CultureInfo]::InvariantCulture, $styles)
}

function ConvertTo-SafeFileName {
    <# Replaces characters that are invalid in file names so a policy display name can be used as a file name. #>
    param(
        [Parameter()]
        [string]$Name
    )
    $safe = [regex]::Replace([string]$Name, '[\\/:*?"<>|\x00-\x1F]', '_').Trim()
    if ($safe.Length -gt 80) { $safe = $safe.Substring(0, 80).Trim() }
    if ([string]::IsNullOrEmpty($safe)) { $safe = 'Policy' }
    return $safe
}

function Resolve-DisplayName {
    <# Resolves a user, group, role, application or named-location id to a display name through the shared cache. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Id,

        [Parameter(Mandatory = $true)]
        [ValidateSet('User', 'Group', 'Role', 'Application', 'Location')]
        [string]$Type
    )
    # Well-known values (All, None, GuestsOrExternalUsers, Office365, MicrosoftAdminPortals, AllTrusted) are not GUIDs.
    if (-not $ResolveNames -or $Id -notmatch '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$') { return $Id }
    $cacheKey = '{0}:{1}' -f $Type, $Id
    if ($script:NameCache.ContainsKey($cacheKey)) { return $script:NameCache[$cacheKey] }

    # Roles and named locations were seeded into the cache up front; only users, groups and apps need a lookup.
    $uri = $null
    switch ($Type) {
        'User' { $uri = 'https://graph.microsoft.com/v1.0/users/{0}?$select=displayName' -f $Id }
        'Group' { $uri = 'https://graph.microsoft.com/v1.0/groups/{0}?$select=displayName' -f $Id }
        'Application' { $uri = 'https://graph.microsoft.com/v1.0/servicePrincipals?$filter=appId eq ''{0}''&$select=displayName' -f $Id }
    }
    $name = $null
    if ($null -ne $uri) {
        try {
            $response = Invoke-MgGraphRequest -Method GET -Uri $uri -OutputType PSObject -ErrorAction Stop
            Start-Sleep -Milliseconds 200
            if ($null -ne $response.PSObject.Properties['value']) { $name = @($response.value)[0].displayName }
            else { $name = $response.displayName }
        }
        catch {
            Write-Verbose ('Could not resolve {0} {1}: {2}' -f $Type, $Id, $_.Exception.Message)
        }
    }
    if ([string]::IsNullOrEmpty($name)) { $name = '{0} (not found)' -f $Id }
    $script:NameCache[$cacheKey] = $name
    return $name
}

function Resolve-IdList {
    <# Resolves every id in a list and returns the display names as an array (empty when the list is null). #>
    param(
        [Parameter()]
        [object]$Ids,

        [Parameter(Mandatory = $true)]
        [string]$Type
    )
    $names = @()
    foreach ($id in @($Ids)) {
        if ($null -ne $id -and -not [string]::IsNullOrEmpty([string]$id)) {
            $names += Resolve-DisplayName -Id ([string]$id) -Type $Type
        }
    }
    return $names
}

function Format-IncludeExclude {
    <# Combines include/exclude lists into one readable cell. #>
    param(
        [Parameter()]
        [string]$Include,

        [Parameter()]
        [string]$Exclude
    )
    if ([string]::IsNullOrEmpty($Exclude)) { return $Include }
    return 'Include: {0} | Exclude: {1}' -f $Include, $Exclude
}
#endregion Helpers

#region Main
$requiredScopes = @('Policy.Read.All', 'Directory.Read.All', 'Application.Read.All')
$script:NameCache = @{}

if ([string]::IsNullOrWhiteSpace($OutputFolder)) {
    $OutputFolder = Join-Path -Path (Get-Location).Path -ChildPath ('CABackup_{0}' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
if (-not (Test-Path -Path $OutputFolder)) {
    New-Item -Path $OutputFolder -ItemType Directory -Force | Out-Null
}

try {
    Connect-GraphIfNeeded -Scopes $requiredScopes
}
catch {
    throw "Unable to connect to Microsoft Graph: $($_.Exception.Message)"
}

try {
    $policies = Invoke-GraphPaged -Uri 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies'
    $namedLocations = Invoke-GraphPaged -Uri 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/namedLocations'
}
catch {
    throw "Failed to read the Conditional Access configuration: $($_.Exception.Message)"
}
Write-Verbose "Retrieved $($policies.Count) policies and $($namedLocations.Count) named locations."

foreach ($location in $namedLocations) { $script:NameCache['Location:' + $location.id] = $location.displayName }
if ($ResolveNames) {
    try {
        foreach ($template in (Invoke-GraphPaged -Uri 'https://graph.microsoft.com/v1.0/directoryRoleTemplates?$select=id,displayName')) {
            $script:NameCache['Role:' + $template.id] = $template.displayName
        }
    }
    catch {
        Write-Warning "Directory role templates could not be read; role ids will stay unresolved. $($_.Exception.Message)"
    }
}

# Raw bodies are saved as returned by Graph: re-serialising with ConvertTo-Json would rewrite dates on
# Windows PowerShell and risk depth truncation, which would make the backup unusable for a restore.
try {
    $rawLocations = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/namedLocations' -OutputType Json -ErrorAction Stop
    Set-Content -Path (Join-Path -Path $OutputFolder -ChildPath 'NamedLocations.json') -Value $rawLocations -Encoding UTF8
}
catch {
    Write-Warning "Named locations could not be saved to NamedLocations.json: $($_.Exception.Message)"
}

$summary = New-Object -TypeName System.Collections.Generic.List[object]
$processed = 0
foreach ($policy in $policies) {
    $processed++
    Write-Progress -Activity 'Exporting Conditional Access policies' -Status $policy.displayName -PercentComplete (($processed / $policies.Count) * 100)

    try {
        $policyUri = 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies/{0}' -f $policy.id
        $rawPolicy = Invoke-MgGraphRequest -Method GET -Uri $policyUri -OutputType Json -ErrorAction Stop
        $fileName = '{0}_{1}.json' -f (ConvertTo-SafeFileName -Name $policy.displayName), $policy.id.Substring(0, 8)
        Set-Content -Path (Join-Path -Path $OutputFolder -ChildPath $fileName) -Value $rawPolicy -Encoding UTF8
        Start-Sleep -Milliseconds 200
    }
    catch {
        Write-Warning ('Policy "{0}" could not be saved as JSON: {1}' -f $policy.displayName, $_.Exception.Message)
    }

    $conditions = $policy.conditions
    $grant = $policy.grantControls
    $session = $policy.sessionControls

    $includeUsers = @(Resolve-IdList -Ids $conditions.users.includeUsers -Type 'User')
    if ($null -ne $conditions.users.includeGuestsOrExternalUsers) {
        $includeUsers += 'GuestsOrExternalUsers(' + $conditions.users.includeGuestsOrExternalUsers.guestOrExternalUserTypes + ')'
    }
    $excludeUsers = @(Resolve-IdList -Ids $conditions.users.excludeUsers -Type 'User')
    if ($null -ne $conditions.users.excludeGuestsOrExternalUsers) {
        $excludeUsers += 'GuestsOrExternalUsers(' + $conditions.users.excludeGuestsOrExternalUsers.guestOrExternalUserTypes + ')'
    }

    $grantControls = @()
    $authenticationStrength = $null
    if ($null -ne $grant) {
        $grantControls = @($grant.builtInControls | Where-Object { $_ })
        foreach ($termsOfUse in @($grant.termsOfUse | Where-Object { $_ })) { $grantControls += 'termsOfUse:' + $termsOfUse }
        if ($null -ne $grant.authenticationStrength) { $authenticationStrength = $grant.authenticationStrength.displayName }
    }

    $sessionFlags = @()
    if ($null -ne $session) {
        if ($null -ne $session.signInFrequency -and $session.signInFrequency.isEnabled) {
            $frequency = 'everyTime'
            if ($session.signInFrequency.frequencyInterval -ne 'everyTime') { $frequency = '{0} {1}' -f $session.signInFrequency.value, $session.signInFrequency.type }
            $sessionFlags += 'signInFrequency(' + $frequency + ')'
        }
        if ($null -ne $session.persistentBrowser -and $session.persistentBrowser.isEnabled) { $sessionFlags += 'persistentBrowser(' + $session.persistentBrowser.mode + ')' }
        if ($null -ne $session.cloudAppSecurity -and $session.cloudAppSecurity.isEnabled) { $sessionFlags += 'cloudAppSecurity(' + $session.cloudAppSecurity.cloudAppSecurityType + ')' }
        if ($null -ne $session.applicationEnforcedRestrictions -and $session.applicationEnforcedRestrictions.isEnabled) { $sessionFlags += 'applicationEnforcedRestrictions' }
        if ($session.disableResilienceDefaults) { $sessionFlags += 'disableResilienceDefaults' }
    }

    $summary.Add([PSCustomObject]@{
        DisplayName            = $policy.displayName
        State                  = $policy.state
        CreatedDateTime        = ConvertTo-UtcDateTime -Value $policy.createdDateTime
        ModifiedDateTime       = ConvertTo-UtcDateTime -Value $policy.modifiedDateTime
        IncludeUsers           = ($includeUsers -join ';')
        ExcludeUsers           = ($excludeUsers -join ';')
        IncludeGroups          = (@(Resolve-IdList -Ids $conditions.users.includeGroups -Type 'Group') -join ';')
        ExcludeGroups          = (@(Resolve-IdList -Ids $conditions.users.excludeGroups -Type 'Group') -join ';')
        IncludeRoles           = (@(Resolve-IdList -Ids $conditions.users.includeRoles -Type 'Role') -join ';')
        ExcludeRoles           = (@(Resolve-IdList -Ids $conditions.users.excludeRoles -Type 'Role') -join ';')
        IncludeApplications    = (@(Resolve-IdList -Ids $conditions.applications.includeApplications -Type 'Application') -join ';')
        ExcludeApplications    = (@(Resolve-IdList -Ids $conditions.applications.excludeApplications -Type 'Application') -join ';')
        UserActions            = (@(@($conditions.applications.includeUserActions) + @($conditions.applications.includeAuthenticationContextClassReferences) | Where-Object { $_ }) -join ';')
        ClientAppTypes         = (@($conditions.clientAppTypes) -join ';')
        Platforms              = Format-IncludeExclude -Include (@($conditions.platforms.includePlatforms) -join ';') -Exclude (@($conditions.platforms.excludePlatforms) -join ';')
        Locations              = Format-IncludeExclude -Include (@(Resolve-IdList -Ids $conditions.locations.includeLocations -Type 'Location') -join ';') -Exclude (@(Resolve-IdList -Ids $conditions.locations.excludeLocations -Type 'Location') -join ';')
        SignInRiskLevels       = (@($conditions.signInRiskLevels) -join ';')
        UserRiskLevels         = (@($conditions.userRiskLevels) -join ';')
        GrantOperator          = $grant.operator
        GrantControls          = ($grantControls -join ';')
        AuthenticationStrength = $authenticationStrength
        SessionControls        = ($sessionFlags -join ';')
        Id                     = $policy.id
    })
}
Write-Progress -Activity 'Exporting Conditional Access policies' -Completed

$summaryPath = Join-Path -Path $OutputFolder -ChildPath 'ConditionalAccessSummary.csv'
if ($summary.Count -gt 0) {
    $summary | Sort-Object -Property DisplayName | Export-Csv -Path $summaryPath -NoTypeInformation -Encoding UTF8
}
else {
    Write-Warning 'No Conditional Access policies were found; only NamedLocations.json was written.'
}

$enabledCount = @($summary | Where-Object { $_.State -eq 'enabled' }).Count
$reportOnlyCount = @($summary | Where-Object { $_.State -eq 'enabledForReportingButNotEnforced' }).Count
$disabledCount = @($summary | Where-Object { $_.State -eq 'disabled' }).Count
Write-Host ''
Write-Host 'Conditional Access export summary' -ForegroundColor Cyan
Write-Host ('  Policies exported : {0} (enabled {1}, report-only {2}, disabled {3})' -f $summary.Count, $enabledCount, $reportOnlyCount, $disabledCount) -ForegroundColor Green
Write-Host ('  Named locations   : {0}' -f $namedLocations.Count)
Write-Host ('  Output folder     : {0}' -f $OutputFolder)

if ($PassThru) {
    $summary
}
#endregion Main
