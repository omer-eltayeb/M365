<#
.SYNOPSIS
    Restricts Microsoft 365 group creation to the members of one group (or re-opens it to everyone) via the Group.Unified settings.
.DESCRIPTION
    Resolves the allowed group, reads the Group.Unified template (GET /groupSettingTemplates/{id}) and the tenant setting object
    (GET /groupSettings) and builds the full values collection: template defaults, overlaid with the current tenant values, overlaid
    with the requested changes (EnableGroupCreation=false + GroupCreationAllowedGroupId, or EnableGroupCreation=true with an empty
    group for -AllowEveryone, plus the optional guest, usage-guidelines and classification values). Without -Apply only the
    differences are printed; with -Apply the object is created (POST /groupSettings) or updated (PATCH /groupSettings/{id}) while
    every other value is preserved, and the settings are read back to confirm.
.PARAMETER AllowedGroupName
    Display name (must be unique) or object ID of the security or Microsoft 365 group whose members may create groups.
.PARAMETER AllowEveryone
    Re-enable group creation for all users (EnableGroupCreation=true, GroupCreationAllowedGroupId cleared).
.PARAMETER AllowToAddGuests
    Optional: tenant-wide switch that lets owners add guests to groups ($true / $false).
.PARAMETER AllowGuestsToAccessGroups
    Optional: tenant-wide switch that lets existing guests access group content ($true / $false).
.PARAMETER UsageGuidelinesUrl
    Optional: URL of the usage guidelines shown to users when they create a group.
.PARAMETER ClassificationList
    Optional: comma-separated legacy classification list (for example 'Low,Medium,High'). Prefer sensitivity labels.
.PARAMETER Apply
    Perform the change. Without this switch the script only reports what would change. Honours -WhatIf / -Confirm.
.EXAMPLE
    PS> .\Set-M365GroupCreationRestriction.ps1 -AllowedGroupName 'SG-Group-Creators'
    Shows the settings that would change to restrict creation to the members of SG-Group-Creators; nothing is written.
.EXAMPLE
    PS> .\Set-M365GroupCreationRestriction.ps1 -AllowedGroupName 'SG-Group-Creators' -AllowToAddGuests $false -Apply
    Restricts group creation and blocks adding guests tenant-wide after confirmation (use -Confirm:$false in automation).
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : Directory.ReadWrite.All (delegated); the signed-in user needs the Groups Administrator or Global Administrator role.
    Category    : Microsoft 365 Groups governance
    Changes     : Yes
    Notes       : Microsoft requires Microsoft Entra ID P1 licences for the members of the allowed group and for the administrator
                  who configures the restriction. Only direct members count (nested groups are not honoured). Administrators in
                  roles such as Global, Groups, User, Exchange, SharePoint or Teams Administrator can still create groups, including
                  with New-UnifiedGroup in Exchange Online PowerShell. Propagation to Outlook, Teams, SharePoint and Planner can take
                  a while. The restriction applies to Microsoft 365 groups only, not to security or distribution groups.
.LINK
    https://learn.microsoft.com/microsoft-365/solutions/manage-creation-of-groups
.LINK
    https://learn.microsoft.com/graph/api/groupsetting-post-groupsettings
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High', DefaultParameterSetName = 'SettingsOnly')]
param(
    [Parameter(Mandatory = $true, ParameterSetName = 'Restrict')]
    [ValidateNotNullOrEmpty()]
    [string]$AllowedGroupName,

    [Parameter(Mandatory = $true, ParameterSetName = 'Everyone')]
    [switch]$AllowEveryone,

    [Parameter()]
    [bool]$AllowToAddGuests,

    [Parameter()]
    [bool]$AllowGuestsToAccessGroups,

    [Parameter()]
    [string]$UsageGuidelinesUrl,

    [Parameter()]
    [string]$ClassificationList,

    [Parameter()]
    [switch]$Apply
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
$graphV1 = 'https://graph.microsoft.com/v1.0'
$unifiedTemplateId = '62375ab9-6b52-47ed-826b-58e47e0e304b'
$requested = @{}
# Graph stores every setting value as a string; booleans must be the lowercase words true / false.
if ($PSBoundParameters.ContainsKey('AllowToAddGuests')) { $requested['AllowToAddGuests'] = $AllowToAddGuests.ToString().ToLowerInvariant() }
if ($PSBoundParameters.ContainsKey('AllowGuestsToAccessGroups')) { $requested['AllowGuestsToAccessGroups'] = $AllowGuestsToAccessGroups.ToString().ToLowerInvariant() }
if ($PSBoundParameters.ContainsKey('UsageGuidelinesUrl')) { $requested['UsageGuidelinesUrl'] = $UsageGuidelinesUrl }
if ($PSBoundParameters.ContainsKey('ClassificationList')) { $requested['ClassificationList'] = $ClassificationList }
if ($PSCmdlet.ParameterSetName -eq 'SettingsOnly' -and $requested.Count -eq 0) { throw 'Nothing to change: pass -AllowedGroupName, -AllowEveryone and/or one of the optional settings.' }

try { Connect-GraphIfNeeded -Scopes @('Directory.ReadWrite.All') }
catch { throw "Unable to connect to Microsoft Graph: $($_.Exception.Message)" }

$allowedGroup = $null
if ($PSCmdlet.ParameterSetName -eq 'Restrict') {
    $lookupUri = '{0}/groups?$filter=displayName eq ''{1}''&$select=id,displayName,groupTypes' -f $graphV1, $AllowedGroupName.Replace("'", "''")
    if ($AllowedGroupName -match '^[0-9a-fA-F-]{36}$') { $lookupUri = '{0}/groups/{1}?$select=id,displayName,groupTypes' -f $graphV1, $AllowedGroupName }
    try { $candidates = @(Invoke-GraphPaged -Uri $lookupUri) }
    catch { throw "Could not resolve the allowed group '$AllowedGroupName': $($_.Exception.Message)" }
    if ($candidates.Count -ne 1) { throw "Expected exactly one group named '$AllowedGroupName' but found $($candidates.Count); use the object ID instead." }
    $allowedGroup = $candidates[0]
    if (@($allowedGroup.groupTypes) -contains 'DynamicMembership') { Write-Warning 'The allowed group is dynamic; make sure its rule only matches the intended users.' }
    $requested['EnableGroupCreation'] = 'false'
    $requested['GroupCreationAllowedGroupId'] = [string]$allowedGroup.id
}
elseif ($PSCmdlet.ParameterSetName -eq 'Everyone') {
    $requested['EnableGroupCreation'] = 'true'
    $requested['GroupCreationAllowedGroupId'] = ''
}

try {
    $template = Invoke-MgGraphRequest -Method GET -Uri "$graphV1/groupSettingTemplates/$unifiedTemplateId" -OutputType PSObject -ErrorAction Stop
    $setting = @(Invoke-GraphPaged -Uri "$graphV1/groupSettings") | Where-Object { $_.templateId -eq $unifiedTemplateId } | Select-Object -First 1
}
catch { throw "Failed to read the group settings: $($_.Exception.Message)" }

# Full values collection: template defaults, then the tenant's current values, then the requested changes.
$current = @{}
foreach ($definition in $template.values) { $current[[string]$definition.name] = [string]$definition.defaultValue }
if ($null -ne $setting) { foreach ($item in $setting.values) { $current[[string]$item.name] = [string]$item.value } }
else { Write-Warning 'No Group.Unified setting object exists yet (defaults apply: everyone can create groups); it will be created.' }
$changes = New-Object -TypeName System.Collections.Generic.List[object]
$values = New-Object -TypeName System.Collections.Generic.List[object]
foreach ($name in @($current.Keys | Sort-Object)) {
    $newValue = $current[$name]
    if ($requested.ContainsKey($name) -and $requested[$name] -ne $current[$name]) {
        $newValue = $requested[$name]
        $changes.Add([PSCustomObject]@{ Setting = $name; CurrentValue = $current[$name]; NewValue = $newValue })
    }
    $values.Add(@{ name = $name; value = $newValue })
}

Write-Host 'Group.Unified setting changes' -ForegroundColor Cyan
if ($changes.Count -eq 0) { Write-Host '  Nothing to change: the requested values are already in place.' -ForegroundColor Green; return }
foreach ($change in $changes) { Write-Host ('  {0,-30} {1,-40} -> {2}' -f $change.Setting, "'$($change.CurrentValue)'", "'$($change.NewValue)'") }
if ($null -ne $allowedGroup) { Write-Host ('  Allowed group                : {0} ({1})' -f $allowedGroup.displayName, $allowedGroup.id) }
if (-not $Apply) { Write-Host '  Preview only - add -Apply to write these values.' -ForegroundColor Yellow; return }

$action = 'Create the Group.Unified setting object'
if ($null -ne $setting) { $action = "Update setting object $($setting.id)" }
if ($PSCmdlet.ShouldProcess('Tenant Microsoft 365 group settings', "$action ($($changes.Count) value(s) changed)")) {
    $body = @{ values = $values.ToArray() }
    if ($null -eq $setting) { $body['templateId'] = $unifiedTemplateId; $method = 'POST'; $uri = "$graphV1/groupSettings" }
    else { $method = 'PATCH'; $uri = "$graphV1/groupSettings/$($setting.id)" }
    try { $null = Invoke-MgGraphRequest -Method $method -Uri $uri -Body $body -ContentType 'application/json' -ErrorAction Stop }
    catch { throw "Writing the group settings failed: $($_.Exception.Message)" }

    # Read back so the operator sees the effective values rather than trusting the request.
    try {
        $verify = @(Invoke-GraphPaged -Uri "$graphV1/groupSettings") | Where-Object { $_.templateId -eq $unifiedTemplateId } | Select-Object -First 1
        $effective = @{}
        foreach ($item in $verify.values) { $effective[[string]$item.name] = [string]$item.value }
        Write-Host ('  Applied. EnableGroupCreation={0}, GroupCreationAllowedGroupId={1}' -f $effective['EnableGroupCreation'], $effective['GroupCreationAllowedGroupId']) -ForegroundColor Green
        Write-Host '  Remember: members of the allowed group need Microsoft Entra ID P1 licences; admins can always create groups.' -ForegroundColor Yellow
    }
    catch { Write-Warning "The settings were written but could not be read back: $($_.Exception.Message)" }
}
#endregion Main
