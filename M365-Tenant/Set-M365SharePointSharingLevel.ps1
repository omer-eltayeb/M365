<#
.SYNOPSIS
    Changes the tenant-wide SharePoint and OneDrive sharing settings through Microsoft Graph, showing the before/after diff first.
.DESCRIPTION
    Reads the current settings from GET /admin/sharepoint/settings (Microsoft Graph v1.0), compares them with the values
    passed as parameters and sends one PATCH containing only the settings that actually change: sharing capability, domain
    restriction mode and lists, resharing by external users, legacy authentication protocols, invited-user matching,
    OneDrive retention for deleted users and idle session sign-out. Without any setting parameter it just prints the
    current values. Changes are tenant-wide and guarded by ShouldProcess (ConfirmImpact High): -WhatIf previews them.
.PARAMETER SharingCapability
    External sharing level: disabled, existingExternalUserSharingOnly, externalUserSharingOnly (authenticated guests) or
    externalUserAndGuestSharing (Anyone links).
.PARAMETER SharingDomainRestrictionMode
    none, allowList or blockList. allowList requires a non-empty -SharingAllowedDomainList (given now or already set).
.PARAMETER SharingAllowedDomainList
    Domains external sharing is limited to when the restriction mode is allowList. Pass @() to clear the list.
.PARAMETER SharingBlockedDomainList
    Domains external sharing is blocked for when the restriction mode is blockList. Pass @() to clear the list.
.PARAMETER IsResharingByExternalUsersEnabled
    $true lets external users re-share content they received, $false (recommended) does not.
.PARAMETER IsLegacyAuthProtocolsEnabled
    $false (recommended) blocks legacy authentication protocols that cannot enforce MFA or Conditional Access.
.PARAMETER IsRequireAcceptingUserToMatchInvitedUserEnabled
    $true (recommended) means a sharing invitation can only be redeemed by the invited address.
.PARAMETER DeletedUserPersonalSiteRetentionPeriodInDays
    Days a deleted user's OneDrive is kept, 30 to 3650.
.PARAMETER IdleSignOutEnabled
    Turns idle session sign-out for unmanaged browser sessions on ($true) or off ($false).
.PARAMETER IdleWarnAfterMinutes
    Minutes of inactivity before the warning is shown; must be lower than -IdleSignOutAfterMinutes.
.PARAMETER IdleSignOutAfterMinutes
    Minutes of inactivity after which the user is signed out.
.EXAMPLE
    PS> .\Set-M365SharePointSharingLevel.ps1
    Shows the current sharing, authentication, retention and idle sign-out settings without changing anything.
.EXAMPLE
    PS> .\Set-M365SharePointSharingLevel.ps1 -SharingCapability externalUserSharingOnly -IsLegacyAuthProtocolsEnabled $false -WhatIf
    Shows which settings would change (Anyone links off, legacy authentication blocked) without applying them.
.EXAMPLE
    PS> .\Set-M365SharePointSharingLevel.ps1 -SharingDomainRestrictionMode allowList -SharingAllowedDomainList 'fabrikam.com', 'adatum.com'
    Limits external sharing to two partner domains after showing the diff and prompting for confirmation.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : SharePointTenantSettings.ReadWrite.All (delegated); the signed-in user needs the SharePoint Administrator role.
    Category    : Tenant configuration & health
    Changes     : Yes
    Notes       : Changes apply to the whole tenant and can take a few minutes to propagate. Lowering the sharing level does
                  not remove existing links or guests, but site-level sharing can never exceed the tenant level, so tightening
                  it here tightens every site. Idle sign-out values are stored in seconds; the parameters take minutes.
.LINK
    https://learn.microsoft.com/graph/api/sharepointsettings-update
.LINK
    https://learn.microsoft.com/graph/api/resources/sharepointsettings
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter()]
    [ValidateSet('disabled', 'existingExternalUserSharingOnly', 'externalUserSharingOnly', 'externalUserAndGuestSharing')]
    [string]$SharingCapability,

    [Parameter()]
    [ValidateSet('none', 'allowList', 'blockList')]
    [string]$SharingDomainRestrictionMode,

    [Parameter()]
    [AllowEmptyCollection()]
    [string[]]$SharingAllowedDomainList,

    [Parameter()]
    [AllowEmptyCollection()]
    [string[]]$SharingBlockedDomainList,

    [Parameter()]
    [bool]$IsResharingByExternalUsersEnabled,

    [Parameter()]
    [bool]$IsLegacyAuthProtocolsEnabled,

    [Parameter()]
    [bool]$IsRequireAcceptingUserToMatchInvitedUserEnabled,

    [Parameter()]
    [ValidateRange(30, 3650)]
    [int]$DeletedUserPersonalSiteRetentionPeriodInDays,

    [Parameter()]
    [bool]$IdleSignOutEnabled,

    [Parameter()]
    [ValidateRange(1, 1440)]
    [int]$IdleWarnAfterMinutes,

    [Parameter()]
    [ValidateRange(1, 1440)]
    [int]$IdleSignOutAfterMinutes
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

function ConvertTo-DisplayText {
    <# Renders a setting value for the console and result objects: lists joined, objects as compact JSON, empty as '(none)'. #>
    param([Parameter()][AllowNull()]$Value)
    if ($null -eq $Value) { return '(none)' }
    if ($Value -is [System.Collections.IDictionary] -or $Value -is [System.Management.Automation.PSCustomObject]) {
        return (ConvertTo-Json -InputObject $Value -Compress)
    }
    if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]) {
        if (@($Value).Count -eq 0) { return '(none)' }
        return (@($Value) -join ', ')
    }
    return [string]$Value
}
#endregion Helpers

#region Main
$idleParameters = @('IdleSignOutEnabled', 'IdleWarnAfterMinutes', 'IdleSignOutAfterMinutes')
$simpleParameters = @('SharingCapability', 'SharingDomainRestrictionMode', 'SharingAllowedDomainList', 'SharingBlockedDomainList',
    'IsResharingByExternalUsersEnabled', 'IsLegacyAuthProtocolsEnabled', 'IsRequireAcceptingUserToMatchInvitedUserEnabled',
    'DeletedUserPersonalSiteRetentionPeriodInDays')
$requested = @($PSBoundParameters.Keys | Where-Object { ($simpleParameters + $idleParameters) -contains $_ })

try {
    Connect-GraphIfNeeded -Scopes @('SharePointTenantSettings.ReadWrite.All')
}
catch {
    throw "Failed to connect to Microsoft Graph: $($_.Exception.Message)"
}

$settingsUri = 'https://graph.microsoft.com/v1.0/admin/sharepoint/settings'
try {
    $current = @(Invoke-GraphPaged -Uri $settingsUri)[0]
}
catch {
    throw "Failed to read the SharePoint tenant settings (SharePoint Administrator role required): $($_.Exception.Message)"
}
if ($null -eq $current) { throw 'Graph returned no SharePoint settings object.' }

# Graph property names are the parameter names with a lower-case first letter.
$body = @{}
foreach ($name in @($simpleParameters | Where-Object { $requested -contains $_ })) {
    $propertyName = $name.Substring(0, 1).ToLower() + $name.Substring(1)
    $newValue = $PSBoundParameters[$name]
    if ($newValue -is [array]) { $newValue = @($newValue | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }) }
    if ((ConvertTo-DisplayText -Value $newValue) -ne (ConvertTo-DisplayText -Value $current.$propertyName)) { $body[$propertyName] = $newValue }
}
if (@($idleParameters | Where-Object { $requested -contains $_ }).Count -gt 0) {
    # The nested object is sent complete, merged from the current values, because a partial idleSessionSignOut is rejected.
    $idle = [ordered]@{
        isEnabled             = [bool]$current.idleSessionSignOut.isEnabled
        warnAfterInSeconds    = [int]$current.idleSessionSignOut.warnAfterInSeconds
        signOutAfterInSeconds = [int]$current.idleSessionSignOut.signOutAfterInSeconds
    }
    if ($PSBoundParameters.ContainsKey('IdleSignOutEnabled')) { $idle['isEnabled'] = $IdleSignOutEnabled }
    if ($PSBoundParameters.ContainsKey('IdleWarnAfterMinutes')) { $idle['warnAfterInSeconds'] = $IdleWarnAfterMinutes * 60 }
    if ($PSBoundParameters.ContainsKey('IdleSignOutAfterMinutes')) { $idle['signOutAfterInSeconds'] = $IdleSignOutAfterMinutes * 60 }
    if ($idle['isEnabled'] -and $idle['warnAfterInSeconds'] -ge $idle['signOutAfterInSeconds']) {
        throw 'IdleWarnAfterMinutes must be lower than IdleSignOutAfterMinutes.'
    }
    $body['idleSessionSignOut'] = $idle
}
$effectiveMode = $current.sharingDomainRestrictionMode
if ($body.ContainsKey('sharingDomainRestrictionMode')) { $effectiveMode = $body['sharingDomainRestrictionMode'] }
$effectiveAllowList = @($current.sharingAllowedDomainList)
if ($body.ContainsKey('sharingAllowedDomainList')) { $effectiveAllowList = @($body['sharingAllowedDomainList']) }
if ($effectiveMode -eq 'allowList' -and $effectiveAllowList.Count -eq 0) {
    throw 'Restriction mode allowList needs at least one domain in -SharingAllowedDomainList; otherwise all external sharing would be blocked.'
}

$display = @('sharingCapability', 'sharingDomainRestrictionMode', 'sharingAllowedDomainList', 'sharingBlockedDomainList', 'isResharingByExternalUsersEnabled',
    'isLegacyAuthProtocolsEnabled', 'isRequireAcceptingUserToMatchInvitedUserEnabled', 'deletedUserPersonalSiteRetentionPeriodInDays', 'idleSessionSignOut')
Write-Host ''
Write-Host 'SharePoint tenant sharing settings' -ForegroundColor Cyan
foreach ($propertyName in $display) {
    $currentText = ConvertTo-DisplayText -Value $current.$propertyName
    if ($body.ContainsKey($propertyName)) {
        Write-Host ('  {0,-48} {1}  ->  {2}' -f $propertyName, $currentText, (ConvertTo-DisplayText -Value $body[$propertyName])) -ForegroundColor Yellow
    }
    else {
        Write-Host ('  {0,-48} {1}' -f $propertyName, $currentText)
    }
}

if ($body.Count -eq 0) {
    $reason = 'All requested values are already in place'
    if ($requested.Count -eq 0) { $reason = 'No setting parameters were passed' }
    Write-Host ('  {0}; nothing to change.' -f $reason) -ForegroundColor Green
    return
}

$changeList = ($body.Keys | Sort-Object) -join ', '
$applied = $false
if ($PSCmdlet.ShouldProcess('SharePoint Online tenant settings (all sites)', "Change $($body.Count) setting(s): $changeList")) {
    try {
        Invoke-MgGraphRequest -Method PATCH -Uri $settingsUri -Body ($body | ConvertTo-Json -Depth 5) -ContentType 'application/json' -ErrorAction Stop | Out-Null
        $applied = $true
        Write-Host ('  Applied {0} setting(s): {1}' -f $body.Count, $changeList) -ForegroundColor Green
    }
    catch {
        throw "Failed to update the SharePoint tenant settings: $($_.Exception.Message)"
    }
}

foreach ($propertyName in ($body.Keys | Sort-Object)) {
    [PSCustomObject]@{
        Setting  = $propertyName
        OldValue = ConvertTo-DisplayText -Value $current.$propertyName
        NewValue = ConvertTo-DisplayText -Value $body[$propertyName]
        Applied  = $applied
    }
}
#endregion Main
