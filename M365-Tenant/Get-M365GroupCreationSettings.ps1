<#
.SYNOPSIS
    Reports the tenant-wide Microsoft 365 group settings (Group.Unified) with defaults and recommendations.
.DESCRIPTION
    Reads the Group.Unified setting template (GET /groupSettingTemplates/{id}) and the tenant setting object created from
    it (GET /groupSettings) and outputs one row per setting: current value, template default, whether the value comes from
    the tenant object or the template default, and a short recommendation. Covers group creation restriction (the allowed
    group ID is resolved to its name), guest settings, usage guidelines, classifications, naming policy, blocked words,
    sensitivity labels (EnableMIPLabels) and group writeback. Warns explicitly when no setting object exists, because the
    defaults then apply: every user can create Microsoft 365 groups and add guests. -ShowTemplates lists all templates.
.PARAMETER ShowTemplates
    Also prints every group setting template (GET /groupSettingTemplates) with its ID and display name.
.PARAMETER OutputPath
    Path of the CSV report. Defaults to .\Reports\M365GroupCreationSettings_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emits the setting objects to the pipeline.
.EXAMPLE
    PS> .\Get-M365GroupCreationSettings.ps1
    Exports every Group.Unified setting with its effective value and prints who can create groups and whether guests are allowed.
.EXAMPLE
    PS> .\Get-M365GroupCreationSettings.ps1 -ShowTemplates -OutputPath C:\Temp\GroupSettings.csv -Verbose
    Additionally lists the available setting templates (for example Group.Unified.Guest, Password Rule Settings).
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : Directory.Read.All (delegated; includes reading groups). Global Reader can run it.
    Category    : Microsoft 365 Groups governance
    Changes     : No
    Notes       : Values are strings as stored by Microsoft Entra ID ('true' / 'false' / text). Restricting group creation and
                  the naming policy require Microsoft Entra ID P1 licences. EnableMSStandardBlockedWords is deprecated and has
                  no effect. Use Set-M365GroupCreationRestriction.ps1 to change who may create groups.
.LINK
    https://learn.microsoft.com/graph/api/groupsetting-list
.LINK
    https://learn.microsoft.com/entra/identity/users/groups-settings-cmdlets
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [Parameter()]
    [switch]$ShowTemplates,

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
$graphV1 = 'https://graph.microsoft.com/v1.0'
$unifiedTemplateId = '62375ab9-6b52-47ed-826b-58e47e0e304b'
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('M365GroupCreationSettings_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}

try { Connect-GraphIfNeeded -Scopes @('Directory.Read.All') }
catch { throw "Unable to connect to Microsoft Graph: $($_.Exception.Message)" }

try {
    $template = Invoke-MgGraphRequest -Method GET -Uri "$graphV1/groupSettingTemplates/$unifiedTemplateId" -OutputType PSObject -ErrorAction Stop
    $setting = @(Invoke-GraphPaged -Uri "$graphV1/groupSettings") | Where-Object { $_.templateId -eq $unifiedTemplateId } | Select-Object -First 1
}
catch { throw "Failed to read the group settings: $($_.Exception.Message)" }

$current = @{}
if ($null -ne $setting) { foreach ($item in $setting.values) { $current[[string]$item.name] = [string]$item.value } }
else { Write-Warning 'No Group.Unified setting object exists: template defaults apply, so EVERY user can create Microsoft 365 groups and add guests.' }

$allowedGroupName = $null
$allowedGroupId = $current['GroupCreationAllowedGroupId']
if (-not [string]::IsNullOrWhiteSpace($allowedGroupId)) {
    try { $allowedGroupName = (Invoke-MgGraphRequest -Method GET -Uri ('{0}/groups/{1}?$select=displayName' -f $graphV1, $allowedGroupId) -OutputType PSObject -ErrorAction Stop).displayName }
    catch { Write-Warning "GroupCreationAllowedGroupId points to a group that cannot be read (deleted?): $($_.Exception.Message)" }
}

$results = New-Object -TypeName System.Collections.Generic.List[object]
foreach ($definition in @($template.values | Sort-Object -Property name)) {
    $name = [string]$definition.name
    $fromTenant = $current.ContainsKey($name)
    $value = $current[$name]
    if (-not $fromTenant) { $value = [string]$definition.defaultValue }
    $isEmpty = [string]::IsNullOrWhiteSpace($value)
    $recommendation = switch ($name) {
        'EnableGroupCreation' { if ($value -eq 'true') { 'Everyone can create groups; restrict it with Set-M365GroupCreationRestriction.ps1.' } else { 'OK: group creation is restricted.' } }
        'GroupCreationAllowedGroupId' { if ($isEmpty) { 'Empty: with EnableGroupCreation false only administrators can create groups.' } else { "Members of '$allowedGroupName' may create groups." } }
        'AllowGuestsToBeGroupOwner' { if ($value -eq 'true') { 'Guests can own groups; set to false.' } else { 'OK: guests cannot be group owners.' } }
        'AllowGuestsToAccessGroups' { if ($value -eq 'true') { 'Guests can access group content; block per group with labels or Group.Unified.Guest.' } else { 'Guest access is blocked.' } }
        'AllowToAddGuests' { if ($value -eq 'true') { 'Owners can add guests unless blocked per group (Get-M365GroupGuestSettings.ps1).' } else { 'Adding guests is blocked tenant-wide.' } }
        'UsageGuidelinesUrl' { if ($isEmpty) { 'Publish usage guidelines and set the URL (shown when creating a group).' } else { 'OK' } }
        'GuestUsageGuidelinesUrl' { if ($isEmpty) { 'Consider guidelines for guests.' } else { 'OK' } }
        'ClassificationList' { if ($isEmpty) { 'Not used; sensitivity labels are the replacement.' } else { 'Legacy classifications in use; migrate to sensitivity labels.' } }
        'PrefixSuffixNamingRequirement' { if ($isEmpty) { 'No naming policy; consider one (requires Entra ID P1).' } else { 'Active; audit with Get-M365GroupNamingPolicyCompliance.ps1.' } }
        'CustomBlockedWordsList' { '{0} blocked word(s); matched case-insensitively as whole words only.' -f @($value -split ',' | Where-Object { $_.Trim() }).Count }
        'EnableMSStandardBlockedWords' { 'Deprecated; this setting has no effect.' }
        'EnableMIPLabels' { if ($value -eq 'true') { 'OK: sensitivity labels apply to groups, Teams and sites.' } else { 'Enable labels for groups and sites (Execute-AzureAdLabelSync).' } }
        'NewUnifiedGroupWritebackDefault' { 'Only relevant when Microsoft Entra Connect group writeback is enabled.' }
        default { '' }
    }
    $results.Add([PSCustomObject]@{
        Setting        = $name
        Value          = $value
        Source         = $(if ($fromTenant) { 'Tenant setting' } else { 'Template default' })
        DefaultValue   = [string]$definition.defaultValue
        Recommendation = $recommendation
        Description    = [string]$definition.description
    })
}
$results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

if ($ShowTemplates) {
    Write-Host 'Group setting templates' -ForegroundColor Cyan
    try { foreach ($item in @(Invoke-GraphPaged -Uri "$graphV1/groupSettingTemplates")) { Write-Host ('  {0}  {1}' -f $item.id, $item.displayName) } }
    catch { Write-Warning "Could not list the setting templates: $($_.Exception.Message)" }
}

$lookup = @{}
foreach ($row in $results) { $lookup[$row.Setting] = $row.Value }
$creation = 'Everyone (default)'
if ($lookup['EnableGroupCreation'] -eq 'false') { $creation = 'Restricted to administrators'; if ($allowedGroupName) { $creation = "Restricted to members of '$allowedGroupName'" } }
$settingState = 'Missing - template defaults apply'; $settingColor = 'Yellow'
if ($null -ne $setting) { $settingState = "Present ($($setting.id))"; $settingColor = 'Gray' }
Write-Host 'Microsoft 365 group settings summary' -ForegroundColor Cyan
Write-Host ('  Setting object               : {0}' -f $settingState) -ForegroundColor $settingColor
Write-Host ('  Group creation               : {0}' -f $creation) -ForegroundColor $(if ($creation -like 'Everyone*') { 'Yellow' } else { 'Green' })
Write-Host ('  Guests can be added          : {0} (guest access: {1})' -f $lookup['AllowToAddGuests'], $lookup['AllowGuestsToAccessGroups'])
Write-Host ('  Sensitivity labels           : {0}' -f $(if ($lookup['EnableMIPLabels'] -eq 'true') { 'Enabled' } else { 'Disabled' }))
Write-Host ('  Naming policy                : {0}' -f $(if ([string]::IsNullOrWhiteSpace($lookup['PrefixSuffixNamingRequirement'])) { 'None' } else { $lookup['PrefixSuffixNamingRequirement'] }))
Write-Host ('  Report                       : {0}' -f $OutputPath)
if ($PassThru) { $results }
#endregion Main
