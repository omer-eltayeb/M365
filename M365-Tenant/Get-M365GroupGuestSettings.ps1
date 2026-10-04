<#
.SYNOPSIS
    Reports the effective "guests can be added" setting of every Microsoft 365 group and can block or allow guests per group.
.DESCRIPTION
    Reads the tenant default AllowToAddGuests from the Group.Unified settings (GET /groupSettings) and, for every Microsoft 365
    group (or the groups selected with -GroupName / -GroupId), the group-level Group.Unified.Guest setting (GET /groups/{id}/settings).
    Each row shows whether the group overrides the tenant default (True / False / Inherited), the effective value and, with
    -IncludeCounts, how many guests are members today. -BlockGuests / -AllowGuests write the override for the selected groups
    (POST /groups/{id}/settings or PATCH /groups/{id}/settings/{settingId}). Exports a CSV.
.PARAMETER GroupName
    One or more display names to include; wildcards are supported. Default: every Microsoft 365 group.
.PARAMETER GroupId
    Object ID of a single Microsoft 365 group.
.PARAMETER IncludeCounts
    Adds CurrentGuestsCount (guest members via /members/microsoft.graph.user/$count; one extra call per group).
.PARAMETER BlockGuests
    Set AllowToAddGuests=false on the selected groups (requires -GroupName or -GroupId). Honours -WhatIf / -Confirm.
.PARAMETER AllowGuests
    Set AllowToAddGuests=true on the selected groups (requires -GroupName or -GroupId). Honours -WhatIf / -Confirm.
.PARAMETER OutputPath
    Path of the CSV report. Defaults to .\Reports\M365GroupGuestSettings_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emits the report objects to the pipeline.
.EXAMPLE
    PS> .\Get-M365GroupGuestSettings.ps1 -IncludeCounts
    Lists every Microsoft 365 group with its effective guest setting and the number of guest members.
.EXAMPLE
    PS> .\Get-M365GroupGuestSettings.ps1 -GroupName 'Finance*', 'Legal Team' -BlockGuests
    Blocks adding guests to the Finance groups and the Legal Team after confirmation; existing guests keep their access.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : Group.Read.All, Directory.Read.All (delegated); changes add Group.ReadWrite.All and Directory.ReadWrite.All (Groups Administrator).
    Category    : Microsoft 365 Groups governance
    Changes     : Optional (-BlockGuests / -AllowGuests)
    Notes       : Blocking guests stops owners from adding new guests (also in Teams); existing guests must be removed separately.
                  When AllowGuestsToAccessGroups is false at tenant level, guests cannot access any group regardless of this setting.
                  A sensitivity label with a guest policy (EnableMIPLabels) overrides and locks the per-group value. One settings call
                  is made per group (two with -IncludeCounts), so 2,000 groups take roughly 8 to 15 minutes.
.LINK
    https://learn.microsoft.com/graph/api/group-list-settings
.LINK
    https://learn.microsoft.com/microsoft-365/solutions/per-group-guest-access
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High', DefaultParameterSetName = 'All')]
param(
    [Parameter(ParameterSetName = 'ByName')]
    [string[]]$GroupName,

    [Parameter(ParameterSetName = 'ById')]
    [ValidatePattern('^[0-9a-fA-F-]{36}$')]
    [string]$GroupId,

    [Parameter()]
    [switch]$IncludeCounts,

    [Parameter()]
    [switch]$BlockGuests,

    [Parameter()]
    [switch]$AllowGuests,

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
$eventual = @{ ConsistencyLevel = 'eventual' }
$unifiedTemplateId = '62375ab9-6b52-47ed-826b-58e47e0e304b'
$guestTemplateId = '08d542b9-071f-4e16-94b0-74abb372e3d9'
if ($BlockGuests -and $AllowGuests) { throw 'Use either -BlockGuests or -AllowGuests, not both.' }
$desired = $null; if ($BlockGuests) { $desired = 'false' } elseif ($AllowGuests) { $desired = 'true' }
if ($null -ne $desired -and $PSCmdlet.ParameterSetName -eq 'All') { throw '-BlockGuests / -AllowGuests require -GroupName or -GroupId; use the tenant-wide setting to change every group.' }
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('M365GroupGuestSettings_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}

$requiredScopes = @('Group.Read.All', 'Directory.Read.All')
if ($null -ne $desired) { $requiredScopes += @('Group.ReadWrite.All', 'Directory.ReadWrite.All') }
try { Connect-GraphIfNeeded -Scopes $requiredScopes }
catch { throw "Unable to connect to Microsoft Graph: $($_.Exception.Message)" }

try { $tenantSetting = @(Invoke-GraphPaged -Uri "$graphV1/groupSettings") | Where-Object { $_.templateId -eq $unifiedTemplateId } | Select-Object -First 1 }
catch { throw "Failed to read the tenant group settings: $($_.Exception.Message)" }
# Template default is true, so guests are allowed unless the Group.Unified object explicitly says false.
$tenantValue = @($tenantSetting.values | Where-Object { $_.name -eq 'AllowToAddGuests' } | Select-Object -First 1).value
$tenantAllowsGuests = ($tenantValue -ne 'false')

$filter = 'groupTypes/any(c:c eq ''Unified'')'
if ($PSCmdlet.ParameterSetName -eq 'ById') { $filter += " and id eq '$GroupId'" }
try { $groups = @(Invoke-GraphPaged -Uri ('{0}/groups?$filter={1}&$select=id,displayName,resourceProvisioningOptions&$top=999' -f $graphV1, $filter)) }
catch { throw "Failed to list Microsoft 365 groups: $($_.Exception.Message)" }
if ($PSCmdlet.ParameterSetName -eq 'ByName') { $groups = @($groups | Where-Object { $name = $_.displayName; @($GroupName | Where-Object { $name -like $_ }).Count -gt 0 }) }
if ($groups.Count -eq 0) { Write-Warning 'No Microsoft 365 group matched the selection; nothing to report.'; return }

$results = New-Object -TypeName System.Collections.Generic.List[object]
$processed = 0
foreach ($group in $groups) {
    $processed++
    Write-Progress -Activity 'Reading group guest settings' -Status "$processed of $($groups.Count): $($group.displayName)" -PercentComplete (($processed / $groups.Count) * 100)
    $groupUri = '{0}/groups/{1}' -f $graphV1, $group.id
    $override = $null; $guestSetting = $null; $guestsCount = $null; $action = 'None'
    try {
        $guestSetting = @(Invoke-GraphPaged -Uri "$groupUri/settings") | Where-Object { $_.templateId -eq $guestTemplateId } | Select-Object -First 1
        if ($null -ne $guestSetting) { $override = ([string]@($guestSetting.values | Where-Object { $_.name -eq 'AllowToAddGuests' } | Select-Object -First 1).value).ToLowerInvariant() }
        if ($IncludeCounts) {
            # Some tenants reject the filtered /$count segment; listing the guest members gives the same number.
            $countUri = $groupUri + '/members/microsoft.graph.user/$count?$filter=userType eq ''Guest'''
            try { $guestsCount = [int](([string](Invoke-MgGraphRequest -Method GET -Uri $countUri -Headers $eventual -ErrorAction Stop)).Trim()) }
            catch { $guestsCount = @(Invoke-GraphPaged -Uri ($groupUri + '/members/microsoft.graph.user?$filter=userType eq ''Guest''&$count=true&$select=id') -Headers $eventual).Count }
        }
    }
    catch { Write-Warning "Could not read the settings of '$($group.displayName)': $($_.Exception.Message)" }

    if ($null -ne $desired -and $override -eq $desired) { $action = 'NoChange' }
    elseif ($null -ne $desired -and $PSCmdlet.ShouldProcess($group.displayName, "Set AllowToAddGuests to $desired")) {
        $body = @{ values = @(@{ name = 'AllowToAddGuests'; value = $desired }) }
        if ($null -eq $guestSetting) { $body['templateId'] = $guestTemplateId; $method = 'POST'; $uri = "$groupUri/settings" }
        else { $method = 'PATCH'; $uri = "$groupUri/settings/$($guestSetting.id)" }
        $action = $(if ($desired -eq 'false') { 'GuestsBlocked' } else { 'GuestsAllowed' })
        try { $null = Invoke-MgGraphRequest -Method $method -Uri $uri -Body $body -ContentType 'application/json' -ErrorAction Stop; $override = $desired }
        catch { $action = 'Failed'; Write-Warning "Changing the guest setting of '$($group.displayName)' failed: $($_.Exception.Message)" }
    }

    $results.Add([PSCustomObject]@{
        DisplayName            = $group.displayName
        IsTeam                 = (@($group.resourceProvisioningOptions) -contains 'Team')
        GuestsAllowedOverride  = $(if ($null -eq $override) { 'Inherited' } elseif ($override -eq 'true') { 'True' } else { 'False' })
        TenantDefault          = $tenantAllowsGuests
        EffectiveGuestsAllowed = $(if ($null -eq $override) { $tenantAllowsGuests } else { $override -eq 'true' })
        CurrentGuestsCount     = $guestsCount
        ActionTaken            = $action
        Id                     = $group.id
    })
    Start-Sleep -Milliseconds 200
}
Write-Progress -Activity 'Reading group guest settings' -Completed
$results | Sort-Object -Property DisplayName | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

$blocked = @($results | Where-Object { $_.GuestsAllowedOverride -eq 'False' }).Count
$allowed = @($results | Where-Object { $_.GuestsAllowedOverride -eq 'True' }).Count
Write-Host 'Group guest settings summary' -ForegroundColor Cyan
Write-Host ('  Tenant default (AllowToAddGuests)  : {0}' -f $tenantAllowsGuests)
Write-Host ('  Groups / effectively allowing guests: {0} / {1}' -f $results.Count, @($results | Where-Object { $_.EffectiveGuestsAllowed }).Count) -ForegroundColor Yellow
Write-Host ('  Explicit overrides blocked / allowed: {0} / {1}' -f $blocked, $allowed)
$changed = @($results | Where-Object { $_.ActionTaken -like 'Guests*' }).Count; $failed = @($results | Where-Object { $_.ActionTaken -eq 'Failed' }).Count
if ($null -ne $desired) { Write-Host ('  Changed / failed                    : {0} / {1}' -f $changed, $failed) }
Write-Host ('  Report                              : {0}' -f $OutputPath)
if ($PassThru) { $results }
#endregion Main
