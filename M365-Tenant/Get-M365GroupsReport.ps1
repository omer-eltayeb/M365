<#
.SYNOPSIS
    Inventories Microsoft 365 groups with lifecycle, ownership, guest, Teams and sensitivity-label details.
.DESCRIPTION
    Lists every Microsoft 365 (Unified) group through GET /groups with a server-side groupTypes filter, or only the groups
    selected with -GroupName (wildcards) / -GroupId, and reads the owner, member and guest counts of each group through the
    /$count endpoints (ConsistencyLevel=eventual). Rows show visibility, classification, sensitivity label, Teams provisioning,
    dynamic membership, age, renewal and expiration dates; switches add owners, SharePoint site URL and address-list visibility.
.PARAMETER GroupName
    One or more display names to include; wildcards are supported (for example 'Project-*'). Default: every Microsoft 365 group.
.PARAMETER GroupId
    Object ID of a single Microsoft 365 group.
.PARAMETER Include
    Optional details, each costing one extra call per group: Owners (user principal names joined with ';'), SiteUrl
    (/groups/{id}/sites/root, requests Sites.Read.All) and AddressListVisibility (hideFromAddressLists, only returned by GET /groups/{id}).
.PARAMETER OutputPath
    Path of the CSV report. Defaults to .\Reports\M365Groups_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emits the report objects to the pipeline.
.EXAMPLE
    PS> .\Get-M365GroupsReport.ps1
    Exports every Microsoft 365 group with counts and lifecycle dates and prints the governance summary.
.EXAMPLE
    PS> .\Get-M365GroupsReport.ps1 -GroupName 'Project-*' -Include Owners, SiteUrl -OutputPath C:\Temp\ProjectGroups.csv -Verbose
    Reports only groups whose name starts with Project-, adding the owners and the SharePoint site URL of each group.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : Group.Read.All, GroupMember.Read.All, User.Read.All (delegated); Sites.Read.All only with -Include SiteUrl.
    Category    : Microsoft 365 Groups governance
    Changes     : No
    Notes       : Three /$count calls per group (plus one per optional switch), so 2,000 groups take roughly 15 minutes. Dates
                  are UTC; ExpirationDateTime is empty when no expiration policy covers the group. The guest count falls back to
                  listing guest members when Graph rejects the filtered /$count segment. hideFromAddressLists is Exchange-backed
                  (Teams-created groups are hidden by default) and may be unavailable until the group mailbox exists.
.LINK
    https://learn.microsoft.com/graph/api/group-list
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding(DefaultParameterSetName = 'All')]
param(
    [Parameter(ParameterSetName = 'ByName')]
    [string[]]$GroupName,

    [Parameter(ParameterSetName = 'ById')]
    [ValidatePattern('^[0-9a-fA-F-]{36}$')]
    [string]$GroupId,

    [Parameter()]
    [ValidateSet('Owners', 'SiteUrl', 'AddressListVisibility')]
    [string[]]$Include,

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

function Get-GraphCount {
    <# Reads a /$count endpoint (advanced query, needs ConsistencyLevel=eventual) and returns the value as [int]. #>
    param([Parameter(Mandatory = $true)][string]$Uri)
    $response = Invoke-MgGraphRequest -Method GET -Uri $Uri -Headers @{ ConsistencyLevel = 'eventual' } -ErrorAction Stop
    return [int](([string]$response).Trim())
}
#endregion Helpers

#region Main
$graphV1 = 'https://graph.microsoft.com/v1.0'
$eventual = @{ ConsistencyLevel = 'eventual' }
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('M365Groups_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}

$requiredScopes = @('Group.Read.All', 'GroupMember.Read.All', 'User.Read.All')
if ($Include -contains 'SiteUrl') { $requiredScopes += 'Sites.Read.All' }
try { Connect-GraphIfNeeded -Scopes $requiredScopes }
catch { throw "Unable to connect to Microsoft Graph: $($_.Exception.Message)" }

$select = 'id,displayName,mail,visibility,createdDateTime,renewedDateTime,expirationDateTime,classification,assignedLabels,resourceProvisioningOptions,groupTypes'
$filter = 'groupTypes/any(c:c eq ''Unified'')'
if ($PSCmdlet.ParameterSetName -eq 'ById') { $filter += " and id eq '$GroupId'" }
try { $groups = @(Invoke-GraphPaged -Uri ('{0}/groups?$filter={1}&$select={2}&$top=999' -f $graphV1, $filter, $select)) }
catch { throw "Failed to list Microsoft 365 groups: $($_.Exception.Message)" }
if ($PSCmdlet.ParameterSetName -eq 'ByName') { $groups = @($groups | Where-Object { $name = $_.displayName; @($GroupName | Where-Object { $name -like $_ }).Count -gt 0 }) }
if ($groups.Count -eq 0) { Write-Warning 'No Microsoft 365 group matched the selection; nothing to report.'; return }
Write-Verbose "Reading counts and details for $($groups.Count) groups."

$results = New-Object -TypeName System.Collections.Generic.List[object]
$nowUtc = [datetime]::UtcNow; $processed = 0
foreach ($group in $groups) {
    $processed++
    Write-Progress -Activity 'Reading group details' -Status "$processed of $($groups.Count): $($group.displayName)" -PercentComplete (($processed / $groups.Count) * 100)
    $groupUri = '{0}/groups/{1}' -f $graphV1, $group.id
    $ownersCount = $null; $membersCount = $null; $guestsCount = $null; $owners = $null; $siteUrl = $null; $hidden = $null
    try {
        $ownersCount = Get-GraphCount -Uri ($groupUri + '/owners/$count')
        $membersCount = Get-GraphCount -Uri ($groupUri + '/members/$count')
        # Some tenants reject the filtered /$count segment; listing the guest members gives the same number.
        try { $guestsCount = Get-GraphCount -Uri ($groupUri + '/members/microsoft.graph.user/$count?$filter=userType eq ''Guest''') }
        catch { $guestsCount = @(Invoke-GraphPaged -Uri ($groupUri + '/members/microsoft.graph.user?$filter=userType eq ''Guest''&$count=true&$select=id') -Headers $eventual).Count }
        if ($Include -contains 'Owners') { $owners = (@(Invoke-GraphPaged -Uri ($groupUri + '/owners?$select=userPrincipalName')).userPrincipalName | Where-Object { $_ }) -join ';' }
        if ($Include -contains 'AddressListVisibility') { $hidden = (Invoke-MgGraphRequest -Method GET -Uri ($groupUri + '?$select=hideFromAddressLists') -ErrorAction Stop).hideFromAddressLists }
    }
    catch { Write-Warning "Could not read every detail of '$($group.displayName)': $($_.Exception.Message)" }
    if ($Include -contains 'SiteUrl') {
        # Graph answers 404 until the group site is provisioned; that is not worth a warning.
        try { $siteUrl = (Invoke-MgGraphRequest -Method GET -Uri ($groupUri + '/sites/root?$select=webUrl') -OutputType PSObject -ErrorAction Stop).webUrl }
        catch { Write-Verbose "No SharePoint site found for '$($group.displayName)': $($_.Exception.Message)" }
    }

    $created = $null; if ($group.createdDateTime) { $created = ([datetime]$group.createdDateTime).ToUniversalTime() }
    $renewed = $null; if ($group.renewedDateTime) { $renewed = ([datetime]$group.renewedDateTime).ToUniversalTime() }
    $expires = $null; if ($group.expirationDateTime) { $expires = ([datetime]$group.expirationDateTime).ToUniversalTime() }
    $ageDays = $null; if ($null -ne $created) { $ageDays = [int][math]::Floor(($nowUtc - $created).TotalDays) }
    $daysUntilExpiration = $null; if ($null -ne $expires) { $daysUntilExpiration = [int][math]::Ceiling(($expires - $nowUtc).TotalDays) }
    $results.Add([PSCustomObject]@{
        DisplayName            = $group.displayName
        Mail                   = $group.mail
        Visibility             = $group.visibility
        Classification         = $group.classification
        SensitivityLabel       = ($group.assignedLabels | Select-Object -First 1).displayName
        IsTeam                 = (@($group.resourceProvisioningOptions) -contains 'Team')
        IsDynamic              = (@($group.groupTypes) -contains 'DynamicMembership')
        CreatedDateTime        = $created
        AgeDays                = $ageDays
        RenewedDateTime        = $renewed
        ExpirationDateTime     = $expires
        DaysUntilExpiration    = $daysUntilExpiration
        OwnersCount            = $ownersCount
        MembersCount           = $membersCount
        GuestsCount            = $guestsCount
        HiddenFromAddressLists = $hidden
        SiteUrl                = $siteUrl
        Owners                 = $owners
        Id                     = $group.id
    })
    Start-Sleep -Milliseconds 200
}
Write-Progress -Activity 'Reading group details' -Completed
$results | Sort-Object -Property DisplayName | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

$teamsCount = @($results | Where-Object { $_.IsTeam }).Count
$expiringCount = @($results | Where-Object { $null -ne $_.DaysUntilExpiration -and $_.DaysUntilExpiration -le 30 }).Count
Write-Host 'Microsoft 365 groups summary' -ForegroundColor Cyan
Write-Host ('  Groups                       : {0}' -f $results.Count)
Write-Host ('  Teams-enabled                : {0} ({1:N1} %)' -f $teamsCount, (($teamsCount / $results.Count) * 100))
Write-Host ('  Ownerless                    : {0}' -f @($results | Where-Object { $_.OwnersCount -eq 0 }).Count) -ForegroundColor Yellow
Write-Host ('  With guest members           : {0}' -f @($results | Where-Object { $_.GuestsCount -gt 0 }).Count)
Write-Host ('  Expiring within 30 days      : {0} (including already expired)' -f $expiringCount) -ForegroundColor Yellow
Write-Host ('  Report                       : {0}' -f $OutputPath)
if ($PassThru) { $results }
#endregion Main
