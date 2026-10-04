<#
.SYNOPSIS
    Inventories every Microsoft Entra ID group with its resolved type, dynamic rule, Teams status and optional member/owner counts.
.DESCRIPTION
    Lists all groups through Microsoft Graph (GET /groups with $select) and derives a readable GroupType - Microsoft 365,
    Security, Mail-enabled security or Distribution, prefixed with "Dynamic" for rule-based groups - plus whether the group
    backs a Microsoft Teams team, its visibility, classification, role-assignability, lifecycle (renewed / expiration)
    dates and on-premises sync state. With -IncludeCounts the member and owner counts are read per group through the
    /$count endpoints. The result is exported to CSV and summarised by group type in the console.
.PARAMETER GroupType
    Restricts the report to one or more types: Microsoft365, Security, MailEnabledSecurity, Distribution or Dynamic.
    Type filters include both static and dynamic groups of that type; Dynamic selects every rule-based group.
.PARAMETER OnlyCloud
    Excludes groups synchronised from on-premises Active Directory (onPremisesSyncEnabled eq true).
.PARAMETER IncludeCounts
    Adds MemberCount and OwnerCount columns. Costs two extra Graph calls per group, so it is slower in large tenants.
.PARAMETER OutputPath
    Path of the CSV report. Defaults to .\Reports\EntraGroupInventory_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emits the report objects to the pipeline.
.EXAMPLE
    PS> .\Get-EntraGroupInventory.ps1
    Exports every group with its type, dynamic rule, Teams flag and lifecycle dates to .\Reports.
.EXAMPLE
    PS> .\Get-EntraGroupInventory.ps1 -GroupType Microsoft365 -OnlyCloud -IncludeCounts
    Reports cloud-only Microsoft 365 groups (static and dynamic) together with their member and owner counts.
.EXAMPLE
    PS> .\Get-EntraGroupInventory.ps1 -GroupType Dynamic -PassThru | Where-Object { $_.MembershipRuleProcessingState -ne 'On' }
    Lists dynamic groups whose rule processing is paused.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : Group.Read.All (delegated). GroupMember.Read.All is requested only with -IncludeCounts.
    Category    : Groups
    Changes     : No
    Notes       : -IncludeCounts issues two /$count requests per group (ConsistencyLevel=eventual) with a short pause
                  between groups, so expect roughly one minute per 250 groups. ExpirationDateTime is only populated for
                  Microsoft 365 groups covered by a group expiration policy.
.LINK
    https://learn.microsoft.com/graph/api/group-list
.LINK
    https://learn.microsoft.com/graph/api/resources/group
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateSet('Microsoft365', 'Security', 'MailEnabledSecurity', 'Distribution', 'Dynamic')]
    [string[]]$GroupType,

    [Parameter()]
    [switch]$OnlyCloud,

    [Parameter()]
    [switch]$IncludeCounts,

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
    param(
        [Parameter(Mandatory = $true)]
        [string]$Uri
    )
    $response = Invoke-MgGraphRequest -Method GET -Uri $Uri -Headers @{ 'ConsistencyLevel' = 'eventual' } -ErrorAction Stop
    return [int](([string]$response).Trim())
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
#endregion Helpers

#region Main
$requiredScopes = @('Group.Read.All')
if ($IncludeCounts) { $requiredScopes += 'GroupMember.Read.All' }

if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('EntraGroupInventory_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}

try {
    Connect-GraphIfNeeded -Scopes $requiredScopes
}
catch {
    throw "Unable to connect to Microsoft Graph: $($_.Exception.Message)"
}

$graphV1 = 'https://graph.microsoft.com/v1.0'
$selectProperties = 'id,displayName,description,mail,mailEnabled,securityEnabled,groupTypes,membershipRule,membershipRuleProcessingState,visibility,' +
    'createdDateTime,renewedDateTime,expirationDateTime,onPremisesSyncEnabled,isAssignableToRole,classification,resourceProvisioningOptions'
Write-Verbose 'Retrieving groups.'
try {
    $groups = Invoke-GraphPaged -Uri ('{0}/groups?$select={1}&$top=999' -f $graphV1, $selectProperties)
}
catch {
    throw "Failed to list groups: $($_.Exception.Message)"
}
Write-Verbose "Retrieved $($groups.Count) groups."

# Maps the -GroupType values to the base type names; Dynamic is handled separately because it is a modifier, not a type.
$typeNames = @{ Microsoft365 = 'Microsoft 365'; Security = 'Security'; MailEnabledSecurity = 'Mail-enabled security'; Distribution = 'Distribution' }
$wantedBaseTypes = @()
foreach ($requested in @($GroupType)) { if ($typeNames.ContainsKey($requested)) { $wantedBaseTypes += $typeNames[$requested] } }
$wantDynamic = (@($GroupType) -contains 'Dynamic')

$results = New-Object -TypeName System.Collections.Generic.List[object]
$processed = 0
foreach ($group in $groups) {
    $processed++
    if ($processed % 25 -eq 0) {
        Write-Progress -Activity 'Processing groups' -Status "$processed of $($groups.Count)" -PercentComplete (($processed / $groups.Count) * 100)
    }
    if ($OnlyCloud -and $group.onPremisesSyncEnabled -eq $true) { continue }

    $groupTypes = @($group.groupTypes)
    $isDynamic = ($groupTypes -contains 'DynamicMembership')
    if ($groupTypes -contains 'Unified') { $baseType = 'Microsoft 365' }
    elseif ($group.mailEnabled -and $group.securityEnabled) { $baseType = 'Mail-enabled security' }
    elseif ($group.securityEnabled) { $baseType = 'Security' }
    else { $baseType = 'Distribution' }
    if ($null -ne $GroupType -and -not (($wantedBaseTypes -contains $baseType) -or ($wantDynamic -and $isDynamic))) { continue }

    $typeName = $baseType
    if ($isDynamic) { $typeName = 'Dynamic ' + $baseType }
    $memberCount = $null
    $ownerCount = $null
    if ($IncludeCounts) {
        try {
            $memberCount = Get-GraphCount -Uri ('{0}/groups/{1}/members/$count' -f $graphV1, $group.id)
            $ownerCount = Get-GraphCount -Uri ('{0}/groups/{1}/owners/$count' -f $graphV1, $group.id)
            Start-Sleep -Milliseconds 200
        }
        catch {
            Write-Warning "Could not read member/owner counts for '$($group.displayName)': $($_.Exception.Message)"
        }
    }

    $results.Add([PSCustomObject]@{
        DisplayName                   = $group.displayName
        GroupType                     = $typeName
        IsDynamic                     = $isDynamic
        IsTeam                        = (@($group.resourceProvisioningOptions) -contains 'Team')
        Mail                          = $group.mail
        Visibility                    = $group.visibility
        Classification                = $group.classification
        IsAssignableToRole            = ($group.isAssignableToRole -eq $true)
        OnPremisesSyncEnabled         = ($group.onPremisesSyncEnabled -eq $true)
        MembershipRule                = $group.membershipRule
        MembershipRuleProcessingState = $group.membershipRuleProcessingState
        MemberCount                   = $memberCount
        OwnerCount                    = $ownerCount
        CreatedDateTime               = ConvertTo-UtcDateTime -Value $group.createdDateTime
        RenewedDateTime               = ConvertTo-UtcDateTime -Value $group.renewedDateTime
        ExpirationDateTime            = ConvertTo-UtcDateTime -Value $group.expirationDateTime
        Description                   = $group.description
        Id                            = $group.id
    })
}
Write-Progress -Activity 'Processing groups' -Completed

if ($results.Count -gt 0) {
    $results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
}
else {
    Write-Warning 'No groups matched the selected filters; no CSV was written.'
}

Write-Host ''
Write-Host 'Entra ID group inventory' -ForegroundColor Cyan
Write-Host ('  Groups in tenant : {0}' -f $groups.Count)
Write-Host ('  Groups reported  : {0}' -f $results.Count) -ForegroundColor Yellow
foreach ($bucket in ($results | Group-Object -Property GroupType | Sort-Object -Property Count -Descending)) {
    Write-Host ('    {0,-30}: {1}' -f $bucket.Name, $bucket.Count)
}
Write-Host ('  Teams-enabled    : {0}' -f @($results | Where-Object { $_.IsTeam }).Count)
Write-Host ('  Role-assignable  : {0}' -f @($results | Where-Object { $_.IsAssignableToRole }).Count)
Write-Host ('  Report           : {0}' -f $OutputPath)

if ($PassThru) {
    $results
}
#endregion Main
