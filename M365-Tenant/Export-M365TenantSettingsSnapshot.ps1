<#
.SYNOPSIS
    Exports a JSON snapshot of tenant-wide Microsoft 365 settings and diffs it against a previous snapshot for change tracking.
.DESCRIPTION
    Reads the organization profile, SharePoint tenant settings, report settings, authorization policy, security defaults,
    authentication methods policy, cross-tenant access defaults, admin consent request policy, group settings and lifecycle
    policies, domains, directory synchronization status and Conditional Access policy names/states through Microsoft Graph
    v1.0 and writes one JSON file per area into -OutputFolder. Areas the signed-in user cannot read (HTTP 403) are reported
    and skipped. With -CompareWith the snapshot is compared recursively with an earlier one and every difference is written
    to Changes.csv (Area, Path, Old, New), giving an audit trail of tenant configuration changes.
.PARAMETER OutputFolder
    Folder for the JSON files (created when missing). Default .\M365TenantSnapshot_yyyyMMdd-HHmm.
.PARAMETER CompareWith
    Folder of a previous snapshot written by this script. Differences go to Changes.csv inside -OutputFolder; volatile
    properties (lastModifiedDateTime, modifiedDateTime, last sync times, @odata.*) are ignored.
.PARAMETER IncludeBeta
    Also capture the Microsoft 365 Apps installation options from the beta endpoint (adds OrgSettings-Microsoft365Install.Read.All).
.PARAMETER PassThru
    Also emit one summary object per area, followed by the change objects when -CompareWith is used.
.EXAMPLE
    PS> .\Export-M365TenantSettingsSnapshot.ps1
    Writes the snapshot into .\M365TenantSnapshot_<timestamp>\ and lists the areas captured or skipped.
.EXAMPLE
    PS> .\Export-M365TenantSettingsSnapshot.ps1 -OutputFolder C:\Snapshots\2026-10 -CompareWith C:\Snapshots\2026-09 -IncludeBeta
    Captures the current settings and writes every difference against the September snapshot to C:\Snapshots\2026-10\Changes.csv.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : Organization.Read.All, SharePointTenantSettings.Read.All, ReportSettings.Read.All, Policy.Read.All,
                  Directory.Read.All, Domain.Read.All, OnPremDirectorySynchronization.Read.All (delegated);
                  OrgSettings-Microsoft365Install.Read.All only with -IncludeBeta. Global Reader can read every area.
    Category    : Tenant configuration & health
    Changes     : No
    Notes       : Read-only. The files contain configuration only (no secrets) but are tenant-specific, so keep the
                  folders in a private repository or share. Collections are matched on 'id' (or 'name' for group setting
                  values), so Changes.csv lists added, removed and changed items by key. Beta endpoints can change without notice.
.LINK
    https://learn.microsoft.com/graph/api/organization-get
.LINK
    https://learn.microsoft.com/graph/api/sharepointsettings-get
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputFolder,

    [Parameter()]
    [string]$CompareWith,

    [Parameter()]
    [switch]$IncludeBeta,

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

function ConvertTo-CanonicalValue {
    <# Recursively copies a Graph/JSON value into ordered hashtables with sorted keys, volatile keys removed and dates as UTC text. #>
    param([Parameter()][AllowNull()]$Value, [Parameter()][string[]]$IgnoreKeys)
    if ($null -eq $Value) { return $null }
    if ($Value -is [datetime]) { return $Value.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') }
    if ($Value -is [string]) {
        # ISO dates become fixed UTC text so string and [datetime] representations compare equal across PowerShell versions.
        $parsed = [datetime]::MinValue
        $styles = [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal
        if ($Value -match '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}' -and [datetime]::TryParse($Value, [cultureinfo]::InvariantCulture, $styles, [ref]$parsed)) {
            return $parsed.ToString('yyyy-MM-ddTHH:mm:ssZ')
        }
        return $Value
    }
    if ($Value -is [System.Collections.IDictionary]) { $Value = [PSCustomObject]$Value }
    if ($Value -is [System.Management.Automation.PSCustomObject]) {
        $ordered = [ordered]@{}
        foreach ($property in @($Value.PSObject.Properties | Sort-Object -Property Name)) {
            if ($IgnoreKeys -contains $property.Name -or $property.Name -like '@odata.*') { continue }
            $ordered[$property.Name] = ConvertTo-CanonicalValue -Value $property.Value -IgnoreKeys $IgnoreKeys
        }
        return $ordered
    }
    if ($Value -is [System.Collections.IEnumerable]) {
        return , @(foreach ($item in $Value) { , (ConvertTo-CanonicalValue -Value $item -IgnoreKeys $IgnoreKeys) })
    }
    return $Value
}

function Compare-CanonicalValue {
    <# Recursively compares two canonical values and adds one change object per differing leaf to $Changes. #>
    param([AllowNull()]$Old, [AllowNull()]$New, [string]$Area, [string]$Path, [System.Collections.Generic.List[object]]$Changes)
    if ($Old -is [System.Collections.IDictionary] -and $New -is [System.Collections.IDictionary]) {
        foreach ($key in @(@($Old.Keys) + @($New.Keys) | Sort-Object -Unique)) {
            Compare-CanonicalValue -Old $Old[$key] -New $New[$key] -Area $Area -Path "$Path/$key" -Changes $Changes
        }
        return
    }
    if ($Old -is [array] -and $New -is [array]) {
        # Collections whose items all carry an 'id' (policies, domains) or 'name' (group setting values) are matched by that key.
        foreach ($keyName in @('id', 'name')) {
            $keyed = @($Old + $New | Where-Object { $_ -is [System.Collections.IDictionary] -and $_.Contains($keyName) })
            if ($keyed.Count -eq 0 -or $keyed.Count -ne ($Old.Count + $New.Count)) { continue }
            $oldMap = @{}
            $newMap = @{}
            foreach ($item in $Old) { $oldMap[[string]$item[$keyName]] = $item }
            foreach ($item in $New) { $newMap[[string]$item[$keyName]] = $item }
            Compare-CanonicalValue -Old $oldMap -New $newMap -Area $Area -Path $Path -Changes $Changes
            return
        }
    }
    $texts = foreach ($side in @($Old, $New)) {
        if ($null -eq $side) { '' }
        elseif ($side -is [System.Collections.IDictionary] -or $side -is [array]) { ConvertTo-Json -InputObject $side -Depth 20 -Compress }
        else { [string]$side }
    }
    if ($texts[0] -cne $texts[1]) { $Changes.Add([PSCustomObject]@{ Area = $Area; Path = $Path; Old = $texts[0]; New = $texts[1] }) }
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputFolder)) {
    $OutputFolder = Join-Path -Path (Get-Location).Path -ChildPath ('M365TenantSnapshot_{0}' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
if (-not (Test-Path -Path $OutputFolder)) { New-Item -Path $OutputFolder -ItemType Directory -Force | Out-Null }
if (-not [string]::IsNullOrWhiteSpace($CompareWith) -and -not (Test-Path -Path $CompareWith -PathType Container)) {
    throw "Previous snapshot folder '$CompareWith' was not found."
}
$ignoredKeys = @('lastModifiedDateTime', 'modifiedDateTime', 'onPremisesLastSyncDateTime', 'onPremisesLastPasswordSyncDateTime')
$orgSelect = 'id,displayName,createdDateTime,countryLetterCode,preferredLanguage,technicalNotificationMails,marketingNotificationEmails,' +
    'securityComplianceNotificationMails,securityComplianceNotificationPhones,privacyProfile,verifiedDomains,onPremisesSyncEnabled,' +
    'tenantType,partnerTenantType,mobileDeviceManagementAuthority'
# Single = the endpoint returns one object instead of a collection; the file then holds the object itself.
$areas = @(
    @{ Name = 'Organization'; Scope = 'Organization.Read.All'; Path = ('organization?$select=' + $orgSelect) }
    @{ Name = 'SharePointSettings'; Scope = 'SharePointTenantSettings.Read.All'; Path = 'admin/sharepoint/settings'; Single = $true }
    @{ Name = 'ReportSettings'; Scope = 'ReportSettings.Read.All'; Path = 'admin/reportSettings'; Single = $true }
    @{ Name = 'AuthorizationPolicy'; Scope = 'Policy.Read.All'; Path = 'policies/authorizationPolicy'; Single = $true }
    @{ Name = 'SecurityDefaults'; Scope = 'Policy.Read.All'; Path = 'policies/identitySecurityDefaultsEnforcementPolicy'; Single = $true }
    @{ Name = 'AuthenticationMethodsPolicy'; Scope = 'Policy.Read.All'; Path = 'policies/authenticationMethodsPolicy'; Single = $true }
    @{ Name = 'CrossTenantAccessDefault'; Scope = 'Policy.Read.All'; Path = 'policies/crossTenantAccessPolicy/default'; Single = $true }
    @{ Name = 'AdminConsentRequestPolicy'; Scope = 'Policy.Read.All'; Path = 'policies/adminConsentRequestPolicy'; Single = $true }
    @{ Name = 'GroupSettings'; Scope = 'Directory.Read.All'; Path = 'groupSettings' }
    @{ Name = 'GroupLifecyclePolicies'; Scope = 'Directory.Read.All'; Path = 'groupLifecyclePolicies' }
    @{ Name = 'Domains'; Scope = 'Domain.Read.All'; Path = 'domains' }
    @{ Name = 'OnPremisesSynchronization'; Scope = 'OnPremDirectorySynchronization.Read.All'; Path = 'directory/onPremisesSynchronization' }
    @{ Name = 'ConditionalAccessPolicies'; Scope = 'Policy.Read.All'; Path = 'identity/conditionalAccess/policies?$select=id,displayName,state,createdDateTime' }
)
if ($IncludeBeta) {
    # beta: m365AppsInstallationOptions (update channel, Windows/Mac app installs) is documented on the beta endpoint.
    $areas += @{ Name = 'M365AppsInstallationOptions'; Scope = 'OrgSettings-Microsoft365Install.Read.All'
        Path = 'admin/microsoft365Apps/installationOptions'; Single = $true; Beta = $true }
}
try {
    Connect-GraphIfNeeded -Scopes @($areas | ForEach-Object { $_.Scope } | Sort-Object -Unique)
}
catch {
    throw "Failed to connect to Microsoft Graph: $($_.Exception.Message)"
}

$summary = New-Object -TypeName System.Collections.Generic.List[object]
$current = @{}
foreach ($area in $areas) {
    $version = 'v1.0'
    if ($area.Beta) { $version = 'beta' }
    $filePath = Join-Path -Path $OutputFolder -ChildPath ('{0}.json' -f $area.Name)
    $status = 'Captured'
    $itemCount = 0
    try {
        $items = @(Invoke-GraphPaged -Uri ('https://graph.microsoft.com/{0}/{1}' -f $version, $area.Path))
        $payload = $items
        if ($area.Single -and $items.Count -eq 1) { $payload = $items[0] }
        $current[$area.Name] = ConvertTo-CanonicalValue -Value $payload -IgnoreKeys $ignoredKeys
        $itemCount = $items.Count
        ConvertTo-Json -InputObject $current[$area.Name] -Depth 20 | Set-Content -Path $filePath -Encoding UTF8
    }
    catch {
        $status = 'Failed'
        $detail = $_.Exception.Message
        if ($detail -match 'Forbidden|403|Authorization_RequestDenied|AccessDenied') {
            $status = 'Forbidden'
            $detail = 'access denied; the signed-in user needs {0} and an admin role that can read this area.' -f $area.Scope
        }
        Write-Warning ('{0}: {1} Area skipped.' -f $area.Name, $detail)
    }
    $summary.Add([PSCustomObject]@{ Area = $area.Name; Status = $status; Items = $itemCount; File = $filePath })
}

$changes = New-Object -TypeName System.Collections.Generic.List[object]
if (-not [string]::IsNullOrWhiteSpace($CompareWith)) {
    foreach ($area in @($areas | Where-Object { $current.ContainsKey($_.Name) })) {
        $previousFile = Join-Path -Path $CompareWith -ChildPath ('{0}.json' -f $area.Name)
        if (-not (Test-Path -Path $previousFile)) {
            Write-Warning "$($area.Name).json does not exist in the previous snapshot; area not compared."
            continue
        }
        # @() keeps collections stable: PowerShell 7 enumerates JSON arrays, Windows PowerShell returns them whole.
        $previous = @(Get-Content -Path $previousFile -Raw -Encoding UTF8 | ConvertFrom-Json)
        if ($area.Single -and $previous.Count -eq 1) { $previous = $previous[0] }
        $previous = ConvertTo-CanonicalValue -Value $previous -IgnoreKeys $ignoredKeys
        Compare-CanonicalValue -Old $previous -New $current[$area.Name] -Area $area.Name -Path '' -Changes $changes
    }
    if ($changes.Count -gt 0) {
        $changes | Export-Csv -Path (Join-Path -Path $OutputFolder -ChildPath 'Changes.csv') -NoTypeInformation -Encoding UTF8
    }
}

$captured = @($summary | Where-Object { $_.Status -eq 'Captured' })
Write-Host ''
Write-Host 'Tenant settings snapshot' -ForegroundColor Cyan
Write-Host ('  Snapshot folder : {0}' -f $OutputFolder)
Write-Host ('  Areas captured  : {0} of {1}' -f $captured.Count, $summary.Count) -ForegroundColor Green
foreach ($skipped in @($summary | Where-Object { $_.Status -ne 'Captured' })) {
    Write-Host ('    {0,-28} {1}' -f $skipped.Area, $skipped.Status) -ForegroundColor Yellow
}
if (-not [string]::IsNullOrWhiteSpace($CompareWith)) {
    $changeColor = 'Green'
    if ($changes.Count -gt 0) { $changeColor = 'Yellow' }
    Write-Host ('  Changes since {0}: {1}' -f $CompareWith, $changes.Count) -ForegroundColor $changeColor
    foreach ($group in @($changes | Group-Object -Property Area | Sort-Object -Property Count -Descending)) {
        Write-Host ('    {0,-28} {1,4}' -f $group.Name, $group.Count)
    }
}

if ($PassThru) {
    $summary
    $changes
}
#endregion Main
