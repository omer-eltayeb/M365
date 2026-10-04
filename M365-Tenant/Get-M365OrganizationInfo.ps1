<#
.SYNOPSIS
    Reports the Microsoft 365 organization profile (contacts, domains, plans, directory quota, MDM authority) with hygiene findings.
.DESCRIPTION
    Reads GET /organization (Microsoft Graph v1.0) and turns the tenant profile into Setting / Value / Finding rows:
    tenant identity and type, address, notification contacts, privacy profile, directory synchronization, MDM
    authority, directory size quota, verified domains and assigned service plans per service. Findings flag an empty
    or personal technical notification address, missing privacy profile, an MDM authority other than Intune, a
    directory that is more than 80 % full and a default domain that is still the initial .onmicrosoft.com domain.
.PARAMETER ResolveNotificationMails
    Looks up every technical notification address in /users to tell an individual mailbox (enabled, licensed user)
    from a shared mailbox or group. Requests the User.Read.All scope.
.PARAMETER OutputPath
    Path of the CSV report. Defaults to .\Reports\M365OrganizationInfo_yyyyMMdd-HHmm.csv.
.PARAMETER Json
    Also saves the raw organization object as returned by Graph to <OutputPath base>.json.
.PARAMETER PassThru
    Also emits the Setting / Value / Finding objects to the pipeline.
.EXAMPLE
    PS> .\Get-M365OrganizationInfo.ps1
    Exports the organization profile to .\Reports\ and prints the findings.
.EXAMPLE
    PS> .\Get-M365OrganizationInfo.ps1 -ResolveNotificationMails -Json -OutputPath C:\Temp\Org.csv -Verbose
    Also checks whether the technical notification addresses are personal mailboxes and writes C:\Temp\Org.json.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : Organization.Read.All (delegated); User.Read.All only with -ResolveNotificationMails. Any directory
                  reader role (for example Global Reader or Directory Readers) can read /organization.
    Category    : Tenant configuration & health
    Changes     : No
    Notes       : mobileDeviceManagementAuthority is 'unknown' until Intune is licensed and the MDM authority is chosen.
                  The directory size quota can only be raised by Microsoft support. All date/time values are UTC.
.LINK
    https://learn.microsoft.com/graph/api/organization-get
.LINK
    https://learn.microsoft.com/graph/api/resources/organization
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [Parameter()]
    [switch]$ResolveNotificationMails,

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

function ConvertTo-UtcDateTime {
    <# Normalises a Graph date value (ISO 8601 string or [datetime]) to a UTC [datetime]; $null when empty. #>
    param([Parameter()][AllowNull()]$Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [datetime]) {
        if ($Value.Kind -eq [System.DateTimeKind]::Local) { return $Value.ToUniversalTime() }
        return [datetime]::SpecifyKind($Value, [System.DateTimeKind]::Utc)
    }
    if ([string]::IsNullOrWhiteSpace([string]$Value)) { return $null }
    $parsed = [datetime]::MinValue
    $styles = [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal
    if ([datetime]::TryParse([string]$Value, [System.Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$parsed)) { return $parsed }
    return $null
}

function Add-SettingRow {
    <# Appends one Setting / Value / Finding row; collections are joined with '; '. #>
    param([string]$Setting, [AllowNull()]$Value, [string]$Finding = '')
    if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]) {
        $Value = (@($Value | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) }) -join '; ')
    }
    $rows.Add([PSCustomObject]@{ Setting = $Setting; Value = $Value; Finding = $Finding })
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('M365OrganizationInfo_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}
$jsonPath = [System.IO.Path]::Combine([string]$outputFolder, ('{0}.json' -f [System.IO.Path]::GetFileNameWithoutExtension($OutputPath)))

$scopes = @('Organization.Read.All')
if ($ResolveNotificationMails) { $scopes += 'User.Read.All' }
try {
    Connect-GraphIfNeeded -Scopes $scopes
}
catch {
    throw "Failed to connect to Microsoft Graph: $($_.Exception.Message)"
}

$select = 'id,displayName,createdDateTime,countryLetterCode,preferredLanguage,street,city,state,postalCode,businessPhones,' +
    'technicalNotificationMails,marketingNotificationEmails,securityComplianceNotificationMails,securityComplianceNotificationPhones,' +
    'privacyProfile,verifiedDomains,onPremisesSyncEnabled,onPremisesLastSyncDateTime,assignedPlans,provisionedPlans,tenantType,' +
    'partnerTenantType,directorySizeQuota,mobileDeviceManagementAuthority'
$organizationUri = 'https://graph.microsoft.com/v1.0/organization?$select={0}' -f $select
try {
    $organization = @(Invoke-GraphPaged -Uri $organizationUri)[0]
    # The raw JSON text is saved exactly as Graph returns it, so dates and property names are not reformatted.
    if ($Json) { Invoke-MgGraphRequest -Method GET -Uri $organizationUri -OutputType Json -ErrorAction Stop | Set-Content -Path $jsonPath -Encoding UTF8 }
}
catch {
    throw "Failed to read the organization profile: $($_.Exception.Message)"
}
if ($null -eq $organization) { throw 'Graph returned no organization object.' }

# Shared mailboxes are disabled, unlicensed user objects; an enabled and licensed user is an individual's mailbox.
$personalMails = @()
$technicalMails = @($organization.technicalNotificationMails | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
foreach ($address in @($technicalMails | Where-Object { $ResolveNotificationMails })) {
    $filter = "mail eq '{0}' or userPrincipalName eq '{0}'" -f $address.Replace("'", "''")
    $userUri = 'https://graph.microsoft.com/v1.0/users?$filter={0}&$select=id,accountEnabled,assignedLicenses' -f [uri]::EscapeDataString($filter)
    try {
        if (@(Invoke-GraphPaged -Uri $userUri | Where-Object { $_.accountEnabled -and @($_.assignedLicenses).Count -gt 0 }).Count -gt 0) { $personalMails += $address }
    }
    catch {
        Write-Warning "Could not resolve ${address}: $($_.Exception.Message)"
    }
}

$nowUtc = [datetime]::UtcNow
$rows = New-Object -TypeName System.Collections.Generic.List[object]
$simpleRows = @(@('TenantId', 'id'), @('DisplayName', 'displayName'), @('TenantType', 'tenantType'), @('PartnerTenantType', 'partnerTenantType'),
    @('CountryLetterCode', 'countryLetterCode'), @('PreferredLanguage', 'preferredLanguage'), @('BusinessPhones', 'businessPhones'))
foreach ($pair in $simpleRows) { Add-SettingRow -Setting $pair[0] -Value $organization.($pair[1]) }
Add-SettingRow -Setting 'CreatedDateTime' -Value (ConvertTo-UtcDateTime -Value $organization.createdDateTime)
Add-SettingRow -Setting 'Address' -Value @($organization.street, $organization.city, $organization.state, $organization.postalCode)

$technicalFinding = ''
if ($technicalMails.Count -eq 0) {
    $technicalFinding = 'No technical notification address; service and billing notifications from Microsoft are lost.'
}
elseif ($personalMails.Count -gt 0) {
    $technicalFinding = 'Points to an individual mailbox ({0}); use a shared mailbox or group monitored by the admin team.' -f ($personalMails -join ', ')
}
Add-SettingRow -Setting 'TechnicalNotificationMails' -Value $technicalMails -Finding $technicalFinding
Add-SettingRow -Setting 'MarketingNotificationEmails' -Value $organization.marketingNotificationEmails
Add-SettingRow -Setting 'SecurityComplianceNotificationMails' -Value $organization.securityComplianceNotificationMails
Add-SettingRow -Setting 'SecurityComplianceNotificationPhones' -Value $organization.securityComplianceNotificationPhones

$privacyFinding = ''
if ([string]::IsNullOrWhiteSpace($organization.privacyProfile.contactEmail) -or [string]::IsNullOrWhiteSpace($organization.privacyProfile.statementUrl)) {
    $privacyFinding = 'Privacy profile incomplete; set the contact and statement URL in Org settings > Organization profile > Privacy profile.'
}
Add-SettingRow -Setting 'PrivacyContactEmail' -Value $organization.privacyProfile.contactEmail -Finding $privacyFinding
Add-SettingRow -Setting 'PrivacyStatementUrl' -Value $organization.privacyProfile.statementUrl

$lastSync = ConvertTo-UtcDateTime -Value $organization.onPremisesLastSyncDateTime
$syncFinding = ''
if ($organization.onPremisesSyncEnabled -and $null -ne $lastSync -and ($nowUtc - $lastSync).TotalHours -gt 3) {
    $syncFinding = 'Last directory synchronization was {0:N1} hours ago; check Microsoft Entra Connect or Cloud Sync.' -f ($nowUtc - $lastSync).TotalHours
}
Add-SettingRow -Setting 'OnPremisesSyncEnabled' -Value ([bool]$organization.onPremisesSyncEnabled)
Add-SettingRow -Setting 'OnPremisesLastSyncDateTime' -Value $lastSync -Finding $syncFinding

$mdmAuthority = [string]$organization.mobileDeviceManagementAuthority
$mdmFinding = ''
if ($mdmAuthority -ne 'intune') { $mdmFinding = 'MDM authority is not Intune; devices cannot enroll into Intune until the MDM authority is set to Intune.' }
Add-SettingRow -Setting 'MobileDeviceManagementAuthority' -Value $mdmAuthority -Finding $mdmFinding

$quota = $organization.directorySizeQuota
$quotaValue = $null
$quotaFinding = ''
if ($null -ne $quota -and [int64]$quota.total -gt 0) {
    $percentUsed = [math]::Round(([double]$quota.used / [double]$quota.total) * 100, 1)
    $quotaValue = '{0:N0} of {1:N0} objects ({2} %)' -f [int64]$quota.used, [int64]$quota.total, $percentUsed
    if ($percentUsed -gt 80) { $quotaFinding = 'Directory is {0} % full; clean up stale objects or ask Microsoft support for a quota increase.' -f $percentUsed }
}
Add-SettingRow -Setting 'DirectorySizeQuota' -Value $quotaValue -Finding $quotaFinding

$domains = @($organization.verifiedDomains)
$defaultDomain = $domains | Where-Object { $_.isDefault } | Select-Object -First 1
$domainFinding = ''
if ($null -ne $defaultDomain -and $defaultDomain.isInitial) { $domainFinding = 'The default domain is still the initial .onmicrosoft.com domain; make a custom domain the default.' }
Add-SettingRow -Setting 'VerifiedDomains' -Value $domains.Count
Add-SettingRow -Setting 'DefaultDomain' -Value $defaultDomain.name -Finding $domainFinding
Add-SettingRow -Setting 'InitialDomain' -Value ($domains | Where-Object { $_.isInitial } | Select-Object -First 1).name
$planGroups = @($organization.assignedPlans | Where-Object { -not [string]::IsNullOrWhiteSpace($_.service) } | Group-Object -Property service | Sort-Object -Property Name)
foreach ($planGroup in $planGroups) {
    $statusCounts = @($planGroup.Group | Group-Object -Property capabilityStatus | Sort-Object -Property Name | ForEach-Object { '{0}: {1}' -f $_.Name, $_.Count })
    Add-SettingRow -Setting ('AssignedPlans.{0}' -f $planGroup.Name) -Value ($statusCounts -join '; ')
}

$rows | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
$findings = @($rows | Where-Object { -not [string]::IsNullOrWhiteSpace($_.Finding) })
$findingColor = 'Green'
if ($findings.Count -gt 0) { $findingColor = 'Yellow' }
Write-Host ''
Write-Host 'Organization profile summary' -ForegroundColor Cyan
Write-Host ('  Tenant         : {0} ({1})' -f $organization.displayName, $organization.id)
Write-Host ('  Default domain : {0}   MDM authority: {1}   Services with plans: {2}' -f $defaultDomain.name, $mdmAuthority, $planGroups.Count)
Write-Host ('  Findings       : {0}' -f $findings.Count) -ForegroundColor $findingColor
foreach ($finding in $findings) { Write-Host ('    {0,-32} {1}' -f $finding.Setting, $finding.Finding) -ForegroundColor Yellow }
Write-Host ('  Report         : {0}' -f $OutputPath)
if ($Json) { Write-Host ('  JSON           : {0}' -f $jsonPath) }

if ($PassThru) { $rows }
#endregion Main
