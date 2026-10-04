<#
.SYNOPSIS
    Checks the Microsoft Entra Connect / Cloud Sync health: last sync times, enabled sync features and objects with provisioning errors.
.DESCRIPTION
    Reads the tenant sync status (GET /organization: onPremisesSyncEnabled, onPremisesLastSyncDateTime,
    onPremisesLastPasswordSyncDateTime) and flags stale directory or password hash synchronisation, lists the configured
    synchronisation features and accidental deletion prevention (GET /directory/onPremisesSynchronization) and collects every
    user, group and organizational contact that has an on-premises provisioning error such as a duplicate proxyAddress or UPN
    (GET /users, /groups and /contacts filtered on onPremisesProvisioningErrors). The errors are exported to -OutputPath and the
    status rows to <OutputPath>_SyncStatus.csv.
.PARAMETER MaxSyncAgeHours
    Hours after which the last directory synchronisation is reported as stale. Default 3 (the default sync cycle is 30 minutes).
.PARAMETER MaxPasswordSyncAgeHours
    Hours after which the last password hash synchronisation is reported as stale. Default 6.
.PARAMETER OutputPath
    Path of the provisioning error CSV. Defaults to .\Reports\EntraSyncErrors_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emits the provisioning error objects to the pipeline.
.EXAMPLE
    PS> .\Get-EntraSyncStatusAndErrors.ps1
    Prints the sync status and feature list and exports every object with a provisioning error.
.EXAMPLE
    PS> .\Get-EntraSyncStatusAndErrors.ps1 -MaxSyncAgeHours 1 -PassThru | Where-Object { $_.ObjectType -eq 'User' }
    Flags a directory sync older than one hour and lists only the user objects with errors in the console.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : Organization.Read.All, OnPremDirectorySynchronization.Read.All, User.Read.All, Group.Read.All, OrgContact.Read.All
                  (delegated); Global Reader or Hybrid Identity Administrator.
    Category    : Roles, governance & tenant policy
    Changes     : No
    Notes       : Tenants without directory synchronisation return no features and no last sync time; the script reports this and
                  still checks for provisioning errors. Objects quarantined by Entra Connect itself are only visible on the sync server.
.LINK
    https://learn.microsoft.com/graph/api/onpremisesdirectorysynchronization-get
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateRange(1, 168)]
    [int]$MaxSyncAgeHours = 3,

    [Parameter()]
    [ValidateRange(1, 168)]
    [int]$MaxPasswordSyncAgeHours = 6,

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

function ConvertTo-UtcDateTime {
    <# Normalises a Graph date value (ISO 8601 string or [datetime]) to a UTC [datetime]; returns $null when empty. #>
    param([object]$Value)
    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) { return $null }
    return ([datetime]$Value).ToUniversalTime()
}

function Add-Status {
    <# Records one line of the sync status table. #>
    param([string]$Setting, [object]$Value, [string]$Status = 'Info')
    $script:StatusRows.Add([PSCustomObject]@{ Setting = $Setting; Value = [string]$Value; Status = $Status })
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('EntraSyncErrors_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}
$statusPath = [System.IO.Path]::Combine($outputFolder, [System.IO.Path]::GetFileNameWithoutExtension($OutputPath) + '_SyncStatus.csv')

try { Connect-GraphIfNeeded -Scopes @('Organization.Read.All', 'OnPremDirectorySynchronization.Read.All', 'User.Read.All', 'Group.Read.All', 'OrgContact.Read.All') }
catch { throw "Unable to connect to Microsoft Graph: $($_.Exception.Message)" }

$v1 = 'https://graph.microsoft.com/v1.0'
$script:StatusRows = New-Object -TypeName System.Collections.Generic.List[object]
$now = [datetime]::UtcNow
try { $organization = @(Invoke-GraphPaged -Uri "$v1/organization?`$select=id,displayName,onPremisesSyncEnabled,onPremisesLastSyncDateTime,onPremisesLastPasswordSyncDateTime")[0] }
catch { throw "Failed to read the organization: $($_.Exception.Message)" }
$syncEnabled = [bool]$organization.onPremisesSyncEnabled
Add-Status -Setting 'Tenant' -Value $organization.displayName
Add-Status -Setting 'Directory synchronization enabled' -Value $syncEnabled -Status $(if ($syncEnabled) { 'OK' } else { 'Info' })
foreach ($check in @(@{ Name = 'Last directory sync'; Property = 'onPremisesLastSyncDateTime'; MaxHours = $MaxSyncAgeHours },
        @{ Name = 'Last password hash sync'; Property = 'onPremisesLastPasswordSyncDateTime'; MaxHours = $MaxPasswordSyncAgeHours })) {
    $lastSync = ConvertTo-UtcDateTime -Value $organization.($check.Property)
    if ($null -eq $lastSync) { Add-Status -Setting $check.Name -Value 'never'; continue }
    $ageHours = [math]::Round(($now - $lastSync).TotalHours, 1)
    $status = 'OK'
    if ($ageHours -gt $check.MaxHours) { $status = 'Warning' }
    Add-Status -Setting $check.Name -Value ('{0:yyyy-MM-dd HH:mm} UTC ({1} h ago)' -f $lastSync, $ageHours) -Status $status
}

$syncConfig = $null
try { $syncConfig = @(Invoke-GraphPaged -Uri "$v1/directory/onPremisesSynchronization")[0] }
catch { Write-Warning "The on-premises synchronization configuration could not be read: $($_.Exception.Message)" }
if ($null -ne $syncConfig) {
    $featureNames = @('passwordSyncEnabled', 'passwordWritebackEnabled', 'groupWriteBackEnabled', 'deviceWritebackEnabled', 'userWritebackEnabled',
        'directoryExtensionsEnabled', 'synchronizeUpnForManagedUsersEnabled', 'cloudPasswordPolicyForPasswordSyncedUsersEnabled',
        'blockCloudObjectTakeoverThroughHardMatchEnabled', 'blockSoftMatchEnabled', 'softMatchOnUpnEnabled')
    foreach ($featureName in $featureNames) { Add-Status -Setting ('Feature: ' + $featureName) -Value ([bool]$syncConfig.features.$featureName) }
    $prevention = $syncConfig.configuration.accidentalDeletionPrevention
    $preventionStatus = 'OK'
    if ([string]$prevention.synchronizationPreventionType -eq 'disabled') { $preventionStatus = 'Warning' }
    Add-Status -Setting 'Accidental deletion prevention (type / threshold)' -Value ('{0} / {1}' -f $prevention.synchronizationPreventionType, $prevention.alertThreshold) -Status $preventionStatus
    Add-Status -Setting 'Synchronization interval' -Value $syncConfig.configuration.synchronizationInterval
}

# Every object type uses the same lambda filter; ConsistencyLevel=eventual with $count=true keeps the query on the advanced path.
$errorFilter = "`$filter=onPremisesProvisioningErrors/any(e:e/category eq 'PropertyConflict')&`$count=true"
$objectTypes = @(@{ Type = 'User'; Path = 'users'; Select = 'id,displayName,userPrincipalName,mail,onPremisesProvisioningErrors' },
    @{ Type = 'Group'; Path = 'groups'; Select = 'id,displayName,mail,onPremisesProvisioningErrors' },
    @{ Type = 'Contact'; Path = 'contacts'; Select = 'id,displayName,mail,onPremisesProvisioningErrors' })
$rows = New-Object -TypeName System.Collections.Generic.List[object]
foreach ($objectType in $objectTypes) {
    Write-Progress -Activity 'Collecting provisioning errors' -Status $objectType.Type
    try { $objects = @(Invoke-GraphPaged -Uri ('{0}/{1}?{2}&$select={3}' -f $v1, $objectType.Path, $errorFilter, $objectType.Select) -Headers @{ ConsistencyLevel = 'eventual' }) }
    catch { Write-Warning ('{0} objects with provisioning errors could not be read: {1}' -f $objectType.Type, $_.Exception.Message); continue }
    Write-Verbose ('{0}: {1} object(s) with provisioning errors.' -f $objectType.Type, $objects.Count)
    foreach ($object in $objects) {
        foreach ($provisioningError in @($object.onPremisesProvisioningErrors)) {
            $rows.Add([PSCustomObject]@{
                ObjectType           = $objectType.Type
                DisplayName          = $object.displayName
                UpnOrMail            = @($object.userPrincipalName, $object.mail) | Where-Object { -not [string]::IsNullOrEmpty($_) } | Select-Object -First 1
                Category             = $provisioningError.category
                PropertyCausingError = $provisioningError.propertyCausingError
                Value                = $provisioningError.value
                OccurredDateTime     = ConvertTo-UtcDateTime -Value $provisioningError.occurredDateTime
                ObjectId             = $object.id
            })
        }
    }
}
Write-Progress -Activity 'Collecting provisioning errors' -Completed

$script:StatusRows | Export-Csv -Path $statusPath -NoTypeInformation -Encoding UTF8
if ($rows.Count -gt 0) { $rows | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 }
else { Write-Host 'No objects with on-premises provisioning errors were found; no error CSV was written.' -ForegroundColor Green }

Write-Host ''
Write-Host 'Directory synchronization status' -ForegroundColor Cyan
foreach ($statusRow in ($script:StatusRows | Where-Object { $_.Setting -notlike 'Feature:*' })) {
    $colour = 'Gray'
    if ($statusRow.Status -eq 'OK') { $colour = 'Green' } elseif ($statusRow.Status -eq 'Warning') { $colour = 'Yellow' }
    Write-Host ('  {0,-50} {1}' -f $statusRow.Setting, $statusRow.Value) -ForegroundColor $colour
}
$enabledFeatures = @($script:StatusRows | Where-Object { $_.Setting -like 'Feature:*' -and $_.Value -eq 'True' } | ForEach-Object { $_.Setting -replace '^Feature: ', '' })
Write-Host ('  {0,-50} {1}' -f 'Enabled features', ($enabledFeatures -join ', '))
Write-Host ('  Status rows exported : {0} -> {1}' -f $script:StatusRows.Count, $statusPath)
foreach ($group in ($rows | Group-Object -Property ObjectType)) { Write-Host ('  {0}s with provisioning errors : {1}' -f $group.Name, $group.Count) -ForegroundColor Yellow }
if ($rows.Count -gt 0) { Write-Host ('  Provisioning errors exported : {0} -> {1}' -f $rows.Count, $OutputPath) }

if ($PassThru) { $rows }
#endregion Main
