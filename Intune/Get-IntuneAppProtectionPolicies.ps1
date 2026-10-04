<#
.SYNOPSIS
    Reports every Intune app protection (MAM) policy for iOS, Android and Windows with its key settings, targeted apps and assignments.
.DESCRIPTION
    Reads the app protection policy collections from Microsoft Graph beta (/deviceAppManagement/iosManagedAppProtections,
    /androidManagedAppProtections and /windowsManagedAppProtections expanded with apps and assignments) and flattens the settings an
    administrator reviews most often - PIN, data transfer, clipboard, backup, Save As, printing, offline wipe period and minimum OS/app
    versions - into one row per policy. Group ids are resolved to names, every policy can be saved as JSON, and each platform is
    queried independently so a failure on one collection does not stop the others.
.PARAMETER Platform
    One or more platforms to include: iOS, Android, Windows. Default: all three.
.PARAMETER ExportJsonFolder
    Folder that receives one <Platform>_<PolicyName>_<id>.json file per policy (created when missing). Nothing is exported when omitted.
.PARAMETER OutputPath
    CSV file to create. Defaults to .\Reports\IntuneAppProtectionPolicies_yyyyMMdd-HHmm.csv; the folder is created when missing.
.PARAMETER PassThru
    Also emit the report objects to the pipeline.
.EXAMPLE
    PS> .\Get-IntuneAppProtectionPolicies.ps1
    Exports all MAM policies to .\Reports and prints a per-platform summary including the number of unassigned policies.
.EXAMPLE
    PS> .\Get-IntuneAppProtectionPolicies.ps1 -Platform iOS, Android -ExportJsonFolder D:\Backups\MAM -PassThru | Where-Object { -not $_.PinRequired }
    Backs up the mobile policies as JSON and lists those that do not require an app PIN.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : DeviceManagementApps.Read.All and Group.Read.All (delegated) plus an Intune RBAC role with
                  "Managed apps" read permission (for example Read Only Operator).
    Category    : Apps & app protection
    Changes     : No
    Notes       : beta is used because v1.0 lacks the Windows MAM collection and newer settings; it may change without notice. Windows
                  MAM policies have no PIN, backup, Save As, contact sync or fingerprint settings, so those columns stay empty for them.
.LINK
    https://learn.microsoft.com/graph/api/intune-mam-iosmanagedappprotection-list?view=graph-rest-beta
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateSet('iOS', 'Android', 'Windows')]
    [string[]]$Platform = @('iOS', 'Android', 'Windows'),

    [Parameter()]
    [string]$ExportJsonFolder,

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

$script:groupNameCache = @{}
function Get-GroupDisplayName {
    <# Resolves a group id to its display name through a script-level cache; deleted groups return '<deleted group>'. #>
    param([string]$GroupId)
    if (-not $script:groupNameCache.ContainsKey($GroupId)) {
        $uri = 'https://graph.microsoft.com/v1.0/groups/{0}?$select=displayName' -f $GroupId
        try { $script:groupNameCache[$GroupId] = [string](Invoke-MgGraphRequest -Method GET -Uri $uri -OutputType PSObject -ErrorAction Stop).displayName }
        catch {
            if ($_.Exception.Message -match 'Request_ResourceNotFound|does not exist') { $script:groupNameCache[$GroupId] = '<deleted group>' }
            else { $script:groupNameCache[$GroupId] = $GroupId; Write-Warning ('Could not resolve group {0}: {1}' -f $GroupId, $_.Exception.Message) }
        }
    }
    return $script:groupNameCache[$GroupId]
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('IntuneAppProtectionPolicies_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}
if (-not [string]::IsNullOrWhiteSpace($ExportJsonFolder) -and -not (Test-Path -LiteralPath $ExportJsonFolder)) { New-Item -Path $ExportJsonFolder -ItemType Directory -Force | Out-Null }

try { Connect-GraphIfNeeded -Scopes @('DeviceManagementApps.Read.All', 'Group.Read.All') }
catch { throw "Failed to connect to Microsoft Graph: $($_.Exception.Message)" }

# beta: Windows MAM policies and several newer protection settings are not exposed on v1.0.
$collections = @{ iOS = 'iosManagedAppProtections'; Android = 'androidManagedAppProtections'; Windows = 'windowsManagedAppProtections' }
$rows = New-Object -TypeName System.Collections.Generic.List[object]
foreach ($platformName in $Platform) {
    $uri = 'https://graph.microsoft.com/beta/deviceAppManagement/{0}?$expand=apps,assignments' -f $collections[$platformName]
    try { $policies = @(Invoke-GraphPaged -Uri $uri) }
    catch { Write-Warning ('Failed to read {0} app protection policies: {1}' -f $platformName, $_.Exception.Message); continue }
    Write-Verbose ('{0}: {1} policies.' -f $platformName, $policies.Count)

    foreach ($policy in $policies) {
        # The app identifier property depends on the platform (bundleId / packageId / windowsAppId); take whichever is populated.
        $targetedApps = @(foreach ($app in @($policy.apps)) {
                $identifier = $app.mobileAppIdentifier
                if ($null -ne $identifier) { @($identifier.bundleId, $identifier.packageId, $identifier.windowsAppId) | Where-Object { $_ } | Select-Object -First 1 }
            })
        # Order matters: the exclusion type also matches '*groupAssignmentTarget', hence the explicit breaks.
        $assignmentGroups = @(foreach ($assignment in @($policy.assignments)) {
                $target = $assignment.target
                switch -Wildcard ([string]$target.'@odata.type') {
                    '*exclusionGroupAssignmentTarget' { 'Exclude: {0}' -f (Get-GroupDisplayName -GroupId $target.groupId); break }
                    '*groupAssignmentTarget' { Get-GroupDisplayName -GroupId $target.groupId; break }
                    '*allLicensedUsersAssignmentTarget' { 'All users'; break }
                    default { [string]$target.'@odata.type' -replace '^#microsoft\.graph\.', '' }
                }
            })
        $lastModified = $null
        if ($policy.lastModifiedDateTime) { $lastModified = ([datetime]$policy.lastModifiedDateTime).ToUniversalTime() }
        # Graph returns the offline wipe period as an ISO 8601 duration (for example P90D); report it in days.
        $offlineWipeDays = $null
        if ($policy.periodOfflineBeforeWipeIsEnforced) {
            try { $offlineWipeDays = [math]::Round([System.Xml.XmlConvert]::ToTimeSpan([string]$policy.periodOfflineBeforeWipeIsEnforced).TotalDays, 2) }
            catch { $offlineWipeDays = [string]$policy.periodOfflineBeforeWipeIsEnforced }
        }
        if (-not [string]::IsNullOrWhiteSpace($ExportJsonFolder)) {
            $safeName = (([string]$policy.displayName) -replace '[\\/:*?"<>|\x00-\x1F]', '_').Trim()
            if ($safeName.Length -gt 80) { $safeName = $safeName.Substring(0, 80).TrimEnd() }
            $jsonPath = Join-Path -Path $ExportJsonFolder -ChildPath ('{0}_{1}_{2}.json' -f $platformName, $safeName, $policy.id.Substring(0, 8))
            try { $policy | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $jsonPath -Encoding UTF8 }
            catch { Write-Warning ("Failed to write JSON for '{0}': {1}" -f $policy.displayName, $_.Exception.Message) }
        }

        $rows.Add([PSCustomObject]@{
                Platform                    = $platformName
                Name                        = $policy.displayName
                TargetedApps                = ($targetedApps -join '; ')
                AssignmentGroups            = ($assignmentGroups -join '; ')
                PinRequired                 = $policy.pinRequired
                MinimumPinLength            = $policy.minimumPinLength
                DataBackupBlocked           = $policy.dataBackupBlocked
                AllowedOutboundDataTransfer = $policy.allowedOutboundDataTransferDestinations
                AllowedInboundDataTransfer  = $policy.allowedInboundDataTransferSources
                SaveAsBlocked               = $policy.saveAsBlocked
                ClipboardSharing            = $policy.allowedOutboundClipboardSharingLevel
                ManagedBrowserRequired      = $policy.managedBrowserToOpenLinksRequired
                ContactSyncBlocked          = $policy.contactSyncBlocked
                PrintBlocked                = $policy.printBlocked
                PeriodOfflineBeforeWipe     = $offlineWipeDays
                MinimumRequiredOsVersion    = $policy.minimumRequiredOsVersion
                MinimumRequiredAppVersion   = $policy.minimumRequiredAppVersion
                DeviceComplianceRequired    = $policy.deviceComplianceRequired
                FingerprintBlocked          = $policy.fingerprintBlocked
                LastModified                = $lastModified
                PolicyId                    = $policy.id
            })
    }
}

if ($rows.Count -gt 0) {
    $rows | Sort-Object -Property Platform, Name | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
    Write-Host ('Report written to {0}' -f $OutputPath) -ForegroundColor Green
}
else { Write-Warning 'No app protection policies were returned for the selected platforms.' }
$unassigned = @($rows | Where-Object { [string]::IsNullOrEmpty($_.AssignmentGroups) }).Count
$unassignedColour = 'Green'; if ($unassigned -gt 0) { $unassignedColour = 'Yellow' }
Write-Host ("`nPolicies total      : {0}" -f $rows.Count) -ForegroundColor Cyan
Write-Host ('Policies unassigned : {0}' -f $unassigned) -ForegroundColor $unassignedColour
foreach ($group in ($rows | Group-Object -Property Platform | Sort-Object -Property Name)) { Write-Host ('  {0,-10} {1,6}' -f $group.Name, $group.Count) }

if ($PassThru) { $rows }
#endregion Main
