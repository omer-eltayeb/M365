<#
.SYNOPSIS
    Exports Intune enrollment configurations (restrictions, device limits, ESP, Windows Hello, co-management, notifications) plus Apple ADE and Android Enterprise enrollment profiles.
.DESCRIPTION
    Reads beta /deviceManagement/deviceEnrollmentConfigurations?$expand=assignments, classifies each configuration by @odata.type
    (PlatformRestrictions, DeviceLimit, EnrollmentStatusPage, WindowsHelloForBusiness, CoManagement, EnrollmentNotifications), saves it as JSON
    under <OutputFolder>\EnrollmentConfigurations and indexes it in EnrollmentConfigurations.csv (kind, name, priority, settings summary, assignments
    with group names). Apple ADE profiles (depOnboardingSettings/{id}/enrollmentProfiles) and Android Enterprise profiles
    (androidDeviceOwnerEnrollmentProfiles, tokens expiring within 30 days flagged) are written to their own CSVs.
.PARAMETER OutputFolder
    Root folder for the export. Defaults to .\IntuneEnrollmentExport_yyyyMMdd-HHmm and is created when missing.
.PARAMETER PassThru
    Also emit the EnrollmentConfigurations.csv rows to the pipeline.
.EXAMPLE
    PS> .\Export-IntuneEnrollmentConfigurations.ps1
    Exports every enrollment configuration and profile and prints counts per kind plus any Android tokens that expire soon.
.EXAMPLE
    PS> .\Export-IntuneEnrollmentConfigurations.ps1 -OutputFolder D:\Backups\Enrollment -PassThru | Where-Object { $_.Kind -eq 'PlatformRestrictions' }
    Backs up the configurations and shows the platform restriction policies with their blocked platforms and OS version limits.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : DeviceManagementServiceConfig.Read.All, DeviceManagementConfiguration.Read.All and Group.Read.All (delegated); Intune RBAC Read Only Operator.
    Category    : Enrollment & Autopilot
    Changes     : No
    Notes       : All endpoints are beta because v1.0 lacks the assignments, the per-platform restriction type and the Apple/Android profile
                  collections; beta may change. Both the legacy all-platform restriction default and the newer per-platform policies are summarised.
.LINK
    https://learn.microsoft.com/graph/api/intune-onboarding-deviceenrollmentconfiguration-list?view=graph-rest-beta
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputFolder,

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
function Get-AssignmentText {
    <# Turns an assignments collection into 'Group; Exclude: Group; All devices' text; group names are cached, deleted groups show as '<deleted group>'. #>
    param([object[]]$Assignments)
    $parts = @(foreach ($assignment in @($Assignments)) {
            $target = $assignment.target; $type = [string]$target.'@odata.type'
            if ($type -like '*AllDevicesAssignmentTarget') { 'All devices'; continue }
            if ($type -like '*AllLicensedUsersAssignmentTarget') { 'All users'; continue }
            $groupId = [string]$target.groupId
            if (-not $script:groupNameCache.ContainsKey($groupId)) {
                $uri = 'https://graph.microsoft.com/v1.0/groups/{0}?$select=displayName' -f $groupId
                try { $script:groupNameCache[$groupId] = [string](Invoke-MgGraphRequest -Method GET -Uri $uri -OutputType PSObject -ErrorAction Stop).displayName }
                catch { $script:groupNameCache[$groupId] = '<deleted group>' }
            }
            if ($type -like '*exclusionGroupAssignmentTarget') { 'Exclude: {0}' -f $script:groupNameCache[$groupId] } else { $script:groupNameCache[$groupId] }
        })
    return ($parts -join '; ')
}

function Get-RestrictionText {
    <# Formats one platform restriction block (shared by the legacy all-platform and the newer per-platform configuration types). #>
    param([string]$Platform, [object]$Restriction)
    if ($null -eq $Restriction) { return $null }
    $values = @($Platform, $Restriction.platformBlocked, $Restriction.personalDeviceEnrollmentBlocked, $Restriction.osMinimumVersion, $Restriction.osMaximumVersion)
    return '{0}: blocked={1} personalBlocked={2} osMin={3} osMax={4}' -f $values
}

function Get-SettingsSummary {
    <# Returns Kind and a one-line 'name=value' settings summary for an enrollment configuration based on its @odata.type. #>
    param([object]$Config)
    $type = ([string]$Config.'@odata.type') -replace '^#microsoft\.graph\.', ''
    $kind = 'Other:' + $type; $names = @(); $extra = $null
    switch ($type) {
        'deviceEnrollmentPlatformRestrictionsConfiguration' {
            $kind = 'PlatformRestrictions'; $platforms = @('ios', 'windows', 'windowsMobile', 'android', 'androidForWork', 'macOS')
            $extra = @(@(foreach ($p in $platforms) { Get-RestrictionText -Platform $p -Restriction $Config.($p + 'Restriction') }) | Where-Object { $_ }) -join '; '
        }
        'deviceEnrollmentPlatformRestrictionConfiguration' { $kind = 'PlatformRestrictions'; $extra = Get-RestrictionText -Platform $Config.platformType -Restriction $Config.platformRestriction }
        'deviceEnrollmentLimitConfiguration' { $kind = 'DeviceLimit'; $names = @('limit') }
        'windows10EnrollmentCompletionPageConfiguration' {
            $kind = 'EnrollmentStatusPage'; $extra = 'selectedApps={0}' -f @($Config.selectedMobileAppIds).Count
            $names = @('showInstallationProgress', 'blockDeviceSetupRetryByUser', 'allowDeviceResetOnInstallFailure', 'allowDeviceUseOnInstallFailure',
                'installProgressTimeoutInMinutes', 'trackInstallProgressForAutopilotOnly')
        }
        'deviceEnrollmentWindowsHelloForBusinessConfiguration' {
            $kind = 'WindowsHelloForBusiness'; $names = @('state', 'pinMinimumLength', 'pinMaximumLength', 'securityDeviceRequired', 'unlockWithBiometricsEnabled', 'enhancedBiometricsState')
        }
        'deviceComanagementAuthorityConfiguration' { $kind = 'CoManagement'; $names = @('managedDeviceAuthority', 'installConfigurationManagerAgent', 'configurationManagerAgentCommandLineArgument') }
        'deviceEnrollmentNotificationConfiguration' { $kind = 'EnrollmentNotifications'; $names = @('platformType', 'templateType', 'brandingOptions', 'defaultLocale') }
    }
    $parts = @(foreach ($name in $names) { '{0}={1}' -f $name, $Config.$name }); if ($extra) { $parts += $extra }
    return @{ Kind = $kind; Summary = ($parts -join ' ') }
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputFolder)) {
    $OutputFolder = Join-Path -Path (Get-Location).Path -ChildPath ('IntuneEnrollmentExport_{0}' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$jsonFolder = Join-Path -Path $OutputFolder -ChildPath 'EnrollmentConfigurations'; if (-not (Test-Path -LiteralPath $jsonFolder)) { New-Item -Path $jsonFolder -ItemType Directory -Force | Out-Null }
$OutputFolder = (Resolve-Path -LiteralPath $OutputFolder).ProviderPath

try { Connect-GraphIfNeeded -Scopes @('DeviceManagementServiceConfig.Read.All', 'DeviceManagementConfiguration.Read.All', 'Group.Read.All') }
catch { throw "Failed to connect to Microsoft Graph: $($_.Exception.Message)" }

# beta: v1.0 lacks the assignments expansion, the per-platform restriction type and the Apple/Android profile collections.
$beta = 'https://graph.microsoft.com/beta/deviceManagement'
try { $configurations = @(Invoke-GraphPaged -Uri "$beta/deviceEnrollmentConfigurations?`$expand=assignments" | Sort-Object -Property priority) }
catch { throw "Failed to list enrollment configurations: $($_.Exception.Message)" }
$rows = New-Object -TypeName System.Collections.Generic.List[object]
foreach ($config in $configurations) {
    Write-Progress -Activity 'Exporting enrollment configurations' -Status $config.displayName -PercentComplete ([int](($rows.Count + 1) / $configurations.Count * 100))
    $info = Get-SettingsSummary -Config $config
    $safeName = (([string]$config.displayName) -replace '[\\/:*?"<>|\x00-\x1F]', '_').Trim(); if ($safeName.Length -gt 80) { $safeName = $safeName.Substring(0, 80).TrimEnd() }
    $jsonPath = Join-Path -Path $jsonFolder -ChildPath ('{0}_{1}_{2}.json' -f ($info.Kind -replace ':', '-'), $safeName, ([string]$config.id).Substring(0, 8))
    try { $config | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $jsonPath -Encoding UTF8 }
    catch { $jsonPath = $null; Write-Warning ("Failed to write '{0}': {1}" -f $config.displayName, $_.Exception.Message) }
    $lastModified = $null; if ($config.lastModifiedDateTime) { $lastModified = ([datetime]$config.lastModifiedDateTime).ToUniversalTime() }
    $rows.Add([PSCustomObject]@{ Kind = $info.Kind; Name = $config.displayName; Priority = $config.priority; SettingsSummary = $info.Summary
            Assignments = Get-AssignmentText -Assignments $config.assignments; LastModified = $lastModified; ConfigurationId = $config.id; ExportFile = $jsonPath })
}
Write-Progress -Activity 'Exporting enrollment configurations' -Completed
$rows | Export-Csv -Path (Join-Path -Path $OutputFolder -ChildPath 'EnrollmentConfigurations.csv') -NoTypeInformation -Encoding UTF8

$appleRows = New-Object -TypeName System.Collections.Generic.List[object]
try {
    foreach ($token in @(Invoke-GraphPaged -Uri "$beta/depOnboardingSettings?`$select=id,appleIdentifier,tokenName")) {
        foreach ($profile in @(Invoke-GraphPaged -Uri ('{0}/depOnboardingSettings/{1}/enrollmentProfiles' -f $beta, $token.id))) {
            $platform = ([string]$profile.'@odata.type') -replace '^#microsoft\.graph\.dep', '' -replace 'EnrollmentProfile$', ''
            $appleRows.Add([PSCustomObject]@{ Token = $token.appleIdentifier; Name = $profile.displayName; Platform = $platform; IsDefault = $profile.isDefault
                    SupervisionEnabled = $profile.supervisionEnabled; RequiresUserAuthentication = $profile.requiresUserAuthentication
                    AuthenticationViaCompanyPortal = $profile.enableAuthenticationViaCompanyPortal; ProfileId = $profile.id })
        }
    }
    if ($appleRows.Count -gt 0) { $appleRows | Export-Csv -Path (Join-Path -Path $OutputFolder -ChildPath 'AppleEnrollmentProfiles.csv') -NoTypeInformation -Encoding UTF8 }
}
catch { Write-Warning ('Apple ADE profiles could not be read (no ADE token configured?): {0}' -f $_.Exception.Message) }

$androidRows = New-Object -TypeName System.Collections.Generic.List[object]
try {
    foreach ($profile in @(Invoke-GraphPaged -Uri "$beta/androidDeviceOwnerEnrollmentProfiles")) {
        $expires = $null; $daysLeft = $null
        if ($profile.tokenExpirationDateTime) {
            $expires = ([datetime]$profile.tokenExpirationDateTime).ToUniversalTime(); $daysLeft = [int][math]::Floor(($expires - (Get-Date).ToUniversalTime()).TotalDays)
        }
        $androidRows.Add([PSCustomObject]@{ Name = $profile.displayName; EnrollmentMode = $profile.enrollmentMode; TokenExpires = $expires; DaysUntilTokenExpiry = $daysLeft
                TokenExpiringSoon = ($null -ne $daysLeft -and $daysLeft -le 30); EnrolledDeviceCount = $profile.enrolledDeviceCount; ProfileId = $profile.id })
    }
    if ($androidRows.Count -gt 0) { $androidRows | Export-Csv -Path (Join-Path -Path $OutputFolder -ChildPath 'AndroidEnrollmentProfiles.csv') -NoTypeInformation -Encoding UTF8 }
}
catch { Write-Warning ('Android Enterprise enrollment profiles could not be read (Managed Google Play not bound?): {0}' -f $_.Exception.Message) }

$expiring = @($androidRows | Where-Object { $_.TokenExpiringSoon }); $expiringColour = 'Green'; if ($expiring.Count -gt 0) { $expiringColour = 'Yellow' }
Write-Host ("`nExport folder              : {0}" -f $OutputFolder) -ForegroundColor Cyan
Write-Host ('Enrollment configurations  : {0}' -f $rows.Count) -ForegroundColor Cyan
foreach ($group in ($rows | Group-Object -Property Kind | Sort-Object -Property Name)) { Write-Host ('  {0,-28} {1,6}' -f $group.Name, $group.Count) }
Write-Host ('Apple ADE profiles         : {0}' -f $appleRows.Count) -ForegroundColor Cyan
Write-Host ('Android Enterprise profiles: {0} ({1} token(s) expiring within 30 days)' -f $androidRows.Count, $expiring.Count) -ForegroundColor $expiringColour
foreach ($item in $expiring) { Write-Host ('  {0}: token expires {1:yyyy-MM-dd} ({2} days)' -f $item.Name, $item.TokenExpires, $item.DaysUntilTokenExpiry) -ForegroundColor Yellow }

if ($PassThru) { $rows }
#endregion Main
