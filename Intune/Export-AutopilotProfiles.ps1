<#
.SYNOPSIS
    Exports Windows Autopilot deployment profiles and Enrollment Status Page profiles to JSON plus two flattened CSV indexes.
.DESCRIPTION
    Reads the Autopilot deployment profiles (beta /deviceManagement/windowsAutopilotDeploymentProfiles?$expand=assignments) and the
    Enrollment Status Page configurations (beta /deviceManagement/deviceEnrollmentConfigurations filtered to
    windows10EnrollmentCompletionPageConfiguration) and writes every profile as JSON under <OutputFolder>\DeploymentProfiles and
    \EnrollmentStatusPages. AutopilotProfiles.csv lists join type, deployment mode, user type, OOBE page settings, name template and assigned
    groups; EnrollmentStatusPages.csv lists priority, progress tracking, retry/reset/use-on-failure options, timeout and blocking app count.
.PARAMETER OutputFolder
    Root folder for the export. Defaults to .\AutopilotProfilesExport_yyyyMMdd-HHmm and is created when missing.
.PARAMETER PassThru
    Also emit the AutopilotProfiles.csv rows to the pipeline.
.EXAMPLE
    PS> .\Export-AutopilotProfiles.ps1
    Exports all deployment and ESP profiles and prints how many of each exist and how many are unassigned.
.EXAMPLE
    PS> .\Export-AutopilotProfiles.ps1 -OutputFolder D:\Backups\Autopilot -PassThru | Format-Table Name, JoinType, DeploymentMode, UserType, AssignedGroups
    Backs up the profiles to a fixed folder and shows the key settings of each deployment profile.
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
    Notes       : Both endpoints are beta because v1.0 does not return the profile assignments or the newer OOBE/pre-provisioning
                  properties; beta may change without notice. Profiles carry either the legacy outOfBoxExperienceSettings or the newer
                  outOfBoxExperienceSetting shape - the script reads whichever is populated. Documentation backup only, not a restore tool.
.LINK
    https://learn.microsoft.com/graph/api/intune-shared-windowsautopilotdeploymentprofile-list?view=graph-rest-beta
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

function Get-FirstValue {
    <# Returns the first non-null property among several candidate names, so legacy and current Graph property shapes are both supported. #>
    param([object]$Object, [string[]]$Names)
    foreach ($name in $Names) { $property = $Object.PSObject.Properties[$name]; if ($null -ne $property -and $null -ne $property.Value) { return $property.Value } }
    return $null
}

function Save-ProfileJson {
    <# Writes one Graph object as <Folder>\<SafeName>_<id8>.json and returns the path, or $null when the write failed. #>
    param([object]$Object, [string]$Folder)
    $safeName = (([string]$Object.displayName) -replace '[\\/:*?"<>|\x00-\x1F]', '_').Trim()
    if ($safeName.Length -gt 80) { $safeName = $safeName.Substring(0, 80).TrimEnd() }
    $path = Join-Path -Path $Folder -ChildPath ('{0}_{1}.json' -f $safeName, ([string]$Object.id).Substring(0, 8))
    try { $Object | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $path -Encoding UTF8; return $path }
    catch { Write-Warning ("Failed to write '{0}': {1}" -f $Object.displayName, $_.Exception.Message); return $null }
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputFolder)) {
    $OutputFolder = Join-Path -Path (Get-Location).Path -ChildPath ('AutopilotProfilesExport_{0}' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$profileFolder = Join-Path -Path $OutputFolder -ChildPath 'DeploymentProfiles'; $espFolder = Join-Path -Path $OutputFolder -ChildPath 'EnrollmentStatusPages'
foreach ($folder in @($OutputFolder, $profileFolder, $espFolder)) { if (-not (Test-Path -LiteralPath $folder)) { New-Item -Path $folder -ItemType Directory -Force | Out-Null } }
$OutputFolder = (Resolve-Path -LiteralPath $OutputFolder).ProviderPath

try { Connect-GraphIfNeeded -Scopes @('DeviceManagementServiceConfig.Read.All', 'DeviceManagementConfiguration.Read.All', 'Group.Read.All') }
catch { throw "Failed to connect to Microsoft Graph: $($_.Exception.Message)" }

# beta: v1.0 does not expose the profile assignments or the newer OOBE and pre-provisioning properties.
$beta = 'https://graph.microsoft.com/beta/deviceManagement'
try { $profiles = @(Invoke-GraphPaged -Uri "$beta/windowsAutopilotDeploymentProfiles?`$expand=assignments") }
catch { throw "Failed to list Autopilot deployment profiles: $($_.Exception.Message)" }
$profileRows = New-Object -TypeName System.Collections.Generic.List[object]
foreach ($profile in $profiles) {
    Write-Progress -Activity 'Exporting Autopilot deployment profiles' -Status $profile.displayName -PercentComplete ([int](($profileRows.Count + 1) / $profiles.Count * 100))
    # Newer tenants return outOfBoxExperienceSetting (singular, renamed properties); older ones still return outOfBoxExperienceSettings.
    $oobe = Get-FirstValue -Object $profile -Names @('outOfBoxExperienceSetting', 'outOfBoxExperienceSettings')
    if ($null -eq $oobe) { $oobe = [PSCustomObject]@{} }
    $joinType = 'EntraJoined'; if ([string]$profile.'@odata.type' -like '*activeDirectoryWindowsAutopilotDeploymentProfile') { $joinType = 'HybridJoined' }
    $lastModified = $null; if ($profile.lastModifiedDateTime) { $lastModified = ([datetime]$profile.lastModifiedDateTime).ToUniversalTime() }
    $profileRows.Add([PSCustomObject]@{
            Name                   = $profile.displayName
            JoinType               = $joinType
            DeploymentMode         = $oobe.deviceUsageType
            UserType               = $oobe.userType
            SkipKeyboard           = Get-FirstValue -Object $oobe -Names @('keyboardSelectionPageSkipped', 'skipKeyboardSelectionPage')
            HideEula               = Get-FirstValue -Object $oobe -Names @('eulaHidden', 'hideEULA')
            HidePrivacy            = Get-FirstValue -Object $oobe -Names @('privacySettingsHidden', 'hidePrivacySettings')
            HideEscapeLink         = Get-FirstValue -Object $oobe -Names @('escapeLinkHidden', 'hideEscapeLink')
            NameTemplate           = $profile.deviceNameTemplate
            DeviceType             = $profile.deviceType
            Language               = Get-FirstValue -Object $profile -Names @('locale', 'language')
            ExtractHardwareHash    = Get-FirstValue -Object $profile -Names @('hardwareHashExtractionEnabled', 'extractHardwareHash')
            PreProvisioningAllowed = Get-FirstValue -Object $profile -Names @('preprovisioningAllowed', 'enableWhiteGlove')
            SkipConnectivityCheck  = $profile.hybridAzureADJoinSkipConnectivityCheck
            AssignedGroups         = Get-AssignmentText -Assignments $profile.assignments
            LastModified           = $lastModified
            ProfileId              = $profile.id
            ExportFile             = Save-ProfileJson -Object $profile -Folder $profileFolder
        })
}
Write-Progress -Activity 'Exporting Autopilot deployment profiles' -Completed

try { $allConfigurations = @(Invoke-GraphPaged -Uri "$beta/deviceEnrollmentConfigurations?`$expand=assignments") }
catch { throw "Failed to list enrollment configurations: $($_.Exception.Message)" }
$espProfiles = @($allConfigurations | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.windows10EnrollmentCompletionPageConfiguration' } | Sort-Object -Property priority)
$espRows = New-Object -TypeName System.Collections.Generic.List[object]
foreach ($esp in $espProfiles) {
    $assigned = Get-AssignmentText -Assignments $esp.assignments
    # Priority 0 is the built-in default ESP; it has no assignments because it applies to every device not matched by a higher profile.
    if ([int]$esp.priority -eq 0 -and [string]::IsNullOrEmpty($assigned)) { $assigned = 'Default (all users and devices)' }
    $espRows.Add([PSCustomObject]@{
            Name                                 = $esp.displayName
            Priority                             = $esp.priority
            ShowInstallationProgress             = $esp.showInstallationProgress
            BlockDeviceSetupRetryByUser          = $esp.blockDeviceSetupRetryByUser
            AllowDeviceResetOnInstallFailure     = $esp.allowDeviceResetOnInstallFailure
            AllowDeviceUseOnInstallFailure       = $esp.allowDeviceUseOnInstallFailure
            InstallProgressTimeoutInMinutes      = $esp.installProgressTimeoutInMinutes
            SelectedAppCount                     = @($esp.selectedMobileAppIds).Count
            TrackInstallProgressForAutopilotOnly = $esp.trackInstallProgressForAutopilotOnly
            AssignedGroups                       = $assigned
            ProfileId                            = $esp.id
            ExportFile                           = Save-ProfileJson -Object $esp -Folder $espFolder
        })
}

if ($profileRows.Count -gt 0) { $profileRows | Sort-Object -Property Name | Export-Csv -Path (Join-Path -Path $OutputFolder -ChildPath 'AutopilotProfiles.csv') -NoTypeInformation -Encoding UTF8 }
else { Write-Warning 'No Autopilot deployment profiles were found.' }
if ($espRows.Count -gt 0) { $espRows | Export-Csv -Path (Join-Path -Path $OutputFolder -ChildPath 'EnrollmentStatusPages.csv') -NoTypeInformation -Encoding UTF8 }
else { Write-Warning 'No Enrollment Status Page profiles were found.' }

$unassigned = @($profileRows | Where-Object { -not $_.AssignedGroups }).Count
$unassignedColour = 'Green'; if ($unassigned -gt 0) { $unassignedColour = 'Yellow' }
Write-Host ("`nExport folder                  : {0}" -f $OutputFolder) -ForegroundColor Cyan
Write-Host ('Deployment profiles exported   : {0}' -f $profileRows.Count) -ForegroundColor Cyan
Write-Host ('Deployment profiles unassigned : {0}' -f $unassigned) -ForegroundColor $unassignedColour
Write-Host ('ESP profiles exported          : {0}' -f $espRows.Count) -ForegroundColor Cyan

if ($PassThru) { $profileRows }
#endregion Main
