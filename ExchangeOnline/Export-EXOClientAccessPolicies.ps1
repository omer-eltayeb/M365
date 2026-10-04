<#
.SYNOPSIS
    Exports the OWA, mobile device, authentication and role assignment policies to JSON files with a CSV index and usage counts.
.DESCRIPTION
    Reads Get-OwaMailboxPolicy, Get-MobileDeviceMailboxPolicy, Get-AuthenticationPolicy (with the organization default from
    Get-OrganizationConfig) and Get-RoleAssignmentPolicy, saves every policy as a JSON file in -OutputFolder and writes
    ClientAccessPolicies.csv with the policy type, default flag, key settings (attachment handling, file type counts, storage
    providers, device password and encryption rules, AllowBasicAuth* flags, assigned roles) and, for OWA and ActiveSync
    policies, how many mailboxes use each policy (Get-EXOCASMailbox). Useful as a configuration baseline before changes.
.PARAMETER OutputFolder
    Folder that receives the JSON files and the CSV index. Defaults to .\EXOClientAccessPoliciesExport_yyyyMMdd-HHmm.
.PARAMETER SkipUsageCounts
    Skip the per-mailbox policy usage counts, which enumerate every mailbox with Get-EXOCASMailbox and are slow in large tenants.
.PARAMETER PassThru
    Also emit the index objects to the pipeline.
.EXAMPLE
    PS> .\Export-EXOClientAccessPolicies.ps1
    Exports all client access policies to a timestamped folder and prints how many mailboxes use each OWA and ActiveSync policy.
.EXAMPLE
    PS> .\Export-EXOClientAccessPolicies.ps1 -OutputFolder C:\Baselines\EXO-Policies -SkipUsageCounts -PassThru | Where-Object { $_.IsDefault }
    Exports into a fixed folder without usage counts and returns only the default policies of each type.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, ExchangeOnlineManagement 3.x
    Permissions : View-Only Configuration + View-Only Recipients (or Global Reader)
    Category    : Client access & mobile devices
    Changes     : No
    Notes       : A blank ActiveSyncMailboxPolicy on a mailbox means the default policy applies, so those mailboxes are counted
                  under the default policy. Authentication policies only matter for Basic authentication (now limited to SMTP
                  AUTH); users without an assigned policy fall back to DefaultAuthenticationPolicy, or to no policy if none is set.
.LINK
    https://learn.microsoft.com/exchange/clients-and-mobile-in-exchange-online/outlook-on-the-web/outlook-on-the-web-mailbox-policies
#>
#Requires -Version 5.1
#Requires -Modules ExchangeOnlineManagement

[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputFolder,

    [Parameter()]
    [switch]$SkipUsageCounts,

    [Parameter()]
    [switch]$PassThru
)

$ErrorActionPreference = 'Stop'

#region Helpers
function Connect-ExchangeIfNeeded {
    <# Connects to Exchange Online (or Security & Compliance PowerShell) only when no live session exists. #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [switch]$Compliance
    )
    $connections = @(Get-ConnectionInformation -ErrorAction SilentlyContinue)
    if ($Compliance) {
        $active = @($connections | Where-Object { $_.ConnectionUri -like '*compliance*' -and $_.State -eq 'Connected' })
        if ($active.Count -eq 0) {
            Write-Verbose 'Connecting to Security & Compliance PowerShell.'
            Connect-IPPSSession -ErrorAction Stop
        }
    }
    else {
        $active = @($connections | Where-Object { $_.ConnectionUri -notlike '*compliance*' -and $_.State -eq 'Connected' })
        if ($active.Count -eq 0) {
            Write-Verbose 'Connecting to Exchange Online.'
            Connect-ExchangeOnline -ShowBanner:$false -ErrorAction Stop
        }
    }
}

function Format-PolicySetting {
    <# Builds "Name=value | Name=value" from the given policy properties; collections named in $CountNames are reported as item counts. #>
    param(
        [Parameter(Mandatory = $true)]
        [object]$Policy,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [string[]]$Names,

        [Parameter()]
        [string[]]$CountNames
    )
    $parts = @()
    foreach ($name in $Names) {
        $value = $Policy.$name
        if ($null -ne $value -and $value -isnot [string] -and $value -is [System.Collections.IEnumerable]) {
            if (@($CountNames) -contains $name) { $value = @($value).Count }
            else { $value = (@($value | ForEach-Object { [string]$_ }) -join ';') }
        }
        $text = ([string]$value -replace '\s+', ' ').Trim()
        if ($text.Length -gt 120) { $text = $text.Substring(0, 120) + '...' }
        $parts += '{0}={1}' -f $name, $text
    }
    return ($parts -join ' | ')
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputFolder)) {
    $OutputFolder = Join-Path -Path (Get-Location).Path -ChildPath ('EXOClientAccessPoliciesExport_{0}' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
if (-not (Test-Path -Path $OutputFolder)) { New-Item -Path $OutputFolder -ItemType Directory -Force | Out-Null }
$OutputFolder = (Resolve-Path -Path $OutputFolder).Path

try { Connect-ExchangeIfNeeded }
catch { throw "Unable to connect to Exchange Online: $($_.Exception.Message)" }

$defaultAuthPolicy = ''
try { $defaultAuthPolicy = [string](Get-OrganizationConfig -ErrorAction Stop).DefaultAuthenticationPolicy }
catch { Write-Warning "Could not read the organization configuration: $($_.Exception.Message)" }

# Usage counts come from the mailbox side; a blank ActiveSync policy on a mailbox means the default policy applies.
$owaUsage = @{}
$easUsage = @{}
if (-not $SkipUsageCounts) {
    Write-Progress -Activity 'Counting policy assignments' -Status 'Reading every CAS mailbox (this can take a while)'
    try {
        foreach ($cas in (Get-EXOCASMailbox -ResultSize Unlimited -Properties OwaMailboxPolicy, ActiveSyncMailboxPolicy -ErrorAction Stop)) {
            $owaName = [string]$cas.OwaMailboxPolicy
            $easName = [string]$cas.ActiveSyncMailboxPolicy
            if ($owaName -eq '') { $owaName = '(default)' }
            if ($easName -eq '') { $easName = '(default)' }
            $owaUsage[$owaName] = [int]$owaUsage[$owaName] + 1
            $easUsage[$easName] = [int]$easUsage[$easName] + 1
        }
    }
    catch { Write-Warning "Could not count policy assignments: $($_.Exception.Message)" }
    Write-Progress -Activity 'Counting policy assignments' -Completed
}

$policySets = @(
    @{ Type = 'OwaMailboxPolicy'; Cmdlet = 'Get-OwaMailboxPolicy'; Usage = $owaUsage; CountNames = @('AllowedFileTypes', 'BlockedFileTypes')
        Names = @('ActiveSyncIntegrationEnabled', 'DirectFileAccessOnPublicComputersEnabled', 'DirectFileAccessOnPrivateComputersEnabled',
            'ForceSaveAttachmentFilteringEnabled', 'AllowedFileTypes', 'BlockedFileTypes', 'ThirdPartyFileProvidersEnabled',
            'AdditionalStorageProvidersAvailable', 'ConditionalAccessPolicy', 'ExternalImageProxyEnabled', 'ReportJunkEmailEnabled',
            'SetPhotoEnabled', 'LinkedInEnabled', 'PlacesEnabled', 'WeatherEnabled')
    },
    @{ Type = 'MobileDeviceMailboxPolicy'; Cmdlet = 'Get-MobileDeviceMailboxPolicy'; Usage = $easUsage; CountNames = @()
        Names = @('PasswordEnabled', 'AlphanumericPasswordRequired', 'MinPasswordLength', 'MaxInactivityTimeLock', 'MaxPasswordFailedAttempts',
            'DeviceEncryptionEnabled', 'RequireDeviceEncryption', 'AllowNonProvisionableDevices', 'AllowSimplePassword', 'PasswordExpiration',
            'PasswordHistory', 'AllowStorageCard', 'AllowCamera')
    },
    @{ Type = 'AuthenticationPolicy'; Cmdlet = 'Get-AuthenticationPolicy'; Usage = $null; CountNames = @(); Names = @() },
    @{ Type = 'RoleAssignmentPolicy'; Cmdlet = 'Get-RoleAssignmentPolicy'; Usage = $null; CountNames = @(); Names = @('Description', 'AssignedRoles') }
)

$index = New-Object -TypeName System.Collections.Generic.List[object]
foreach ($set in $policySets) {
    try { $policies = @(& $set.Cmdlet -ErrorAction Stop) }
    catch { Write-Warning "$($set.Cmdlet) failed: $($_.Exception.Message)"; continue }
    Write-Verbose "$($set.Type): $($policies.Count) policy object(s)."
    foreach ($policy in $policies) {
        $fileName = '{0}_{1}.json' -f $set.Type, ([regex]::Replace([string]$policy.Name, '[\\/:*?"<>|\x00-\x1F]', '_').Trim())
        try { $policy | ConvertTo-Json -Depth 5 -WarningAction SilentlyContinue | Set-Content -Path (Join-Path -Path $OutputFolder -ChildPath $fileName) -Encoding UTF8 }
        catch { Write-Warning ('Policy "{0}" could not be saved as JSON: {1}' -f $policy.Name, $_.Exception.Message) }

        $names = @($set.Names)
        $isDefault = [bool]$policy.IsDefault
        if ($set.Type -eq 'AuthenticationPolicy') {
            # Authentication policies carry no IsDefault flag and expose one AllowBasicAuth* switch per protocol.
            $names = @($policy.PSObject.Properties.Name | Where-Object { $_ -like 'AllowBasicAuth*' } | Sort-Object)
            $isDefault = ($defaultAuthPolicy -ne '' -and ($defaultAuthPolicy -eq [string]$policy.Name -or $defaultAuthPolicy -eq [string]$policy.Identity))
        }
        $assigned = $null
        if ($null -ne $set.Usage -and -not $SkipUsageCounts) {
            $assigned = [int]$set.Usage[[string]$policy.Name]
            if ($isDefault) { $assigned += [int]$set.Usage['(default)'] }
        }

        $index.Add([PSCustomObject]@{
                PolicyType        = $set.Type
                Name              = [string]$policy.Name
                IsDefault         = $isDefault
                AssignedMailboxes = $assigned
                Settings          = Format-PolicySetting -Policy $policy -Names $names -CountNames $set.CountNames
                WhenChanged       = $policy.WhenChanged
                JsonFile          = $fileName
            })
    }
}

if ($index.Count -eq 0) { Write-Warning 'No policies were exported.'; return }
$indexPath = Join-Path -Path $OutputFolder -ChildPath 'ClientAccessPolicies.csv'
$index | Export-Csv -Path $indexPath -NoTypeInformation -Encoding UTF8
$basicAuthPolicies = @($index | Where-Object { $_.PolicyType -eq 'AuthenticationPolicy' -and $_.Settings -like '*=True*' }).Count

Write-Host "Client access policy export ($($index.Count) policies)" -ForegroundColor Cyan
foreach ($group in ($index | Group-Object -Property PolicyType)) {
    $defaults = @($group.Group | Where-Object { $_.IsDefault } | ForEach-Object { $_.Name })
    Write-Host ('  {0,-26}: {1} (default: {2})' -f $group.Name, $group.Count, $(if ($defaults.Count -gt 0) { $defaults -join ', ' } else { 'none' }))
}
if (-not $SkipUsageCounts) {
    $nonDefaultOwa = [int](@($index | Where-Object { $_.PolicyType -eq 'OwaMailboxPolicy' -and -not $_.IsDefault }) | Measure-Object -Property AssignedMailboxes -Sum).Sum
    Write-Host ('  Mailboxes counted         : {0}' -f [int]($owaUsage.Values | Measure-Object -Sum).Sum)
    Write-Host ('  Non-default OWA policy    : {0} mailboxes' -f $nonDefaultOwa)
}
if ($defaultAuthPolicy -eq '') { Write-Host '  No default authentication policy is set (Set-OrganizationConfig -DefaultAuthenticationPolicy).' -ForegroundColor Yellow }
Write-Host ('  Policies allowing Basic   : {0}' -f $basicAuthPolicies) -ForegroundColor $(if ($basicAuthPolicies -gt 0) { 'Yellow' } else { 'Green' })
Write-Host ('  Output folder             : {0}' -f $OutputFolder)

if ($PassThru) { $index }
#endregion Main
