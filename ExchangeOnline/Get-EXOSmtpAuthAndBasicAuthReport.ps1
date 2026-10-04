<#
.SYNOPSIS
    Reports which mailboxes can still use SMTP AUTH, the authentication policies in force, and how to close the remaining gaps.
.DESCRIPTION
    Combines the organization SMTP AUTH default (Get-TransportConfig) with the per-mailbox overrides from Get-EXOCASMailbox to
    list every mailbox that is effectively allowed to use SMTP AUTH. It then reads the authentication policies
    (Get-AuthenticationPolicy, AllowBasicAuth* flags), the organization default policy and the policy assigned to each user
    (Get-User) to show whether Basic authentication over SMTP is still possible for that mailbox. Writes the mailbox report
    and a <report>_AuthenticationPolicies.csv with assignment counts, then prints prioritised recommendations.
.PARAMETER Identity
    One or more mailbox identities (UPN, primary SMTP address, alias or GUID) to report instead of all mailboxes.
.PARAMETER InputCsv
    Path of a CSV file with a UserPrincipalName column listing the mailboxes to report.
.PARAMETER RecipientTypeDetails
    Mailbox types to include when neither -Identity nor -InputCsv is used. Default: UserMailbox.
.PARAMETER OutputPath
    Path of the CSV report. Defaults to .\Reports\EXOSmtpAuthReport_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emit the report objects to the pipeline.
.EXAMPLE
    PS> .\Get-EXOSmtpAuthAndBasicAuthReport.ps1
    Reports every user mailbox, the authentication policies and the recommended hardening steps.
.EXAMPLE
    PS> .\Get-EXOSmtpAuthAndBasicAuthReport.ps1 -RecipientTypeDetails UserMailbox, SharedMailbox -PassThru | Where-Object { $_.BasicAuthSmtpPossible }
    Includes shared mailboxes and returns only those where Basic authentication over SMTP is still possible.
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
    Notes       : Basic authentication was retired for every protocol except SMTP AUTH, and Microsoft has announced its retirement
                  for SMTP AUTH client submission as well; OAuth-based SMTP AUTH stays available. The report enumerates all users
                  once with Get-User to resolve policy assignments, which takes a few minutes in large tenants.
.LINK
    https://learn.microsoft.com/exchange/clients-and-mobile-in-exchange-online/authenticated-client-smtp-submission
#>
#Requires -Version 5.1
#Requires -Modules ExchangeOnlineManagement

[CmdletBinding(DefaultParameterSetName = 'All')]
param(
    [Parameter(Mandatory = $true, ParameterSetName = 'Identity')]
    [string[]]$Identity,

    [Parameter(Mandatory = $true, ParameterSetName = 'Csv')]
    [ValidateScript({ Test-Path -Path $_ -PathType Leaf })]
    [string]$InputCsv,

    [Parameter(ParameterSetName = 'All')]
    [ValidateSet('UserMailbox', 'SharedMailbox', 'RoomMailbox', 'EquipmentMailbox')]
    [string[]]$RecipientTypeDetails = @('UserMailbox'),

    [Parameter()]
    [string]$OutputPath,

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
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('EXOSmtpAuthReport_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}
$policyPath = [System.IO.Path]::Combine([string]$outputFolder, ([System.IO.Path]::GetFileNameWithoutExtension($OutputPath) + '_AuthenticationPolicies.csv'))

try { Connect-ExchangeIfNeeded }
catch { throw "Unable to connect to Exchange Online: $($_.Exception.Message)" }

try {
    $orgSmtpAuthDisabled = [bool](Get-TransportConfig -ErrorAction Stop).SmtpClientAuthenticationDisabled
    $defaultPolicyName = [string](Get-OrganizationConfig -ErrorAction Stop).DefaultAuthenticationPolicy
    $authPolicies = @(Get-AuthenticationPolicy -ErrorAction Stop)
}
catch { throw "Failed to read the organization configuration: $($_.Exception.Message)" }

$policyByName = @{}
foreach ($policy in $authPolicies) {
    $allowed = @($policy.PSObject.Properties | Where-Object { $_.Name -like 'AllowBasicAuth*' -and $_.Value -eq $true } | ForEach-Object { $_.Name.Substring(14) })
    $policyByName[[string]$policy.Name] = [PSCustomObject]@{
        Name                      = [string]$policy.Name
        IsDefault                 = ($defaultPolicyName -ne '' -and ($defaultPolicyName -eq [string]$policy.Name -or $defaultPolicyName -eq [string]$policy.Identity))
        AssignedUsers             = 0
        AllowBasicAuthSmtp        = [bool]$policy.AllowBasicAuthSmtp
        AllowedBasicAuthProtocols = $(if ($allowed.Count -gt 0) { $allowed -join ', ' } else { 'none' })
    }
}
$defaultPolicy = $null
foreach ($entry in $policyByName.Values) { if ($entry.IsDefault) { $defaultPolicy = $entry } }

# Policy assignments live on the user object; one enumeration indexed by directory object ID avoids a Get-User call per mailbox.
Write-Progress -Activity 'Reading authentication policy assignments' -Status 'Enumerating all users with Get-User (this can take a while)'
$userPolicy = @{}
try {
    foreach ($user in (Get-User -ResultSize Unlimited -ErrorAction Stop | Select-Object -Property UserPrincipalName, AuthenticationPolicy, ExternalDirectoryObjectId)) {
        $userPolicy[[string]$user.ExternalDirectoryObjectId] = $user
        $assignedName = [string]$user.AuthenticationPolicy
        if ($assignedName -ne '' -and $policyByName.ContainsKey($assignedName)) { $policyByName[$assignedName].AssignedUsers++ }
    }
}
catch { throw "Failed to enumerate users: $($_.Exception.Message)" }
Write-Progress -Activity 'Reading authentication policy assignments' -Completed

$selection = @($Identity)
if ($PSCmdlet.ParameterSetName -eq 'Csv') {
    $selection = @(Import-Csv -Path $InputCsv | ForEach-Object { [string]$_.UserPrincipalName } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if ($selection.Count -eq 0) { throw "No UserPrincipalName values were found in '$InputCsv'." }
}
$casProperties = @('DisplayName', 'PrimarySmtpAddress', 'SmtpClientAuthenticationDisabled', 'ExternalDirectoryObjectId')
$casMailboxes = New-Object -TypeName System.Collections.Generic.List[object]
foreach ($id in $selection) {
    try { $casMailboxes.Add((Get-EXOCASMailbox -Identity $id -Properties $casProperties -ErrorAction Stop)) }
    catch { Write-Warning "Mailbox '$id' was not found or is not accessible: $($_.Exception.Message)" }
}
if ($selection.Count -eq 0) {
    try { $casMailboxes.AddRange(@(Get-EXOCASMailbox -ResultSize Unlimited -RecipientTypeDetails $RecipientTypeDetails -Properties $casProperties -ErrorAction Stop)) }
    catch { throw "Failed to retrieve CAS mailbox settings: $($_.Exception.Message)" }
}

$results = New-Object -TypeName System.Collections.Generic.List[object]
foreach ($cas in $casMailboxes) {
    $overrideText = [string]$cas.SmtpClientAuthenticationDisabled
    $smtpAuthOverride = 'Inherit'
    $smtpAuthEnabled = -not $orgSmtpAuthDisabled
    if ($overrideText -eq 'True') { $smtpAuthOverride = 'Disabled'; $smtpAuthEnabled = $false }
    elseif ($overrideText -eq 'False') { $smtpAuthOverride = 'Enabled'; $smtpAuthEnabled = $true }

    $user = $userPolicy[[string]$cas.ExternalDirectoryObjectId]
    $policy = $null
    $policySource = 'None'
    if ($null -ne $user -and [string]$user.AuthenticationPolicy -ne '' -and $policyByName.ContainsKey([string]$user.AuthenticationPolicy)) {
        $policy = $policyByName[[string]$user.AuthenticationPolicy]
        $policySource = 'User'
    }
    elseif ($null -ne $defaultPolicy) { $policy = $defaultPolicy; $policySource = 'Organization default' }
    $basicSmtpAllowed = ($null -eq $policy -or $policy.AllowBasicAuthSmtp)

    $results.Add([PSCustomObject]@{
            DisplayName           = $cas.DisplayName
            PrimarySmtpAddress    = [string]$cas.PrimarySmtpAddress
            UserPrincipalName     = $(if ($null -ne $user) { [string]$user.UserPrincipalName } else { '' })
            SmtpAuthOverride      = $smtpAuthOverride
            EffectiveSmtpAuth     = $smtpAuthEnabled
            AuthenticationPolicy  = $(if ($null -ne $policy) { $policy.Name } else { '' })
            PolicySource          = $policySource
            AllowBasicAuthSmtp    = $(if ($null -ne $policy) { $policy.AllowBasicAuthSmtp } else { $null })
            BasicAuthSmtpPossible = ($smtpAuthEnabled -and $basicSmtpAllowed)
        })
}

if ($results.Count -eq 0) { Write-Warning 'No mailboxes were found; nothing to export.'; return }
$results | Sort-Object -Property BasicAuthSmtpPossible, EffectiveSmtpAuth, DisplayName -Descending | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
if ($policyByName.Count -gt 0) { $policyByName.Values | Sort-Object -Property Name | Export-Csv -Path $policyPath -NoTypeInformation -Encoding UTF8 }
$smtpAuthCount = @($results | Where-Object { $_.EffectiveSmtpAuth }).Count
$explicitEnabled = @($results | Where-Object { $_.SmtpAuthOverride -eq 'Enabled' }).Count
$basicPossible = @($results | Where-Object { $_.BasicAuthSmtpPossible }).Count

$orgText = 'Enabled'
if ($orgSmtpAuthDisabled) { $orgText = 'Disabled' }
$defaultText = 'none'
if ($null -ne $defaultPolicy) { $defaultText = $defaultPolicy.Name }
Write-Host "SMTP AUTH and Basic authentication summary ($($results.Count) mailboxes)" -ForegroundColor Cyan
Write-Host ('  Org SMTP AUTH default         : {0}' -f $orgText) -ForegroundColor $(if ($orgSmtpAuthDisabled) { 'Green' } else { 'Yellow' })
Write-Host ('  SMTP AUTH effectively allowed : {0} ({1} explicit exceptions)' -f $smtpAuthCount, $explicitEnabled) -ForegroundColor $(if ($smtpAuthCount -gt 0) { 'Yellow' } else { 'Green' })
Write-Host ('  Basic auth over SMTP possible : {0}' -f $basicPossible) -ForegroundColor $(if ($basicPossible -gt 0) { 'Yellow' } else { 'Green' })
Write-Host ('  Authentication policies       : {0} (default: {1})' -f $policyByName.Count, $defaultText)
foreach ($entry in ($policyByName.Values | Sort-Object -Property Name)) {
    Write-Host ('    {0}: {1} users assigned; Basic auth allowed for: {2}' -f $entry.Name, $entry.AssignedUsers, $entry.AllowedBasicAuthProtocols)
}
Write-Host '  Recommendations' -ForegroundColor Cyan
if (-not $orgSmtpAuthDisabled) { Write-Host '    1. Disable SMTP AUTH org-wide (Set-TransportConfig -SmtpClientAuthenticationDisabled $true); then allow it per mailbox.' -ForegroundColor Yellow }
if ($explicitEnabled -gt 0) { Write-Host "    2. Review the $explicitEnabled per-mailbox exceptions; move devices and apps to OAuth, Graph sendMail or High Volume Email." -ForegroundColor Yellow }
if ($null -eq $defaultPolicy -or $defaultPolicy.AllowBasicAuthSmtp) { Write-Host '    3. Create an authentication policy that blocks Basic auth and set it as default.' -ForegroundColor Yellow }
Write-Host '    4. Block legacy authentication with Conditional Access (Exchange ActiveSync clients, Other clients) and watch sign-in logs for "Authenticated SMTP".'
Write-Host ('  Report                        : {0}' -f $OutputPath)
Write-Host ('  Policies CSV                  : {0}' -f $policyPath)

if ($PassThru) { $results }
#endregion Main
