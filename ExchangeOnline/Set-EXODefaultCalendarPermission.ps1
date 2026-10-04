<#
.SYNOPSIS
    Standardises the Default (and optionally Anonymous) calendar permission on user mailboxes.
.DESCRIPTION
    Reads the current Default/Anonymous permission of the Calendar folder on every mailbox in scope with
    Get-EXOMailboxFolderPermission (localised folder names are discovered with Get-EXOMailboxFolderStatistics) and
    compares it with the desired level. Compliant mailboxes are skipped; the others are changed with
    Set-MailboxFolderPermission, but only when -Apply is specified - without it the script just reports what would
    change. Every change is wrapped in ShouldProcess (-WhatIf / -Confirm). A results CSV records the before/after state.
.PARAMETER Identity
    One or more mailbox identities (UPN, primary SMTP address, alias or GUID). When omitted, every user mailbox is processed.
.PARAMETER InputCsv
    Path to a CSV with an Identity, UserPrincipalName or PrimarySmtpAddress column listing the mailboxes to process.
.PARAMETER AccessRights
    Level to enforce for the Default user, e.g. AvailabilityOnly (free/busy) or LimitedDetails (free/busy, subject, location).
.PARAMETER AnonymousAccessRights
    Optional level to enforce for the Anonymous user (None, AvailabilityOnly or LimitedDetails).
.PARAMETER Apply
    Perform the changes. Without this switch the script is read-only and only reports the non-compliant mailboxes.
.PARAMETER OutputPath
    Path of the results CSV. Defaults to .\Reports\EXODefaultCalendarPermission_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emit the result objects to the pipeline.
.EXAMPLE
    PS> .\Set-EXODefaultCalendarPermission.ps1 -AccessRights LimitedDetails
    Reports every user mailbox whose Default calendar permission differs from LimitedDetails. Nothing is changed.
.EXAMPLE
    PS> .\Set-EXODefaultCalendarPermission.ps1 -AccessRights LimitedDetails -AnonymousAccessRights None -Apply -WhatIf
    Shows the Set-MailboxFolderPermission calls that would run, without executing them.
.EXAMPLE
    PS> .\Set-EXODefaultCalendarPermission.ps1 -InputCsv .\Finance.csv -AccessRights AvailabilityOnly -Apply -Confirm:$false
    Sets Default to free/busy only on the listed mailboxes without prompting for each one.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, ExchangeOnlineManagement 3.x
    Permissions : View-Only Recipients for the report; Mail Recipients role (Recipient Management / Exchange Administrator) for -Apply
    Category    : Calendar & resource mailboxes
    Changes     : Yes
    Notes       : Only the Default and Anonymous entries are touched; named delegates are never modified. New mailboxes
                  receive the tenant default (AvailabilityOnly), so schedule the script to keep the baseline in place.
.LINK
    https://learn.microsoft.com/powershell/module/exchange/set-mailboxfolderpermission
#>
#Requires -Version 5.1
#Requires -Modules ExchangeOnlineManagement

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High', DefaultParameterSetName = 'All')]
param(
    [Parameter(ParameterSetName = 'Identity', Mandatory = $true)]
    [string[]]$Identity,

    [Parameter(ParameterSetName = 'Csv', Mandatory = $true)]
    [ValidateScript({ Test-Path -Path $_ -PathType Leaf })]
    [string]$InputCsv,

    [Parameter(Mandatory = $true)]
    [ValidateSet('None', 'AvailabilityOnly', 'LimitedDetails', 'Reviewer', 'Contributor', 'Author', 'Editor', 'PublishingEditor', 'Owner')]
    [string]$AccessRights,

    [Parameter()]
    [ValidateSet('None', 'AvailabilityOnly', 'LimitedDetails')]
    [string]$AnonymousAccessRights,

    [Parameter()]
    [switch]$Apply,

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
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('EXODefaultCalendarPermission_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}

if ($PSCmdlet.ParameterSetName -eq 'Csv') {
    $rows = @(Import-Csv -Path $InputCsv -ErrorAction Stop)
    $column = @('Identity', 'UserPrincipalName', 'PrimarySmtpAddress') | Where-Object { $rows.Count -gt 0 -and $rows[0].PSObject.Properties.Name -contains $_ } | Select-Object -First 1
    if ($null -eq $column) { throw "InputCsv must contain an 'Identity', 'UserPrincipalName' or 'PrimarySmtpAddress' column." }
    $Identity = @($rows | ForEach-Object { $_.$column } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
}

try { Connect-ExchangeIfNeeded } catch { throw "Unable to connect to Exchange Online: $($_.Exception.Message)" }

$mailboxProperties = @('DisplayName', 'UserPrincipalName', 'RecipientTypeDetails')
$mailboxes = New-Object -TypeName System.Collections.Generic.List[object]
if ($null -ne $Identity -and $Identity.Count -gt 0) {
    foreach ($id in $Identity) {
        try { $mailboxes.Add((Get-EXOMailbox -Identity $id -Properties $mailboxProperties -ErrorAction Stop)) }
        catch { Write-Warning "Mailbox '$id' was not found or is not accessible: $($_.Exception.Message)" }
    }
}
else {
    try { foreach ($mailbox in (Get-EXOMailbox -RecipientTypeDetails UserMailbox -ResultSize Unlimited -Properties $mailboxProperties -ErrorAction Stop)) { $mailboxes.Add($mailbox) } }
    catch { throw "Failed to retrieve mailboxes: $($_.Exception.Message)" }
}

$targets = @(@{ User = 'Default'; Rights = $AccessRights })
if ($PSBoundParameters.ContainsKey('AnonymousAccessRights')) { $targets += @{ User = 'Anonymous'; Rights = $AnonymousAccessRights } }
if (-not $Apply) { Write-Host 'Read-only mode: add -Apply to change permissions.' -ForegroundColor Yellow }

$results = New-Object -TypeName System.Collections.Generic.List[object]
$index = 0
foreach ($mailbox in $mailboxes) {
    $index++
    $upn = [string]$mailbox.UserPrincipalName
    Write-Progress -Activity 'Processing calendar permissions' -Status "$index of $($mailboxes.Count) - $upn" -PercentComplete (($index / $mailboxes.Count) * 100)

    $folderId = '{0}:\Calendar' -f $upn
    $current = @()
    $readFailed = $false
    try {
        try { $current = @(Get-EXOMailboxFolderPermission -Identity $folderId -ErrorAction Stop) }
        catch {
            # Localised mailboxes (Kalender, Calendrier...) need the real folder path; the default calendar sorts first.
            $calendar = @(Get-EXOMailboxFolderStatistics -Identity $upn -FolderScope Calendar -ErrorAction Stop) | Sort-Object -Property { $_.FolderType -ne 'Calendar' } | Select-Object -First 1
            $folderId = '{0}:{1}' -f $upn, (([string]$calendar.FolderPath) -replace '/', '\')
            $current = @(Get-EXOMailboxFolderPermission -Identity $folderId -ErrorAction Stop)
        }
    }
    catch { $readFailed = $true; Write-Warning "Could not read calendar permissions for '$upn': $($_.Exception.Message)" }

    # The REST cmdlet returns User as an object (DisplayName); older output is a plain string.
    $rightsByUser = @{}
    foreach ($permission in $current) {
        $name = [string]$permission.User
        if ($null -ne $permission.User.PSObject.Properties['DisplayName']) { $name = [string]$permission.User.DisplayName }
        $rightsByUser[$name] = (@($permission.AccessRights | ForEach-Object { [string]$_ }) -join ',')
    }

    foreach ($target in $targets) {
        $currentRights = [string]$rightsByUser[$target.User]
        $status = 'Compliant'
        if ($readFailed) { $status = 'ReadFailed' }
        elseif ($currentRights -ne $target.Rights) {
            $status = 'WouldChange'
            if ($Apply -and $PSCmdlet.ShouldProcess($upn, ('Set {0} calendar permission {1} -> {2}' -f $target.User, $currentRights, $target.Rights))) {
                try { Set-MailboxFolderPermission -Identity $folderId -User $target.User -AccessRights $target.Rights -Confirm:$false -ErrorAction Stop; $status = 'Changed' }
                catch { $status = 'Failed'; Write-Warning "Set-MailboxFolderPermission failed for '$upn' ($($target.User)): $($_.Exception.Message)" }
            }
            elseif ($Apply) { $status = 'Skipped' }
        }
        $results.Add([PSCustomObject]@{
                Mailbox             = $mailbox.DisplayName
                MailboxUPN          = $upn
                Folder              = $folderId
                User                = $target.User
                CurrentAccessRights = $currentRights
                DesiredAccessRights = $target.Rights
                Status              = $status
            })
    }
}
Write-Progress -Activity 'Processing calendar permissions' -Completed

if ($results.Count -gt 0) { $results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 }

Write-Host ''
Write-Host 'Default calendar permission summary' -ForegroundColor Cyan
Write-Host ('  Mailboxes evaluated : {0}' -f $mailboxes.Count)
Write-Host ('  Desired level       : Default={0}{1}' -f $AccessRights, $(if ($PSBoundParameters.ContainsKey('AnonymousAccessRights')) { ", Anonymous=$AnonymousAccessRights" } else { '' }))
foreach ($group in ($results | Group-Object -Property Status | Sort-Object -Property Name)) {
    $colour = switch ($group.Name) { 'Compliant' { 'Green' } 'Changed' { 'Green' } 'Failed' { 'Red' } 'ReadFailed' { 'Red' } default { 'Yellow' } }
    Write-Host ('    {0,-16}: {1}' -f $group.Name, $group.Count) -ForegroundColor $colour
}
if ($results.Count -gt 0) { Write-Host ('  Results             : {0}' -f $OutputPath) }

if ($PassThru) {
    $results
}
#endregion Main
