<#
.SYNOPSIS
    Reports calendar folder permissions on user (and optionally resource) mailboxes and flags over-permissive Default/Anonymous access.
.DESCRIPTION
    Reads the permissions of the default Calendar folder of every mailbox in scope with Get-EXOMailboxFolderPermission.
    Mailboxes whose calendar folder has a localised name (Kalender, Calendrier...) are handled by discovering the real
    folder path with Get-EXOMailboxFolderStatistics -FolderScope Calendar. One row per permission entry is written to
    CSV with the access rights, the sharing flags (Delegate, CanViewPrivateItems) and two findings: Default/Anonymous
    access above -MaxDefaultLevel and entries granted to external (published calendar) users. The script is read-only.
.PARAMETER Identity
    One or more mailbox identities (UPN, primary SMTP address, alias or GUID).
.PARAMETER InputCsv
    Path to a CSV with an Identity, UserPrincipalName or PrimarySmtpAddress column listing the mailboxes to audit.
.PARAMETER IncludeResources
    Also audit room and equipment mailboxes. By default only user mailboxes are included.
.PARAMETER MaxDefaultLevel
    Highest acceptable level for Default and Anonymous: AvailabilityOnly or LimitedDetails (default). Anything above is flagged.
.PARAMETER OutputPath
    Path of the CSV report. Defaults to .\Reports\EXOCalendarPermissions_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emit the report objects to the pipeline.
.EXAMPLE
    PS> .\Get-EXOCalendarPermissionsReport.ps1
    Audits the calendar of every user mailbox and writes .\Reports\EXOCalendarPermissions_<timestamp>.csv.
.EXAMPLE
    PS> .\Get-EXOCalendarPermissionsReport.ps1 -IncludeResources -MaxDefaultLevel AvailabilityOnly -Verbose
    Includes rooms and equipment and flags every Default/Anonymous entry that exposes more than free/busy.
.EXAMPLE
    PS> .\Get-EXOCalendarPermissionsReport.ps1 -InputCsv .\Executives.csv -PassThru | Where-Object { $_.Finding }
    Audits the mailboxes listed in the CSV and shows only the entries that carry a finding.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, ExchangeOnlineManagement 3.x
    Permissions : View-Only Recipients (Exchange Online) for the report; Mail Recipients role to act on the findings
    Category    : Calendar & resource mailboxes
    Changes     : No
    Notes       : One REST call per mailbox (two when the calendar folder has a localised name). Default = every signed-in
                  user of the organisation; Anonymous only matters when the sharing policy allows anonymous publishing.
                  External entries appear as ExchangePublishedUser.<address> and come from calendar sharing invitations.
.LINK
    https://learn.microsoft.com/powershell/module/exchange/get-exomailboxfolderpermission
#>
#Requires -Version 5.1
#Requires -Modules ExchangeOnlineManagement

[CmdletBinding(DefaultParameterSetName = 'All')]
param(
    [Parameter(ParameterSetName = 'Identity', Mandatory = $true)]
    [string[]]$Identity,

    [Parameter(ParameterSetName = 'Csv', Mandatory = $true)]
    [ValidateScript({ Test-Path -Path $_ -PathType Leaf })]
    [string]$InputCsv,

    [Parameter()]
    [switch]$IncludeResources,

    [Parameter()]
    [ValidateSet('AvailabilityOnly', 'LimitedDetails')]
    [string]$MaxDefaultLevel = 'LimitedDetails',

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

function Get-CalendarPermissionEntry {
    <# Returns the permission entries of the default calendar. '<mailbox>:\Calendar' only resolves for English
       mailboxes, so on failure the localised folder path is discovered through the folder statistics. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$MailboxId
    )
    try { return @(Get-EXOMailboxFolderPermission -Identity ('{0}:\Calendar' -f $MailboxId) -ErrorAction Stop) }
    catch { Write-Verbose "'$MailboxId' has no folder named Calendar; looking up the localised calendar folder." }
    $folders = @(Get-EXOMailboxFolderStatistics -Identity $MailboxId -FolderScope Calendar -ErrorAction Stop)
    $calendar = $folders | Where-Object { $_.FolderType -eq 'Calendar' } | Select-Object -First 1
    if ($null -eq $calendar) { $calendar = $folders | Select-Object -First 1 }
    if ($null -eq $calendar) { throw 'Get-EXOMailboxFolderStatistics returned no calendar folder.' }
    $folderId = '{0}:{1}' -f $MailboxId, (([string]$calendar.FolderPath) -replace '/', '\')
    return @(Get-EXOMailboxFolderPermission -Identity $folderId -ErrorAction Stop)
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('EXOCalendarPermissions_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
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

$mailboxProperties = @('DisplayName', 'UserPrincipalName', 'PrimarySmtpAddress', 'RecipientTypeDetails')
$mailboxes = New-Object -TypeName System.Collections.Generic.List[object]
if ($null -ne $Identity -and $Identity.Count -gt 0) {
    foreach ($id in $Identity) {
        try { $mailboxes.Add((Get-EXOMailbox -Identity $id -Properties $mailboxProperties -ErrorAction Stop)) }
        catch { Write-Warning "Mailbox '$id' was not found or is not accessible: $($_.Exception.Message)" }
    }
}
else {
    $types = @('UserMailbox') + $(if ($IncludeResources) { @('RoomMailbox', 'EquipmentMailbox') } else { @() })
    try { foreach ($mailbox in (Get-EXOMailbox -RecipientTypeDetails $types -ResultSize Unlimited -Properties $mailboxProperties -ErrorAction Stop)) { $mailboxes.Add($mailbox) } }
    catch { throw "Failed to retrieve mailboxes: $($_.Exception.Message)" }
}
Write-Verbose "Auditing calendar permissions on $($mailboxes.Count) mailbox(es)."

# Calendar roles ranked by exposure; roles or granular rights not listed here always exceed the threshold.
$levelRank = @{ None = 0; AvailabilityOnly = 1; LimitedDetails = 2 }
$maxRank = $levelRank[$MaxDefaultLevel]
$results = New-Object -TypeName System.Collections.Generic.List[object]
$failed = 0
$index = 0
foreach ($mailbox in $mailboxes) {
    $index++
    $upn = [string]$mailbox.UserPrincipalName
    Write-Progress -Activity 'Reading calendar permissions' -Status "$index of $($mailboxes.Count) - $upn" -PercentComplete (($index / $mailboxes.Count) * 100)
    try { $entries = @(Get-CalendarPermissionEntry -MailboxId $upn) }
    catch { $failed++; Write-Warning "Could not read calendar permissions for '$upn': $($_.Exception.Message)"; continue }
    foreach ($entry in $entries) {
        # The REST cmdlet returns User as an object (DisplayName/UserType); fall back to its string form otherwise.
        $userObject = $entry.User
        $user = [string]$userObject
        $userType = ''
        if ($null -ne $userObject.PSObject.Properties['DisplayName']) { $user = [string]$userObject.DisplayName; $userType = [string]$userObject.UserType }
        if ($user -in @('Default', 'Anonymous')) { $userType = $user }
        $isDefaultOrAnonymous = $userType -in @('Default', 'Anonymous')
        $isExternal = ($userType -eq 'External') -or ($user -like 'ExchangePublishedUser.*')
        $rights = @($entry.AccessRights | ForEach-Object { [string]$_ })
        $findings = New-Object -TypeName System.Collections.Generic.List[string]
        if ($isDefaultOrAnonymous -and @($rights | Where-Object { -not $levelRank.ContainsKey($_) -or $levelRank[$_] -gt $maxRank }).Count -gt 0) {
            $findings.Add(('{0} access above {1}' -f $user, $MaxDefaultLevel))
        }
        if ($isExternal) { $findings.Add('External user') }
        $results.Add([PSCustomObject]@{
                Mailbox                = $mailbox.DisplayName
                MailboxUPN             = $upn
                MailboxType            = [string]$mailbox.RecipientTypeDetails
                Folder                 = [string]$entry.FolderName
                User                   = $user
                UserType               = $userType
                AccessRights           = ($rights -join ', ')
                SharingPermissionFlags = (@($entry.SharingPermissionFlags | ForEach-Object { [string]$_ }) -join ', ')
                IsDefaultOrAnonymous   = $isDefaultOrAnonymous
                IsExternal             = $isExternal
                Finding                = ($findings -join '; ')
            })
    }
}
Write-Progress -Activity 'Reading calendar permissions' -Completed

if ($results.Count -gt 0) { $results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 }

$flaggedDefault = @($results | Where-Object { $_.IsDefaultOrAnonymous -and -not [string]::IsNullOrEmpty($_.Finding) })
$externalEntries = @($results | Where-Object { $_.IsExternal })
Write-Host ''
Write-Host 'Calendar permissions summary' -ForegroundColor Cyan
Write-Host ('  Mailboxes audited     : {0} ({1} failed)' -f $mailboxes.Count, $failed)
Write-Host ('  Permission entries    : {0}' -f $results.Count)
Write-Host '  Default access levels :'
foreach ($group in ($results | Where-Object { $_.User -eq 'Default' } | Group-Object -Property AccessRights | Sort-Object -Property Count -Descending)) {
    Write-Host ('    {0,-20}: {1}' -f $group.Name, $group.Count)
}
Write-Host ('  Above {0,-16}: {1}' -f $MaxDefaultLevel, $flaggedDefault.Count) -ForegroundColor $(if ($flaggedDefault.Count -gt 0) { 'Yellow' } else { 'Green' })
Write-Host ('  External user entries : {0}' -f $externalEntries.Count) -ForegroundColor $(if ($externalEntries.Count -gt 0) { 'Yellow' } else { 'Green' })
if ($results.Count -gt 0) { Write-Host ('  Report                : {0}' -f $OutputPath) }

if ($PassThru) {
    $results
}
#endregion Main
