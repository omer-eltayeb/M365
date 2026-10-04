<#
.SYNOPSIS
    Audits delegated mailbox access: FullAccess, SendAs and SendOnBehalf grants across Exchange Online mailboxes.
.DESCRIPTION
    For every mailbox in scope the script collects explicit (non-inherited) FullAccess grants with
    Get-EXOMailboxPermission, SendAs grants with Get-EXORecipientPermission and SendOnBehalf delegates from the
    mailbox's GrantSendOnBehalfTo property. Each trustee is resolved once through a cached Get-EXORecipient
    lookup so the report shows its primary SMTP address and recipient type; trustees that remain on the ACL as
    bare SIDs (deleted accounts) are flagged as Orphaned.
    One row per grant is written to CSV; the console summary lists the mailboxes with the most delegates and the
    number of orphaned grants. The script is read-only.
.PARAMETER Identity
    One or more mailbox identities (UPN, primary SMTP address, alias or GUID). When omitted, every mailbox is audited.
.PARAMETER SharedOnly
    Limit the audit to SharedMailbox, RoomMailbox and EquipmentMailbox recipients, where delegation is the norm.
.PARAMETER OutputPath
    Path of the CSV report. Defaults to .\Reports\EXOMailboxPermissions_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emit the report objects to the pipeline.
.EXAMPLE
    PS> .\Get-EXOMailboxPermissionsReport.ps1
    Audits every mailbox and writes .\Reports\EXOMailboxPermissions_<timestamp>.csv.
.EXAMPLE
    PS> .\Get-EXOMailboxPermissionsReport.ps1 -SharedOnly -Verbose
    Audits shared, room and equipment mailboxes only, showing each lookup as it happens.
.EXAMPLE
    PS> .\Get-EXOMailboxPermissionsReport.ps1 -Identity ceo@contoso.com -PassThru | Where-Object { $_.TrusteeType -eq 'Orphaned' }
    Lists grants on one mailbox whose trustee no longer exists in the directory.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-03
    Requires    : PowerShell 5.1 or 7.x, ExchangeOnlineManagement 3.x
    Permissions : View-Only Recipients for the report; Exchange Administrator / Recipient Management to act on the findings
    Category    : Mailbox content & settings
    Changes     : No
    Notes       : Two REST calls per mailbox (Get-EXOMailboxPermission and Get-EXORecipientPermission) - expect roughly
                  1-2 seconds per mailbox. AutoMapping is not exposed by the EXO cmdlets and is therefore not reported.
                  TrusteeType 'Orphaned' means the ACL holds a SID (S-1-5-21-...) for a deleted account; clean it up with
                  Remove-MailboxPermission -Identity <mailbox> -User <SID> -AccessRights FullAccess. 'Unknown' means the
                  trustee could not be resolved as a recipient, for example a security group without an email address.
.LINK
    https://learn.microsoft.com/powershell/module/exchange/get-exomailboxpermission
.LINK
    https://learn.microsoft.com/powershell/module/exchange/get-exorecipientpermission
#>
#Requires -Version 5.1
#Requires -Modules ExchangeOnlineManagement

[CmdletBinding()]
param(
    [Parameter()]
    [string[]]$Identity,

    [Parameter()]
    [switch]$SharedOnly,

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

function Resolve-Trustee {
    <# Resolves a trustee (UPN, name, canonical name or SID) to its primary SMTP address and RecipientTypeDetails.
       Results are cached because the same delegates usually appear on many mailboxes. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TrusteeIdentity
    )
    if (-not $script:TrusteeCache.ContainsKey($TrusteeIdentity)) {
        $resolved = [PSCustomObject]@{ Trustee = $TrusteeIdentity; TrusteeType = 'Unknown' }
        if ($TrusteeIdentity -match '^S-1-5-') {
            # Deleted accounts stay on the ACL as a bare SID.
            $resolved.TrusteeType = 'Orphaned'
        }
        else {
            try {
                $recipient = Get-EXORecipient -Identity $TrusteeIdentity -Properties PrimarySmtpAddress, RecipientTypeDetails -ErrorAction Stop | Select-Object -First 1
                if ($null -ne $recipient) {
                    if (-not [string]::IsNullOrWhiteSpace($recipient.PrimarySmtpAddress)) { $resolved.Trustee = [string]$recipient.PrimarySmtpAddress }
                    $resolved.TrusteeType = [string]$recipient.RecipientTypeDetails
                }
            }
            catch {
                Write-Verbose "Trustee '$TrusteeIdentity' could not be resolved: $($_.Exception.Message)"
            }
        }
        $script:TrusteeCache[$TrusteeIdentity] = $resolved
    }
    return $script:TrusteeCache[$TrusteeIdentity]
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('EXOMailboxPermissions_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}

try {
    Connect-ExchangeIfNeeded
}
catch {
    throw "Unable to connect to Exchange Online: $($_.Exception.Message)"
}

$script:TrusteeCache = @{}
$mailboxProperties = @('DisplayName', 'UserPrincipalName', 'PrimarySmtpAddress', 'RecipientTypeDetails', 'GrantSendOnBehalfTo')
$mailboxes = New-Object -TypeName System.Collections.Generic.List[object]
if ($PSBoundParameters.ContainsKey('Identity')) {
    foreach ($id in $Identity) {
        try {
            $mailboxes.Add((Get-EXOMailbox -Identity $id -Properties $mailboxProperties -ErrorAction Stop))
        }
        catch {
            Write-Warning "Mailbox '$id' was not found or is not accessible: $($_.Exception.Message)"
        }
    }
}
else {
    $getParams = @{ ResultSize = 'Unlimited'; Properties = $mailboxProperties; ErrorAction = 'Stop' }
    if ($SharedOnly) { $getParams['RecipientTypeDetails'] = @('SharedMailbox', 'RoomMailbox', 'EquipmentMailbox') }
    try {
        foreach ($mailbox in (Get-EXOMailbox @getParams)) { $mailboxes.Add($mailbox) }
    }
    catch {
        throw "Failed to retrieve mailboxes: $($_.Exception.Message)"
    }
}
Write-Verbose "Auditing $($mailboxes.Count) mailbox(es)."

$results = New-Object -TypeName System.Collections.Generic.List[object]
$index = 0
foreach ($mailbox in $mailboxes) {
    $index++
    $upn = $mailbox.UserPrincipalName
    Write-Progress -Activity 'Collecting mailbox permissions' -Status "$index of $($mailboxes.Count) - $upn ($($results.Count) grants so far)" -PercentComplete (($index / $mailboxes.Count) * 100)

    # Gather raw grants first, then resolve trustees once per grant.
    $grants = New-Object -TypeName System.Collections.Generic.List[object]
    try {
        $fullAccess = Get-EXOMailboxPermission -Identity $upn -ErrorAction Stop |
            Where-Object { $_.IsInherited -ne $true -and $_.User -notlike 'NT AUTHORITY\SELF' -and (@($_.AccessRights) -join ',') -match 'FullAccess' }
        foreach ($entry in @($fullAccess)) {
            $grants.Add(@{ Type = 'FullAccess'; Trustee = [string]$entry.User; Rights = (@($entry.AccessRights) -join ', '); Deny = [bool]$entry.Deny })
        }
    }
    catch {
        Write-Warning "Could not read mailbox permissions for '$upn': $($_.Exception.Message)"
    }

    try {
        $sendAs = Get-EXORecipientPermission -Identity $upn -ErrorAction Stop |
            Where-Object { (@($_.AccessRights) -join ',') -match 'SendAs' -and $_.Trustee -notlike 'NT AUTHORITY\SELF' }
        foreach ($entry in @($sendAs)) {
            $grants.Add(@{ Type = 'SendAs'; Trustee = [string]$entry.Trustee; Rights = 'SendAs'; Deny = ([string]$entry.AccessControlType -eq 'Deny') })
        }
    }
    catch {
        Write-Warning "Could not read SendAs permissions for '$upn': $($_.Exception.Message)"
    }

    foreach ($entry in @($mailbox.GrantSendOnBehalfTo)) {
        if ([string]::IsNullOrWhiteSpace([string]$entry)) { continue }
        $grants.Add(@{ Type = 'SendOnBehalf'; Trustee = [string]$entry; Rights = 'SendOnBehalf'; Deny = $false })
    }

    foreach ($grant in $grants) {
        $trustee = Resolve-Trustee -TrusteeIdentity $grant.Trustee
        $results.Add([PSCustomObject]@{
                Mailbox         = $mailbox.DisplayName
                MailboxUPN      = $upn
                MailboxType     = [string]$mailbox.RecipientTypeDetails
                PermissionType  = $grant.Type
                Trustee         = $trustee.Trustee
                TrusteeIdentity = $grant.Trustee
                TrusteeType     = $trustee.TrusteeType
                AccessRights    = $grant.Rights
                Deny            = $grant.Deny
            })
    }
}
Write-Progress -Activity 'Collecting mailbox permissions' -Completed

if ($results.Count -gt 0) {
    $results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
}
else {
    Write-Verbose 'No delegated permissions were found; no CSV written.'
}

$orphaned = @($results | Where-Object { $_.TrusteeType -eq 'Orphaned' })
$topMailboxes = @($results | Group-Object -Property MailboxUPN | Sort-Object -Property Count -Descending | Select-Object -First 5)

Write-Host ''
Write-Host 'Mailbox permissions summary' -ForegroundColor Cyan
Write-Host ('  Mailboxes audited   : {0}' -f $mailboxes.Count)
Write-Host ('  Grants found        : {0}' -f $results.Count)
foreach ($group in ($results | Group-Object -Property PermissionType | Sort-Object -Property Name)) {
    Write-Host ('    {0,-14}: {1}' -f $group.Name, $group.Count)
}
Write-Host ('  Orphaned trustees   : {0}' -f $orphaned.Count) -ForegroundColor $(if ($orphaned.Count -gt 0) { 'Yellow' } else { 'Green' })
if ($topMailboxes.Count -gt 0) {
    Write-Host '  Most delegated mailboxes:'
    foreach ($group in $topMailboxes) {
        Write-Host ('    {0,3} grant(s)  {1}' -f $group.Count, $group.Name)
    }
}
if ($results.Count -gt 0) {
    Write-Host ('  Report              : {0}' -f $OutputPath)
}

if ($PassThru) {
    $results
}
#endregion Main
