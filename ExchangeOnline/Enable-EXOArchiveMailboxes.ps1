<#
.SYNOPSIS
    Enables the In-Place Archive (optionally auto-expanding) and assigns a retention policy for mailboxes that lack one.
.DESCRIPTION
    Enumerates mailboxes with Get-EXOMailbox, derives the Exchange Online plan from PersistedCapabilities and SKUAssigned
    and plans the steps per mailbox: Enable-Mailbox -Archive where no archive exists, Enable-Mailbox -AutoExpandingArchive
    when -AutoExpanding is requested and the plan allows it, and Set-Mailbox -RetentionPolicy when -RetentionPolicy is
    given. The default run only reports the plan; -Enable applies it with ShouldProcess (-WhatIf / -Confirm).
.PARAMETER Identity
    One or more mailbox identities (UPN, primary SMTP address, alias or GUID); shared mailboxes are accepted here.
.PARAMETER InputCsv
    Path of a CSV file with a UserPrincipalName column listing the mailboxes to process.
.PARAMETER All
    Required together with -Enable when no -Identity / -InputCsv is given, as a guard against enabling archives tenant-wide by accident.
.PARAMETER Enable
    Apply the planned changes. Without it the script is read-only.
.PARAMETER AutoExpanding
    Also enable auto-expanding archiving (Plan 2 or Exchange Online Archiving only). This cannot be undone once enabled.
.PARAMETER RetentionPolicy
    Name of an MRM retention policy to assign; it must contain a "move to archive" tag or nothing is ever archived.
.PARAMETER OutputPath
    Path of the CSV results file. Defaults to .\Reports\EXOArchiveEnablement_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emit the result objects to the pipeline.
.EXAMPLE
    PS> .\Enable-EXOArchiveMailboxes.ps1 -AutoExpanding
    Reports which user mailboxes would get an archive or auto-expanding archive, and which plans do not allow it.
.EXAMPLE
    PS> .\Enable-EXOArchiveMailboxes.ps1 -InputCsv .\Finance.csv -RetentionPolicy 'Finance 7 Year Archive' -Enable -Confirm:$false
    Enables archives for the listed mailboxes and assigns the retention policy without prompting per mailbox.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, ExchangeOnlineManagement 3.x
    Permissions : Exchange Administrator (or Mail Recipients role) for -Enable; View-Only Recipients for the report
    Category    : Mailbox lifecycle & compliance
    Changes     : Yes
    Notes       : Plan detection reads PersistedCapabilities (BPOS_S_Enterprise = Plan 2, BPOS_S_ArchiveAddOn = Exchange Online
                  Archiving, BPOS_S_Standard = Plan 1, BPOS_S_Deskless = Kiosk, which has no archive). Plan 1 gets a 50 GB archive,
                  Plan 2 / Archiving 100 GB plus auto-expanding (or tenant-wide via Set-OrganizationConfig -AutoExpandingArchive).
.LINK
    https://learn.microsoft.com/purview/enable-archive-mailboxes
#>
#Requires -Version 5.1
#Requires -Modules ExchangeOnlineManagement

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High', DefaultParameterSetName = 'All')]
param(
    [Parameter(Mandatory = $true, ParameterSetName = 'Identity')]
    [string[]]$Identity,

    [Parameter(Mandatory = $true, ParameterSetName = 'Csv')]
    [ValidateScript({ Test-Path -Path $_ -PathType Leaf })]
    [string]$InputCsv,

    [Parameter(ParameterSetName = 'All')]
    [switch]$All,

    [Parameter()]
    [switch]$Enable,

    [Parameter()]
    [switch]$AutoExpanding,

    [Parameter()]
    [string]$RetentionPolicy,

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
if ($Enable -and $PSCmdlet.ParameterSetName -eq 'All' -and -not $All) { throw 'Pass -All to enable archives for every eligible mailbox, or scope the run with -Identity / -InputCsv.' }
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('EXOArchiveEnablement_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}

try { Connect-ExchangeIfNeeded }
catch { throw "Unable to connect to Exchange Online: $($_.Exception.Message)" }

if (-not [string]::IsNullOrWhiteSpace($RetentionPolicy)) {
    try { $RetentionPolicy = [string](Get-RetentionPolicy -Identity $RetentionPolicy -ErrorAction Stop).Name }
    catch { throw "Retention policy '$RetentionPolicy' was not found: $($_.Exception.Message)" }
}
$mailboxProperties = @('DisplayName', 'UserPrincipalName', 'SKUAssigned', 'PersistedCapabilities', 'ArchiveStatus', 'AutoExpandingArchiveEnabled', 'RetentionPolicy')
$selection = @()
if ($PSCmdlet.ParameterSetName -eq 'Csv') {
    $selection = @(Import-Csv -Path $InputCsv | ForEach-Object { [string]$_.UserPrincipalName } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if ($selection.Count -eq 0) { throw "No UserPrincipalName values were found in '$InputCsv'." }
}
elseif ($PSCmdlet.ParameterSetName -eq 'Identity') { $selection = @($Identity) }

$mailboxes = New-Object -TypeName System.Collections.Generic.List[object]
if ($selection.Count -gt 0) {
    foreach ($id in $selection) {
        try { $mailboxes.Add((Get-EXOMailbox -Identity $id -Properties $mailboxProperties -ErrorAction Stop)) }
        catch { Write-Warning "Mailbox '$id' was not found or is not accessible: $($_.Exception.Message)" }
    }
}
else {
    try {
        foreach ($mailbox in (Get-EXOMailbox -ResultSize Unlimited -RecipientTypeDetails UserMailbox -Properties $mailboxProperties -ErrorAction Stop)) {
            $mailboxes.Add($mailbox)
        }
    }
    catch { throw "Failed to retrieve mailboxes: $($_.Exception.Message)" }
}

$results = New-Object -TypeName System.Collections.Generic.List[object]
$index = 0
foreach ($mailbox in $mailboxes) {
    $index++
    $upn = $mailbox.UserPrincipalName
    Write-Progress -Activity 'Planning archive changes' -Status "$index of $($mailboxes.Count) - $upn" -PercentComplete (($index / $mailboxes.Count) * 100)

    # The service plan decides what Exchange will accept: Kiosk has no archive, unlicensed shared mailboxes need a license first.
    $capabilities = @($mailbox.PersistedCapabilities | ForEach-Object { [string]$_ })
    $plan = 'Unknown'
    if ($mailbox.SKUAssigned -ne $true) { $plan = 'Unlicensed' }
    elseif ($capabilities -contains 'BPOS_S_Enterprise') { $plan = 'Plan 2' }
    elseif ($capabilities -contains 'BPOS_S_ArchiveAddOn' -or $capabilities -contains 'BPOS_S_Archive') { $plan = 'Plan 1 + Archiving' }
    elseif ($capabilities -contains 'BPOS_S_Standard') { $plan = 'Plan 1' }
    elseif ($capabilities -contains 'BPOS_S_Deskless') { $plan = 'Kiosk' }
    $hasArchive = ([string]$mailbox.ArchiveStatus -eq 'Active')
    $canArchive = ($plan -notin @('Unlicensed', 'Kiosk'))
    $canAutoExpand = ($plan -in @('Plan 2', 'Plan 1 + Archiving', 'Unknown'))

    $doArchive = (-not $hasArchive -and $canArchive)
    $doAutoExpand = ($AutoExpanding -and $canAutoExpand -and -not [bool]$mailbox.AutoExpandingArchiveEnabled -and ($hasArchive -or $doArchive))
    $doPolicy = (-not [string]::IsNullOrWhiteSpace($RetentionPolicy) -and [string]$mailbox.RetentionPolicy -ne $RetentionPolicy)
    $steps = New-Object -TypeName System.Collections.Generic.List[string]
    if ($doArchive) { $steps.Add('Enable archive') }
    if ($doAutoExpand) { $steps.Add('Enable auto-expanding archive') }
    if ($doPolicy) { $steps.Add("Assign retention policy '$RetentionPolicy'") }
    $note = ''
    if (-not $hasArchive -and -not $canArchive) { $note = "No archive available for plan '$plan' - assign Plan 2 or Exchange Online Archiving first" }
    elseif ($AutoExpanding -and -not $canAutoExpand) { $note = "Auto-expanding archive requires Plan 2 or Exchange Online Archiving (current: $plan)" }

    $result = 'Report only'
    if ($steps.Count -eq 0) { $result = 'Nothing to do' }
    elseif ($Enable) {
        if ($PSCmdlet.ShouldProcess($upn, ($steps -join '; '))) {
            try {
                if ($doArchive) { Enable-Mailbox -Identity $upn -Archive -ErrorAction Stop | Out-Null }
                if ($doAutoExpand) { Enable-Mailbox -Identity $upn -AutoExpandingArchive -ErrorAction Stop | Out-Null }
                if ($doPolicy) { Set-Mailbox -Identity $upn -RetentionPolicy $RetentionPolicy -ErrorAction Stop }
                $result = 'Done'
            }
            catch { $result = "Failed: $($_.Exception.Message)"; Write-Warning "Archive change for '$upn' failed: $($_.Exception.Message)" }
        }
        else { $result = 'Not confirmed' }
    }

    $results.Add([PSCustomObject]@{
            DisplayName          = $mailbox.DisplayName
            UserPrincipalName    = $upn
            LicensePlan          = $plan
            ArchiveStatus        = [string]$mailbox.ArchiveStatus
            AutoExpandingEnabled = [bool]$mailbox.AutoExpandingArchiveEnabled
            RetentionPolicy      = [string]$mailbox.RetentionPolicy
            PlannedActions       = ($steps -join '; ')
            Note                 = $note
            Result               = $result
        })
}
Write-Progress -Activity 'Planning archive changes' -Completed

if ($results.Count -eq 0) { Write-Warning 'No mailboxes were evaluated; nothing to export.'; return }
$results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
$failed = @($results | Where-Object { $_.Result -like 'Failed*' }).Count
Write-Host "Archive enablement summary ($($results.Count) mailboxes evaluated)" -ForegroundColor Cyan
Write-Host ('  Archives to enable       : {0}' -f @($results | Where-Object { $_.PlannedActions -like '*Enable archive*' }).Count)
Write-Host ('  Auto-expanding to enable : {0}' -f @($results | Where-Object { $_.PlannedActions -like '*auto-expanding*' }).Count)
Write-Host ('  Blocked by license plan  : {0}' -f @($results | Where-Object { $_.Note -ne '' }).Count) -ForegroundColor Yellow
Write-Host ('  Done / failed            : {0} / {1}' -f @($results | Where-Object { $_.Result -eq 'Done' }).Count, $failed) -ForegroundColor $(if ($failed -gt 0) { 'Red' } else { 'Green' })
if (-not $Enable) { Write-Host '  Report only - re-run with -Enable to apply the planned actions.' -ForegroundColor Yellow }
Write-Host ('  Results                  : {0}' -f $OutputPath)

if ($PassThru) { $results }
#endregion Main
