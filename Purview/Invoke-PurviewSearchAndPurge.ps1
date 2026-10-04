<#
.SYNOPSIS
    Purges the mailbox items found by a completed content search (soft or hard delete), optionally repeating until nothing is left.
.DESCRIPTION
    Shows the item count and size of the completed search, prints a red warning, and after ShouldProcess confirmation creates a
    purge action with New-ComplianceSearchAction -Purge -PurgeType SoftDelete|HardDelete. It polls '<SearchName>_Purge' every
    15 seconds and parses the purged and failed item counts from Results. A purge removes at most 10 items per mailbox, so
    -RepeatUntilClean removes the previous purge action, re-runs the search and purges again until a pass removes nothing,
    the search returns no items, or -MaxIterations is reached. Only Exchange locations are purged. One result row per pass.
.PARAMETER SearchName
    Name of the completed compliance search whose results should be purged.
.PARAMETER PurgeType
    SoftDelete (default; items go to Recoverable Items and users can restore them) or HardDelete (marked for permanent removal).
.PARAMETER RepeatUntilClean
    Re-run the search and purge again after each pass until no items are purged or -MaxIterations is reached.
.PARAMETER MaxIterations
    Maximum number of purge passes with -RepeatUntilClean (default 20, which covers up to 200 items per mailbox).
.PARAMETER TimeoutMinutes
    Maximum time to wait for each search run and each purge action (default 30).
.EXAMPLE
    PS> .\Invoke-PurviewSearchAndPurge.ps1 -SearchName 'Phish-0410'
    Shows the hit count, then after confirmation soft-deletes up to 10 matching items per mailbox.
.EXAMPLE
    PS> .\Invoke-PurviewSearchAndPurge.ps1 -SearchName 'Phish-0410' -PurgeType HardDelete -RepeatUntilClean -MaxIterations 10 -Confirm:$false
    Hard-deletes the matching items in up to 10 passes without prompting, re-running the search between passes.
.EXAMPLE
    PS> .\Invoke-PurviewSearchAndPurge.ps1 -SearchName 'Phish-0410' -WhatIf
    Shows what would be purged without creating a purge action.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, ExchangeOnlineManagement 3.x
    Permissions : Search And Purge role (Organization Management or Data Investigator role group) plus eDiscovery Manager for the search
    Category    : eDiscovery & content search
    Changes     : Yes
    Notes       : Purge is an incident-response tool: 10 items per mailbox per pass, mailbox items only (SharePoint and OneDrive hits
                  are ignored), and items protected by a hold or retention policy are kept in Recoverable Items. Soft-deleted items
                  stay searchable in Recoverable Items, which is why the loop stops when a pass purges nothing new rather than only
                  when the search returns zero items. Make the search as precise as possible before running this script.
.LINK
    https://learn.microsoft.com/powershell/module/exchange/new-compliancesearchaction
#>
#Requires -Version 5.1
#Requires -Modules ExchangeOnlineManagement

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $true)]
    [string]$SearchName,

    [Parameter()]
    [ValidateSet('SoftDelete', 'HardDelete')]
    [string]$PurgeType = 'SoftDelete',

    [Parameter()]
    [switch]$RepeatUntilClean,

    [Parameter()]
    [ValidateRange(1, 100)]
    [int]$MaxIterations = 20,

    [Parameter()]
    [ValidateRange(1, 1440)]
    [int]$TimeoutMinutes = 30
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

function Wait-ComplianceJob {
    <# Polls a compliance search (or, with -Action, a search action) every 15 seconds until it reaches a terminal status or the timeout elapses. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Identity,

        [Parameter()]
        [switch]$Action,

        [Parameter(Mandatory = $true)]
        [int]$TimeoutMinutes
    )
    $terminal = @('Completed', 'PartiallySucceeded', 'Failed', 'Stopped')
    $deadline = (Get-Date).AddMinutes($TimeoutMinutes)
    do {
        if ($Action) { $job = Get-ComplianceSearchAction -Identity $Identity -Details -ErrorAction Stop }
        else { $job = Get-ComplianceSearch -Identity $Identity -ErrorAction Stop }
        if ($terminal -notcontains [string]$job.Status) {
            Write-Progress -Activity "Waiting for $Identity" -Status ('Status: {0}' -f $job.Status)
            Start-Sleep -Seconds 15
        }
    } while ($terminal -notcontains [string]$job.Status -and (Get-Date) -lt $deadline)
    Write-Progress -Activity "Waiting for $Identity" -Completed
    return $job
}
#endregion Helpers

#region Main
try { Connect-ExchangeIfNeeded -Compliance } catch { throw "Unable to connect to Security & Compliance PowerShell: $($_.Exception.Message)" }
try { $search = Get-ComplianceSearch -Identity $SearchName -ErrorAction Stop } catch { throw "The compliance search '$SearchName' was not found: $($_.Exception.Message)" }
if (@('Completed', 'PartiallySucceeded') -notcontains [string]$search.Status) { throw "The search '$SearchName' has status '$($search.Status)'; only a completed search can be purged." }
if (@($search.ExchangeLocation).Count -eq 0) { throw "The search '$SearchName' has no Exchange locations. Purge only removes mailbox items." }
if (@($search.SharePointLocation).Count -gt 0) { Write-Warning 'The search also covers SharePoint/OneDrive locations; those hits are not purged.' }

# SuccessResults holds one "{Location: <mailbox>, Item count: <n>, Total size: <bytes>}" entry per location.
$locationHits = @([regex]::Matches([string]$search.SuccessResults, 'Location: (.+?), Item count: (\d+), Total size: (\d+)') | ForEach-Object { [long]$_.Groups[2].Value } | Where-Object { $_ -gt 0 })
$largest = 0
if ($locationHits.Count -gt 0) { $largest = ($locationHits | Measure-Object -Maximum).Maximum }
$purgeName = '{0}_Purge' -f $SearchName

Write-Host ("`nSearch '{0}': {1:N0} items, {2:N2} GB, {3} mailbox(es) with hits" -f $search.Name, [long]$search.Items, ([double]$search.Size / 1GB), $locationHits.Count) -ForegroundColor Cyan
Write-Host ('  Query : {0}' -f $search.ContentMatchQuery)
$passesNeeded = [math]::Max(1, [math]::Ceiling($largest / 10))
Write-Host ("WARNING: {0} deletes up to 10 items per mailbox per pass; the largest mailbox holds {1} hits ({2} pass(es) needed)." -f $PurgeType, $largest, $passesNeeded) -ForegroundColor Red
if ($PurgeType -eq 'HardDelete') { Write-Host 'WARNING: HardDelete marks items for permanent removal; only items under hold or retention remain recoverable by administrators.' -ForegroundColor Red }
else { Write-Host 'SoftDelete moves items to Recoverable Items\Deletions, where users can still restore them until the retention period ends.' -ForegroundColor Yellow }

$results = New-Object -TypeName System.Collections.Generic.List[object]
$pass = 0; $purged = 0
do {
    $pass++
    $description = '{0} purge, pass {1}: remove the previous purge action, re-run the search and purge the remaining items' -f $PurgeType, $pass
    if ($pass -eq 1) { $description = '{0} purge, pass 1: up to 10 items per mailbox ({1} items found)' -f $PurgeType, $search.Items }
    if (-not $PSCmdlet.ShouldProcess($SearchName, $description)) { break }

    $existing = Get-ComplianceSearchAction -Identity $purgeName -ErrorAction SilentlyContinue
    if ($null -ne $existing) {
        try { Remove-ComplianceSearchAction -Identity $purgeName -Confirm:$false -ErrorAction Stop }
        catch { Write-Warning ("Could not remove the previous purge action '{0}': {1}" -f $purgeName, $_.Exception.Message); break }
    }
    if ($pass -gt 1) {
        try { Start-ComplianceSearch -Identity $SearchName -ErrorAction Stop; $search = Wait-ComplianceJob -Identity $SearchName -TimeoutMinutes $TimeoutMinutes }
        catch { Write-Warning ("Re-running the search failed: {0}" -f $_.Exception.Message); break }
        if ([string]$search.Status -ne 'Completed') { Write-Warning ("The search did not complete (status {0}); stopping." -f $search.Status); break }
        if ([long]$search.Items -eq 0) { Write-Host ('  Pass {0}: the search returns no items - nothing left to purge.' -f $pass) -ForegroundColor Green; break }
    }

    $status = 'Failed'; $purged = 0; $failed = 0; $resultText = $null
    try {
        New-ComplianceSearchAction -SearchName $SearchName -Purge -PurgeType $PurgeType -Confirm:$false -ErrorAction Stop | Out-Null
        $action = Wait-ComplianceJob -Identity $purgeName -Action -TimeoutMinutes $TimeoutMinutes
        $status = [string]$action.Status
        $resultText = [string]$action.Results
        $countMatch = [regex]::Match($resultText, 'Item count:\s*([\d,]+)')
        if ($countMatch.Success) { $purged = [long]($countMatch.Groups[1].Value -replace ',', '') }
        foreach ($failMatch in [regex]::Matches($resultText, 'Failed count:\s*([\d,]+)')) { $failed += [long]($failMatch.Groups[1].Value -replace ',', '') }
    }
    catch {
        $resultText = $_.Exception.Message
        Write-Warning ("Pass {0} failed: {1}" -f $pass, $resultText)
    }
    if ($resultText.Length -gt 300) { $resultText = $resultText.Substring(0, 300) + '...' }
    $results.Add([PSCustomObject]@{
            SearchName  = $SearchName
            Pass        = $pass
            PurgeType   = $PurgeType
            SearchItems = [long]$search.Items
            PurgeStatus = $status
            PurgedItems = $purged
            FailedItems = $failed
            Results     = $resultText
            Timestamp   = Get-Date
        })
    Write-Host ('  Pass {0}: status {1}, {2} item(s) purged, {3} failed.' -f $pass, $status, $purged, $failed) -ForegroundColor $(if ($status -eq 'Completed') { 'Green' } else { 'Yellow' })
    if ($status -ne 'Completed' -or $purged -eq 0) { break }
} while ($RepeatUntilClean -and $pass -lt $MaxIterations)

if ($RepeatUntilClean -and $pass -ge $MaxIterations -and $purged -gt 0) { Write-Warning ("Stopped after {0} passes; items may remain. Re-run the script to continue." -f $MaxIterations) }
Write-Host ("`nPurge summary for '{0}'" -f $SearchName) -ForegroundColor Cyan
Write-Host ('  Passes run    : {0}' -f $results.Count)
Write-Host ('  Items purged  : {0}' -f (($results | Measure-Object -Property PurgedItems -Sum).Sum))
Write-Host ('  Items failed  : {0}' -f (($results | Measure-Object -Property FailedItems -Sum).Sum))
Write-Host "  Verify with   : Get-ComplianceSearchAction -Identity '$purgeName' -Details | Format-List Status, Results"
$results
#endregion Main
