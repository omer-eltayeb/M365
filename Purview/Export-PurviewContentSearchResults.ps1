<#
.SYNOPSIS
    Starts an export of a completed content search and returns the container URL, SAS token and item counts needed to download it.
.DESCRIPTION
    Validates that the search exists and has completed, then creates the export action with New-ComplianceSearchAction -Export
    (format, PST layout, indexed/unindexed scope, de-duplication, SharePoint packaging, retry on error). It polls
    Get-ComplianceSearchAction '<SearchName>_Export' -IncludeCredential every 15 seconds and parses the Results text into
    a result object (Status, ContainerUrl, SasToken, estimated and transferred items). When an export action already exists
    the script reports it instead of failing; -Force removes it first. Creation and removal are wrapped in ShouldProcess.
.PARAMETER SearchName
    Name of the completed compliance search to export.
.PARAMETER Format
    Export format: FxStream (PST, required by the eDiscovery Export Tool), Mime (.eml) or Msg (.msg). Default FxStream.
.PARAMETER ExchangeArchiveFormat
    PST layout: PerUserPst (default), SinglePst, SingleFolderPst or IndividualMessage.
.PARAMETER Scope
    IndexedItemsOnly (default), BothIndexedAndUnindexedItems or UnindexedItemsOnly.
.PARAMETER EnableDedupe
    Export only one copy of messages that were found in several mailboxes.
.PARAMETER SharePointArchiveFormat
    IndividualMessage (default, loose files) or SingleZip for SharePoint and OneDrive content.
.PARAMETER RetryOnError
    Retry items that failed in a previous export of the same search.
.PARAMETER Force
    Remove an existing '<SearchName>_Export' action before creating a new one.
.PARAMETER TimeoutMinutes
    Maximum time to wait for the export to complete (default 60). The script reports the current state when the time is up.
.EXAMPLE
    PS> .\Export-PurviewContentSearchResults.ps1 -SearchName 'HR-Case-42'
    Exports the search as one PST per mailbox (indexed items only) and prints the container URL and SAS token when it completes.
.EXAMPLE
    PS> .\Export-PurviewContentSearchResults.ps1 -SearchName 'Legal-7-Finance' -Scope BothIndexedAndUnindexedItems -EnableDedupe -SharePointArchiveFormat SingleZip -Force -Confirm:$false
    Recreates the export including partially indexed items, de-duplicated, with SharePoint files packed in a single ZIP.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, ExchangeOnlineManagement 3.x
    Permissions : eDiscovery Manager role group (Export role) in Security & Compliance PowerShell; case membership for case searches
    Category    : eDiscovery & content search
    Changes     : Yes
    Notes       : The SAS token grants read access to the export container for its lifetime - treat it as a secret; it is shown in
                  the console and result object only. Downloading needs the eDiscovery Export Tool (ClickOnce, from the Exports tab)
                  with this export key; tenants on the new Purview eDiscovery experience download exports directly from the portal.
.LINK
    https://learn.microsoft.com/powershell/module/exchange/new-compliancesearchaction
.LINK
    https://learn.microsoft.com/powershell/module/exchange/get-compliancesearchaction
#>
#Requires -Version 5.1
#Requires -Modules ExchangeOnlineManagement

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $true)]
    [string]$SearchName,

    [Parameter()]
    [ValidateSet('FxStream', 'Mime', 'Msg')]
    [string]$Format = 'FxStream',

    [Parameter()]
    [ValidateSet('PerUserPst', 'SinglePst', 'SingleFolderPst', 'IndividualMessage')]
    [string]$ExchangeArchiveFormat = 'PerUserPst',

    [Parameter()]
    [ValidateSet('IndexedItemsOnly', 'BothIndexedAndUnindexedItems', 'UnindexedItemsOnly')]
    [string]$Scope = 'IndexedItemsOnly',

    [Parameter()]
    [switch]$EnableDedupe,

    [Parameter()]
    [ValidateSet('IndividualMessage', 'SingleZip')]
    [string]$SharePointArchiveFormat = 'IndividualMessage',

    [Parameter()]
    [switch]$RetryOnError,

    [Parameter()]
    [switch]$Force,

    [Parameter()]
    [ValidateRange(1, 1440)]
    [int]$TimeoutMinutes = 60
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

function Get-ResultField {
    <# Extracts one "Name: value" field from the semicolon-separated Results text of a compliance search action. #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [AllowNull()]
        [string]$Results,

        [Parameter(Mandatory = $true)]
        [string]$Name
    )
    $match = [regex]::Match([string]$Results, [regex]::Escape($Name) + ':\s*([^;]*)')
    if ($match.Success) { return $match.Groups[1].Value.Trim() }
    return $null
}
#endregion Helpers

#region Main
try { Connect-ExchangeIfNeeded -Compliance } catch { throw "Unable to connect to Security & Compliance PowerShell: $($_.Exception.Message)" }

try { $search = Get-ComplianceSearch -Identity $SearchName -ErrorAction Stop } catch { throw "The compliance search '$SearchName' was not found: $($_.Exception.Message)" }
if (@('Completed', 'PartiallySucceeded') -notcontains [string]$search.Status) {
    throw "The search '$SearchName' has status '$($search.Status)'. Only a completed search can be exported."
}
Write-Host ("`nSearch '{0}': {1:N0} items, {2:N2} GB, status {3}" -f $search.Name, [long]$search.Items, ([double]$search.Size / 1GB), $search.Status) -ForegroundColor Cyan

$actionName = '{0}_Export' -f $SearchName
$action = Get-ComplianceSearchAction -Identity $actionName -ErrorAction SilentlyContinue
if ($null -ne $action -and $Force) {
    if ($PSCmdlet.ShouldProcess($actionName, 'Remove the existing export action')) {
        try { Remove-ComplianceSearchAction -Identity $actionName -Confirm:$false -ErrorAction Stop; $action = $null }
        catch { throw "Could not remove the existing export action '$actionName': $($_.Exception.Message)" }
    }
}
elseif ($null -ne $action) {
    Write-Warning ("An export action '{0}' already exists (status {1}); reporting it instead of creating a new one. Use -Force to recreate it." -f $actionName, $action.Status)
}

if ($null -eq $action) {
    $exportParams = @{
        SearchName              = $SearchName
        Export                  = $true
        Format                  = $Format
        ExchangeArchiveFormat   = $ExchangeArchiveFormat
        Scope                   = $Scope
        EnableDedupe            = $EnableDedupe.IsPresent
        SharePointArchiveFormat = $SharePointArchiveFormat
        RetryOnError            = $RetryOnError.IsPresent
        Confirm                 = $false
        ErrorAction             = 'Stop'
    }
    $description = 'Export as {0} ({1}, {2}, dedupe {3}, SharePoint {4})' -f $Format, $ExchangeArchiveFormat, $Scope, $EnableDedupe.IsPresent, $SharePointArchiveFormat
    if (-not $PSCmdlet.ShouldProcess($SearchName, $description)) { return }
    try { $action = New-ComplianceSearchAction @exportParams } catch { throw "Failed to create the export action for '$SearchName': $($_.Exception.Message)" }
    Write-Verbose "Created export action '$actionName'."
}

# -IncludeCredential reveals the SAS token in Results; -Details adds the progress counters.
$started = Get-Date
$terminalStatuses = @('Completed', 'PartiallySucceeded', 'Failed')
do {
    try { $action = Get-ComplianceSearchAction -Identity $actionName -IncludeCredential -Details -ErrorAction Stop }
    catch { Write-Warning ("Polling '{0}' failed: {1}" -f $actionName, $_.Exception.Message) }
    $progress = Get-ResultField -Results $action.Results -Name 'Progress'
    if ($terminalStatuses -contains [string]$action.Status -or (Get-Date) -ge $started.AddMinutes($TimeoutMinutes)) { break }
    Write-Progress -Activity ("Exporting '{0}'" -f $SearchName) -Status ('{0}, progress {1}, {2:N0} min' -f $action.Status, $progress, ((Get-Date) - $started).TotalMinutes)
    Start-Sleep -Seconds 15
} while ($true)
Write-Progress -Activity ("Exporting '{0}'" -f $SearchName) -Completed
if ($terminalStatuses -notcontains [string]$action.Status) {
    Write-Warning ("The export is still '{0}' after {1} minutes. Re-run this script later to pick up the status and credentials." -f $action.Status, $TimeoutMinutes)
}

$result = [PSCustomObject]@{
    SearchName       = $SearchName
    ActionName       = $actionName
    Status           = [string]$action.Status
    Format           = $Format
    Scope            = $Scope
    SearchItems      = [long]$search.Items
    SearchSizeGB     = [math]::Round([double]$search.Size / 1GB, 2)
    EstimatedItems   = Get-ResultField -Results $action.Results -Name 'Total estimated items'
    TransferredItems = Get-ResultField -Results $action.Results -Name 'Total transferred items'
    Progress         = $progress
    ContainerUrl     = Get-ResultField -Results $action.Results -Name 'Container url'
    SasToken         = Get-ResultField -Results $action.Results -Name 'SAS token'
    JobStartTime     = $action.JobStartTime
    JobEndTime       = $action.JobEndTime
}

Write-Host ("`nExport '{0}' - status {1}" -f $actionName, $result.Status) -ForegroundColor $(if ($result.Status -eq 'Completed') { 'Green' } else { 'Yellow' })
Write-Host ('  Items         : {0} estimated, {1} transferred, progress {2}' -f $result.EstimatedItems, $result.TransferredItems, $result.Progress)
Write-Host ('  Container URL : {0}' -f $result.ContainerUrl)
Write-Host ('  SAS token     : {0}' -f $result.SasToken)
Write-Host ''
Write-Host 'How to download:' -ForegroundColor Cyan
Write-Host '  1. Purview portal > eDiscovery > Content search (or the case) > Exports tab > select the export > Download results.'
Write-Host '  2. The eDiscovery Export Tool (ClickOnce; use Edge with ClickOnce enabled) starts and asks for the export key:'
Write-Host '     paste the SAS token above, choose a local folder, and the PST/ZIP files plus the reports are downloaded.'
Write-Host '  3. Tenants on the new eDiscovery experience download exports directly from the portal, without the tool.'
Write-Host '  Keep the SAS token private: anyone holding it can download the exported content until the export is deleted.' -ForegroundColor Yellow
$result
#endregion Main
