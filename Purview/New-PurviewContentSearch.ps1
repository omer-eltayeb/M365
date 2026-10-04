<#
.SYNOPSIS
    Creates and starts a Purview content search from a KQL query or simple mail criteria, optionally waiting for the results.
.DESCRIPTION
    Builds a KQL query (-ContentMatchQuery as-is, or from -Sender, -Recipient, -Subject, -DateStart, -DateEnd and -Keywords), creates
    the search with New-ComplianceSearch against mailboxes and/or SharePoint sites (or All), optionally inside an eDiscovery (Standard)
    case, and starts it with Start-ComplianceSearch. With -Wait it polls Get-ComplianceSearch every 15 s, prints items and size, and
    writes a summary CSV plus the per-location statistics parsed from SuccessResults (<base>_Locations.csv).
.PARAMETER Name
    Name of the new search. Must be unique in the tenant (or in the case).
.PARAMETER ContentMatchQuery
    Complete KQL query to use as-is, for example 'subject:"Project X" AND received>=2026-01-01'.
.PARAMETER From
    One or more sender addresses or display names (from:), combined with OR. Alias: -Sender.
.PARAMETER Recipient
    One or more recipient addresses (recipients:), combined with OR.
.PARAMETER Subject
    Subject text or phrase (subject:).
.PARAMETER DateStart
    Earliest received date (received>=yyyy-MM-dd).
.PARAMETER DateEnd
    Latest received date (received<=yyyy-MM-dd).
.PARAMETER Keywords
    Free-text keywords or phrases, combined with OR.
.PARAMETER Mailboxes
    Mailbox addresses to search, or 'All' for every mailbox. At least one of -Mailboxes / -Sites is required.
.PARAMETER Sites
    SharePoint or OneDrive site URLs to search, or 'All' for every site.
.PARAMETER Case
    Name of an existing eDiscovery (Standard) case to create the search in. Default: a standalone content search.
.PARAMETER Description
    Optional description stored on the search.
.PARAMETER Wait
    Wait for the search to finish and report item counts and per-location statistics.
.PARAMETER TimeoutMinutes
    Maximum time to wait when -Wait is used (default 60).
.PARAMETER OutputPath
    Summary CSV written with -Wait (default .\Reports\PurviewContentSearch_yyyyMMdd-HHmm.csv); locations go to <base>_Locations.csv.
.EXAMPLE
    PS> .\New-PurviewContentSearch.ps1 -Name 'HR-Case-42' -Sender alex@contoso.com -Subject 'offer letter' -DateStart 2026-01-01 -Mailboxes All -Wait
    Searches every mailbox for messages from Alex with 'offer letter' in the subject received since 1 January 2026 and waits for the statistics.
.EXAMPLE
    PS> .\New-PurviewContentSearch.ps1 -Name 'Legal-7-Finance' -ContentMatchQuery 'FY26 AND (budget OR forecast)' -Sites https://contoso.sharepoint.com/sites/Finance -Case 'Legal 7' -WhatIf
    Shows the search that would be created inside the case 'Legal 7' without creating it.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, ExchangeOnlineManagement 3.x
    Permissions : eDiscovery Manager role group (Compliance Search role) in Security & Compliance PowerShell; case membership for -Case
    Category    : eDiscovery & content search
    Changes     : Yes
    Notes       : The criteria builder is mail-centric (from, recipients, subject, received); use -ContentMatchQuery for SharePoint properties.
.LINK
    https://learn.microsoft.com/powershell/module/exchange/new-compliancesearch
#>
#Requires -Version 5.1
#Requires -Modules ExchangeOnlineManagement

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High', DefaultParameterSetName = 'Builder')]
param(
    [Parameter(Mandatory = $true)]
    [string]$Name,

    [Parameter(Mandatory = $true, ParameterSetName = 'Kql')]
    [string]$ContentMatchQuery,

    [Parameter(ParameterSetName = 'Builder')]
    [Alias('Sender')]
    [string[]]$From,

    [Parameter(ParameterSetName = 'Builder')]
    [string[]]$Recipient,

    [Parameter(ParameterSetName = 'Builder')]
    [string]$Subject,

    [Parameter(ParameterSetName = 'Builder')]
    [datetime]$DateStart,

    [Parameter(ParameterSetName = 'Builder')]
    [datetime]$DateEnd,

    [Parameter(ParameterSetName = 'Builder')]
    [string[]]$Keywords,

    [Parameter()]
    [string[]]$Mailboxes,

    [Parameter()]
    [string[]]$Sites,

    [Parameter()]
    [string]$Case,

    [Parameter()]
    [string]$Description,

    [Parameter()]
    [switch]$Wait,

    [Parameter()]
    [ValidateRange(1, 1440)]
    [int]$TimeoutMinutes = 60,

    [Parameter()]
    [string]$OutputPath
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
if ($null -eq $Mailboxes -and $null -eq $Sites) { throw 'Specify at least one location: -Mailboxes <addresses | All> and/or -Sites <urls | All>.' }
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('PurviewContentSearch_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if ($Wait -and -not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}
$locationsPath = ($OutputPath -replace '\.[^.\\/]+$', '') + '_Locations.csv'

# Values are always quoted, which is valid KQL for single words and required for phrases; embedded quotes are dropped.
$query = $ContentMatchQuery
if ($PSCmdlet.ParameterSetName -eq 'Builder') {
    $clauses = @()
    if ($From) { $clauses += '({0})' -f (@($From | ForEach-Object { 'from:"{0}"' -f $_.Replace('"', '') }) -join ' OR ') }
    if ($Recipient) { $clauses += '({0})' -f (@($Recipient | ForEach-Object { 'recipients:"{0}"' -f $_.Replace('"', '') }) -join ' OR ') }
    if ($Subject) { $clauses += 'subject:"{0}"' -f $Subject.Replace('"', '') }
    if ($PSBoundParameters.ContainsKey('DateStart')) { $clauses += 'received>={0:yyyy-MM-dd}' -f $DateStart }
    if ($PSBoundParameters.ContainsKey('DateEnd')) { $clauses += 'received<={0:yyyy-MM-dd}' -f $DateEnd }
    if ($Keywords) { $clauses += '({0})' -f (@($Keywords | ForEach-Object { '"{0}"' -f $_.Replace('"', '') }) -join ' OR ') }
    $query = $clauses -join ' AND '
}
$queryText = $(if ([string]::IsNullOrWhiteSpace($query)) { '(none - every item in the selected locations)' } else { $query })
$locationText = 'Mailboxes: {0} | Sites: {1}' -f $(if ($Mailboxes) { $Mailboxes -join ', ' } else { '-' }), $(if ($Sites) { $Sites -join ', ' } else { '-' })

try { Connect-ExchangeIfNeeded -Compliance } catch { throw "Unable to connect to Security & Compliance PowerShell: $($_.Exception.Message)" }
if ($null -ne (Get-ComplianceSearch -Identity $Name -ErrorAction SilentlyContinue)) { throw "A compliance search named '$Name' already exists; choose another name." }

$searchParams = @{ Name = $Name; Confirm = $false; ErrorAction = 'Stop' }
if ($Mailboxes) { $searchParams['ExchangeLocation'] = $Mailboxes }
if ($Sites) { $searchParams['SharePointLocation'] = $Sites }
if (-not [string]::IsNullOrWhiteSpace($query)) { $searchParams['ContentMatchQuery'] = $query }
if ($Case) { $searchParams['Case'] = $Case }
if ($Description) { $searchParams['Description'] = $Description }

$target = "Content search '$Name'" + $(if ($Case) { " in case '$Case'" } else { '' })
if (-not $PSCmdlet.ShouldProcess($target, ('Create and start the search. Query: {0} | {1}' -f $queryText, $locationText))) { return }
try { New-ComplianceSearch @searchParams | Out-Null } catch { throw "Failed to create the search '$Name': $($_.Exception.Message)" }
try { Start-ComplianceSearch -Identity $Name -ErrorAction Stop } catch { throw "The search '$Name' was created but could not be started: $($_.Exception.Message)" }
$search = Get-ComplianceSearch -Identity $Name -ErrorAction Stop
$terminalStatuses = @('Completed', 'PartiallySucceeded', 'Failed', 'Stopped')
if ($Wait) {
    $started = Get-Date
    while ($terminalStatuses -notcontains [string]$search.Status -and (Get-Date) -lt $started.AddMinutes($TimeoutMinutes)) {
        Write-Progress -Activity ("Waiting for search '{0}'" -f $Name) -Status ('Status: {0} - elapsed {1:N0} s' -f $search.Status, ((Get-Date) - $started).TotalSeconds)
        Start-Sleep -Seconds 15
        $search = Get-ComplianceSearch -Identity $Name -ErrorAction Stop
    }
    Write-Progress -Activity ("Waiting for search '{0}'" -f $Name) -Completed
    if ($terminalStatuses -notcontains [string]$search.Status) { Write-Warning ("The search is still '{0}' after {1} minutes; check it again later." -f $search.Status, $TimeoutMinutes) }
}

$locationStats = New-Object -TypeName System.Collections.Generic.List[object]
foreach ($hit in [regex]::Matches([string]$search.SuccessResults, 'Location: (.+?), Item count: (\d+), Total size: (\d+)')) {
    $locationStats.Add([PSCustomObject]@{ SearchName = $Name; Location = $hit.Groups[1].Value; ItemCount = [long]$hit.Groups[2].Value; SizeMB = [math]::Round([double]$hit.Groups[3].Value / 1MB, 2) })
}
$result = [PSCustomObject]@{
    Name               = [string]$search.Name
    Case               = [string]$search.CaseName
    Status             = [string]$search.Status
    Items              = [long]$search.Items
    SizeGB             = [math]::Round([double]$search.Size / 1GB, 2)
    ContentMatchQuery  = [string]$search.ContentMatchQuery
    ExchangeLocation   = (@($search.ExchangeLocation) -join '; ')
    SharePointLocation = (@($search.SharePointLocation) -join '; ')
    LocationsWithItems = @($locationStats | Where-Object { $_.ItemCount -gt 0 }).Count
    Errors             = [string]$search.Errors
}

Write-Host ("`nContent search '{0}' - status {1} - query: {2}" -f $Name, $result.Status, $queryText) -ForegroundColor $(if ($result.Status -eq 'Completed') { 'Green' } else { 'Cyan' })
if ($Wait) {
    Write-Host ('  Items     : {0:N0} ({1} GB) in {2} location(s) with hits' -f $result.Items, $result.SizeGB, $result.LocationsWithItems)
    $result | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
    if ($locationStats.Count -gt 0) { $locationStats | Export-Csv -Path $locationsPath -NoTypeInformation -Encoding UTF8 }
    Write-Host ('  Reports   : {0} | {1}' -f $OutputPath, $(if ($locationStats.Count -gt 0) { $locationsPath } else { 'no per-location statistics yet' }))
}
else { Write-Host "  The search is running; check it with Get-PurviewContentSearchResults.ps1 -Name '$Name' -IncludeLocationStatistics" }
$result
#endregion Main
