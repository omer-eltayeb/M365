<#
.SYNOPSIS
    Previews dynamic distribution groups: recipient filter, conditional attributes, calculated member count, sample members and an optional recipient test.
.DESCRIPTION
    Reads every dynamic distribution group in scope with Get-DynamicDistributionGroup (RecipientFilter, RecipientContainer,
    IncludedRecipients, Conditional* attributes, owners) and the membership Exchange Online last calculated for it with
    Get-DynamicDistributionGroupMember. Each row shows the filter (truncated to 300 characters), the member count and a
    sample of member addresses. -TestRecipient reports whether a given recipient is currently a member of each group and
    -ExportMembers writes the full member list to <OutputPath base>_Members.csv. The script is read-only.
.PARAMETER Identity
    One or more dynamic group identities (name, alias, primary SMTP address or GUID). When omitted, every dynamic group is previewed.
.PARAMETER InputCsv
    Path to a CSV with an Identity or PrimarySmtpAddress column listing the groups to preview.
.PARAMETER SampleSize
    Number of member addresses shown in the SampleMembers column (1-100, default 10).
.PARAMETER ExportMembers
    Also export every member of every group (Group, Member, PrimarySmtpAddress, RecipientTypeDetails) to a second CSV.
.PARAMETER TestRecipient
    UPN or SMTP address of a recipient; the TestRecipientMatches column shows whether it is a member of each group.
.PARAMETER OutputPath
    Path of the CSV report. Defaults to .\Reports\EXODynamicDistributionGroups_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emit the report objects to the pipeline.
.EXAMPLE
    PS> .\Get-EXODynamicDistributionGroupPreview.ps1
    Previews every dynamic distribution group with its calculated member count and ten sample members.
.EXAMPLE
    PS> .\Get-EXODynamicDistributionGroupPreview.ps1 -TestRecipient jane@contoso.com -PassThru | Where-Object { $_.TestRecipientMatches }
    Lists the dynamic groups Jane currently resolves into.
.EXAMPLE
    PS> .\Get-EXODynamicDistributionGroupPreview.ps1 -Identity 'All Sales' -ExportMembers -SampleSize 25
    Previews one group and writes its full member list to .\Reports\EXODynamicDistributionGroups_<timestamp>_Members.csv.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, ExchangeOnlineManagement 3.x
    Permissions : View-Only Recipients (Exchange Online)
    Category    : Distribution groups
    Changes     : No
    Notes       : Get-DynamicDistributionGroupMember returns the membership as last calculated by Exchange Online (refreshed on a
                  schedule, roughly hourly), so very recent attribute changes may not be reflected yet. For a live evaluation of a
                  filter use Get-Recipient -RecipientPreviewFilter <filter> -OrganizationalUnit <RecipientContainer>.
.LINK
    https://learn.microsoft.com/powershell/module/exchange/get-dynamicdistributiongroupmember
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
    [ValidateRange(1, 100)]
    [int]$SampleSize = 10,

    [Parameter()]
    [switch]$ExportMembers,

    [Parameter()]
    [string]$TestRecipient,

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
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('EXODynamicDistributionGroups_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}
$membersPath = [System.IO.Path]::Combine($outputFolder, [System.IO.Path]::GetFileNameWithoutExtension($OutputPath) + '_Members.csv')

if ($PSCmdlet.ParameterSetName -eq 'Csv') {
    $rows = @(Import-Csv -Path $InputCsv -ErrorAction Stop)
    $column = @('Identity', 'PrimarySmtpAddress') | Where-Object { $rows.Count -gt 0 -and $rows[0].PSObject.Properties.Name -contains $_ } | Select-Object -First 1
    if ($null -eq $column) { throw "InputCsv must contain an 'Identity' or 'PrimarySmtpAddress' column." }
    $Identity = @($rows | ForEach-Object { $_.$column } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
}

try { Connect-ExchangeIfNeeded } catch { throw "Unable to connect to Exchange Online: $($_.Exception.Message)" }

$testAddress = $null
if (-not [string]::IsNullOrWhiteSpace($TestRecipient)) {
    try {
        $testRecipientObject = Get-EXORecipient -Identity $TestRecipient -Properties PrimarySmtpAddress -ErrorAction Stop | Select-Object -First 1
        $testAddress = ([string]$testRecipientObject.PrimarySmtpAddress).ToLowerInvariant()
    }
    catch { throw "Test recipient '$TestRecipient' could not be resolved: $($_.Exception.Message)" }
}

if ($null -ne $Identity -and $Identity.Count -gt 0) {
    $groups = @(foreach ($id in $Identity) { try { Get-DynamicDistributionGroup -Identity $id -ErrorAction Stop } catch { Write-Warning "Dynamic group '$id' not found: $($_.Exception.Message)" } })
}
else {
    try { $groups = @(Get-DynamicDistributionGroup -ResultSize Unlimited -ErrorAction Stop) } catch { throw "Failed to retrieve dynamic distribution groups: $($_.Exception.Message)" }
}

$results = New-Object -TypeName System.Collections.Generic.List[object]
$memberRows = New-Object -TypeName System.Collections.Generic.List[object]
$index = 0
foreach ($group in $groups) {
    $index++
    $smtp = [string]$group.PrimarySmtpAddress
    Write-Progress -Activity 'Previewing dynamic distribution groups' -Status "$index of $($groups.Count) - $smtp" -PercentComplete (($index / $groups.Count) * 100)
    $memberCount = $null
    $members = @()
    try { $members = @(Get-DynamicDistributionGroupMember -Identity $smtp -ResultSize Unlimited -ErrorAction Stop); $memberCount = $members.Count }
    catch { Write-Warning "Members of '$smtp' could not be read: $($_.Exception.Message)" }
    $addresses = @($members | ForEach-Object { ([string]$_.PrimarySmtpAddress).ToLowerInvariant() })

    # Conditional* properties (Department, Company, StateOrProvince, CustomAttribute1-15) are summarised as Name=values.
    $conditions = New-Object -TypeName System.Collections.Generic.List[string]
    foreach ($property in @($group.PSObject.Properties | Where-Object { $_.Name -like 'Conditional*' })) {
        $values = @($property.Value | ForEach-Object { [string]$_ } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        if ($values.Count -gt 0) { $conditions.Add(('{0}={1}' -f ($property.Name -replace '^Conditional', ''), ($values -join ','))) }
    }
    $filter = [string]$group.RecipientFilter
    if ($filter.Length -gt 300) { $filter = $filter.Substring(0, 297) + '...' }

    $results.Add([PSCustomObject]@{
            Group                 = [string]$group.DisplayName
            PrimarySmtpAddress    = $smtp
            ManagedBy             = (@($group.ManagedBy | ForEach-Object { [string]$_ }) -join '; ')
            RecipientContainer    = [string]$group.RecipientContainer
            IncludedRecipients    = [string]$group.IncludedRecipients
            ConditionalAttributes = ($conditions -join '; ')
            Filter                = $filter
            MemberCount           = $memberCount
            SampleMembers         = (@($addresses | Select-Object -First $SampleSize) -join '; ')
            TestRecipientMatches  = $(if ($null -ne $testAddress -and $null -ne $memberCount) { $addresses -contains $testAddress } else { $null })
            WhenChanged           = $group.WhenChanged
        })
    if ($ExportMembers) {
        foreach ($member in $members) {
            $memberRows.Add([PSCustomObject]@{
                    Group                = [string]$group.DisplayName
                    Member               = [string]$member.DisplayName
                    PrimarySmtpAddress   = [string]$member.PrimarySmtpAddress
                    RecipientTypeDetails = [string]$member.RecipientTypeDetails
                })
        }
    }
}
Write-Progress -Activity 'Previewing dynamic distribution groups' -Completed

if ($results.Count -gt 0) { $results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 }
if ($ExportMembers -and $memberRows.Count -gt 0) { $memberRows | Export-Csv -Path $membersPath -NoTypeInformation -Encoding UTF8 }

$emptyGroups = @($results | Where-Object { $_.MemberCount -eq 0 })
Write-Host ''
Write-Host 'Dynamic distribution group summary' -ForegroundColor Cyan
Write-Host ('  Groups previewed   : {0}' -f $results.Count)
Write-Host ('  Calculated members : {0}' -f ($results | Where-Object { $null -ne $_.MemberCount } | Measure-Object -Property MemberCount -Sum).Sum)
Write-Host ('  Empty groups       : {0}' -f $emptyGroups.Count) -ForegroundColor $(if ($emptyGroups.Count -gt 0) { 'Yellow' } else { 'Green' })
if ($null -ne $testAddress) { Write-Host ('  {0} matches     : {1} group(s)' -f $testAddress, @($results | Where-Object { $_.TestRecipientMatches }).Count) }
if ($results.Count -gt 0) { Write-Host ('  Report             : {0}' -f $OutputPath) }
if ($ExportMembers -and $memberRows.Count -gt 0) { Write-Host ('  Members            : {0}' -f $membersPath) }

if ($PassThru) {
    $results
}
#endregion Main
