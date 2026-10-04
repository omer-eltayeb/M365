<#
.SYNOPSIS
    Documents information barrier segments, policies and application status, tests a recipient pair and can start policy application.
.DESCRIPTION
    Connects to Security & Compliance PowerShell and exports the organization segments (Get-OrganizationSegment), the
    information barrier policies (Get-InformationBarrierPolicy), the policy application history
    (Get-InformationBarrierPoliciesApplicationStatus -All) and the tenant InformationBarrierMode (Get-PolicyConfig) to CSV
    files. Inactive policies and policies changed after the last application run are flagged. -TestRecipients checks whether
    two recipients can communicate (Get-ExoInformationBarrierRelationship, Exchange Online session) and -Apply starts a new
    policy application (Start-InformationBarrierPoliciesApplication) with -WhatIf / -Confirm support.
.PARAMETER TestRecipients
    Exactly two recipient identities (UPN or alias) whose information barrier relationship is evaluated.
.PARAMETER Apply
    Start the application of the information barrier policies. Without this switch the script only reports.
.PARAMETER OutputPath
    Path of the policies CSV (default .\Reports\PurviewInformationBarriers_yyyyMMdd-HHmm.csv); <base>_Segments.csv and <base>_ApplicationStatus.csv are written next to it.
.PARAMETER PassThru
    Also emit the policy rows to the pipeline.
.EXAMPLE
    PS> .\Get-PurviewInformationBarriers.ps1
    Exports segments, policies and application history and flags inactive or not-yet-applied policies.
.EXAMPLE
    PS> .\Get-PurviewInformationBarriers.ps1 -TestRecipients alex@contoso.com, kim@contoso.com
    Additionally shows whether Alex and Kim are blocked from communicating by an information barrier policy.
.EXAMPLE
    PS> .\Get-PurviewInformationBarriers.ps1 -Apply -Confirm:$false
    Exports the configuration and starts applying the active policies without prompting.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, ExchangeOnlineManagement 3.x
    Permissions : Compliance Administrator or IB Compliance Management role (Security & Compliance PowerShell); -TestRecipients needs
                  an Exchange Online session with View-Only Recipients or higher
    Category    : Risk, compliance & roles
    Changes     : Optional (-Apply)
    Notes       : Information barriers need Microsoft 365 E5, E5 Compliance or the Insider Risk Management add-on. Policy changes take
                  effect only after Start-InformationBarrierPoliciesApplication, which runs for 30 minutes or more and fails while a
                  previous application is still in progress. Segments must not overlap (each user in one segment) in legacy mode.
.LINK
    https://learn.microsoft.com/purview/information-barriers-policies
.LINK
    https://learn.microsoft.com/powershell/module/exchange/get-informationbarrierpolicy
#>
#Requires -Version 5.1
#Requires -Modules ExchangeOnlineManagement

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter()]
    [ValidateCount(2, 2)]
    [string[]]$TestRecipients,

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
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('PurviewInformationBarriers_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}
$basePath = [System.IO.Path]::ChangeExtension($OutputPath, $null)
$segmentsPath = $basePath + '_Segments.csv'
$statusPath = $basePath + '_ApplicationStatus.csv'

try {
    Connect-ExchangeIfNeeded -Compliance
}
catch {
    throw "Unable to connect to Security & Compliance PowerShell: $($_.Exception.Message)"
}
$ibMode = '(unknown)'
try { $ibMode = [string](Get-PolicyConfig -ErrorAction Stop).InformationBarrierMode } catch { Write-Warning "Could not read InformationBarrierMode: $($_.Exception.Message)" }
try {
    Write-Progress -Activity 'Reading information barriers' -Status 'Segments and policies' -PercentComplete 20
    $segments = @(Get-OrganizationSegment -ErrorAction Stop)
    $policies = @(Get-InformationBarrierPolicy -ErrorAction Stop)
}
catch {
    throw "Unable to read information barrier segments or policies (requires the IB Compliance Management or Compliance Administrator role): $($_.Exception.Message)"
}
$applications = @()
try {
    Write-Progress -Activity 'Reading information barriers' -Status 'Application status' -PercentComplete 60
    $applications = @(Get-InformationBarrierPoliciesApplicationStatus -All -ErrorAction Stop | Sort-Object -Property StartTime -Descending)
}
catch {
    Write-Warning "Could not read the policy application status: $($_.Exception.Message)"
}
Write-Progress -Activity 'Reading information barriers' -Completed

$segmentRows = foreach ($segment in $segments) {
    [PSCustomObject]@{
        Name            = [string]$segment.Name
        Guid            = [string]$segment.Guid
        UserGroupFilter = [string]$segment.UserGroupFilter
        CreatedBy       = [string]$segment.CreatedBy
        WhenCreated     = $segment.WhenCreated
    }
}
$statusRows = foreach ($application in $applications) {
    [PSCustomObject]@{
        Identity         = [string]$application.Identity
        Status           = [string]$application.Status
        StartTime        = $application.StartTime
        EndTime          = $application.EndTime
        TotalBatches     = $application.TotalBatches
        ProcessedBatches = $application.ProcessedBatches
        PercentProgress  = $application.PercentProgress
        FailureCategory  = [string]$application.FailureCategory
    }
}
# A policy only takes effect once an application run started after its last change has completed.
$latestRun = $applications | Select-Object -First 1
$policyRows = foreach ($policy in $policies) {
    $flags = @()
    if ([string]$policy.State -ne 'Active') { $flags += 'Inactive' }
    if ($null -eq $latestRun -or ($policy.WhenChanged -gt $latestRun.StartTime) -or ([string]$latestRun.Status -ne 'Completed')) { $flags += 'PendingApplication' }
    [PSCustomObject]@{
        Name            = [string]$policy.Name
        Guid            = [string]$policy.Guid
        State           = [string]$policy.State
        AssignedSegment = [string]$policy.AssignedSegment
        SegmentsAllowed = (@($policy.SegmentsAllowed) -join '; ')
        SegmentsBlocked = (@($policy.SegmentsBlocked) -join '; ')
        Comment         = [string]$policy.Comment
        WhenChanged     = $policy.WhenChanged
        Flag            = ($flags -join '; ')
    }
}
$policyRows = @($policyRows)
if ($policyRows.Count -gt 0) { $policyRows | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 }
if (@($segmentRows).Count -gt 0) { $segmentRows | Export-Csv -Path $segmentsPath -NoTypeInformation -Encoding UTF8 }
if (@($statusRows).Count -gt 0) { $statusRows | Export-Csv -Path $statusPath -NoTypeInformation -Encoding UTF8 }

$relationship = $null
if ($TestRecipients) {
    try {
        Connect-ExchangeIfNeeded
        $relationship = Get-ExoInformationBarrierRelationship -RecipientId1 $TestRecipients[0] -RecipientId2 $TestRecipients[1] -ErrorAction Stop
    }
    catch {
        Write-Warning "Could not evaluate the relationship between $($TestRecipients[0]) and $($TestRecipients[1]): $($_.Exception.Message)"
    }
}
if ($Apply -and $PSCmdlet.ShouldProcess('Information barrier policies', 'Start-InformationBarrierPoliciesApplication')) {
    try {
        Start-InformationBarrierPoliciesApplication -ErrorAction Stop
        Write-Host 'Policy application started; track it with Get-InformationBarrierPoliciesApplicationStatus (30 minutes or more).' -ForegroundColor Green
    }
    catch {
        Write-Error "Start-InformationBarrierPoliciesApplication failed: $($_.Exception.Message)" -ErrorAction Continue
    }
}

Write-Host ''
Write-Host 'Information barriers summary' -ForegroundColor Cyan
Write-Host ('  Mode                : {0}' -f $ibMode)
Write-Host ('  Segments            : {0}' -f $segments.Count)
$activeCount = @($policyRows | Where-Object { $_.State -eq 'Active' }).Count
Write-Host ('  Policies            : {0}  (active {1}, inactive {2})' -f $policyRows.Count, $activeCount, ($policyRows.Count - $activeCount))
Write-Host ('  Pending application : {0}' -f @($policyRows | Where-Object { $_.Flag -like '*PendingApplication*' }).Count) -ForegroundColor Yellow
if ($null -ne $latestRun) { Write-Host ('  Last application    : {0:yyyy-MM-dd HH:mm} status {1} ({2}%)' -f $latestRun.StartTime, $latestRun.Status, $latestRun.PercentProgress) }
if ($null -ne $relationship) {
    Write-Host ('  Relationship test   : {0} <-> {1}' -f $TestRecipients[0], $TestRecipients[1])
    Write-Host (($relationship | Format-List | Out-String).TrimEnd())
}
if ($policyRows.Count -gt 0) { Write-Host ('  Report              : {0}' -f $OutputPath) }

if ($PassThru) {
    $policyRows
}
#endregion Main
