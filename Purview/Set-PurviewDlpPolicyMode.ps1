<#
.SYNOPSIS
    Switches Purview DLP policies between test and enforcement modes, in bulk and with a before/after report.
.DESCRIPTION
    Connects to Security & Compliance PowerShell and resolves the target policies from -PolicyName (wildcards allowed),
    from a CSV (-InputCsv with a PolicyName column and an optional Mode column) or with -EnableAllTestPolicies, which
    selects every policy still in TestWithNotifications / TestWithoutNotifications and sets it to Enable. For each policy
    the current and new mode are compared; policies already in the requested mode are reported as NoChange. Changes are
    made with Set-DlpCompliancePolicy -Mode only when -Apply is specified and each one goes through ShouldProcess, so
    -WhatIf and -Confirm work. Without -Apply the script is read-only and only reports what would change.
    Writes a results CSV (PolicyName, CurrentMode, NewMode, Status, Message) and prints a summary.
.PARAMETER PolicyName
    One or more policy names; wildcards are allowed (for example 'PCI*').
.PARAMETER InputCsv
    CSV with a PolicyName column and an optional Mode column. Rows without a Mode value use -Mode.
.PARAMETER EnableAllTestPolicies
    Select every policy currently in a test mode and set it to Enable.
.PARAMETER Mode
    Target mode: Enable, TestWithNotifications, TestWithoutNotifications or Disable. Mandatory with -PolicyName.
.PARAMETER Apply
    Perform the changes. Without this switch the script only reports the policies and the modes they would get.
.PARAMETER OutputPath
    Path of the results CSV. Defaults to .\Reports\PurviewDlpPolicyMode_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emit the result rows to the pipeline.
.EXAMPLE
    PS> .\Set-PurviewDlpPolicyMode.ps1 -PolicyName 'PCI*', 'GDPR - Finance' -Mode Enable
    Reports which PCI and GDPR policies would be switched to Enable, without changing anything.
.EXAMPLE
    PS> .\Set-PurviewDlpPolicyMode.ps1 -EnableAllTestPolicies -Apply -WhatIf
    Shows the Set-DlpCompliancePolicy calls that would move every test-mode policy to Enable.
.EXAMPLE
    PS> .\Set-PurviewDlpPolicyMode.ps1 -InputCsv .\modes.csv -Mode TestWithNotifications -Apply -Confirm:$false
    Applies the Mode column of the CSV (falling back to TestWithNotifications) to each listed policy without prompting.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, ExchangeOnlineManagement 3.x
    Permissions : View-Only DLP Compliance Management for the report; DLP Compliance Management (Compliance Administrator) for -Apply
    Category    : Data loss prevention
    Changes     : Yes
    Notes       : Opens a Security & Compliance PowerShell session (Connect-IPPSSession). A mode change takes up to an hour to
                  reach all workloads - check DistributionStatus with Get-DlpCompliancePolicy -DistributionDetail. The -WhatIf
                  switch of Set-DlpCompliancePolicy itself is not honoured by the service, so this script evaluates ShouldProcess
                  before calling it. Switching to Enable starts blocking and notifying immediately once distributed.
.LINK
    https://learn.microsoft.com/powershell/module/exchange/set-dlpcompliancepolicy
#>
#Requires -Version 5.1
#Requires -Modules ExchangeOnlineManagement

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High', DefaultParameterSetName = 'ByName')]
param(
    [Parameter(Mandatory = $true, ParameterSetName = 'ByName')]
    [ValidateNotNullOrEmpty()]
    [string[]]$PolicyName,

    [Parameter(Mandatory = $true, ParameterSetName = 'ByCsv')]
    [ValidateScript({ Test-Path -Path $_ -PathType Leaf })]
    [string]$InputCsv,

    [Parameter(Mandatory = $true, ParameterSetName = 'AllTest')]
    [switch]$EnableAllTestPolicies,

    [Parameter(Mandatory = $true, ParameterSetName = 'ByName')]
    [Parameter(ParameterSetName = 'ByCsv')]
    [ValidateSet('Enable', 'TestWithNotifications', 'TestWithoutNotifications', 'Disable')]
    [string]$Mode,

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

function New-ModeResult {
    <# Shapes one result row. #>
    param([Parameter(Mandatory = $true)][string]$Name, [Parameter()][string]$CurrentMode, [Parameter()][string]$NewMode,
        [Parameter(Mandatory = $true)][string]$Status, [Parameter()][string]$Message)
    [PSCustomObject]@{ PolicyName = $Name; CurrentMode = $CurrentMode; NewMode = $NewMode; Status = $Status; Message = $Message }
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('PurviewDlpPolicyMode_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}
if (-not $Apply) { Write-Host 'Read-only mode: add -Apply to change policy modes.' -ForegroundColor Yellow }

try { Connect-ExchangeIfNeeded -Compliance }
catch { throw "Unable to connect to Security & Compliance PowerShell: $($_.Exception.Message)" }

try { $policies = @(Get-DlpCompliancePolicy -ErrorAction Stop) }
catch { throw "Failed to retrieve DLP policies: $($_.Exception.Message)" }

# Resolve the work list: one entry per policy with the mode it should get. Unknown names become NotFound rows.
$validModes = 'Enable', 'TestWithNotifications', 'TestWithoutNotifications', 'Disable'
$results = New-Object -TypeName System.Collections.Generic.List[object]
$targets = New-Object -TypeName System.Collections.Generic.List[object]
switch ($PSCmdlet.ParameterSetName) {
    'ByName' {
        foreach ($pattern in $PolicyName) {
            $matched = @($policies | Where-Object { $_.Name -like $pattern })
            if ($matched.Count -eq 0) { $results.Add((New-ModeResult -Name $pattern -NewMode $Mode -Status 'NotFound' -Message 'No DLP policy matches this name.')) }
            foreach ($policy in $matched) { $targets.Add(@{ Policy = $policy; NewMode = $Mode }) }
        }
    }
    'ByCsv' {
        $rows = @(Import-Csv -Path $InputCsv -ErrorAction Stop)
        if ($rows.Count -eq 0 -or $null -eq $rows[0].PSObject.Properties['PolicyName']) { throw "The CSV '$InputCsv' must contain a PolicyName column." }
        foreach ($row in $rows) {
            $rowMode = [string]$row.Mode
            if ([string]::IsNullOrWhiteSpace($rowMode)) { $rowMode = $Mode }
            $policy = $policies | Where-Object { $_.Name -eq $row.PolicyName } | Select-Object -First 1
            if ($null -eq $policy) { $results.Add((New-ModeResult -Name $row.PolicyName -NewMode $rowMode -Status 'NotFound' -Message 'No DLP policy has this exact name.')) }
            elseif ($validModes -notcontains $rowMode) {
                $results.Add((New-ModeResult -Name $policy.Name -CurrentMode $policy.Mode -NewMode $rowMode -Status 'InvalidMode' -Message 'Set a valid Mode in the CSV row or pass -Mode.'))
            }
            else { $targets.Add(@{ Policy = $policy; NewMode = $rowMode }) }
        }
    }
    'AllTest' {
        foreach ($policy in ($policies | Where-Object { $_.Mode -like 'Test*' })) { $targets.Add(@{ Policy = $policy; NewMode = 'Enable' }) }
        if ($targets.Count -eq 0) { Write-Host 'No DLP policy is currently in a test mode.' -ForegroundColor Green }
    }
}

$index = 0
foreach ($target in $targets) {
    $index++
    $policy = $target.Policy
    $currentMode = [string]$policy.Mode
    Write-Progress -Activity 'Setting DLP policy modes' -Status $policy.Name -PercentComplete (($index / $targets.Count) * 100)
    if ($currentMode -eq $target.NewMode) {
        $results.Add((New-ModeResult -Name $policy.Name -CurrentMode $currentMode -NewMode $target.NewMode -Status 'NoChange' -Message 'Already in the requested mode.'))
        continue
    }
    if (-not $Apply) {
        $results.Add((New-ModeResult -Name $policy.Name -CurrentMode $currentMode -NewMode $target.NewMode -Status 'WouldChange' -Message 'Re-run with -Apply to change.'))
        continue
    }
    if ($PSCmdlet.ShouldProcess($policy.Name, ('Set DLP policy mode {0} -> {1}' -f $currentMode, $target.NewMode))) {
        try {
            Set-DlpCompliancePolicy -Identity $policy.Name -Mode $target.NewMode -ErrorAction Stop
            $results.Add((New-ModeResult -Name $policy.Name -CurrentMode $currentMode -NewMode $target.NewMode -Status 'Changed' -Message 'Mode updated; allow up to an hour for distribution.'))
        }
        catch {
            Write-Warning ('{0}: {1}' -f $policy.Name, $_.Exception.Message)
            $results.Add((New-ModeResult -Name $policy.Name -CurrentMode $currentMode -NewMode $target.NewMode -Status 'Failed' -Message $_.Exception.Message))
        }
    }
    else {
        $results.Add((New-ModeResult -Name $policy.Name -CurrentMode $currentMode -NewMode $target.NewMode -Status 'Skipped' -Message 'Skipped by -WhatIf or at the confirmation prompt.'))
    }
}
Write-Progress -Activity 'Setting DLP policy modes' -Completed

if ($results.Count -gt 0) { $results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 }

Write-Host 'Purview DLP policy mode summary' -ForegroundColor Cyan
Write-Host ('  Policies targeted : {0}' -f $targets.Count)
foreach ($group in ($results | Group-Object -Property Status | Sort-Object -Property Name)) {
    $colour = 'White'
    if ($group.Name -in 'Failed', 'NotFound', 'InvalidMode') { $colour = 'Red' } elseif ($group.Name -eq 'Changed') { $colour = 'Green' }
    Write-Host ('  {0,-18}: {1}' -f $group.Name, $group.Count) -ForegroundColor $colour
}
foreach ($row in ($results | Where-Object { $_.Status -in 'WouldChange', 'Changed' })) {
    Write-Host ('    {0}: {1} -> {2}' -f $row.PolicyName, $row.CurrentMode, $row.NewMode)
}
if (@($results | Where-Object { $_.Status -eq 'Changed' }).Count -gt 0) {
    Write-Host '  Mode changes propagate to Exchange, SharePoint, OneDrive, Teams and devices within about an hour.' -ForegroundColor Yellow
}
Write-Host ('  Results           : {0}' -f $OutputPath)

if ($PassThru) { $results }
#endregion Main
