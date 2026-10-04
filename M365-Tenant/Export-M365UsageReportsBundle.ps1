<#
.SYNOPSIS
    Downloads a bundle of Microsoft 365 usage detail reports (users, mailboxes, apps, OneDrive, SharePoint, Teams, groups, Viva Engage, activations) as CSV files.
.DESCRIPTION
    Downloads up to 14 Microsoft Graph usage detail reports (/reports/get*Detail) for the selected period into one folder,
    one CSV per report, and writes Manifest.csv with the report name, period, row count, file and status. Reports that
    fail (typically HTTP 403 for workloads the tenant is not licensed for) are logged as warnings and the run continues.
    -IncludeSettingsCheck warns when the tenant conceals names (/admin/reportSettings); -Zip compresses the folder when done.
.PARAMETER Period
    Report period: D7, D30, D90 or D180 (days). Default D30. The activations report is a snapshot and ignores it.
.PARAMETER Reports
    Report functions to download. Defaults to all 14 supported detail reports.
.PARAMETER OutputFolder
    Folder for the CSV files. Defaults to .\M365UsageReports_<Period>_<timestamp>; created when missing.
.PARAMETER IncludeSettingsCheck
    Also read the tenant report settings (requires ReportSettings.Read.All) and warn when names are concealed.
.PARAMETER Zip
    Compress the output folder to <OutputFolder>.zip after the downloads.
.PARAMETER PassThru
    Also emit the manifest objects to the pipeline.
.EXAMPLE
    PS> .\Export-M365UsageReportsBundle.ps1
    Downloads all 14 detail reports for the last 30 days into .\M365UsageReports_D30_<timestamp> and prints the manifest.
.EXAMPLE
    PS> .\Export-M365UsageReportsBundle.ps1 -Period D90 -Reports getTeamsUserActivityUserDetail, getTeamsTeamActivityDetail -IncludeSettingsCheck -Zip -OutputFolder C:\Temp\Teams90
    Downloads only the two Teams reports for 90 days, checks the concealed-names setting and zips C:\Temp\Teams90 to C:\Temp\Teams90.zip.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : Reports.Read.All (delegated); plus ReportSettings.Read.All with -IncludeSettingsCheck; Reports Reader or Global Reader role
    Category    : Usage & adoption reports
    Changes     : No
    Notes       : Report data lags about 48 hours. When "Display concealed user, group, and site names in all reports" is on (admin
                  center > Settings > Org settings > Reports) names and UPNs in every CSV are hashes; -IncludeSettingsCheck detects this.
.LINK
    https://learn.microsoft.com/graph/api/resources/report
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateSet('D7', 'D30', 'D90', 'D180')]
    [string]$Period = 'D30',

    [Parameter()]
    [ValidateSet('getOffice365ActiveUserDetail', 'getEmailActivityUserDetail', 'getMailboxUsageDetail', 'getM365AppUserDetail',
        'getOneDriveActivityUserDetail', 'getOneDriveUsageAccountDetail', 'getSharePointActivityUserDetail', 'getSharePointSiteUsageDetail',
        'getTeamsUserActivityUserDetail', 'getTeamsDeviceUsageUserDetail', 'getTeamsTeamActivityDetail', 'getOffice365GroupsActivityDetail',
        'getYammerActivityUserDetail', 'getOffice365ActivationsUserDetail')]
    [string[]]$Reports,

    [Parameter()]
    [string]$OutputFolder,

    [Parameter()]
    [switch]$IncludeSettingsCheck,

    [Parameter()]
    [switch]$Zip,

    [Parameter()]
    [switch]$PassThru
)

$ErrorActionPreference = 'Stop'

#region Helpers
function Connect-GraphIfNeeded {
    <# Connects to Microsoft Graph only when there is no usable session for the required scopes. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Scopes
    )
    $context = Get-MgContext
    $missingScopes = @()
    if ($null -ne $context) {
        $missingScopes = @($Scopes | Where-Object { $context.Scopes -notcontains $_ })
    }
    if ($null -eq $context -or $missingScopes.Count -gt 0) {
        Write-Verbose "Connecting to Microsoft Graph with scopes: $($Scopes -join ', ')"
        Connect-MgGraph -Scopes $Scopes -NoWelcome -ErrorAction Stop | Out-Null
    }
    else {
        Write-Verbose "Reusing existing Microsoft Graph session for $($context.Account)."
    }
}

function Invoke-GraphPaged {
    <# GET helper that follows @odata.nextLink and returns every item in 'value'. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Uri,

        [Parameter()]
        [hashtable]$Headers
    )
    $results = New-Object -TypeName System.Collections.Generic.List[object]
    $nextLink = $Uri
    while (-not [string]::IsNullOrEmpty($nextLink)) {
        $requestParams = @{ Method = 'GET'; Uri = $nextLink; OutputType = 'PSObject'; ErrorAction = 'Stop' }
        if ($null -ne $Headers) { $requestParams['Headers'] = $Headers }
        $response = Invoke-MgGraphRequest @requestParams
        if ($null -ne $response.PSObject.Properties['value']) {
            foreach ($item in $response.value) { $results.Add($item) }
        }
        elseif ($null -ne $response) {
            $results.Add($response)
        }
        $nextLink = $response.'@odata.nextLink'
    }
    return $results
}

function Get-UsageReportCsv {
    <# Downloads a Microsoft Graph usage report (CSV) and imports it; pass an empty Period for the activation reports. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ReportFunction,

        [Parameter()]
        [string]$Period
    )
    $uri = 'https://graph.microsoft.com/v1.0/reports/{0}' -f $ReportFunction
    if (-not [string]::IsNullOrEmpty($Period)) { $uri = '{0}(period=''{1}'')' -f $uri, $Period }
    $tempCsv = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath ('{0}_{1}.csv' -f $ReportFunction, [guid]::NewGuid())
    try {
        Invoke-MgGraphRequest -Method GET -Uri $uri -OutputFilePath $tempCsv -ErrorAction Stop
        return @(Import-Csv -Path $tempCsv)
    }
    finally {
        if (Test-Path -Path $tempCsv) { Remove-Item -Path $tempCsv -Force -ErrorAction SilentlyContinue }
    }
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputFolder)) {
    $OutputFolder = Join-Path -Path (Get-Location).Path -ChildPath ('M365UsageReports_{0}_{1}' -f $Period, (Get-Date -Format 'yyyyMMdd-HHmm'))
}
if (-not (Test-Path -Path $OutputFolder)) { New-Item -Path $OutputFolder -ItemType Directory -Force | Out-Null }
$OutputFolder = (Resolve-Path -Path $OutputFolder).Path
if ($null -eq $Reports -or $Reports.Count -eq 0) {
    # Default to every report in the ValidateSet without repeating the list.
    $Reports = @(($MyInvocation.MyCommand.Parameters['Reports'].Attributes | Where-Object { $_ -is [System.Management.Automation.ValidateSetAttribute] }).ValidValues)
}

$scopes = @('Reports.Read.All'); if ($IncludeSettingsCheck) { $scopes += 'ReportSettings.Read.All' }
try {
    Connect-GraphIfNeeded -Scopes $scopes
}
catch {
    throw "Failed to connect to Microsoft Graph: $($_.Exception.Message)"
}

$concealedNames = $null
if ($IncludeSettingsCheck) {
    try {
        $settings = @(Invoke-GraphPaged -Uri 'https://graph.microsoft.com/v1.0/admin/reportSettings?$select=displayConcealedNames') | Select-Object -First 1
        if ($null -ne $settings -and $null -ne $settings.PSObject.Properties['displayConcealedNames']) { $concealedNames = [bool]$settings.displayConcealedNames }
    }
    catch {
        Write-Warning "Could not read /admin/reportSettings (ReportSettings.Read.All needed): $($_.Exception.Message)"
    }
}
if ($concealedNames) { Write-Warning 'This tenant conceals names in reports: names and UPNs in the CSV files are hashes (admin center > Settings > Org settings > Reports).' }

$manifest = New-Object -TypeName System.Collections.Generic.List[object]
$index = 0
foreach ($reportFunction in $Reports) {
    $index++
    Write-Progress -Activity 'Downloading usage reports' -Status $reportFunction -PercentComplete ([int](($index / $Reports.Count) * 100))
    # The activations report is a snapshot and rejects the period parameter.
    $reportPeriod = $Period; $periodLabel = $Period
    if ($reportFunction -eq 'getOffice365ActivationsUserDetail') { $reportPeriod = ''; $periodLabel = 'snapshot' }
    $filePath = Join-Path -Path $OutputFolder -ChildPath ('{0}_{1}.csv' -f $reportFunction, $periodLabel)
    $status = 'OK'; $rowCount = 0
    try {
        $data = @(Get-UsageReportCsv -ReportFunction $reportFunction -Period $reportPeriod)
        $rowCount = $data.Count
        if ($rowCount -gt 0) { $data | Export-Csv -Path $filePath -NoTypeInformation -Encoding UTF8 } else { $status = 'Empty'; $filePath = $null }
    }
    catch {
        # HTTP 403 is normal for workloads the tenant does not own (for example Viva Engage); record it and carry on.
        $status = 'Failed: {0}' -f (($_.Exception.Message -split "`r?`n")[0])
        $filePath = $null
        Write-Warning ('{0} failed: {1}' -f $reportFunction, $_.Exception.Message)
    }
    $manifest.Add([PSCustomObject]@{ Report = $reportFunction; Period = $periodLabel; Rows = $rowCount; File = $filePath; Status = $status })
}
Write-Progress -Activity 'Downloading usage reports' -Completed
$manifest | Export-Csv -Path (Join-Path -Path $OutputFolder -ChildPath 'Manifest.csv') -NoTypeInformation -Encoding UTF8

$zipPath = '{0}.zip' -f $OutputFolder.TrimEnd('\', '/')
if ($Zip) { Compress-Archive -Path (Join-Path -Path $OutputFolder -ChildPath '*') -DestinationPath $zipPath -Force }

$downloaded = @($manifest | Where-Object { $_.Status -eq 'OK' })
$failed = @($manifest | Where-Object { $_.Status -like 'Failed*' })
$concealedText = 'not checked (use -IncludeSettingsCheck)'
if ($concealedNames -eq $true) { $concealedText = 'ON - names and UPNs are hashed' } elseif ($concealedNames -eq $false) { $concealedText = 'off' }
Write-Host ('Microsoft 365 usage report bundle ({0})' -f $Period) -ForegroundColor Cyan
Write-Host ('  Reports requested / downloaded / empty / failed : {0} / {1} / {2} / {3}' -f $manifest.Count, $downloaded.Count, ($manifest.Count - $downloaded.Count - $failed.Count), $failed.Count)
Write-Host ('  Concealed names                                 : {0}' -f $concealedText)
foreach ($entry in $manifest) { Write-Host ('    {0,-36} {1,8} rows  {2}' -f $entry.Report, $entry.Rows, $entry.Status) }
Write-Host ('  Folder : {0}' -f $OutputFolder)
if ($Zip) { Write-Host ('  Zip    : {0}' -f $zipPath) }

if ($PassThru) { $manifest }
#endregion Main
