<#
.SYNOPSIS
    Exports any built-in Intune report (Devices, DeviceCompliance, DefenderAgents, update and app install status, ...) to CSV through the Graph export jobs API.
.DESCRIPTION
    Creates an export job with POST v1.0 /deviceManagement/reports/exportJobs for the requested report name, optional OData
    filter and column selection, polls the job every 10 seconds until it completes, downloads the resulting zip from the
    time-limited URL and extracts the CSV to -OutputPath. The same reports the Intune admin center exports are available,
    without scrolling or per-page limits. With -PassThru the CSV is imported and emitted to the pipeline.
.PARAMETER ReportName
    Name of the Intune report. Common names: Devices, DevicesWithInventory, DeviceCompliance, DeviceNonCompliance,
    DefenderAgents, UnhealthyDefenderAgents, ActiveMalware, FirewallStatus, MAMAppProtectionStatus, AppInvByDevice,
    AppInvRawData, FeatureUpdatePolicyFailuresAggregate, QualityUpdateDeviceStatusByPolicy (needs -Filter on PolicyId),
    DeviceInstallStatusByApp (needs -Filter on ApplicationId), UserInstallStatusAggregateByApp,
    DeviceRunStatesByProactiveRemediation (needs -Filter on PolicyId).
.PARAMETER Filter
    OData filter applied by the report, for example "(PolicyId eq '00000000-0000-0000-0000-000000000000')" or
    "(ComplianceState eq 'Noncompliant')". Some reports require a filter and fail without one.
.PARAMETER Select
    Report columns to include (report-specific names such as DeviceName, UPN, OSVersion). Default: every column.
.PARAMETER TimeoutMinutes
    How long to wait for the export job to complete before giving up. Default 15.
.PARAMETER OutputPath
    CSV file to create. Defaults to .\Reports\IntuneReport_<ReportName>_yyyyMMdd-HHmm.csv; the folder is created when missing.
.PARAMETER PassThru
    Import the downloaded CSV and emit its rows to the pipeline.
.EXAMPLE
    PS> .\Export-IntuneReport.ps1 -ReportName DevicesWithInventory
    Exports the full device inventory report (all columns) to .\Reports.
.EXAMPLE
    PS> .\Export-IntuneReport.ps1 -ReportName DeviceInstallStatusByApp -Filter "(ApplicationId eq '<app id>')" -Select DeviceName, UserName, InstallState -PassThru
    Exports the install status of one app with three columns and returns the rows for further filtering.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : DeviceManagementConfiguration.Read.All, DeviceManagementManagedDevices.Read.All, DeviceManagementApps.Read.All
                  (delegated) plus an Intune RBAC role with the matching read permissions
    Category    : Updates & remediations
    Changes     : No
    Notes       : Export jobs run asynchronously; large tenants may need several minutes and the finished zip can be downloaded
                  only until the job's expirationDateTime. Column names are report-specific - an invalid -Select or -Filter
                  makes the job fail. localizationType localizedValuesAsAdditionalColumn adds *_loc columns with display
                  text next to the raw enum values. The download URL is a pre-signed blob link and needs no Graph token.
.LINK
    https://learn.microsoft.com/graph/api/intune-reporting-devicemanagementexportjob-create
.LINK
    https://learn.microsoft.com/mem/intune/fundamentals/reports-export-graph-available-reports
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$ReportName,

    [Parameter()]
    [string]$Filter,

    [Parameter()]
    [string[]]$Select,

    [Parameter()]
    [ValidateRange(1, 180)]
    [int]$TimeoutMinutes = 15,

    [Parameter()]
    [string]$OutputPath,

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
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('IntuneReport_{0}_{1}.csv' -f $ReportName, (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if ([string]::IsNullOrWhiteSpace($outputFolder)) { $outputFolder = (Get-Location).ProviderPath }
if (-not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}
# .NET APIs resolve relative paths against the process directory, not the PowerShell location, so make the target absolute.
$OutputPath = Join-Path -Path (Resolve-Path -LiteralPath $outputFolder).ProviderPath -ChildPath (Split-Path -Path $OutputPath -Leaf)

$scopes = @('DeviceManagementConfiguration.Read.All', 'DeviceManagementManagedDevices.Read.All', 'DeviceManagementApps.Read.All')
try { Connect-GraphIfNeeded -Scopes $scopes } catch { throw "Failed to connect to Microsoft Graph: $($_.Exception.Message)" }

$jobsUri = 'https://graph.microsoft.com/v1.0/deviceManagement/reports/exportJobs'
$body = @{ reportName = $ReportName; format = 'csv'; localizationType = 'localizedValuesAsAdditionalColumn' }
if (-not [string]::IsNullOrWhiteSpace($Filter)) { $body['filter'] = $Filter }
if ($null -ne $Select -and $Select.Count -gt 0) { $body['select'] = @($Select) }
Write-Verbose ('Requesting export job: {0}' -f ($body | ConvertTo-Json -Compress))
try { $job = Invoke-MgGraphRequest -Method POST -Uri $jobsUri -Body ($body | ConvertTo-Json -Depth 5) -ContentType 'application/json' -OutputType PSObject -ErrorAction Stop }
catch { throw "Failed to create the export job for report '$ReportName': $($_.Exception.Message)" }
Write-Host ('Export job {0} created for report {1}; waiting for completion...' -f $job.id, $ReportName) -ForegroundColor Cyan

$deadline = (Get-Date).AddMinutes($TimeoutMinutes)
$started = Get-Date
while ($job.status -ne 'completed' -and $job.status -ne 'failed') {
    if ((Get-Date) -gt $deadline) {
        throw "Export job $($job.id) did not complete within $TimeoutMinutes minutes (last status: $($job.status)). Increase -TimeoutMinutes or retry later."
    }
    Start-Sleep -Seconds 10
    $elapsed = [int]((Get-Date) - $started).TotalSeconds
    $percent = [int][Math]::Min(95, ($elapsed / ($TimeoutMinutes * 60)) * 100)
    Write-Progress -Activity ('Exporting Intune report {0}' -f $ReportName) -Status ('Status: {0} - {1}s elapsed' -f $job.status, $elapsed) -PercentComplete $percent
    # A transient poll failure should not abandon a job that is still running server-side.
    try { $job = Invoke-MgGraphRequest -Method GET -Uri ('{0}/{1}' -f $jobsUri, $job.id) -OutputType PSObject -ErrorAction Stop }
    catch { Write-Warning ('Polling export job {0} failed, retrying: {1}' -f $job.id, $_.Exception.Message) }
    Write-Verbose ('Job {0} status: {1}' -f $job.id, $job.status)
}
Write-Progress -Activity ('Exporting Intune report {0}' -f $ReportName) -Completed
if ($job.status -eq 'failed' -or [string]::IsNullOrEmpty($job.url)) {
    throw "Export job $($job.id) for report '$ReportName' failed. Check that the report name, -Filter and -Select column names are valid."
}

Add-Type -AssemblyName System.IO.Compression.FileSystem
$tempZip = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath ('IntuneReport_{0}.zip' -f $job.id)
$zip = $null
try {
    Write-Verbose ('Downloading {0}' -f $tempZip)
    Invoke-WebRequest -Uri $job.url -OutFile $tempZip -UseBasicParsing -ErrorAction Stop
    $zip = [System.IO.Compression.ZipFile]::OpenRead($tempZip)
    $entry = $zip.Entries | Where-Object { $_.Name -like '*.csv' } | Select-Object -First 1
    if ($null -eq $entry) { throw 'The downloaded archive does not contain a CSV file.' }
    [System.IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $OutputPath, $true)
}
catch {
    throw "Failed to download or extract the report: $($_.Exception.Message)"
}
finally {
    if ($null -ne $zip) { $zip.Dispose() }
    if (Test-Path -LiteralPath $tempZip) { Remove-Item -LiteralPath $tempZip -Force -ErrorAction SilentlyContinue }
}

$rows = @(Import-Csv -LiteralPath $OutputPath -Encoding UTF8)
Write-Host ''
Write-Host ('Report {0}: {1} rows exported in {2:N0} seconds.' -f $ReportName, $rows.Count, ((Get-Date) - $started).TotalSeconds) -ForegroundColor Cyan
Write-Host ('Report written to {0}' -f $OutputPath) -ForegroundColor Green

if ($PassThru) { $rows }
#endregion Main
