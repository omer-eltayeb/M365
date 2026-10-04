<#
.SYNOPSIS
    Reports the vulnerabilities (CVEs) found on devices by Microsoft Defender Vulnerability Management, per device or aggregated per CVE.
.DESCRIPTION
    Reads GET /vulnerabilities/machinesVulnerabilities from the Defender for Endpoint API (filtered server-side on -Severity and on the
    machine ids matching -DeviceName) and joins each finding with the cached device inventory (GET /machines) for name and OS platform.
    -IncludeCveDetails adds CVSS, exploit status, exposure and dates from GET /vulnerabilities/{cveId} (read once per CVE); -OnlyWithKb
    keeps findings a KB fixes; -Summary aggregates per CVE with affected devices, products and fixing KBs.
.PARAMETER TenantId
    Directory (tenant) ID or verified domain of the tenant that hosts the app registration.
.PARAMETER AppCredential
    PSCredential whose user name is the application (client) ID and whose password is the client secret.
.PARAMETER Severity
    Only return findings of this severity: Low, Medium, High or Critical.
.PARAMETER DeviceName
    One or more device names; matched on computerDnsName exactly or as a prefix (so a short host name works).
.PARAMETER OnlyWithKb
    Only return findings for which Defender knows a fixing KB (patchable through Windows Update / WSUS / Intune).
.PARAMETER IncludeCveDetails
    Reads the CVE details (cvssV3, exploitVerified, publicExploit, exposedMachines, publishedOn, updatedOn, description) for every distinct CVE.
.PARAMETER Summary
    Exports one row per CVE (AffectedDevices, Products, FixingKbIds and the CVE details) instead of one row per device and product.
.PARAMETER OutputPath
    Path of the CSV report. Defaults to .\Reports\MDEMachineVulnerabilities_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emits the report objects to the pipeline.
.EXAMPLE
    PS> .\Get-MDEMachineVulnerabilities.ps1 -TenantId contoso.onmicrosoft.com -AppCredential $cred -Severity Critical -IncludeCveDetails -Summary
    Exports every critical CVE with the number of affected devices, the vulnerable products, fixing KBs and exploit status.
.EXAMPLE
    PS> .\Get-MDEMachineVulnerabilities.ps1 -TenantId contoso.onmicrosoft.com -AppCredential $cred -DeviceName 'SRV-SQL01' -OnlyWithKb -PassThru | Format-Table CveId, Severity, ProductName, FixingKbId
    Lists the patchable vulnerabilities of one server with the KB that fixes each of them.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x (REST calls only, no modules)
    Permissions : Application permissions Vulnerability.Read.All and Machine.Read.All granted with admin consent to an app registration.
    Category    : Defender for Endpoint API
    Changes     : No
    Notes       : Requires Defender for Endpoint Plan 2 or Defender Vulnerability Management. Without -Severity or -DeviceName the whole
                  organisation is downloaded (pages of 10,000 rows); -IncludeCveDetails adds one call per distinct CVE (150 ms pause). Dates are UTC.
.LINK
    https://learn.microsoft.com/defender-endpoint/api/get-all-vulnerabilities-by-machines
#>
#Requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$TenantId,

    [Parameter(Mandatory = $true)]
    [pscredential]$AppCredential,

    [Parameter()]
    [ValidateSet('Low', 'Medium', 'High', 'Critical')]
    [string]$Severity,

    [Parameter()]
    [string[]]$DeviceName,

    [Parameter()]
    [switch]$OnlyWithKb,

    [Parameter()]
    [switch]$IncludeCveDetails,

    [Parameter()]
    [switch]$Summary,

    [Parameter()]
    [string]$OutputPath,

    [Parameter()]
    [switch]$PassThru
)

$ErrorActionPreference = 'Stop'
$baseUri = 'https://api.securitycenter.microsoft.com/api'

#region Helpers
function Get-MdeAccessToken {
    <# Acquires an app-only token for the Defender for Endpoint API with the client-credentials flow. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TenantId,

        [Parameter(Mandatory = $true)]
        [pscredential]$AppCredential
    )
    $body = @{
        client_id     = $AppCredential.UserName
        client_secret = $AppCredential.GetNetworkCredential().Password
        scope         = 'https://api.securitycenter.microsoft.com/.default'
        grant_type    = 'client_credentials'
    }
    $tokenUri = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
    $response = Invoke-RestMethod -Method POST -Uri $tokenUri -Body $body -ContentType 'application/x-www-form-urlencoded' -ErrorAction Stop
    return $response.access_token
}

function Invoke-MdeRequest {
    <# Calls the Defender for Endpoint API; GET requests follow @odata.nextLink. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Token,

        [Parameter(Mandatory = $true)]
        [string]$Uri,

        [Parameter()]
        [ValidateSet('GET', 'POST', 'PATCH', 'DELETE')]
        [string]$Method = 'GET',

        [Parameter()]
        [object]$Body
    )
    $headers = @{ Authorization = "Bearer $Token"; 'Content-Type' = 'application/json' }
    if ($Method -ne 'GET') {
        $json = $null
        if ($null -ne $Body) { $json = $Body | ConvertTo-Json -Depth 10 }
        return Invoke-RestMethod -Method $Method -Uri $Uri -Headers $headers -Body $json -ErrorAction Stop
    }
    $results = New-Object -TypeName System.Collections.Generic.List[object]
    $nextLink = $Uri
    while (-not [string]::IsNullOrEmpty($nextLink)) {
        $response = Invoke-RestMethod -Method GET -Uri $nextLink -Headers $headers -ErrorAction Stop
        if ($null -ne $response.PSObject.Properties['value']) { foreach ($item in $response.value) { $results.Add($item) } }
        else { $results.Add($response) }
        $nextLink = $response.'@odata.nextLink'
    }
    return $results
}

function ConvertTo-UtcDateTime {
    <# Normalises an API date value (ISO 8601 string or [datetime]) to a UTC [datetime]; returns $null when empty. #>
    param([object]$Value)
    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) { return $null }
    if ($Value -is [datetime]) { return $Value.ToUniversalTime() }
    return [datetime]::Parse([string]$Value, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]'AssumeUniversal, AdjustToUniversal')
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('MDEMachineVulnerabilities_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}
try { $token = Get-MdeAccessToken -TenantId $TenantId -AppCredential $AppCredential }
catch { throw "Unable to acquire a Defender for Endpoint API token: $($_.Exception.Message)" }

try { $machines = @(Invoke-MdeRequest -Token $token -Uri "$baseUri/machines") }
catch { throw "Failed to read the device inventory: $($_.Exception.Message)" }
$machineCache = @{}; foreach ($machine in $machines) { $machineCache[[string]$machine.id] = $machine }
$filters = @($(if ([string]::IsNullOrEmpty($Severity)) { '' } else { "severity eq '$Severity'" }))
if (@($DeviceName).Count -gt 0) {
    $targets = @($machines | Where-Object { $machine = $_; @($DeviceName | Where-Object { $machine.computerDnsName -eq $_ -or $machine.computerDnsName -like "$_*" }).Count -gt 0 })
    if ($targets.Count -eq 0) { throw "No device matches $($DeviceName -join ', ')." }
    # One query per selected device keeps the download small; without -DeviceName the whole organisation is read in one paged query.
    $filters = @($targets | ForEach-Object { (@("machineId eq '$($_.id)'") + @($filters | Where-Object { $_ })) -join ' and ' })
}
$findings = New-Object -TypeName System.Collections.Generic.List[object]
foreach ($filter in $filters) {
    $uri = "$baseUri/vulnerabilities/machinesVulnerabilities"
    if (-not [string]::IsNullOrEmpty($filter)) { $uri = '{0}?$filter={1}' -f $uri, $filter }
    try { foreach ($item in @(Invoke-MdeRequest -Token $token -Uri $uri)) { $findings.Add($item) } }
    catch { throw "Failed to read the machine vulnerabilities: $($_.Exception.Message)" }
}
if ($OnlyWithKb) { $findings = @($findings | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_.fixingKbId) }) }

$cveCache = @{}; $cveIds = @($findings | ForEach-Object { [string]$_.cveId } | Sort-Object -Unique)
if ($IncludeCveDetails) {
    for ($i = 0; $i -lt $cveIds.Count; $i++) {
        Write-Progress -Activity 'Reading CVE details' -Status ('{0} of {1}: {2}' -f ($i + 1), $cveIds.Count, $cveIds[$i]) -PercentComplete ([int](($i + 1) / $cveIds.Count * 100))
        try { $cveCache[$cveIds[$i]] = @(Invoke-MdeRequest -Token $token -Uri "$baseUri/vulnerabilities/$($cveIds[$i])")[0] }
        catch { Write-Warning "CVE details for $($cveIds[$i]) could not be read: $($_.Exception.Message)" }
        Start-Sleep -Milliseconds 150
    }
    Write-Progress -Activity 'Reading CVE details' -Completed
}

$rows = @(foreach ($finding in ($findings | Sort-Object -Property @{ Expression = { $machineCache[[string]$_.machineId].computerDnsName } }, cveId)) {
        $machine = $machineCache[[string]$finding.machineId]; $cve = $cveCache[[string]$finding.cveId]
        [PSCustomObject]@{
            MachineId = $finding.machineId; ComputerDnsName = $machine.computerDnsName; OsPlatform = $machine.osPlatform; CveId = $finding.cveId
            Severity = $finding.severity; ProductVendor = $finding.productVendor; ProductName = $finding.productName; ProductVersion = $finding.productVersion
            FixingKbId = $finding.fixingKbId; CvssV3 = $cve.cvssV3; ExploitVerified = $cve.exploitVerified; PublicExploit = $cve.publicExploit
            ExposedMachines = $cve.exposedMachines; PublishedOn = ConvertTo-UtcDateTime -Value $cve.publishedOn; UpdatedOn = ConvertTo-UtcDateTime -Value $cve.updatedOn
            Description = $cve.description
        }
    })
$deviceCount = @($rows | ForEach-Object { $_.MachineId } | Sort-Object -Unique).Count
if ($Summary) {
    $rows = @(foreach ($group in ($rows | Group-Object -Property CveId | Sort-Object -Property Count -Descending)) {
            $first = $group.Group[0]
            $summaryRow = [ordered]@{ CveId = $group.Name; Severity = $first.Severity; AffectedDevices = @($group.Group | ForEach-Object { $_.MachineId } | Sort-Object -Unique).Count
                Products = (@($group.Group | ForEach-Object { '{0} {1}' -f $_.ProductVendor, $_.ProductName } | Sort-Object -Unique) -join '; ')
                FixingKbIds = (@($group.Group | ForEach-Object { $_.FixingKbId } | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | Sort-Object -Unique) -join ';') }
            foreach ($name in @('CvssV3', 'ExploitVerified', 'PublicExploit', 'ExposedMachines', 'PublishedOn', 'UpdatedOn', 'Description')) { $summaryRow[$name] = $first.$name }
            [PSCustomObject]$summaryRow
        })
}
if ($rows.Count -gt 0) { $rows | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 } else { Write-Warning 'No vulnerability matched the given filter; nothing was exported.' }

$bySeverity = @($findings | Group-Object -Property severity | Sort-Object -Property Count -Descending | ForEach-Object { '{0}={1}' -f $_.Name, $_.Count }) -join ', '
Write-Host ('Defender Vulnerability Management: {0} finding(s), {1} distinct CVE(s) on {2} device(s) (report: {3})' -f $findings.Count, $cveIds.Count, $deviceCount, $OutputPath) -ForegroundColor Cyan
Write-Host ('  By severity: {0}; with a fixing KB: {1}' -f $bySeverity, @($findings | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_.fixingKbId) }).Count) -ForegroundColor Green

if ($PassThru) { $rows }
#endregion Main
