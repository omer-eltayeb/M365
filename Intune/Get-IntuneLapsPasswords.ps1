<#
.SYNOPSIS
    Reports Windows LAPS password backups in Entra ID, flags stale or overdue backups and optionally retrieves the current local administrator password.
.DESCRIPTION
    Lists deviceLocalCredentialInfo objects from Microsoft Graph v1.0 (/directory/deviceLocalCredentials) with the last
    backup and next refresh time of every device whose Windows LAPS password is backed up to Entra ID. Backups older than
    -MaxAgeDays are flagged as StaleBackup and devices past their refreshDateTime as RotationOverdue. With -IncludePasswords
    the newest credential of each device is read (.../deviceLocalCredentials/{id}?$select=credentials) and decoded. Exports to CSV.
.PARAMETER DeviceName
    One or more wildcard patterns matched against the device name, for example 'LT-FIN-*', 'DT-0042'.
.PARAMETER MaxAgeDays
    Backups older than this many days are flagged as stale. Default 60.
.PARAMETER OnlyStale
    Report only devices whose backup is stale or whose rotation is overdue.
.PARAMETER IncludePasswords
    Also retrieve the current local administrator password. Requires -DeviceName and DeviceLocalCredential.Read.All; every read is audited.
.PARAMETER OutputPath
    CSV file to create. Defaults to .\Reports\IntuneLapsPasswords_yyyyMMdd-HHmm.csv; the folder is created when missing.
.PARAMETER PassThru
    Also emit the report objects to the pipeline.
.EXAMPLE
    PS> .\Get-IntuneLapsPasswords.ps1 -OnlyStale -MaxAgeDays 45
    Lists devices whose LAPS backup is older than 45 days or whose scheduled rotation has not happened.
.EXAMPLE
    PS> .\Get-IntuneLapsPasswords.ps1 -DeviceName 'LT-0042' -IncludePasswords -PassThru | Select-Object DeviceName, AccountName, Password
    Retrieves the current local administrator password of one device for a support call; the read is logged in the Entra ID audit log.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : DeviceLocalCredential.ReadBasic.All; DeviceLocalCredential.Read.All only with -IncludePasswords (delegated).
    Category    : Devices & remote actions
    Changes     : No
    Notes       : Only devices with the Windows LAPS policy "Backup directory = Microsoft Entra ID" appear. Listing needs a role such
                  as Helpdesk Administrator, Security Reader or Intune Administrator; reading passwords needs Cloud Device
                  Administrator or Intune Administrator and is recorded in the Entra ID audit log. With -IncludePasswords the CSV
                  holds clear-text passwords: protect and delete it after use. One Graph call per device with a 200 ms pause. Dates are UTC.
.LINK
    https://learn.microsoft.com/graph/api/directory-list-devicelocalcredentials
.LINK
    https://learn.microsoft.com/graph/api/devicelocalcredentialinfo-get
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [Parameter()]
    [string[]]$DeviceName,

    [Parameter()]
    [ValidateRange(1, 3650)]
    [int]$MaxAgeDays = 60,

    [Parameter()]
    [switch]$OnlyStale,

    [Parameter()]
    [switch]$IncludePasswords,

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

function ConvertTo-UtcDateTime {
    <# Converts a Graph date value (string or DateTime) to a UTC [datetime]; $null for empty values or the 0001-01-01 placeholder. #>
    param([object]$Value)
    if ([string]::IsNullOrWhiteSpace([string]$Value)) { return $null }
    try { $parsed = ([datetime]$Value).ToUniversalTime() } catch { return $null }
    if ($parsed.Year -le 1) { return $null }
    return $parsed
}

function ConvertFrom-LapsPassword {
    <# Decodes passwordBase64. The service has returned both UTF-16LE and UTF-8; UTF-16LE text contains zero bytes, UTF-8 text never does. #>
    param([string]$PasswordBase64)
    if ([string]::IsNullOrEmpty($PasswordBase64)) { return $null }
    $bytes = [Convert]::FromBase64String($PasswordBase64)
    if ($bytes -contains 0) { return [System.Text.Encoding]::Unicode.GetString($bytes) }
    return [System.Text.Encoding]::UTF8.GetString($bytes)
}
#endregion Helpers

#region Main
$hasDeviceName = ($null -ne $DeviceName -and @($DeviceName | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }).Count -gt 0)
if ($IncludePasswords -and -not $hasDeviceName) { throw '-IncludePasswords requires -DeviceName so that passwords are only retrieved for specific devices.' }
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('IntuneLapsPasswords_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}

$scopes = @('DeviceLocalCredential.ReadBasic.All')
if ($IncludePasswords) { $scopes += 'DeviceLocalCredential.Read.All' }
try { Connect-GraphIfNeeded -Scopes $scopes } catch { throw "Failed to connect to Microsoft Graph: $($_.Exception.Message)" }

$graphV1 = 'https://graph.microsoft.com/v1.0'
try { $credentialInfos = @(Invoke-GraphPaged -Uri ($graphV1 + '/directory/deviceLocalCredentials?$select=id,deviceName,lastBackupDateTime,refreshDateTime')) }
catch { throw "Failed to list LAPS password backups: $($_.Exception.Message)" }
Write-Verbose ('{0} devices have a LAPS password backed up to Entra ID.' -f $credentialInfos.Count)
if ($hasDeviceName) { $credentialInfos = @($credentialInfos | Where-Object { $name = $_.deviceName; @($DeviceName | Where-Object { $name -like $_ }).Count -gt 0 }) }
if ($IncludePasswords -and $credentialInfos.Count -gt 0) {
    Write-Warning ('Reading the local administrator password of {0} device(s); each read is audited in Entra ID and the output holds clear-text passwords.' -f $credentialInfos.Count)
}

$now = (Get-Date).ToUniversalTime()
$report = New-Object -TypeName System.Collections.Generic.List[object]; $index = 0
foreach ($info in $credentialInfos) {
    $index++
    $lastBackup = ConvertTo-UtcDateTime -Value $info.lastBackupDateTime; $refresh = ConvertTo-UtcDateTime -Value $info.refreshDateTime
    $ageDays = $null; $stale = $null
    if ($null -ne $lastBackup) { $ageDays = [int][math]::Floor(($now - $lastBackup).TotalDays); $stale = ($ageDays -gt $MaxAgeDays) }
    $overdue = ($null -ne $refresh -and $refresh -lt $now)
    if ($OnlyStale -and -not $stale -and -not $overdue) { continue }

    $accountName = $null; $passwordBackup = $null; $password = $null
    if ($IncludePasswords) {
        Write-Progress -Activity 'Reading LAPS passwords' -Status ('{0} of {1}' -f $index, $credentialInfos.Count) -PercentComplete ([int](($index / $credentialInfos.Count) * 100))
        try {
            $detail = Invoke-MgGraphRequest -Method GET -Uri ('{0}/directory/deviceLocalCredentials/{1}?$select=credentials' -f $graphV1, $info.id) -OutputType PSObject -ErrorAction Stop
            # Several credentials are kept after rotations; the newest backup is the password currently set on the device.
            $newest = @($detail.credentials) | Sort-Object -Property { ConvertTo-UtcDateTime -Value $_.backupDateTime } -Descending | Select-Object -First 1
            if ($null -ne $newest) {
                $accountName = $newest.accountName; $passwordBackup = ConvertTo-UtcDateTime -Value $newest.backupDateTime
                $password = ConvertFrom-LapsPassword -PasswordBase64 $newest.passwordBase64
            }
        }
        catch { Write-Warning ('Failed to read the password of {0}: {1}' -f $info.deviceName, $_.Exception.Message) }
        Start-Sleep -Milliseconds 200
    }
    $report.Add([PSCustomObject]@{
            DeviceName             = $info.deviceName
            DeviceId               = $info.id
            LastBackupDateTime     = $lastBackup
            BackupAgeDays          = $ageDays
            StaleBackup            = $stale
            RefreshDateTime        = $refresh
            RotationOverdue        = $overdue
            AccountName            = $accountName
            PasswordBackupDateTime = $passwordBackup
            Password               = $password
        })
}
Write-Progress -Activity 'Reading LAPS passwords' -Completed

if ($report.Count -eq 0) { Write-Warning 'No LAPS password backups matched the selection; no CSV file was written.' }
else {
    $report | Sort-Object -Property DeviceName | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
    Write-Host ('Report written to {0}' -f $OutputPath) -ForegroundColor Green
}

Write-Host ''
Write-Host ('Devices with a LAPS backup / reported : {0} / {1}' -f $credentialInfos.Count, $report.Count) -ForegroundColor Cyan
Write-Host ('Stale backups (older than {0} days)   : {1}' -f $MaxAgeDays, @($report | Where-Object { $_.StaleBackup -eq $true }).Count) -ForegroundColor Yellow
Write-Host ('Rotation overdue                      : {0}' -f @($report | Where-Object { $_.RotationOverdue -eq $true }).Count) -ForegroundColor Yellow

if ($PassThru) { $report }
#endregion Main
