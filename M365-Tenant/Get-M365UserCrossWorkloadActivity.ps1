<#
.SYNOPSIS
    Finds truly inactive users by combining Entra sign-in activity with the last Exchange, OneDrive, SharePoint, Teams and Viva Engage activity.
.DESCRIPTION
    Reads every member user from /users (with signInActivity when the tenant has Entra ID P1 and the scope is granted) and
    downloads the usage report /reports/getOffice365ActiveUserDetail(period='D90') that carries the last activity date per
    workload. Both are joined on the UPN into one row per user with LastSignIn, LastExchange, LastOneDrive, LastSharePoint,
    LastTeams, LastYammer, LastAnyActivity (the latest of all), DaysSinceAnyActivity and a Classification: Active, Inactive
    (no activity for more than -DaysInactive days), NeverActive (older account without any activity) or New (young account
    without activity). Exports CSV and prints a summary with the licenses that inactive users still hold.
.PARAMETER DaysInactive
    Days without any activity after which a user is Inactive. Default 90; should not exceed the days covered by -Period.
.PARAMETER Period
    Usage report window: D7, D30, D90 or D180. Default D90.
.PARAMETER OnlyInactive
    Export only Inactive and NeverActive users.
.PARAMETER OutputPath
    Path of the CSV file. Defaults to .\Reports\M365UserCrossWorkloadActivity_<timestamp>.csv.
.PARAMETER PassThru
    Also emit the user objects to the pipeline.
.EXAMPLE
    PS> .\Get-M365UserCrossWorkloadActivity.ps1
    Classifies every member user over the last 90 days and prints how many licenses sit on inactive accounts.
.EXAMPLE
    PS> .\Get-M365UserCrossWorkloadActivity.ps1 -DaysInactive 180 -Period D180 -OnlyInactive -OutputPath C:\Temp\Inactive.csv
    Exports only users without any activity in the last 180 days.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : User.Read.All, AuditLog.Read.All, Reports.Read.All, Organization.Read.All (delegated); Global Reader or
                  Reports Reader plus User Administrator can run it.
    Category    : User lifecycle & tenant hygiene
    Changes     : No
    Notes       : signInActivity needs Entra ID P1; without it the script continues with the usage report only. If the setting
                  "Display concealed user, group, and site names in all reports" is on (Microsoft 365 admin center > Settings >
                  Org settings > Reports) the report shows hashed UPNs and nothing can be joined - the script warns about it.
                  Report data lags about 48 hours behind. Users who never signed in are only NeverActive once the account is
                  older than -DaysInactive days.
.LINK
    https://learn.microsoft.com/graph/api/reportroot-getoffice365activeuserdetail
.LINK
    https://learn.microsoft.com/graph/api/resources/signinactivity
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateRange(1, 3650)]
    [int]$DaysInactive = 90,

    [Parameter()]
    [ValidateSet('D7', 'D30', 'D90', 'D180')]
    [string]$Period = 'D90',

    [Parameter()]
    [switch]$OnlyInactive,

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

function ConvertTo-DateTimeOrNull {
    <# Normalises a Graph or report date (ISO string, yyyy-MM-dd or [datetime]) to a UTC [datetime]; $null when empty. #>
    param([AllowNull()] $Value)
    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) { return $null }
    if ($Value -is [datetime]) {
        if ($Value.Kind -eq [System.DateTimeKind]::Unspecified) { return [datetime]::SpecifyKind($Value, [System.DateTimeKind]::Utc) }
        return $Value.ToUniversalTime()
    }
    $parsed = [datetime]::MinValue
    $styles = [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal
    if ([datetime]::TryParse([string]$Value, [System.Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$parsed)) { return $parsed }
    return $null
}

function Get-LatestDate {
    <# Returns the latest non-empty date among the values, or $null. #>
    param([AllowNull()] [object[]]$Values)
    $dates = @(foreach ($value in $Values) { $parsed = ConvertTo-DateTimeOrNull -Value $value; if ($null -ne $parsed) { $parsed } })
    if ($dates.Count -eq 0) { return $null }
    return ($dates | Sort-Object -Descending | Select-Object -First 1)
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('M365UserCrossWorkloadActivity_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}
if ($DaysInactive -gt [int]$Period.Substring(1)) { Write-Warning "-DaysInactive $DaysInactive exceeds the $Period report window; workload dates older than the window are not reported." }

$scopes = @('User.Read.All', 'AuditLog.Read.All', 'Reports.Read.All', 'Organization.Read.All')
try { Connect-GraphIfNeeded -Scopes $scopes } catch { throw "Could not connect to Microsoft Graph: $($_.Exception.Message)" }
$graphBase = 'https://graph.microsoft.com/v1.0'

$skuNames = @{}
foreach ($sku in (Invoke-GraphPaged -Uri "$graphBase/subscribedSkus?`$select=skuId,skuPartNumber")) { $skuNames[[string]$sku.skuId] = $sku.skuPartNumber }

$userSelect = 'id,displayName,userPrincipalName,accountEnabled,createdDateTime,assignedLicenses'
$hasSignIn = $true
try { $users = Invoke-GraphPaged -Uri "$graphBase/users?`$filter=userType eq 'Member'&`$select=$userSelect,signInActivity" }
catch {
    # Typical causes: no Entra ID P1 license or AuditLog.Read.All not consented; the usage report still gives workload dates.
    Write-Warning "signInActivity is not available, continuing without sign-in dates: $($_.Exception.Message)"
    $hasSignIn = $false
    $users = Invoke-GraphPaged -Uri "$graphBase/users?`$filter=userType eq 'Member'&`$select=$userSelect"
}

$usage = @{}
$tempCsv = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath ('ActiveUserDetail_{0}.csv' -f [guid]::NewGuid())
try {
    Invoke-MgGraphRequest -Method GET -Uri "$graphBase/reports/getOffice365ActiveUserDetail(period='$Period')" -OutputFilePath $tempCsv -ErrorAction Stop
    foreach ($row in (Import-Csv -Path $tempCsv)) { $usage[([string]$row.'User Principal Name').ToLowerInvariant()] = $row }
}
catch { Write-Warning "Usage report could not be downloaded, workload dates will be empty: $($_.Exception.Message)" }
finally { if (Test-Path -Path $tempCsv) { Remove-Item -Path $tempCsv -Force -ErrorAction SilentlyContinue } }
Write-Verbose "Member users: $($users.Count) (sign-in activity: $hasSignIn); usage report rows: $($usage.Count)."

$now = (Get-Date).ToUniversalTime()
$cutoff = $now.AddDays(-$DaysInactive)
$matched = 0
$index = 0
$rows = foreach ($user in $users) {
    $index++
    if ($index % 200 -eq 0) { Write-Progress -Activity 'Evaluating users' -Status "$index of $($users.Count)" -PercentComplete (($index / $users.Count) * 100) }
    $report = $usage[([string]$user.userPrincipalName).ToLowerInvariant()]
    if ($null -ne $report) { $matched++ }
    $lastSignIn = Get-LatestDate -Values @($user.signInActivity.lastSignInDateTime, $user.signInActivity.lastNonInteractiveSignInDateTime)
    $lastExchange = ConvertTo-DateTimeOrNull -Value $report.'Exchange Last Activity Date'
    $lastOneDrive = ConvertTo-DateTimeOrNull -Value $report.'OneDrive Last Activity Date'
    $lastSharePoint = ConvertTo-DateTimeOrNull -Value $report.'SharePoint Last Activity Date'
    $lastTeams = ConvertTo-DateTimeOrNull -Value $report.'Teams Last Activity Date'
    $lastYammer = ConvertTo-DateTimeOrNull -Value $report.'Yammer Last Activity Date'
    $lastAny = Get-LatestDate -Values @($lastSignIn, $lastExchange, $lastOneDrive, $lastSharePoint, $lastTeams, $lastYammer)
    $created = ConvertTo-DateTimeOrNull -Value $user.createdDateTime
    $days = if ($null -ne $lastAny) { [int][math]::Floor(($now - $lastAny).TotalDays) } else { $null }
    $classification = 'NeverActive'
    if ($null -ne $lastAny) { $classification = if ($lastAny -ge $cutoff) { 'Active' } else { 'Inactive' } }
    elseif ($null -ne $created -and $created -ge $cutoff) { $classification = 'New' }
    $licenses = @($user.assignedLicenses | ForEach-Object { $id = [string]$_.skuId; if ($skuNames.ContainsKey($id)) { $skuNames[$id] } else { $id } })
    [PSCustomObject]@{
        UserPrincipalName    = $user.userPrincipalName
        DisplayName          = $user.displayName
        AccountEnabled       = $user.accountEnabled
        CreatedDateTime      = $created
        LicenseCount         = $licenses.Count
        Licenses             = ($licenses -join ';')
        LastSignIn           = $lastSignIn
        LastExchange         = $lastExchange
        LastOneDrive         = $lastOneDrive
        LastSharePoint       = $lastSharePoint
        LastTeams            = $lastTeams
        LastYammer           = $lastYammer
        LastAnyActivity      = $lastAny
        DaysSinceAnyActivity = $days
        Classification       = $classification
    }
}
Write-Progress -Activity 'Evaluating users' -Completed
if ($usage.Count -gt 0 -and $matched -eq 0) {
    Write-Warning 'No user could be matched to the usage report. Check whether concealed names are enabled in the reports settings.'
}

$inactive = @($rows | Where-Object { $_.Classification -in 'Inactive', 'NeverActive' })
$output = if ($OnlyInactive) { $inactive } else { @($rows) }
$output | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

$reclaimable = @($inactive | Where-Object { $_.LicenseCount -gt 0 })
$licenseTotal = ($reclaimable | Measure-Object -Property LicenseCount -Sum).Sum
$summary = $rows | Group-Object -Property Classification | Sort-Object -Property Name | ForEach-Object { '{0}: {1}' -f $_.Name, $_.Count }
Write-Host ("Member users: {0}  {1}" -f @($rows).Count, ($summary -join '  ')) -ForegroundColor Cyan
Write-Host ("Potentially reclaimable licenses: {0} on {1} inactive licensed users" -f [int]$licenseTotal, $reclaimable.Count) -ForegroundColor Yellow
$reclaimable | ForEach-Object { $_.Licenses -split ';' } | Group-Object | Sort-Object -Property Count -Descending | Select-Object -First 5 |
    ForEach-Object { Write-Host ('  {0,5}  {1}' -f $_.Count, $_.Name) -ForegroundColor Yellow }
Write-Host "Report: $OutputPath" -ForegroundColor Cyan
if ($PassThru) { $output }
#endregion Main
