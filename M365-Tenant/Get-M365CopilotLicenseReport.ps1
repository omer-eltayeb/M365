<#
.SYNOPSIS
    Reports Microsoft 365 Copilot license consumption, every licensed user and, optionally, their Copilot usage per app.
.DESCRIPTION
    Detects Copilot SKUs in /subscribedSkus (part number containing Copilot or any M365_COPILOT_* service plan), prints their
    consumption and lists every user holding one (/users filtered on assignedLicenses) with the assignment path from
    licenseAssignmentStates and the last interactive sign-in (signInActivity). With -IncludeUsage it downloads the beta report
    getMicrosoft365CopilotUsageUserDetail, joins it by UPN and adds per-app last activity, DaysSinceLastCopilotActivity and IsInactive.
.PARAMETER IncludeUsage
    Download the Copilot usage report (beta, Reports.Read.All) and join it to the licensed users.
.PARAMETER DaysInactive
    Days without any Copilot activity after which a licensed user is flagged IsInactive. Default 30 (report period D30/D90/D180).
.PARAMETER OutputPath
    Path of the CSV file. Defaults to .\Reports\M365CopilotLicenses_<timestamp>.csv.
.PARAMETER PassThru
    Also emit the user objects to the pipeline.
.EXAMPLE
    PS> .\Get-M365CopilotLicenseReport.ps1
    Prints Copilot SKU consumption and exports all Copilot-licensed users with assignment path and last sign-in.
.EXAMPLE
    PS> .\Get-M365CopilotLicenseReport.ps1 -IncludeUsage -DaysInactive 45 -OutputPath C:\Temp\Copilot.csv
    Adds per-app usage from the last 90 days and flags users without Copilot activity for 45 days as reclaim candidates.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : Organization.Read.All, User.Read.All, AuditLog.Read.All (delegated); -IncludeUsage adds Reports.Read.All. Global Reader.
    Category    : Licensing
    Changes     : No
    Notes       : Beta report endpoint: columns change over time and missing ones read as empty. signInActivity needs Entra ID P1
                  and is skipped when Graph refuses it. If "Display concealed user, group, and site names in all reports" is on
                  (Microsoft 365 admin center > Settings > Org settings > Reports), names are hashed and the UPN join matches nobody.
.LINK
    https://learn.microsoft.com/graph/api/reportroot-getmicrosoft365copilotusageuserdetail?view=graph-rest-beta
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [Parameter()]
    [switch]$IncludeUsage,

    [Parameter()]
    [ValidateRange(1, 180)]
    [int]$DaysInactive = 30,

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
    <# Normalises a Graph date value (ISO 8601 string or [datetime]) to a UTC [datetime]; $null when empty or unparseable. #>
    param([Parameter()][AllowNull()]$Value)
    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) { return $null }
    if ($Value -is [datetime]) { if ($Value.Kind -eq 'Local') { return $Value.ToUniversalTime() }; return [datetime]::SpecifyKind($Value, 'Utc') }
    $parsed = [datetime]::MinValue
    if ([datetime]::TryParse([string]$Value, [System.Globalization.CultureInfo]::InvariantCulture, 'AssumeUniversal, AdjustToUniversal', [ref]$parsed)) { return $parsed }
    return $null
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('M365CopilotLicenses_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}
$scopes = @('Organization.Read.All', 'User.Read.All', 'AuditLog.Read.All')
if ($IncludeUsage) { $scopes += 'Reports.Read.All' }
try { Connect-GraphIfNeeded -Scopes $scopes }
catch { throw "Failed to connect to Microsoft Graph: $($_.Exception.Message)" }
try { $skus = @(Invoke-GraphPaged -Uri 'https://graph.microsoft.com/v1.0/subscribedSkus?$select=skuId,skuPartNumber,prepaidUnits,consumedUnits,servicePlans') }
catch { throw "Failed to read subscribed SKUs: $($_.Exception.Message)" }
$skuNameById = @{}
foreach ($sku in $skus) {
    $hasCopilotPlan = @($sku.servicePlans | Where-Object { $_.servicePlanName -like 'M365_COPILOT*' }).Count -gt 0
    if ($hasCopilotPlan -or ($sku.skuPartNumber -like '*Copilot*' -and $sku.skuPartNumber -notlike '*Copilot_Studio*')) { $skuNameById[[string]$sku.skuId] = [string]$sku.skuPartNumber }
}
if ($skuNameById.Count -eq 0) { Write-Warning 'No Microsoft 365 Copilot SKU was found in /subscribedSkus.'; return }
$copilotSkus = @($skus | Where-Object { $skuNameById.ContainsKey([string]$_.skuId) })
$userFilter = (@($skuNameById.Keys | ForEach-Object { 'assignedLicenses/any(s:s/skuId eq {0})' -f $_ }) -join ' or ')
$userSelect = 'id,displayName,userPrincipalName,accountEnabled,assignedLicenses,licenseAssignmentStates,signInActivity'
$usersUri = 'https://graph.microsoft.com/v1.0/users?$filter={0}&$count=true&$top=999&$select={1}' -f $userFilter, $userSelect
try { $users = @(Invoke-GraphPaged -Uri $usersUri -Headers @{ ConsistencyLevel = 'eventual' }) }
catch {
    # Graph answers 403/400 for signInActivity without Entra ID P1 or without the AuditLog scope; retry without the property.
    Write-Warning "Sign-in activity is not available ($($_.Exception.Message)); retrying without it."
    try { $users = @(Invoke-GraphPaged -Uri $usersUri.Replace(',signInActivity', '') -Headers @{ ConsistencyLevel = 'eventual' }) }
    catch { throw "Failed to list Copilot-licensed users: $($_.Exception.Message)" }
}
$usageByUpn = @{}
if ($IncludeUsage) {
    $period = $(if ($DaysInactive -le 30) { 'D30' } elseif ($DaysInactive -le 90) { 'D90' } else { 'D180' })
    # beta: the Copilot usage report has no v1.0 equivalent yet. Graph redirects to a CSV, downloaded to a temp file.
    $reportUri = "https://graph.microsoft.com/beta/reports/getMicrosoft365CopilotUsageUserDetail(period='$period')?`$format=text/csv"
    $tempCsv = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath ('GraphReport_{0}.csv' -f [guid]::NewGuid().ToString('N'))
    try {
        Invoke-MgGraphRequest -Method GET -Uri $reportUri -OutputFilePath $tempCsv -ErrorAction Stop
        foreach ($line in @(Import-Csv -Path $tempCsv -Encoding UTF8)) { $usageByUpn[([string]$line.'User Principal Name').ToLower()] = $line }
    }
    catch { Write-Warning "The Copilot usage report could not be downloaded ($($_.Exception.Message)); usage columns will be empty."; $IncludeUsage = $false }
    finally { if (Test-Path -Path $tempCsv) { Remove-Item -Path $tempCsv -Force -ErrorAction SilentlyContinue } }
}
# Report column per app. A column missing from the CSV simply reads as $null, so schema changes do not break the script.
$usageColumns = [ordered]@{
    CopilotChat = 'Copilot Chat Last Activity Date'; Teams = 'Microsoft Teams Copilot Last Activity Date'; Word = 'Word Copilot Last Activity Date'
    Excel = 'Excel Copilot Last Activity Date'; PowerPoint = 'PowerPoint Copilot Last Activity Date'; Outlook = 'Outlook Copilot Last Activity Date'
    OneNote = 'OneNote Copilot Last Activity Date'; Loop = 'Loop Copilot Last Activity Date'
}
$nowUtc = [datetime]::UtcNow
$rows = New-Object -TypeName System.Collections.Generic.List[object]
$counter = 0
foreach ($user in $users) {
    $counter++
    if ($counter % 100 -eq 0) { Write-Progress -Activity 'Shaping Copilot-licensed users' -Status "$counter of $($users.Count)" -PercentComplete ([int](($counter / $users.Count) * 100)) }
    $states = @($user.licenseAssignmentStates | Where-Object { $skuNameById.ContainsKey([string]$_.skuId) })
    $groupStates = @($states | Where-Object { -not [string]::IsNullOrEmpty($_.assignedByGroup) }).Count
    $path = 'Direct'
    if ($groupStates -gt 0 -and $groupStates -eq $states.Count) { $path = 'Group' } elseif ($groupStates -gt 0) { $path = 'Both' }
    $lastSignIn = ConvertTo-UtcDateTime -Value $user.signInActivity.lastSignInDateTime
    $usage = $usageByUpn[([string]$user.userPrincipalName).ToLower()]
    $appDates = @{}
    foreach ($app in $usageColumns.Keys) { $appDates[$app] = ConvertTo-UtcDateTime -Value $usage.($usageColumns[$app]) }
    $lastCopilot = @(@($appDates.Values) + @(ConvertTo-UtcDateTime -Value $usage.'Last Activity Date') | Where-Object { $null -ne $_ } | Sort-Object -Descending)[0]
    $daysSince = $null; $isInactive = $null
    if ($null -ne $lastCopilot) { $daysSince = [int](($nowUtc - $lastCopilot).TotalDays) }
    if ($IncludeUsage) { $isInactive = ($null -eq $daysSince -or $daysSince -ge $DaysInactive) }
    $row = [PSCustomObject]@{
        UserPrincipalName            = $user.userPrincipalName
        DisplayName                  = $user.displayName
        AccountEnabled               = [bool]$user.accountEnabled
        CopilotSku                   = (@($user.assignedLicenses | Where-Object { $skuNameById.ContainsKey([string]$_.skuId) } | ForEach-Object { $skuNameById[[string]$_.skuId] }) -join ';')
        AssignmentPath               = $path
        LastSignInDateTime           = $lastSignIn
        LastCopilotActivity          = $lastCopilot
        DaysSinceLastCopilotActivity = $daysSince
        IsInactive                   = $isInactive
    }
    foreach ($app in $usageColumns.Keys) { $row | Add-Member -NotePropertyName ('{0}CopilotLastActivity' -f $app) -NotePropertyValue $appDates[$app] }
    $rows.Add($row)
}
Write-Progress -Activity 'Shaping Copilot-licensed users' -Completed
$output = @($rows | Sort-Object -Property @{ Expression = 'IsInactive'; Descending = $true }, UserPrincipalName)
$output | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
Write-Host 'Microsoft 365 Copilot license summary' -ForegroundColor Cyan
foreach ($sku in $copilotSkus) { Write-Host ('  {0,-34} enabled {1,6}  consumed {2,6}' -f $sku.skuPartNumber, [int]$sku.prepaidUnits.enabled, [int]$sku.consumedUnits) }
Write-Host ('  Licensed users                : {0} ({1} disabled accounts)' -f $output.Count, @($output | Where-Object { -not $_.AccountEnabled }).Count)
if ($IncludeUsage -and $output.Count -gt 0) {
    $active = @($output | Where-Object { -not $_.IsInactive })
    Write-Host ('  Active in the last {0,3} days   : {1} ({2}%)' -f $DaysInactive, $active.Count, [math]::Round(($active.Count / $output.Count) * 100, 1))
    Write-Host ('  Inactive (reclaim candidates) : {0}' -f ($output.Count - $active.Count)) -ForegroundColor Yellow
    foreach ($app in $usageColumns.Keys) {
        Write-Host ('    {0,-12} users with activity : {1,6}' -f $app, @($output | Where-Object { $null -ne $_.('{0}CopilotLastActivity' -f $app) }).Count)
    }
}
Write-Host ('  CSV                           : {0}' -f $OutputPath)
if ($PassThru) { $output }
#endregion Main
