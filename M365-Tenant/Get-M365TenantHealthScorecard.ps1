<#
.SYNOPSIS
    One-page tenant health scorecard: identity, security, device, license and service metrics rated Green, Amber or Red.
.DESCRIPTION
    Evaluates 13 metrics with Microsoft Graph v1.0 and rates each against a target: MFA registration and admins without MFA
    (/reports/authenticationMethods/userRegistrationDetails), Global Administrator count (/roleManagement/directory/roleAssignments),
    Secure Score (/security/secureScores), enabled Conditional Access policies and a legacy-authentication block
    (/identity/conditionalAccess/policies), security defaults, stale devices (/devices), inactive users and guests (/users),
    unassigned and wasted licenses (/subscribedSkus, /users), open service incidents (/admin/serviceAnnouncement/issues) and Intune
    compliance (/deviceManagement/managedDevices). Every metric runs in its own try/catch, so a missing permission gives a NoAccess
    row instead of an abort. Outputs Metric, Value, Target, Status, Detail rows to CSV and the console, optionally to a coloured
    HTML page and to a JSON history file for trend tracking.
.PARAMETER DaysInactive
    Days without sign-in after which users and devices count as stale. Default 90.
.PARAMETER HtmlPath
    Optional path of a one-page HTML scorecard with coloured status cells.
.PARAMETER JsonPath
    Optional JSON file; each run appends a timestamped snapshot so the metrics can be trended.
.PARAMETER OutputPath
    Path of the CSV file. Defaults to .\Reports\M365TenantHealthScorecard_<timestamp>.csv.
.PARAMETER PassThru
    Also emit the metric objects to the pipeline.
.EXAMPLE
    PS> .\Get-M365TenantHealthScorecard.ps1
    Prints the coloured scorecard and writes the CSV to the Reports folder.
.EXAMPLE
    PS> .\Get-M365TenantHealthScorecard.ps1 -HtmlPath C:\Reports\Scorecard.html -JsonPath C:\Reports\Scorecard-history.json
    Also writes an HTML page for management and appends the snapshot to the history file used for month-over-month trends.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : AuditLog.Read.All, RoleManagement.Read.Directory, SecurityEvents.Read.All, Policy.Read.All, Device.Read.All,
                  User.Read.All, Organization.Read.All, ServiceHealth.Read.All, DeviceManagementManagedDevices.Read.All,
                  Directory.Read.All (delegated); Global Reader plus Security Reader and Intune Read Only Operator cover them.
    Category    : User lifecycle & tenant hygiene
    Changes     : No
    Notes       : MFA registration details and signInActivity need Entra ID P1; Secure Score needs a Defender or Entra P1 workload.
                  Thresholds are opinionated defaults (for example 2-4 Global Administrators, 95 % MFA registration) - adjust
                  them in the Add-Metric calls to your policy. The Global Administrator count covers active assignments only.
.LINK
    https://learn.microsoft.com/graph/api/authenticationmethodsroot-list-userregistrationdetails
.LINK
    https://learn.microsoft.com/graph/api/security-list-securescores
.LINK
    https://learn.microsoft.com/graph/aad-advanced-queries
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateRange(1, 3650)]
    [int]$DaysInactive = 90,

    [Parameter()]
    [string]$HtmlPath,

    [Parameter()]
    [string]$JsonPath,

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

function Get-GraphCount {
    <# Returns @odata.count of an advanced query (ConsistencyLevel eventual) without downloading the objects. #>
    param([Parameter(Mandatory = $true)] [string]$Uri)
    $joiner = if ($Uri.Contains('?')) { '&' } else { '?' }
    $response = Invoke-MgGraphRequest -Method GET -Uri ($Uri + $joiner + '$count=true&$top=1') -Headers @{ ConsistencyLevel = 'eventual' } -OutputType PSObject -ErrorAction Stop
    return [int]$response.'@odata.count'
}

function Get-RagStatus {
    <# Rates a value: lower is better by default (Green up to -Green, Amber up to -Amber); -HigherIsBetter inverts the scale. #>
    param([double]$Value, [double]$Green, [double]$Amber, [switch]$HigherIsBetter)
    if ($HigherIsBetter) {
        if ($Value -ge $Green) { return 'Green' } elseif ($Value -ge $Amber) { return 'Amber' } else { return 'Red' }
    }
    if ($Value -le $Green) { return 'Green' } elseif ($Value -le $Amber) { return 'Amber' } else { return 'Red' }
}

function Add-Metric {
    <# Evaluates one metric; the script block returns @{ Value; Status; Detail }. Failures become NoAccess or Error rows. #>
    param([string]$Metric, [string]$Target, [scriptblock]$Compute)
    try {
        $outcome = & $Compute
        $script:scorecard.Add([PSCustomObject]@{ Metric = $Metric; Value = [string]$outcome.Value; Target = $Target; Status = $outcome.Status; Detail = [string]$outcome.Detail })
    }
    catch {
        $status = if ($_.Exception.Message -match 'Forbidden|Authorization_RequestDenied|403') { 'NoAccess' } else { 'Error' }
        $script:scorecard.Add([PSCustomObject]@{ Metric = $Metric; Value = ''; Target = $Target; Status = $status; Detail = $_.Exception.Message })
        Write-Warning "$Metric - $status : $($_.Exception.Message)"
    }
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('M365TenantHealthScorecard_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}
$scopes = @('AuditLog.Read.All', 'RoleManagement.Read.Directory', 'SecurityEvents.Read.All', 'Policy.Read.All', 'Device.Read.All', 'User.Read.All',
    'Organization.Read.All', 'ServiceHealth.Read.All', 'DeviceManagementManagedDevices.Read.All', 'Directory.Read.All')
try { Connect-GraphIfNeeded -Scopes $scopes } catch { throw "Could not connect to Microsoft Graph: $($_.Exception.Message)" }
$graphBase = 'https://graph.microsoft.com/v1.0'
$now = (Get-Date).ToUniversalTime()
$cutoff = $now.AddDays(-$DaysInactive).ToString('yyyy-MM-ddTHH:mm:ssZ')
$script:scorecard = New-Object -TypeName System.Collections.Generic.List[object]

Add-Metric -Metric 'MFA registration (members)' -Target '>= 95 %' -Compute {
    $registrationUri = "$graphBase/reports/authenticationMethods/userRegistrationDetails?`$filter=userType eq 'member'&`$select=id,isMfaRegistered,isAdmin"
    $script:registration = @(Invoke-GraphPaged -Uri $registrationUri)
    $registered = @($registration | Where-Object { $_.isMfaRegistered }).Count
    $pct = if ($registration.Count -gt 0) { [math]::Round($registered / $registration.Count * 100, 1) } else { 0 }
    @{ Value = "$pct %"; Status = (Get-RagStatus -Value $pct -Green 95 -Amber 80 -HigherIsBetter); Detail = "$registered of $($registration.Count) members registered" }
}
Add-Metric -Metric 'Admins without MFA' -Target '0' -Compute {
    if ($null -eq $registration) { throw 'Registration details were not available (see the previous metric).' }
    $admins = @($registration | Where-Object { $_.isAdmin })
    $noMfa = @($admins | Where-Object { -not $_.isMfaRegistered }).Count
    @{ Value = $noMfa; Status = (Get-RagStatus -Value $noMfa -Green 0 -Amber 0); Detail = "$($admins.Count) admin accounts in the registration report" }
}
Add-Metric -Metric 'Global Administrators (active)' -Target '2-4' -Compute {
    $assignments = @(Invoke-GraphPaged -Uri "$graphBase/roleManagement/directory/roleAssignments?`$filter=roleDefinitionId eq '62e90394-69f5-4237-9190-012177145e10'")
    $count = @($assignments | Select-Object -ExpandProperty principalId -Unique).Count
    $status = if ($count -ge 2 -and $count -le 4) { 'Green' } elseif ($count -ge 1 -and $count -le 8) { 'Amber' } else { 'Red' }
    @{ Value = $count; Status = $status; Detail = 'Distinct principals with an active assignment; PIM-eligible assignments are not counted' }
}
Add-Metric -Metric 'Microsoft Secure Score' -Target '>= 70 %' -Compute {
    $score = @((Invoke-MgGraphRequest -Method GET -Uri "$graphBase/security/secureScores?`$top=1" -OutputType PSObject).value)[0]
    $pct = [math]::Round($score.currentScore / $score.maxScore * 100, 1)
    @{ Value = "$pct %"; Status = (Get-RagStatus -Value $pct -Green 70 -Amber 50 -HigherIsBetter); Detail = "$($score.currentScore) of $($score.maxScore) points, snapshot $($score.createdDateTime)" }
}
Add-Metric -Metric 'Conditional Access policies enabled' -Target '>= 1' -Compute {
    $script:caPolicies = @(Invoke-GraphPaged -Uri "$graphBase/identity/conditionalAccess/policies")
    $enabled = @($caPolicies | Where-Object { $_.state -eq 'enabled' }).Count
    $reportOnly = @($caPolicies | Where-Object { $_.state -eq 'enabledForReportingButNotEnforced' }).Count
    @{ Value = $enabled; Status = $(if ($enabled -gt 0) { 'Green' } else { 'Red' }); Detail = "$($caPolicies.Count) policies in total, $reportOnly in report-only mode" }
}
Add-Metric -Metric 'Legacy authentication blocked' -Target 'Yes' -Compute {
    if ($null -eq $caPolicies) { throw 'Conditional Access policies were not available.' }
    $blockers = @($caPolicies | Where-Object { $_.state -eq 'enabled' -and $_.grantControls.builtInControls -contains 'block' -and
            ($_.conditions.clientAppTypes -contains 'exchangeActiveSync' -or $_.conditions.clientAppTypes -contains 'other') })
    $value = if ($blockers.Count -gt 0) { 'Yes' } else { 'No' }
    @{ Value = $value; Status = $(if ($blockers.Count -gt 0) { 'Green' } else { 'Red' }); Detail = (($blockers | ForEach-Object { $_.displayName }) -join ', ') }
}
Add-Metric -Metric 'Security defaults' -Target 'Enabled or CA in use' -Compute {
    $defaults = Invoke-MgGraphRequest -Method GET -Uri "$graphBase/policies/identitySecurityDefaultsEnforcementPolicy" -OutputType PSObject
    $caEnabled = @($caPolicies | Where-Object { $_.state -eq 'enabled' }).Count
    @{ Value = $defaults.isEnabled; Status = $(if ($defaults.isEnabled -or $caEnabled -gt 0) { 'Green' } else { 'Red' }); Detail = "$caEnabled enabled Conditional Access policies" }
}
Add-Metric -Metric "Stale devices (> $DaysInactive days)" -Target '< 10 % of devices' -Compute {
    $total = Get-GraphCount -Uri "$graphBase/devices"
    $stale = Get-GraphCount -Uri "$graphBase/devices?`$filter=approximateLastSignInDateTime le $cutoff"
    $pct = if ($total -gt 0) { [math]::Round($stale / $total * 100, 1) } else { 0 }
    @{ Value = $stale; Status = (Get-RagStatus -Value $pct -Green 10 -Amber 25); Detail = "$pct % of $total Entra devices; see Get-IntuneStaleDevices.ps1 for clean-up" }
}
Add-Metric -Metric "Inactive users (> $DaysInactive days)" -Target '< 5 % of enabled members' -Compute {
    $members = Get-GraphCount -Uri "$graphBase/users?`$filter=userType eq 'Member' and accountEnabled eq true"
    $inactiveUri = "$graphBase/users?`$filter=signInActivity/lastSignInDateTime le $cutoff&`$select=id,userType,accountEnabled"
    $inactive = @(Invoke-GraphPaged -Uri $inactiveUri | Where-Object { $_.userType -eq 'Member' -and $_.accountEnabled }).Count
    $pct = if ($members -gt 0) { [math]::Round($inactive / $members * 100, 1) } else { 0 }
    @{ Value = $inactive; Status = (Get-RagStatus -Value $pct -Green 5 -Amber 15); Detail = "$pct % of $members enabled members; accounts that never signed in are not counted" }
}
Add-Metric -Metric 'Guest accounts' -Target 'Review' -Compute {
    @{ Value = (Get-GraphCount -Uri "$graphBase/users?`$filter=userType eq 'Guest'"); Status = 'Info'; Detail = 'Details: Get-M365ExternalCollaborationSummary.ps1' }
}
Add-Metric -Metric 'Unassigned paid licenses' -Target '< 10 % of purchased' -Compute {
    # Pools with 10 000+ units are free or trial SKUs and would distort the percentage.
    $skus = @(Invoke-GraphPaged -Uri "$graphBase/subscribedSkus" | Where-Object { $_.capabilityStatus -eq 'Enabled' -and $_.prepaidUnits.enabled -lt 10000 })
    $purchased = ($skus | ForEach-Object { $_.prepaidUnits.enabled } | Measure-Object -Sum).Sum
    $unassigned = ($skus | ForEach-Object { [math]::Max($_.prepaidUnits.enabled - $_.consumedUnits, 0) } | Measure-Object -Sum).Sum
    $pct = if ($purchased -gt 0) { [math]::Round($unassigned / $purchased * 100, 1) } else { 0 }
    @{ Value = [int]$unassigned; Status = (Get-RagStatus -Value $pct -Green 10 -Amber 20); Detail = "$pct % of $purchased purchased units across $($skus.Count) SKUs" }
}
Add-Metric -Metric 'Disabled users still licensed' -Target '0' -Compute {
    $count = Get-GraphCount -Uri "$graphBase/users?`$filter=accountEnabled eq false and assignedLicenses/`$count ne 0"
    @{ Value = $count; Status = (Get-RagStatus -Value $count -Green 0 -Amber 10); Detail = 'Licenses that can usually be reclaimed (see Invoke-M365UserOffboarding.ps1)' }
}
Add-Metric -Metric 'Open service incidents' -Target '0' -Compute {
    $issues = @(Invoke-GraphPaged -Uri "$graphBase/admin/serviceAnnouncement/issues?`$filter=isResolved eq false and classification eq 'incident'")
    $titles = ($issues | Select-Object -First 5 | ForEach-Object { "$($_.service): $($_.title)" }) -join '; '
    @{ Value = $issues.Count; Status = $(if ($issues.Count -eq 0) { 'Green' } else { 'Amber' }); Detail = $titles }
}
Add-Metric -Metric 'Intune device compliance' -Target '>= 90 %' -Compute {
    $devices = @(Invoke-GraphPaged -Uri "$graphBase/deviceManagement/managedDevices?`$select=id,complianceState")
    $compliant = @($devices | Where-Object { $_.complianceState -eq 'compliant' }).Count
    $pct = if ($devices.Count -gt 0) { [math]::Round($compliant / $devices.Count * 100, 1) } else { 0 }
    @{ Value = "$pct %"; Status = (Get-RagStatus -Value $pct -Green 90 -Amber 75 -HigherIsBetter); Detail = "$compliant of $($devices.Count) managed devices compliant" }
}

$scorecard | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
$colours = @{ Green = 'Green'; Amber = 'Yellow'; Red = 'Red'; NoAccess = 'DarkGray'; Error = 'Magenta'; Info = 'Cyan' }
$title = 'Tenant health scorecard - {0} - {1:yyyy-MM-dd HH:mm} UTC' -f (Get-MgContext).TenantId, $now
Write-Host $title -ForegroundColor Cyan
foreach ($metric in $scorecard) {
    $line = '{0,-9} {1,-40} {2,-10} target {3,-26} {4}' -f $metric.Status, $metric.Metric, $metric.Value, $metric.Target, $metric.Detail
    Write-Host $line -ForegroundColor $colours[$metric.Status]
}
if (-not [string]::IsNullOrWhiteSpace($HtmlPath)) {
    $style = '<style>body{font-family:Segoe UI,Arial,sans-serif;font-size:13px;margin:24px}table{border-collapse:collapse}th,td{border:1px solid #d0d0d0;padding:4px 10px;text-align:left}' +
        'th{background:#f3f3f3}td.Green{background:#c6efce}td.Amber{background:#ffeb9c}td.Red{background:#ffc7ce}td.NoAccess,td.Error{background:#e7e6e6}</style>'
    $table = $scorecard | ConvertTo-Html -Fragment -Property Metric, Value, Target, Status, Detail
    foreach ($status in $colours.Keys) { $table = $table -replace "<td>$status</td>", "<td class=`"$status`">$status</td>" }
    ConvertTo-Html -Head $style -Title $title -Body ("<h1>$title</h1>" + ($table -join "`n")) | Set-Content -Path $HtmlPath -Encoding UTF8
    Write-Host "HTML scorecard: $HtmlPath" -ForegroundColor Cyan
}
if (-not [string]::IsNullOrWhiteSpace($JsonPath)) {
    $history = @()
    if (Test-Path -Path $JsonPath) { $history = @(Get-Content -Path $JsonPath -Raw | ConvertFrom-Json) }
    $history += [PSCustomObject]@{ Timestamp = $now.ToString('o'); TenantId = (Get-MgContext).TenantId; Metrics = @($scorecard) }
    ConvertTo-Json -InputObject $history -Depth 5 | Set-Content -Path $JsonPath -Encoding UTF8
    Write-Host "JSON history: $JsonPath ($($history.Count) snapshots)" -ForegroundColor Cyan
}
Write-Host "Report: $OutputPath" -ForegroundColor Cyan
if ($PassThru) { $scorecard }
#endregion Main
