<#
.SYNOPSIS
    Reports every commercial subscription of the tenant with status, trial flag, renewal/expiry date and SKU consumption.
.DESCRIPTION
    Reads /directory/subscriptions (companySubscription: skuPartNumber, totalLicenses, status, isTrial, createdDateTime,
    nextLifecycleDateTime, owner and commerce ids, serviceStatus) and joins the consumption from /subscribedSkus, which
    Graph reports per SKU across all subscriptions of that SKU. Each row gets DaysUntilLifecycle and a Flag (ExpiringSoon
    within -WarnDays, Trial, Warning, Suspended, Deleted, LockedOut). Prints a status breakdown and the subscriptions that
    expire soon so renewals can be planned before users lose service.
.PARAMETER WarnDays
    Number of days before nextLifecycleDateTime at which an enabled subscription is flagged ExpiringSoon. Default 60.
.PARAMETER OutputPath
    Path of the CSV file. Defaults to .\Reports\M365Subscriptions_<timestamp>.csv.
.PARAMETER PassThru
    Also emit the row objects to the pipeline.
.EXAMPLE
    PS> .\Get-M365SubscriptionsReport.ps1
    Exports all subscriptions and lists the ones that renew or expire within 60 days together with trials.
.EXAMPLE
    PS> .\Get-M365SubscriptionsReport.ps1 -WarnDays 90 -OutputPath C:\Temp\Subscriptions.csv -PassThru | Where-Object { $_.IsTrial }
    Uses a 90-day warning window and returns only trial subscriptions to the pipeline.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : Organization.Read.All (delegated; Directory.Read.All also works). Global Reader or Billing Administrator.
    Category    : Licensing
    Changes     : No
    Notes       : nextLifecycleDateTime means different things per status: for Enabled it is the renewal or expiry date, for
                  Warning (expired) the date the subscription becomes Suspended, for Suspended the date it is deleted. Graph
                  does not expose whether auto-renew is on - check the Microsoft 365 admin center > Billing > Your products.
                  Consumption is per SKU, so several subscriptions of the same SKU show the same consumed figure. Dates are UTC.
.LINK
    https://learn.microsoft.com/graph/api/directory-list-subscriptions
.LINK
    https://learn.microsoft.com/graph/api/resources/companysubscription
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateRange(1, 365)]
    [int]$WarnDays = 60,

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
    if ($Value -is [datetime]) {
        if ($Value.Kind -eq [System.DateTimeKind]::Local) { return $Value.ToUniversalTime() }
        return [datetime]::SpecifyKind($Value, [System.DateTimeKind]::Utc)
    }
    $parsed = [datetime]::MinValue
    $styles = [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal
    if ([datetime]::TryParse([string]$Value, [System.Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$parsed)) { return $parsed }
    return $null
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('M365Subscriptions_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}
try { Connect-GraphIfNeeded -Scopes @('Organization.Read.All') }
catch { throw "Failed to connect to Microsoft Graph: $($_.Exception.Message)" }
try {
    $subscriptions = @(Invoke-GraphPaged -Uri 'https://graph.microsoft.com/v1.0/directory/subscriptions')
    $skus = @(Invoke-GraphPaged -Uri 'https://graph.microsoft.com/v1.0/subscribedSkus?$select=skuId,skuPartNumber,prepaidUnits,consumedUnits')
}
catch { throw "Failed to read subscriptions or subscribed SKUs: $($_.Exception.Message)" }
$skuById = @{}
foreach ($sku in $skus) { $skuById[[string]$sku.skuId] = $sku }
Write-Verbose "Shaping $($subscriptions.Count) subscriptions."

$nowUtc = [datetime]::UtcNow
$rows = New-Object -TypeName System.Collections.Generic.List[object]
foreach ($subscription in $subscriptions) {
    $sku = $skuById[[string]$subscription.skuId]
    $enabled = $null; $consumed = $null; $available = $null
    if ($null -ne $sku) {
        $enabled = [int]$sku.prepaidUnits.enabled
        $consumed = [int]$sku.consumedUnits
        $available = $enabled - $consumed
    }
    $lifecycle = ConvertTo-UtcDateTime -Value $subscription.nextLifecycleDateTime
    $daysUntil = $null
    if ($null -ne $lifecycle) { $daysUntil = [int][math]::Floor(($lifecycle - $nowUtc).TotalDays) }
    $status = [string]$subscription.status
    $flags = @()
    if ($status -in @('Warning', 'Suspended', 'Deleted', 'LockedOut')) { $flags += $status }
    if ([bool]$subscription.isTrial) { $flags += 'Trial' }
    if ($status -eq 'Enabled' -and $null -ne $daysUntil -and $daysUntil -le $WarnDays) { $flags += 'ExpiringSoon' }
    $notProvisioned = @($subscription.serviceStatus | Where-Object { $_.provisioningStatus -ne 'Success' } | ForEach-Object { '{0}:{1}' -f $_.servicePlanName, $_.provisioningStatus })
    $rows.Add([PSCustomObject]@{
            SkuPartNumber          = $subscription.skuPartNumber
            SkuId                  = $subscription.skuId
            Status                 = $status
            IsTrial                = [bool]$subscription.isTrial
            TotalLicenses          = [int]$subscription.totalLicenses
            SkuEnabledUnits        = $enabled
            SkuConsumedUnits       = $consumed
            SkuAvailableUnits      = $available
            CreatedDateTime        = (ConvertTo-UtcDateTime -Value $subscription.createdDateTime)
            NextLifecycleDateTime  = $lifecycle
            DaysUntilLifecycle     = $daysUntil
            Flag                   = ($flags -join ';')
            OwnerType              = $subscription.ownerType
            OwnerId                = $subscription.ownerId
            OwnerTenantId          = $subscription.ownerTenantId
            CommerceSubscriptionId = $subscription.commerceSubscriptionId
            SubscriptionId         = $subscription.id
            PlansNotProvisioned    = ($notProvisioned -join ';')
        })
}
# Subscriptions without a lifecycle date (e.g. free SKUs) sort last.
$output = @($rows | Sort-Object -Property @{ Expression = { if ($null -eq $_.DaysUntilLifecycle) { [int]::MaxValue } else { $_.DaysUntilLifecycle } } }, SkuPartNumber)
$output | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

$expiring = @($output | Where-Object { $_.Flag -like '*ExpiringSoon*' })
$unhealthy = @($output | Where-Object { $_.Status -ne 'Enabled' })
$overage = @($output | Where-Object { $null -ne $_.SkuAvailableUnits -and $_.SkuAvailableUnits -lt 0 } | Select-Object -ExpandProperty SkuPartNumber -Unique)
Write-Host 'Subscription summary' -ForegroundColor Cyan
Write-Host ('  Subscriptions               : {0}' -f $output.Count)
foreach ($statusGroup in ($output | Group-Object -Property Status | Sort-Object -Property Name)) {
    Write-Host ('    {0,-12} {1,4}  ({2} licenses)' -f $statusGroup.Name, $statusGroup.Count, (($statusGroup.Group | Measure-Object -Property TotalLicenses -Sum).Sum))
}
Write-Host ('  Trials                      : {0}' -f @($output | Where-Object { $_.IsTrial }).Count)
Write-Host ('  Not enabled (action needed) : {0}' -f $unhealthy.Count) -ForegroundColor Yellow
Write-Host ('  SKUs in overage             : {0}' -f (@($overage) -join ', ')) -ForegroundColor Yellow
Write-Host ('  Renew/expire within {0,3} days : {1}' -f $WarnDays, $expiring.Count) -ForegroundColor Yellow
foreach ($row in $expiring) {
    Write-Host ('    {0,-40} {1,6} licenses  {2:yyyy-MM-dd}  in {3,4} days' -f $row.SkuPartNumber, $row.TotalLicenses, $row.NextLifecycleDateTime, $row.DaysUntilLifecycle)
}
Write-Host ('  CSV                         : {0}' -f $OutputPath)
if ($PassThru) { $output }
#endregion Main
