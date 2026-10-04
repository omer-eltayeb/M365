<#
.SYNOPSIS
    Reports how every licensed user received each SKU (direct, group-based or both) together with assignment errors.
.DESCRIPTION
    Reads /subscribedSkus for SKU names and every licensed user from /users (advanced query on assignedLicenses) including
    licenseAssignmentStates. Each state carries the SKU, the assigning group (null = direct), the state (Active,
    ActiveWithError, Disabled, Error) and the error (CountViolation, MutuallyExclusiveViolation, DependencyViolation,
    ProhibitedInUsageLocationViolation, ...). Group ids are resolved to names through /groups/{id} with a cache.
    Outputs one row per user and SKU; AssignmentPath is Direct, Group:<name> or Both (flagged DuplicateDirectAndGroup).
.PARAMETER Sku
    Only report these SKUs (part numbers such as SPE_E3, or SKU ids).
.PARAMETER OnlyErrors
    Only output rows whose assignment state carries an error.
.PARAMETER OnlyDuplicates
    Only output rows where the same SKU is assigned both directly and through a group (candidates for cleanup).
.PARAMETER OutputPath
    Path of the CSV file. Defaults to .\Reports\M365LicenseAssignmentPaths_<timestamp>.csv.
.PARAMETER PassThru
    Also emit the row objects to the pipeline.
.EXAMPLE
    PS> .\Get-M365LicenseAssignmentPaths.ps1
    Exports every user/SKU combination with its assignment path and prints direct vs group counts per SKU and errors by type.
.EXAMPLE
    PS> .\Get-M365LicenseAssignmentPaths.ps1 -Sku SPE_E3 -OnlyDuplicates -OutputPath C:\Temp\E3Duplicates.csv
    Lists users who hold Microsoft 365 E3 both directly and through a group, so the direct assignment can be removed safely.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : User.Read.All, Group.Read.All, Organization.Read.All (delegated); Global Reader or License Administrator.
    Category    : Licensing
    Changes     : No
    Notes       : licenseAssignmentStates can list a SKU the user does not effectively hold (state Error) - exactly what
                  -OnlyErrors surfaces. Deleted groups are reported by id. One Graph call per distinct group; dates are UTC.
.LINK
    https://learn.microsoft.com/graph/api/resources/licenseassignmentstate
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [Parameter()]
    [string[]]$Sku,

    [Parameter()]
    [switch]$OnlyErrors,

    [Parameter()]
    [switch]$OnlyDuplicates,

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
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('M365LicenseAssignmentPaths_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}
try { Connect-GraphIfNeeded -Scopes @('User.Read.All', 'Group.Read.All', 'Organization.Read.All') }
catch { throw "Failed to connect to Microsoft Graph: $($_.Exception.Message)" }
try {
    $skus = @(Invoke-GraphPaged -Uri 'https://graph.microsoft.com/v1.0/subscribedSkus?$select=skuId,skuPartNumber')
    $userSelect = 'id,displayName,userPrincipalName,accountEnabled,usageLocation,licenseAssignmentStates'
    $usersUri = 'https://graph.microsoft.com/v1.0/users?$filter=assignedLicenses/$count ne 0&$count=true&$top=999&$select=' + $userSelect
    $users = @(Invoke-GraphPaged -Uri $usersUri -Headers @{ ConsistencyLevel = 'eventual' })
}
catch { throw "Failed to read subscribed SKUs or licensed users: $($_.Exception.Message)" }
$skuNameById = @{}
foreach ($sku in $skus) { $skuNameById[[string]$sku.skuId] = [string]$sku.skuPartNumber }
# -Sku accepts part numbers or ids; resolve them once so the per-user loop only compares ids.
$skuIdFilter = @()
foreach ($token in @($Sku)) {
    $match = $skus | Where-Object { $_.skuPartNumber -eq $token -or [string]$_.skuId -eq $token } | Select-Object -First 1
    if ($null -eq $match) { throw "SKU '$token' was not found in /subscribedSkus." }
    $skuIdFilter += [string]$match.skuId
}

$groupNames = @{}
$rows = New-Object -TypeName System.Collections.Generic.List[object]
$counter = 0
foreach ($user in $users) {
    $counter++
    if ($counter % 100 -eq 0) { Write-Progress -Activity 'Resolving license assignment paths' -Status "$counter of $($users.Count)" -PercentComplete ([int](($counter / $users.Count) * 100)) }
    foreach ($skuStates in @($user.licenseAssignmentStates | Group-Object -Property skuId)) {
        $skuId = [string]$skuStates.Name
        if ([string]::IsNullOrEmpty($skuId) -or ($skuIdFilter.Count -gt 0 -and $skuIdFilter -notcontains $skuId)) { continue }
        $direct = @($skuStates.Group | Where-Object { [string]::IsNullOrEmpty($_.assignedByGroup) })
        $viaGroup = @($skuStates.Group | Where-Object { -not [string]::IsNullOrEmpty($_.assignedByGroup) })
        $groupLabels = @()
        foreach ($state in $viaGroup) {
            $groupId = [string]$state.assignedByGroup
            if (-not $groupNames.ContainsKey($groupId)) {
                $groupUri = 'https://graph.microsoft.com/v1.0/groups/{0}?$select=displayName' -f $groupId
                try { $groupNames[$groupId] = [string](Invoke-MgGraphRequest -Method GET -Uri $groupUri -OutputType PSObject).displayName }
                catch { Write-Warning "Group $groupId could not be resolved (deleted?): $($_.Exception.Message)"; $groupNames[$groupId] = $groupId }
            }
            $groupLabels += $groupNames[$groupId]
        }
        $path = 'Direct'
        if ($direct.Count -gt 0 -and $viaGroup.Count -gt 0) { $path = 'Both' }
        elseif ($viaGroup.Count -gt 0) { $path = (@($groupLabels | ForEach-Object { "Group:$_" }) -join ';') }
        $errors = @($skuStates.Group | Where-Object { -not [string]::IsNullOrEmpty($_.error) -and $_.error -ne 'None' } | ForEach-Object { [string]$_.error } | Sort-Object -Unique)
        if (($OnlyErrors -and $errors.Count -eq 0) -or ($OnlyDuplicates -and $path -ne 'Both')) { continue }
        $skuName = $skuId
        if ($skuNameById.ContainsKey($skuId)) { $skuName = $skuNameById[$skuId] }
        $lastUpdated = @($skuStates.Group | ForEach-Object { ConvertTo-UtcDateTime -Value $_.lastUpdatedDateTime } | Where-Object { $null -ne $_ } | Sort-Object -Descending) | Select-Object -First 1
        $rows.Add([PSCustomObject]@{
                UserPrincipalName       = $user.userPrincipalName
                DisplayName             = $user.displayName
                AccountEnabled          = [bool]$user.accountEnabled
                UsageLocation           = $user.usageLocation
                Sku                     = $skuName
                SkuId                   = $skuId
                AssignmentPath          = $path
                Groups                  = ($groupLabels -join ';')
                State                   = (@($skuStates.Group | ForEach-Object { [string]$_.state } | Sort-Object -Unique) -join ';')
                Error                   = ($errors -join ';')
                DisabledPlanCount       = @($skuStates.Group | ForEach-Object { $_.disabledPlans } | Where-Object { $null -ne $_ } | Sort-Object -Unique).Count
                LastUpdatedDateTime     = $lastUpdated
                DuplicateDirectAndGroup = ($path -eq 'Both')
            })
    }
}
Write-Progress -Activity 'Resolving license assignment paths' -Completed
$output = @($rows | Sort-Object -Property Sku, UserPrincipalName)
$output | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

Write-Host ('License assignment paths ({0} user/SKU rows from {1} licensed users)' -f $output.Count, $users.Count) -ForegroundColor Cyan
foreach ($skuGroup in ($output | Group-Object -Property Sku | Sort-Object -Property Name)) {
    $directCount = @($skuGroup.Group | Where-Object { $_.AssignmentPath -eq 'Direct' }).Count
    $bothCount = @($skuGroup.Group | Where-Object { $_.AssignmentPath -eq 'Both' }).Count
    Write-Host ('  {0,-40} direct {1,6}   group {2,6}   both {3,5}' -f $skuGroup.Name, $directCount, ($skuGroup.Count - $directCount - $bothCount), $bothCount)
}
$errorRows = @($output | Where-Object { -not [string]::IsNullOrEmpty($_.Error) })
Write-Host ('  Rows with errors              : {0}' -f $errorRows.Count) -ForegroundColor Yellow
foreach ($errorGroup in ($errorRows | ForEach-Object { $_.Error -split ';' } | Group-Object | Sort-Object -Property Count -Descending)) {
    Write-Host ('    {0,-36} {1}' -f $errorGroup.Name, $errorGroup.Count)
}
Write-Host ('  Duplicate direct + group rows : {0}' -f @($output | Where-Object { $_.DuplicateDirectAndGroup }).Count) -ForegroundColor Yellow
Write-Host ('  CSV                           : {0}' -f $OutputPath)
if ($PassThru) { $output }
#endregion Main
