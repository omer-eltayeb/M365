<#
.SYNOPSIS
    Finds member users without a usage location, suggests one from their country attribute and optionally sets it.
.DESCRIPTION
    Reads all users from /users (userType, accountEnabled, usageLocation, country, officeLocation, assignedLicenses), drops
    guests and filters client-side, because Graph cannot filter usageLocation on null. For every member without a
    usage location it suggests an ISO 3166 alpha-2 code: the country attribute when it already is a two-letter code, a lookup
    of the country name against the .NET region table (for example "United States" -> US), or -DefaultUsageLocation.
    With -Set the suggested value is written with PATCH /users/{id}. Also prints the usage location distribution of all members.
.PARAMETER DefaultUsageLocation
    Two-letter ISO country code used when the country attribute does not yield a suggestion.
.PARAMETER Set
    Write the suggested usage location to the users (ShouldProcess; supports -WhatIf and -Confirm).
.PARAMETER OutputPath
    Path of the CSV file. Defaults to .\Reports\M365UsageLocation_<timestamp>.csv.
.PARAMETER PassThru
    Also emit the row objects to the pipeline.
.EXAMPLE
    PS> .\Get-M365UsageLocationReport.ps1
    Lists every member without a usage location with the suggested code and whether the account already holds licenses.
.EXAMPLE
    PS> .\Get-M365UsageLocationReport.ps1 -DefaultUsageLocation GB -Set -WhatIf
    Shows which users would receive which usage location (country-derived first, GB as fallback) without changing anything.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : User.Read.All (delegated); -Set adds User.ReadWrite.All. Global Reader can report; User Administrator can set.
    Category    : Licensing
    Changes     : Optional (-Set)
    Notes       : Direct license assignment fails for users without a usage location, and group-based licensing can fail with
                  ProhibitedInUsageLocationViolation for services not available in a country. The usage location decides where
                  data may be stored and which services are offered, so review suggestions before using -Set. For synced users
                  set the value on-premises (msExchUsageLocation) or the next sync may overwrite it.
.LINK
    https://learn.microsoft.com/graph/api/user-update
.LINK
    https://learn.microsoft.com/graph/api/user-list
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter()]
    [ValidatePattern('^[A-Za-z]{2}$')]
    [string]$DefaultUsageLocation,

    [Parameter()]
    [switch]$Set,

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
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('M365UsageLocation_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}
$scopes = @('User.Read.All')
if ($Set) { $scopes += 'User.ReadWrite.All' }
try { Connect-GraphIfNeeded -Scopes $scopes }
catch { throw "Failed to connect to Microsoft Graph: $($_.Exception.Message)" }
try {
    $userSelect = 'id,displayName,userPrincipalName,userType,accountEnabled,usageLocation,country,officeLocation,assignedLicenses'
    # Guests are excluded client-side: userType can be null on old synced accounts, which a server-side eq 'Member' filter would drop.
    $allUsers = @(Invoke-GraphPaged -Uri ('https://graph.microsoft.com/v1.0/users?$top=999&$select=' + $userSelect))
    $users = @($allUsers | Where-Object { $_.userType -ne 'Guest' })
}
catch { throw "Failed to list users: $($_.Exception.Message)" }
Write-Verbose "Read $($users.Count) member users."

# Country names in English or the native language map to ISO alpha-2 codes through the .NET region table (no network needed).
$regionByName = @{}
foreach ($culture in [System.Globalization.CultureInfo]::GetCultures([System.Globalization.CultureTypes]::SpecificCultures)) {
    try { $region = New-Object -TypeName System.Globalization.RegionInfo -ArgumentList $culture.Name } catch { continue }
    if ($region.TwoLetterISORegionName -notmatch '^[A-Z]{2}$') { continue }
    foreach ($name in @($region.EnglishName, $region.DisplayName, $region.NativeName, $region.ThreeLetterISORegionName)) {
        if (-not [string]::IsNullOrWhiteSpace($name)) { $regionByName[$name] = $region.TwoLetterISORegionName }
    }
}

$rows = New-Object -TypeName System.Collections.Generic.List[object]
$missing = @($users | Where-Object { [string]::IsNullOrWhiteSpace($_.usageLocation) })
$counter = 0
foreach ($user in $missing) {
    $counter++
    Write-Progress -Activity 'Evaluating users without usage location' -Status "$counter of $($missing.Count)" -PercentComplete ([int](($counter / $missing.Count) * 100))
    $country = ([string]$user.country).Trim()
    $suggested = ''
    $source = ''
    if ($country -match '^[A-Za-z]{2}$') { $suggested = $country.ToUpper(); $source = 'Country' }
    elseif (-not [string]::IsNullOrEmpty($country) -and $regionByName.ContainsKey($country)) { $suggested = $regionByName[$country]; $source = 'CountryName' }
    elseif (-not [string]::IsNullOrWhiteSpace($DefaultUsageLocation)) { $suggested = $DefaultUsageLocation.ToUpper(); $source = 'Default' }
    $row = [PSCustomObject]@{
        UserPrincipalName      = $user.userPrincipalName
        DisplayName            = $user.displayName
        AccountEnabled         = [bool]$user.accountEnabled
        UsageLocation          = $user.usageLocation
        Country                = $country
        OfficeLocation         = $user.officeLocation
        SuggestedUsageLocation = $suggested
        SuggestionSource       = $source
        HasLicenses            = (@($user.assignedLicenses | Where-Object { $null -ne $_ }).Count -gt 0)
        Result                 = 'ReportOnly'
    }
    $rows.Add($row)
    if (-not $Set) { continue }
    if ([string]::IsNullOrEmpty($suggested)) { $row.Result = 'NoSuggestion'; continue }
    if (-not $PSCmdlet.ShouldProcess($user.userPrincipalName, "Set usage location to $suggested ($source)")) { continue }
    try {
        $body = @{ usageLocation = $suggested } | ConvertTo-Json
        Invoke-MgGraphRequest -Method PATCH -Uri "https://graph.microsoft.com/v1.0/users/$($user.id)" -Body $body -ContentType 'application/json' | Out-Null
        $row.Result = 'Set'
    }
    catch { $row.Result = "Failed: $($_.Exception.Message)"; Write-Warning "Could not update $($user.userPrincipalName): $($_.Exception.Message)" }
    Start-Sleep -Milliseconds 200
}
Write-Progress -Activity 'Evaluating users without usage location' -Completed
$output = @($rows | Sort-Object -Property @{ Expression = 'HasLicenses'; Descending = $true }, UserPrincipalName)
$output | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

Write-Host 'Usage location summary' -ForegroundColor Cyan
Write-Host ('  Member users                   : {0}' -f $users.Count)
Write-Host ('  Without usage location         : {0} ({1} already licensed)' -f $output.Count, @($output | Where-Object { $_.HasLicenses }).Count) -ForegroundColor Yellow
Write-Host ('  With a suggestion              : {0}' -f @($output | Where-Object { -not [string]::IsNullOrEmpty($_.SuggestedUsageLocation) }).Count)
if ($Set) { Write-Host ('  Updated                        : {0}' -f @($output | Where-Object { $_.Result -eq 'Set' }).Count) -ForegroundColor Green }
Write-Host '  Distribution (all members)     :'
foreach ($locationGroup in ($users | Group-Object -Property usageLocation | Sort-Object -Property Count -Descending | Select-Object -First 12)) {
    $label = $locationGroup.Name
    if ([string]::IsNullOrWhiteSpace($label)) { $label = '(not set)' }
    Write-Host ('    {0,-10} {1,7}' -f $label, $locationGroup.Count)
}
Write-Host ('  CSV                            : {0}' -f $OutputPath)
if ($PassThru) { $output }
#endregion Main
