<#
.SYNOPSIS
    Reports the Microsoft Teams app catalog: organisation (custom) apps with their versions and publishing state, optionally store and sideloaded apps.
.DESCRIPTION
    Reads /appCatalogs/teamsApps?$filter=distributionMethod eq 'organization'&$expand=appDefinitions and writes one row per
    app definition (version) with its publishing state (published, submitted, rejected), short description, creator, last
    modification date and the resource-specific permissions the manifest requests. -IncludeStoreApps adds the public store
    catalog (distributionMethod eq 'store') and -IncludeSideloaded the apps uploaded directly into teams. The console summary
    counts definitions per publishing state and lists pending submissions that are waiting for an admin decision.
.PARAMETER AppName
    Only export apps whose display name matches this wildcard pattern (for example 'Contoso*'). A value without wildcards is matched as *value*.
.PARAMETER IncludeStoreApps
    Also list the Microsoft Teams store catalog. The store holds thousands of apps, so this call takes noticeably longer.
.PARAMETER IncludeSideloaded
    Also list sideloaded apps (custom apps uploaded straight into a team instead of the organisation catalog).
.PARAMETER OutputPath
    Path of the CSV file. Defaults to .\Reports\TeamsAppCatalog_<timestamp>.csv.
.PARAMETER PassThru
    Also emit the report objects to the pipeline.
.EXAMPLE
    PS> .\Get-TeamsAppCatalogReport.ps1
    Exports every custom app in the organisation catalog with its versions and highlights submissions waiting for approval.
.EXAMPLE
    PS> .\Get-TeamsAppCatalogReport.ps1 -IncludeStoreApps -AppName 'Adobe*' -OutputPath C:\Temp\AdobeApps.csv -Verbose
    Searches the organisation and store catalogs for apps whose name starts with Adobe.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : AppCatalog.Read.All (delegated). Run as a Teams Administrator: the API works in the user context and only returns
                  the apps the signed-in account is allowed to see under the Teams app permission policies.
    Category    : Teams apps, settings & usage
    Changes     : No
    Notes       : A newly published app can take 24-48 hours to appear while app policies are applied. Store apps have no externalId
                  (their id equals the manifest id); organisation apps keep the manifest id in ExternalId. publishingState reflects
                  the app submission review: submitted means an admin still has to approve or reject the version in the Teams admin
                  center. Dates are UTC.
.LINK
    https://learn.microsoft.com/graph/api/appcatalogs-list-teamsapps
.LINK
    https://learn.microsoft.com/graph/api/resources/teamsappdefinition
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [Parameter()]
    [string]$AppName,

    [Parameter()]
    [switch]$IncludeStoreApps,

    [Parameter()]
    [switch]$IncludeSideloaded,

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
    <# Normalises an ISO 8601 string or [datetime] to a UTC [datetime]; $null when empty. #>
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
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('TeamsAppCatalog_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}

try { Connect-GraphIfNeeded -Scopes @('AppCatalog.Read.All') }
catch { throw "Failed to connect to Microsoft Graph: $($_.Exception.Message)" }

$methods = @('organization')
if ($IncludeStoreApps) { $methods += 'store' }
if ($IncludeSideloaded) { $methods += 'sideloaded' }
$rows = New-Object -TypeName System.Collections.Generic.List[object]
foreach ($method in $methods) {
    Write-Progress -Activity 'Reading the Teams app catalog' -Status "Listing $method apps"
    try {
        $catalogUri = 'https://graph.microsoft.com/v1.0/appCatalogs/teamsApps?$filter=distributionMethod eq ''{0}''&$expand=appDefinitions' -f $method
        $apps = @(Invoke-GraphPaged -Uri $catalogUri)
    }
    catch {
        Write-Warning "Could not list $method apps: $($_.Exception.Message)"
        continue
    }
    Write-Verbose "$($apps.Count) $method apps returned."
    foreach ($app in $apps) {
        $definitions = @($app.appDefinitions)
        if ($definitions.Count -eq 0) { $definitions = @($null) }   # keep one row for apps without a readable definition
        foreach ($definition in $definitions) {
            $createdBy = @($definition.createdBy.user.displayName, $definition.createdBy.application.displayName) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -First 1
            $rscPermissions = @($definition.authorization.requiredPermissionSet.resourceSpecificPermissions | ForEach-Object { $_.permissionValue } | Where-Object { $null -ne $_ })
            $rows.Add([PSCustomObject]@{
                AppName                     = $app.displayName
                DistributionMethod          = $app.distributionMethod
                AppId                       = $app.id
                ExternalId                  = $app.externalId
                Version                     = $definition.version
                PublishingState             = $definition.publishingState
                ShortDescription            = $definition.shortDescription
                CreatedBy                   = $createdBy
                LastModifiedDateTime        = ConvertTo-UtcDateTime -Value $definition.lastModifiedDateTime
                ResourceSpecificPermissions = ($rscPermissions -join ';')
                DefinitionCount             = @($app.appDefinitions).Count
            })
        }
    }
}
Write-Progress -Activity 'Reading the Teams app catalog' -Completed

$output = @($rows)
if (-not [string]::IsNullOrWhiteSpace($AppName)) {
    $pattern = $AppName
    if ($pattern -notmatch '[\*\?]') { $pattern = "*$pattern*" }
    $output = @($output | Where-Object { $_.AppName -like $pattern })
}
$output = @($output | Sort-Object -Property DistributionMethod, AppName, Version)
if ($output.Count -gt 0) { $output | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 }
else { Write-Warning 'No catalog apps matched the filters; no CSV was written.' }

$orgRows = @($output | Where-Object { $_.DistributionMethod -eq 'organization' })
$stateSummary = @($orgRows | Group-Object -Property PublishingState | Sort-Object -Property Name | ForEach-Object { '{0} {1}' -f $_.Name, $_.Count })
$pending = @($orgRows | Where-Object { $_.PublishingState -eq 'submitted' })
$storeApps = @($output | Where-Object { $_.DistributionMethod -eq 'store' } | Select-Object -ExpandProperty AppId -Unique).Count
$sideloadedApps = @($output | Where-Object { $_.DistributionMethod -eq 'sideloaded' } | Select-Object -ExpandProperty AppId -Unique).Count
Write-Host ''
Write-Host 'Teams app catalog summary' -ForegroundColor Cyan
Write-Host ('  Organisation apps / definitions : {0} / {1}' -f @($orgRows | Select-Object -ExpandProperty AppId -Unique).Count, $orgRows.Count)
Write-Host ('  Definitions by publishing state : {0}' -f ($stateSummary -join ', '))
Write-Host ('  Pending submissions             : {0}' -f $pending.Count) -ForegroundColor Yellow
foreach ($submission in ($pending | Select-Object -First 10)) { Write-Host ('    {0} v{1} by {2}' -f $submission.AppName, $submission.Version, $submission.CreatedBy) }
if ($IncludeStoreApps) { Write-Host ('  Store apps                      : {0}' -f $storeApps) }
if ($IncludeSideloaded) { Write-Host ('  Sideloaded apps                 : {0}' -f $sideloadedApps) -ForegroundColor Yellow }
Write-Host ('  Apps requesting RSC permissions : {0}' -f @($output | Where-Object { $_.ResourceSpecificPermissions -ne '' } | Select-Object -ExpandProperty AppId -Unique).Count)
Write-Host ('  Rows exported                   : {0} -> {1}' -f $output.Count, $OutputPath)

if ($PassThru) { $output }
#endregion Main
