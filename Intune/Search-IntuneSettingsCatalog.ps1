<#
.SYNOPSIS
    Searches the Intune settings catalog for settings matching a keyword and reports their definition, category, platform and options.
.DESCRIPTION
    Queries the beta collection /deviceManagement/configurationSettings with $search="<keyword>" and falls back to
    $filter=contains(tolower(displayName),'<keyword>') when the search endpoint rejects the request. Category ids are
    resolved through /deviceManagement/configurationCategories (read once and cached) into a readable category path.
    Each row carries the setting definition id, display name, description, platform, technologies, selectable option
    values, help text and documentation URL - ideal for finding the right setting before building a policy or for
    mapping a GPO/CSP setting to its settings catalog equivalent. Writes a CSV and optionally emits the rows.
.PARAMETER Keyword
    Text to search for in the setting definitions, for example 'BitLocker', 'screen saver' or 'DeviceLock'.
.PARAMETER Platform
    Return only settings applicable to this platform: windows10, macOS, iOS, android, androidEnterprise, aosp or linux.
.PARAMETER OutputPath
    CSV path. Defaults to .\Reports\IntuneSettingsCatalog_yyyyMMdd-HHmm.csv; the folder is created when missing.
.PARAMETER PassThru
    Also emit the report objects to the pipeline.
.EXAMPLE
    PS> .\Search-IntuneSettingsCatalog.ps1 -Keyword 'BitLocker' -Platform windows10
    Lists every Windows settings catalog setting that mentions BitLocker, with its category and option values.
.EXAMPLE
    PS> .\Search-IntuneSettingsCatalog.ps1 -Keyword 'password' -PassThru | Select-Object DisplayName, Category, Platform | Out-GridView
    Searches all platforms for password-related settings and browses the result interactively.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : DeviceManagementConfiguration.Read.All (delegated)
    Category    : Compliance, configuration & RBAC
    Changes     : No
    Notes       : The settings catalog definitions exist only on the beta endpoint, which Microsoft may change without notice.
                  $search matches display name, description and keywords; the $filter fallback matches the display name only.
                  Description and HelpText are truncated to 200 characters in the report. The result can include settings that
                  are only visible inside templates (Endpoint security) rather than in the generic settings catalog picker.
.LINK
    https://learn.microsoft.com/graph/api/intune-deviceconfigv2-devicemanagementconfigurationsettingdefinition-list?view=graph-rest-beta
.LINK
    https://learn.microsoft.com/mem/intune/configuration/settings-catalog
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$Keyword,

    [Parameter()]
    [ValidateSet('windows10', 'macOS', 'iOS', 'android', 'androidEnterprise', 'aosp', 'linux')]
    [string]$Platform,

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

function Limit-Text {
    <# Collapses whitespace and truncates long text so the CSV stays readable. #>
    param([string]$Text, [int]$MaxLength = 200)
    $clean = ([string]$Text -replace '\s+', ' ').Trim()
    if ($clean.Length -gt $MaxLength) { $clean = $clean.Substring(0, $MaxLength - 3) + '...' }
    return $clean
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('IntuneSettingsCatalog_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}

try { Connect-GraphIfNeeded -Scopes @('DeviceManagementConfiguration.Read.All') } catch { throw "Failed to connect to Microsoft Graph: $($_.Exception.Message)" }

$graphBeta = 'https://graph.microsoft.com/beta/deviceManagement'   # beta: settings catalog definitions and categories are not exposed in v1.0
$cleanKeyword = ($Keyword -replace '"', '').Trim()
$queryMode = '$search'
try {
    $settings = @(Invoke-GraphPaged -Uri ('{0}/configurationSettings?$search={1}' -f $graphBeta, [uri]::EscapeDataString('"' + $cleanKeyword + '"')))
}
catch {
    Write-Warning ('$search was rejected ({0}); retrying with a display name $filter.' -f $_.Exception.Message)
    $queryMode = '$filter'
    try {
        $filterValue = [uri]::EscapeDataString($cleanKeyword.ToLowerInvariant().Replace("'", "''"))
        $settings = @(Invoke-GraphPaged -Uri ("{0}/configurationSettings?`$filter=contains(tolower(displayName),'{1}')" -f $graphBeta, $filterValue))
    }
    catch {
        Write-Warning ('The settings catalog could not be queried with $search or $filter: {0}' -f $_.Exception.Message)
        return
    }
}
Write-Verbose ('{0} settings returned by {1}.' -f $settings.Count, $queryMode)
if (-not [string]::IsNullOrEmpty($Platform)) {
    # applicability.platform is a flags value such as 'windows10' or 'iOS,macOS', so match the individual tokens.
    $settings = @($settings | Where-Object { @([string]$_.applicability.platform -split ',\s*') -contains $Platform })
}

$categories = @{}
try {
    foreach ($category in @(Invoke-GraphPaged -Uri ('{0}/configurationCategories?$select=id,displayName,parentCategoryId' -f $graphBeta))) { $categories[[string]$category.id] = $category }
}
catch {
    Write-Warning ('Could not read the settings catalog categories; the Category column shows ids only: {0}' -f $_.Exception.Message)
}

$results = New-Object -TypeName System.Collections.Generic.List[object]
foreach ($setting in $settings) {
    # Walk up parentCategoryId to show 'Parent > Child'; the counter guards against circular references.
    $categoryPath = @(); $categoryId = [string]$setting.categoryId; $depth = 0
    while ($categories.ContainsKey($categoryId) -and $depth -lt 5) {
        $categoryPath = @([string]$categories[$categoryId].displayName) + $categoryPath
        $categoryId = [string]$categories[$categoryId].parentCategoryId; $depth++
    }
    if ($categoryPath.Count -eq 0) { $categoryPath = @([string]$setting.categoryId) }
    $options = @(foreach ($option in @($setting.options)) { [string]$option.displayName })
    $results.Add([PSCustomObject]@{
            SettingDefinitionId = $setting.id
            DisplayName         = $setting.displayName
            SettingType         = ([string]$setting.'@odata.type' -replace '^#microsoft\.graph\.deviceManagementConfiguration', '' -replace 'Definition$', '')
            Description         = Limit-Text -Text $setting.description
            Category            = ($categoryPath -join ' > ')
            Platform            = $setting.applicability.platform
            Technologies        = $setting.applicability.technologies
            OptionValues        = ($options -join '; ')
            HelpText            = Limit-Text -Text $setting.helpText
            InfoUrl             = (@($setting.infoUrls) -join ' ')
        })
}

$results | Sort-Object -Property Category, DisplayName | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
Write-Host ("`nKeyword          : '{0}' (query mode {1})" -f $cleanKeyword, $queryMode) -ForegroundColor Cyan
$countColour = 'Green'; if ($results.Count -eq 0) { $countColour = 'Yellow' }
Write-Host ('Matching settings: {0}' -f $results.Count) -ForegroundColor $countColour
foreach ($group in ($results | Group-Object -Property Platform | Sort-Object -Property Count -Descending)) {
    Write-Host ('  {0,-30} {1,5}' -f $group.Name, $group.Count) -ForegroundColor Gray
}
Write-Host ('Report saved to {0}' -f $OutputPath) -ForegroundColor Cyan
if ($PassThru) { $results }
#endregion Main
