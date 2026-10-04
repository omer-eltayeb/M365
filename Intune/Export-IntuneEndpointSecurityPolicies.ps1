<#
.SYNOPSIS
    Exports Intune Endpoint security policies (legacy template intents and settings catalog policies) with settings and assignments to JSON.
.DESCRIPTION
    Downloads the legacy template-based policies from beta /deviceManagement/intents (settings from /intents/{id}/settings,
    template name from /deviceManagement/templates/{templateId}) and the settings catalog based Endpoint security policies
    from beta /deviceManagement/configurationPolicies filtered on templateReference/templateFamily ne 'none' (settings from
    /configurationPolicies/{id}/settings). Every policy is written with its assignments as one JSON file under
    <OutputFolder>\<TemplateFamily>\ and listed in EndpointSecurityPolicies.csv for documentation and change tracking.
.PARAMETER OutputFolder
    Root folder for the export. Defaults to .\IntuneEndpointSecurityExport_yyyyMMdd-HHmm and is created when missing.
.EXAMPLE
    PS> .\Export-IntuneEndpointSecurityPolicies.ps1
    Exports Antivirus, Firewall, Disk encryption, ASR, EDR, Account protection and security baseline policies to .\IntuneEndpointSecurityExport_<timestamp>\.
.EXAMPLE
    PS> .\Export-IntuneEndpointSecurityPolicies.ps1 -OutputFolder D:\Backups\EndpointSecurity -Verbose
    Writes the export into D:\Backups\EndpointSecurity and shows every policy as it is processed.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : DeviceManagementConfiguration.Read.All (delegated) plus an Intune RBAC role such as Endpoint Security Manager or Read Only Operator
    Category    : Compliance, configuration & RBAC
    Changes     : No
    Notes       : Intents, templates and settings catalog policies exist only on the beta endpoint, which Microsoft may change without
                  notice. The templateFamily filter also returns security baselines and other template-based settings catalog policies,
                  each in its own subfolder. This is a documentation backup: the JSON is not directly re-importable. Each policy costs
                  2-3 Graph calls; a 200 ms pause between policies keeps large tenants under the throttling limits.
.LINK
    https://learn.microsoft.com/graph/api/intune-deviceintent-devicemanagementintent-list?view=graph-rest-beta
.LINK
    https://learn.microsoft.com/graph/api/intune-deviceconfigv2-devicemanagementconfigurationpolicy-list?view=graph-rest-beta
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputFolder
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

function Get-SafeName {
    <# Makes a string safe for use as a file or folder name (invalid characters replaced, length limited). #>
    param([string]$Name, [int]$MaxLength = 100)
    $clean = ([string]$Name -replace '[\\/:*?"<>|\x00-\x1F]', '_').Trim()
    if ([string]::IsNullOrWhiteSpace($clean)) { $clean = 'Unnamed' }
    if ($clean.Length -gt $MaxLength) { $clean = $clean.Substring(0, $MaxLength).TrimEnd() }
    return $clean
}

$script:templateCache = @{}
function Get-TemplateInfo {
    <# Reads a legacy Endpoint security template once (display name and platform) and caches it; unknown templates return placeholders. #>
    param([string]$TemplateId)
    if (-not $script:templateCache.ContainsKey($TemplateId)) {
        $info = [PSCustomObject]@{ DisplayName = 'Unknown template'; PlatformType = $null }
        try {
            $templateUri = 'https://graph.microsoft.com/beta/deviceManagement/templates/{0}?$select=id,displayName,platformType' -f $TemplateId
            $template = Invoke-MgGraphRequest -Method GET -Uri $templateUri -OutputType PSObject -ErrorAction Stop
            $info.DisplayName = [string]$template.displayName; $info.PlatformType = [string]$template.platformType
        }
        catch { Write-Warning ('Could not read template {0}: {1}' -f $TemplateId, $_.Exception.Message) }
        $script:templateCache[$TemplateId] = $info
    }
    return $script:templateCache[$TemplateId]
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputFolder)) {
    $OutputFolder = Join-Path -Path (Get-Location).Path -ChildPath ('IntuneEndpointSecurityExport_{0}' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
if (-not (Test-Path -LiteralPath $OutputFolder)) {
    New-Item -Path $OutputFolder -ItemType Directory -Force | Out-Null
}
$OutputFolder = (Resolve-Path -LiteralPath $OutputFolder).ProviderPath

try { Connect-GraphIfNeeded -Scopes @('DeviceManagementConfiguration.Read.All') } catch { throw "Failed to connect to Microsoft Graph: $($_.Exception.Message)" }

$graphBeta = 'https://graph.microsoft.com/beta/deviceManagement'   # beta: intents, templates and settings catalog policies are not exposed in v1.0
$sources = @(
    [PSCustomObject]@{ Source = 'LegacyTemplate'; BaseUri = "$graphBeta/intents"; NameProperty = 'displayName'
        ListQuery = '?$select=id,displayName,description,templateId,isAssigned,lastModifiedDateTime,roleScopeTagIds' }
    [PSCustomObject]@{ Source = 'SettingsCatalog'; BaseUri = "$graphBeta/configurationPolicies"; NameProperty = 'name'
        ListQuery = "?`$filter=templateReference/templateFamily ne 'none'&`$select=id,name,description,platforms,technologies,templateReference,lastModifiedDateTime,roleScopeTagIds" }
)

$indexRows = New-Object -TypeName System.Collections.Generic.List[object]
$failed = 0
foreach ($source in $sources) {
    try {
        $policies = @(Invoke-GraphPaged -Uri ($source.BaseUri + $source.ListQuery))
    }
    catch {
        Write-Warning ('Could not list {0} policies: {1}' -f $source.Source, $_.Exception.Message)
        continue
    }
    Write-Verbose ('{0}: {1} policies found.' -f $source.Source, $policies.Count)
    $index = 0
    foreach ($policy in $policies) {
        $index++
        $policyName = [string]$policy.($source.NameProperty)
        $progress = @{ Activity = ('Exporting {0} policies' -f $source.Source); Status = ('{0} of {1}: {2}' -f $index, $policies.Count, $policyName) }
        Write-Progress @progress -PercentComplete ([int](($index / $policies.Count) * 100))
        $itemUri = '{0}/{1}' -f $source.BaseUri, $policy.id
        try {
            if ($source.Source -eq 'LegacyTemplate') {
                $template = Get-TemplateInfo -TemplateId ([string]$policy.templateId)
                $family = $template.DisplayName; $platform = $template.PlatformType; $technologies = $null
                $policy | Add-Member -NotePropertyName 'templateDisplayName' -NotePropertyValue $template.DisplayName -Force
            }
            else {
                $family = [string]$policy.templateReference.templateFamily; $platform = [string]$policy.platforms; $technologies = [string]$policy.technologies
            }
            $settings = @(Invoke-GraphPaged -Uri ('{0}/settings' -f $itemUri))
            $assignments = @(Invoke-GraphPaged -Uri ('{0}/assignments' -f $itemUri))
            $policy | Add-Member -NotePropertyName 'settings' -NotePropertyValue $settings -Force
            $policy | Add-Member -NotePropertyName 'assignments' -NotePropertyValue $assignments -Force

            $familyFolder = Join-Path -Path $OutputFolder -ChildPath (Get-SafeName -Name $family -MaxLength 60)
            if (-not (Test-Path -LiteralPath $familyFolder)) { New-Item -Path $familyFolder -ItemType Directory -Force | Out-Null }
            $filePath = Join-Path -Path $familyFolder -ChildPath ('{0}_{1}.json' -f (Get-SafeName -Name $policyName), ([string]$policy.id).Substring(0, 8))
            # -LiteralPath: policy names may legitimately contain [ ] which -Path would treat as wildcards.
            $policy | ConvertTo-Json -Depth 50 | Set-Content -LiteralPath $filePath -Encoding UTF8

            $lastModified = $null; if (-not [string]::IsNullOrEmpty($policy.lastModifiedDateTime)) { $lastModified = [datetime]$policy.lastModifiedDateTime }
            $indexRows.Add([PSCustomObject]@{ Source = $source.Source; TemplateFamily = $family; Name = $policyName; Id = $policy.id; Platform = $platform
                    Technologies = $technologies; SettingCount = $settings.Count; AssignmentCount = $assignments.Count; LastModified = $lastModified; FilePath = $filePath })
        }
        catch {
            $failed++
            Write-Warning ("Failed to export {0} policy '{1}' ({2}): {3}" -f $source.Source, $policyName, $policy.id, $_.Exception.Message)
        }
        Start-Sleep -Milliseconds 200
    }
    Write-Progress -Activity ('Exporting {0} policies' -f $source.Source) -Completed
}

$indexRows | Sort-Object -Property TemplateFamily, Name | Export-Csv -Path (Join-Path -Path $OutputFolder -ChildPath 'EndpointSecurityPolicies.csv') -NoTypeInformation -Encoding UTF8
Write-Host ("`nExport folder : {0}" -f $OutputFolder) -ForegroundColor Cyan
Write-Host ('{0,-50} {1,8}' -f 'TemplateFamily', 'Policies') -ForegroundColor Cyan
foreach ($group in ($indexRows | Group-Object -Property TemplateFamily | Sort-Object -Property Name)) {
    Write-Host ('{0,-50} {1,8}' -f $group.Name, $group.Count) -ForegroundColor Green
}
Write-Host ('Exported {0} policies' -f $indexRows.Count) -ForegroundColor Green
if ($failed -gt 0) { Write-Host ('Failed   {0} policies (see warnings)' -f $failed) -ForegroundColor Red }
#endregion Main
