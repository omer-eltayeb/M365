<#
.SYNOPSIS
    Shows or changes the tenant setting that conceals user, group and site names in Microsoft 365 usage reports.
.DESCRIPTION
    Reads displayConcealedNames from GET /admin/reportSettings (Microsoft Graph v1.0) and explains what it means.
    With -Enable or -Disable the value is changed through PATCH /admin/reportSettings after a ShouldProcess prompt
    (ConfirmImpact High) and read back to confirm. When concealment is on, every usage report in the Microsoft 365
    admin center and from the Graph /reports endpoints shows de-identified (hashed) names instead of real user,
    group and site names, so the usage-report scripts in this repository return hashes instead of UPNs.
.PARAMETER Enable
    Turn concealment on: usage reports show hashed identifiers (privacy-first; required in some jurisdictions).
.PARAMETER Disable
    Turn concealment off: usage reports show identifiable user, group and site names.
.EXAMPLE
    PS> .\Set-M365ReportConcealedNames.ps1
    Prints whether names are currently concealed in usage reports and what that means, without changing anything.
.EXAMPLE
    PS> .\Set-M365ReportConcealedNames.ps1 -Disable -WhatIf
    Shows that concealment would be turned off, without applying the change.
.EXAMPLE
    PS> .\Set-M365ReportConcealedNames.ps1 -Enable -Confirm:$false
    Turns concealment on without prompting, for example at the end of a reporting run that needed real names.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : ReportSettings.Read.All (delegated) to show the setting; ReportSettings.ReadWrite.All with -Enable or
                  -Disable. The signed-in user needs the Global Administrator or Reports Administrator role to change it.
    Category    : Tenant configuration & health
    Changes     : Optional (-Enable / -Disable)
    Notes       : The setting is tenant-wide and affects all admins and all report consumers at once. New usage reports
                  reflect the change within a few hours. Showing identifiable names in reports may need approval from the
                  privacy officer or works council; concealed names are the Microsoft default since 2021.
.LINK
    https://learn.microsoft.com/graph/api/adminreportsettings-get
.LINK
    https://learn.microsoft.com/graph/api/adminreportsettings-update
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High', DefaultParameterSetName = 'Show')]
param(
    [Parameter(ParameterSetName = 'Enable')]
    [switch]$Enable,

    [Parameter(ParameterSetName = 'Disable')]
    [switch]$Disable
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
$changeRequested = $Enable -or $Disable
$scopes = @('ReportSettings.Read.All')
if ($changeRequested) { $scopes = @('ReportSettings.ReadWrite.All') }
try {
    Connect-GraphIfNeeded -Scopes $scopes
}
catch {
    throw "Failed to connect to Microsoft Graph: $($_.Exception.Message)"
}

$settingsUri = 'https://graph.microsoft.com/v1.0/admin/reportSettings'
try {
    $settings = @(Invoke-GraphPaged -Uri $settingsUri)[0]
}
catch {
    throw "Failed to read the report settings: $($_.Exception.Message)"
}
if ($null -eq $settings) { throw 'Graph returned no report settings object.' }
$before = [bool]$settings.displayConcealedNames

$explanations = @{
    $true  = 'ON  - usage reports show hashed user, group and site names (privacy mode); report scripts return hashes instead of UPNs.'
    $false = 'OFF - usage reports show identifiable user, group and site names.'
}
Write-Host ''
Write-Host 'Usage report privacy setting (displayConcealedNames)' -ForegroundColor Cyan
Write-Host ('  Current : {0}' -f $explanations[$before])

$after = $before
$changed = $false
if ($changeRequested) {
    $desired = [bool]$Enable
    if ($before -eq $desired) {
        Write-Host '  The setting already has the requested value; nothing to change.' -ForegroundColor Green
    }
    elseif ($PSCmdlet.ShouldProcess('Microsoft 365 usage report settings (tenant-wide)', ('Set displayConcealedNames to {0}' -f $desired))) {
        try {
            $body = @{ displayConcealedNames = $desired } | ConvertTo-Json
            Invoke-MgGraphRequest -Method PATCH -Uri $settingsUri -Body $body -ContentType 'application/json' -ErrorAction Stop | Out-Null
            # Read back instead of trusting the PATCH response so the result reflects what the service stored.
            $after = [bool](@(Invoke-GraphPaged -Uri $settingsUri)[0]).displayConcealedNames
            $changed = ($after -ne $before)
            Write-Host ('  New     : {0}' -f $explanations[$after]) -ForegroundColor Green
        }
        catch {
            throw "Failed to update the report settings: $($_.Exception.Message)"
        }
    }
}
else {
    Write-Host '  Use -Enable or -Disable to change it; -WhatIf previews the change.' -ForegroundColor Gray
}

[PSCustomObject]@{
    Setting = 'displayConcealedNames'
    Before  = $before
    After   = $after
    Changed = $changed
}
#endregion Main
