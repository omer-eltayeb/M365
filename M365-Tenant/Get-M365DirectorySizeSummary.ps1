<#
.SYNOPSIS
    Quick directory size summary: users, groups, devices, applications, roles, administrative units and the directory quota.
.DESCRIPTION
    Runs lightweight $count queries (ConsistencyLevel eventual, $top=1) against /users, /groups, /devices, /applications and
    /servicePrincipals so that even a 200 000-object tenant is summarised in seconds without downloading objects. Adds the
    activated directory roles and how many of them have members (/directoryRoles?$expand=members), the administrative units
    (/directory/administrativeUnits) and the directory object quota (/organization directorySizeQuota). Outputs rows
    (Area, Metric, Count, Note) to CSV and the console, or as JSON with -Json.
.PARAMETER Json
    Write the summary as JSON to the output stream instead of the console table.
.PARAMETER OutputPath
    Path of the CSV file. Defaults to .\Reports\M365DirectorySize_<timestamp>.csv.
.PARAMETER PassThru
    Also emit the row objects to the pipeline.
.EXAMPLE
    PS> .\Get-M365DirectorySizeSummary.ps1
    Prints the counts grouped by area and writes the CSV to the Reports folder.
.EXAMPLE
    PS> .\Get-M365DirectorySizeSummary.ps1 -Json | Set-Content -Path C:\Temp\DirectorySize.json
    Saves the summary as JSON, for example for a monthly capacity record.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : User.Read.All, Group.Read.All, Device.Read.All, Application.Read.All, RoleManagement.Read.Directory,
                  Organization.Read.All, AdministrativeUnit.Read.All (delegated); Global Reader covers all of them.
    Category    : User lifecycle & tenant hygiene
    Changes     : No
    Notes       : Counts come from the eventually consistent directory index and can lag a few minutes behind. First-party
                  Microsoft service principals are excluded by their well-known publisher tenant IDs. Operating system
                  buckets rely on the operatingSystem attribute reported by the device and may not add up to the total.
.LINK
    https://learn.microsoft.com/graph/aad-advanced-queries
.LINK
    https://learn.microsoft.com/graph/api/organization-get
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [Parameter()]
    [switch]$Json,

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

function Add-Row {
    <# Adds one summary row; the script block computes the count and any failure is recorded in Note. #>
    param([string]$Area, [string]$Metric, [scriptblock]$Compute, [string]$Note = '')
    $count = $null
    try { $count = [int](& $Compute) }
    catch { $Note = $_.Exception.Message; Write-Warning "$Metric : $Note" }
    $script:rows.Add([PSCustomObject]@{ Area = $Area; Metric = $Metric; Count = $count; Note = $Note })
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('M365DirectorySize_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}
$scopes = @('User.Read.All', 'Group.Read.All', 'Device.Read.All', 'Application.Read.All', 'RoleManagement.Read.Directory', 'Organization.Read.All', 'AdministrativeUnit.Read.All')
try { Connect-GraphIfNeeded -Scopes $scopes } catch { throw "Could not connect to Microsoft Graph: $($_.Exception.Message)" }
$graphBase = 'https://graph.microsoft.com/v1.0'
$script:rows = New-Object -TypeName System.Collections.Generic.List[object]

# Well-known publisher tenants of Microsoft first-party applications (Microsoft Services and Microsoft corporate).
$firstParty = "appOwnerOrganizationId ne f8cdef31-a31e-4b4a-93e4-5f571e91255a and appOwnerOrganizationId ne 72f988bf-86f1-41af-91ab-2d7cd011db47"
$countQueries = @(
    @{ Area = 'Users'; Metric = 'Users (all)'; Filter = ''; Resource = 'users' }
    @{ Area = 'Users'; Metric = 'Members'; Filter = "userType eq 'Member'"; Resource = 'users' }
    @{ Area = 'Users'; Metric = 'Guests'; Filter = "userType eq 'Guest'"; Resource = 'users' }
    @{ Area = 'Users'; Metric = 'Enabled'; Filter = 'accountEnabled eq true'; Resource = 'users' }
    @{ Area = 'Users'; Metric = 'Disabled'; Filter = 'accountEnabled eq false'; Resource = 'users' }
    @{ Area = 'Users'; Metric = 'Synced from on-premises AD'; Filter = 'onPremisesSyncEnabled eq true'; Resource = 'users' }
    @{ Area = 'Groups'; Metric = 'Groups (all)'; Filter = ''; Resource = 'groups' }
    @{ Area = 'Groups'; Metric = 'Microsoft 365 groups'; Filter = "groupTypes/any(c:c eq 'Unified')"; Resource = 'groups' }
    @{ Area = 'Groups'; Metric = 'Security groups'; Filter = 'securityEnabled eq true and mailEnabled eq false'; Resource = 'groups' }
    @{ Area = 'Groups'; Metric = 'Mail-enabled security groups'; Filter = 'securityEnabled eq true and mailEnabled eq true'; Resource = 'groups' }
    @{ Area = 'Groups'; Metric = 'Distribution lists'; Filter = "mailEnabled eq true and securityEnabled eq false and not(groupTypes/any(c:c eq 'Unified'))"; Resource = 'groups' }
    @{ Area = 'Groups'; Metric = 'Dynamic membership'; Filter = "groupTypes/any(c:c eq 'DynamicMembership')"; Resource = 'groups' }
    @{ Area = 'Groups'; Metric = 'Synced from on-premises AD'; Filter = 'onPremisesSyncEnabled eq true'; Resource = 'groups' }
    @{ Area = 'Devices'; Metric = 'Devices (all)'; Filter = ''; Resource = 'devices' }
    @{ Area = 'Devices'; Metric = 'Entra joined'; Filter = "trustType eq 'AzureAd'"; Resource = 'devices' }
    @{ Area = 'Devices'; Metric = 'Entra hybrid joined'; Filter = "trustType eq 'ServerAd'"; Resource = 'devices' }
    @{ Area = 'Devices'; Metric = 'Entra registered'; Filter = "trustType eq 'Workplace'"; Resource = 'devices' }
    @{ Area = 'Devices'; Metric = 'Windows'; Filter = "startswith(operatingSystem,'Windows')"; Resource = 'devices' }
    @{ Area = 'Devices'; Metric = 'iOS / iPadOS'; Filter = "operatingSystem in ('iOS','IOS','iPadOS','IPadOS','iPhone','IPhone')"; Resource = 'devices' }
    @{ Area = 'Devices'; Metric = 'Android'; Filter = "startswith(operatingSystem,'Android')"; Resource = 'devices' }
    @{ Area = 'Devices'; Metric = 'macOS'; Filter = "startswith(operatingSystem,'Mac')"; Resource = 'devices' }
    @{ Area = 'Devices'; Metric = 'Linux'; Filter = "operatingSystem eq 'Linux'"; Resource = 'devices' }
    @{ Area = 'Applications'; Metric = 'App registrations'; Filter = ''; Resource = 'applications' }
    @{ Area = 'Applications'; Metric = 'Service principals (all)'; Filter = ''; Resource = 'servicePrincipals' }
    @{ Area = 'Applications'; Metric = 'Service principals excluding Microsoft first-party'; Filter = $firstParty; Resource = 'servicePrincipals' }
)
$index = 0
foreach ($query in $countQueries) {
    $index++
    Write-Progress -Activity 'Counting directory objects' -Status $query.Metric -PercentComplete (($index / ($countQueries.Count + 3)) * 100)
    $uri = "$graphBase/$($query.Resource)"
    if (-not [string]::IsNullOrEmpty($query.Filter)) { $uri += '?$filter=' + $query.Filter }
    Add-Row -Area $query.Area -Metric $query.Metric -Compute { Get-GraphCount -Uri $uri }
}
Write-Progress -Activity 'Counting directory objects' -Status 'Roles, administrative units, quota' -PercentComplete 95
Add-Row -Area 'Roles' -Metric 'Directory roles activated' -Compute { @(Invoke-GraphPaged -Uri "$graphBase/directoryRoles?`$select=id").Count }
Add-Row -Area 'Roles' -Metric 'Directory roles with members' -Note 'Direct members only; PIM-eligible assignments are not counted' -Compute {
    @(Invoke-GraphPaged -Uri "$graphBase/directoryRoles?`$expand=members(`$select=id)" | Where-Object { @($_.members).Count -gt 0 }).Count
}
Add-Row -Area 'Administrative units' -Metric 'Administrative units' -Compute { @(Invoke-GraphPaged -Uri "$graphBase/directory/administrativeUnits?`$select=id").Count }
try {
    $quota = @(Invoke-GraphPaged -Uri "$graphBase/organization?`$select=directorySizeQuota")[0].directorySizeQuota
    $pct = if ($quota.total -gt 0) { [math]::Round($quota.used / $quota.total * 100, 1) } else { 0 }
    $rows.Add([PSCustomObject]@{ Area = 'Quota'; Metric = 'Directory objects used'; Count = [int]$quota.used; Note = "$pct % of the $($quota.total) object quota" })
    $rows.Add([PSCustomObject]@{ Area = 'Quota'; Metric = 'Directory object quota'; Count = [int]$quota.total; Note = 'Raise through Microsoft support when above 80 %' })
}
catch { Write-Warning "Directory quota could not be read: $($_.Exception.Message)" }
Write-Progress -Activity 'Counting directory objects' -Completed

$rows | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
if ($Json) { ConvertTo-Json -InputObject @($rows) -Depth 3 }
else {
    foreach ($area in ($rows | Select-Object -ExpandProperty Area -Unique)) {
        Write-Host $area -ForegroundColor Cyan
        foreach ($row in ($rows | Where-Object { $_.Area -eq $area })) {
            $countText = if ($null -eq $row.Count) { 'n/a' } else { '{0:N0}' -f $row.Count }
            Write-Host ('  {0,-52} {1,12}  {2}' -f $row.Metric, $countText, $row.Note)
        }
    }
    Write-Host "Report: $OutputPath" -ForegroundColor Cyan
}
if ($PassThru) { $rows }
#endregion Main
