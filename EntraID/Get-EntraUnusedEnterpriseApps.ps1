<#
.SYNOPSIS
    Finds enterprise applications that have not signed in for a given number of days (or never) and can optionally disable them.
.DESCRIPTION
    Joins the service principal inventory (GET /servicePrincipals) with the beta report GET /reports/servicePrincipalSignInActivities
    to find applications whose last sign-in is older than -DaysInactive or that never signed in. Each row carries the number of secrets
    and certificates stored on the service principal and the number of users and groups assigned to it (appRoleAssignedTo with $count).
    Microsoft first-party apps are always excluded; managed identities only with -IncludeManagedIdentities. The default run is
    read-only; -DisableApps sets accountEnabled to false on every reported app (PATCH /servicePrincipals/{id}) after confirmation.
.PARAMETER DaysInactive
    Apps whose last sign-in is older than this many days are reported as Inactive. Default 90.
.PARAMETER IncludeManagedIdentities
    Also evaluates managed identities (servicePrincipalType ManagedIdentity), which are otherwise excluded.
.PARAMETER DisableApps
    Disables the reported applications. Each change is wrapped in ShouldProcess, so -WhatIf previews and -Confirm prompts per app.
.PARAMETER OutputPath
    Path of the CSV report. Defaults to .\Reports\EntraUnusedEnterpriseApps_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emits the report objects to the pipeline.
.EXAMPLE
    PS> .\Get-EntraUnusedEnterpriseApps.ps1
    Exports every non-Microsoft enterprise app with no sign-in in the last 90 days, or no sign-in at all, to the default CSV.
.EXAMPLE
    PS> .\Get-EntraUnusedEnterpriseApps.ps1 -DaysInactive 180 -DisableApps -WhatIf
    Shows which applications would be disabled with a 180-day threshold without changing anything.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : AuditLog.Read.All, Application.Read.All, Directory.Read.All (delegated); Application.ReadWrite.All is added with -DisableApps.
    Category    : Applications & consent
    Changes     : Optional (-DisableApps)
    Notes       : The sign-in activity report is a beta endpoint that can change without notice, needs Microsoft Entra ID P1 or P2 and
                  can lag a few hours behind. Apps created within the last -DaysInactive days are skipped (no chance to sign in yet).
                  Disabling blocks every sign-in to the app; review AssignedUsersCount first and re-enable by setting accountEnabled true.
.LINK
    https://learn.microsoft.com/graph/api/reportroot-list-serviceprincipalsigninactivities
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter()]
    [ValidateRange(1, 3650)]
    [int]$DaysInactive = 90,

    [Parameter()]
    [switch]$IncludeManagedIdentities,

    [Parameter()]
    [switch]$DisableApps,

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
    <# Normalises a Graph date value (ISO 8601 string or [datetime]) to a UTC [datetime]; returns $null when empty. #>
    param([Parameter()][object]$Value)
    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) { return $null }
    if ($Value -is [datetime]) { return $Value.ToUniversalTime() }
    $styles = [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal
    return [datetime]::Parse([string]$Value, [System.Globalization.CultureInfo]::InvariantCulture, $styles)
}
#endregion Helpers

#region Main
$requiredScopes = @('AuditLog.Read.All', 'Application.Read.All', 'Directory.Read.All')
if ($DisableApps) { $requiredScopes += 'Application.ReadWrite.All' }
$graphV1 = 'https://graph.microsoft.com/v1.0'
# Service principals owned by these two tenants are Microsoft first-party applications and are never reported or disabled.
$microsoftTenantIds = @('f8cdef31-a31e-4b4a-93e4-5f571e91255a', '72f988bf-86f1-41af-91ab-2d7cd011db47')
$kinds = @('Application'); if ($IncludeManagedIdentities) { $kinds += 'ManagedIdentity' }
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('EntraUnusedEnterpriseApps_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}

try {
    Connect-GraphIfNeeded -Scopes $requiredScopes
    $select = 'id,appId,displayName,servicePrincipalType,accountEnabled,appOwnerOrganizationId,createdDateTime,passwordCredentials,keyCredentials'
    $servicePrincipals = @(Invoke-GraphPaged -Uri ('{0}/servicePrincipals?$select={1}&$top=999' -f $graphV1, $select))
    # beta: v1.0 has no sign-in activity report for service principals.
    $activities = @(Invoke-GraphPaged -Uri 'https://graph.microsoft.com/beta/reports/servicePrincipalSignInActivities')
}
catch { throw "Failed to read service principals or sign-in activity from Microsoft Graph: $($_.Exception.Message)" }
$activityByAppId = @{}
foreach ($activity in $activities) { if (-not [string]::IsNullOrEmpty($activity.appId)) { $activityByAppId[$activity.appId] = $activity } }
$now = [datetime]::UtcNow; $rows = New-Object -TypeName System.Collections.Generic.List[object]
$excluded = 0; $activeCount = 0; $recentlyCreated = 0; $processed = 0
foreach ($sp in $servicePrincipals) {
    $processed++
    Write-Progress -Activity 'Evaluating service principals' -Status "$processed of $($servicePrincipals.Count)" -PercentComplete (($processed / $servicePrincipals.Count) * 100)
    if ($microsoftTenantIds -contains $sp.appOwnerOrganizationId -or $kinds -notcontains $sp.servicePrincipalType) { $excluded++; continue }
    $activity = $activityByAppId[$sp.appId]
    $lastSignIn = ConvertTo-UtcDateTime -Value $activity.lastSignInActivity.lastSignInDateTime
    $created = ConvertTo-UtcDateTime -Value $sp.createdDateTime
    $daysSinceLastSignIn = $null; $status = 'NeverSignedIn'
    if ($null -ne $lastSignIn) {
        $daysSinceLastSignIn = [int][math]::Floor(($now - $lastSignIn).TotalDays)
        if ($daysSinceLastSignIn -le $DaysInactive) { $activeCount++; continue }
        $status = 'Inactive'
    }
    elseif ($null -ne $created -and ($now - $created).TotalDays -le $DaysInactive) {
        # An app created inside the inactivity window has not had the chance to sign in yet, so it is not reported as unused.
        $recentlyCreated++; continue
    }
    try {
        $countUri = '{0}/servicePrincipals/{1}/appRoleAssignedTo?$count=true&$top=1' -f $graphV1, $sp.id
        $countResponse = Invoke-MgGraphRequest -Method GET -Uri $countUri -Headers @{ ConsistencyLevel = 'eventual' } -OutputType PSObject -ErrorAction Stop
        $assignedCount = [int]$countResponse.'@odata.count'
    }
    catch { $assignedCount = $null; Write-Warning ("Assigned users of '{0}' could not be counted: {1}" -f $sp.displayName, $_.Exception.Message) }
    Start-Sleep -Milliseconds 200
    $rows.Add([PSCustomObject]@{
        DisplayName         = $sp.displayName
        AppId               = $sp.appId
        ObjectId            = $sp.id
        Kind                = $sp.servicePrincipalType
        AccountEnabled      = $sp.accountEnabled
        Status              = $status
        LastSignInDateTime  = $lastSignIn
        DaysSinceLastSignIn = $daysSinceLastSignIn
        AssignedUsersCount  = $assignedCount
        SecretCount         = @($sp.passwordCredentials | Where-Object { $null -ne $_ }).Count
        CertificateCount    = @($sp.keyCredentials | Where-Object { $null -ne $_ }).Count
        CreatedDateTime     = $created
        ActionTaken         = 'None'
    })
}
Write-Progress -Activity 'Evaluating service principals' -Completed
if ($DisableApps) {
    foreach ($row in $rows) {
        if ($row.AccountEnabled -ne $true) { $row.ActionTaken = 'AlreadyDisabled'; continue }
        if (-not $PSCmdlet.ShouldProcess($row.DisplayName, ('Disable enterprise app (no sign-in for {0}+ days or never)' -f $DaysInactive))) { continue }
        try {
            Invoke-MgGraphRequest -Method PATCH -Uri "$graphV1/servicePrincipals/$($row.ObjectId)" -Body @{ accountEnabled = $false } -ContentType 'application/json' -ErrorAction Stop | Out-Null
            $row.ActionTaken = 'Disabled'
        }
        catch { $row.ActionTaken = 'Failed'; Write-Warning "Disabling '$($row.DisplayName)' failed: $($_.Exception.Message)" }
        Start-Sleep -Milliseconds 200
    }
}
$sortedRows = @($rows | Sort-Object -Property LastSignInDateTime, DisplayName)
if ($sortedRows.Count -gt 0) { $sortedRows | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 }
else { Write-Warning ('No unused enterprise applications were found with a {0}-day threshold; no CSV was written.' -f $DaysInactive) }
Write-Host 'Unused enterprise application summary' -ForegroundColor Cyan
Write-Host ('  Service principals in tenant : {0} ({1} Microsoft first-party or excluded kinds, {2} created recently)' -f $servicePrincipals.Count, $excluded, $recentlyCreated)
Write-Host ('  Active within {0,4} days      : {1}' -f $DaysInactive, $activeCount) -ForegroundColor Green
$neverCount = @($sortedRows | Where-Object { $_.Status -eq 'NeverSignedIn' }).Count
Write-Host ('  Reported as unused           : {0} never signed in, {1} inactive' -f $neverCount, ($sortedRows.Count - $neverCount)) -ForegroundColor Yellow
Write-Host ('  With assigned users/groups   : {0}' -f @($sortedRows | Where-Object { $_.AssignedUsersCount -gt 0 }).Count)
if ($DisableApps) { Write-Host ('  Disabled by this run         : {0}' -f @($sortedRows | Where-Object { $_.ActionTaken -eq 'Disabled' }).Count) -ForegroundColor Red }
Write-Host ('  Rows exported                : {0} -> {1}' -f $sortedRows.Count, $OutputPath)

if ($PassThru) { $sortedRows }
#endregion Main
