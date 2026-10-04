<#
.SYNOPSIS
    Reports the owners of every app registration and enterprise application and flags apps without a working owner.
.DESCRIPTION
    Lists app registrations (GET /applications) and non-Microsoft enterprise applications (GET /servicePrincipals) through
    Microsoft Graph with their owners expanded ($expand=owners with id, userPrincipalName, displayName and accountEnabled) and
    returns one row per object with the owner count, the owner names and a Finding of NoOwners, AllOwnersDisabled or Ok.
    The default run is read-only; -AddOwner adds the given user as owner to every object with a finding
    (POST /applications/{id}/owners/$ref or /servicePrincipals/{id}/owners/$ref) after confirmation.
.PARAMETER AddOwner
    User principal name of the user to add as owner to every app registration or enterprise app that has no enabled owner.
.PARAMETER OutputPath
    Path of the CSV report. Defaults to .\Reports\EntraAppOwners_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emits the report objects to the pipeline.
.EXAMPLE
    PS> .\Get-EntraAppOwnersReport.ps1
    Exports every app registration and enterprise application with its owners and finding to the default CSV.
.EXAMPLE
    PS> .\Get-EntraAppOwnersReport.ps1 -AddOwner appowners@contoso.com -WhatIf
    Shows which objects would receive the new owner without changing anything.
.EXAMPLE
    PS> .\Get-EntraAppOwnersReport.ps1 -AddOwner appowners@contoso.com -OutputPath C:\Temp\AppOwners.csv -Verbose
    Adds the user as owner to every ownerless app (confirming each) and records the outcome in the ActionTaken column.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : Application.Read.All, User.Read.All (delegated); Application.ReadWrite.All is added with -AddOwner.
    Category    : Applications & consent
    Changes     : Optional (-AddOwner)
    Notes       : Graph returns at most 20 expanded owners per object, which is enough to decide the finding. Managed identities, legacy
                  service principals and Microsoft first-party apps are skipped. Service principal owners are listed by display name.
.LINK
    https://learn.microsoft.com/graph/api/application-post-owners
.LINK
    https://learn.microsoft.com/graph/api/serviceprincipal-post-owners
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter()]
    [ValidatePattern('^[^@\s]+@[^@\s]+$')]
    [string]$AddOwner,

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
$requiredScopes = @('Application.Read.All', 'User.Read.All')
if (-not [string]::IsNullOrWhiteSpace($AddOwner)) { $requiredScopes += 'Application.ReadWrite.All' }
$graphV1 = 'https://graph.microsoft.com/v1.0'
# Service principals owned by these two tenants are Microsoft first-party applications; their owners are managed by Microsoft.
$microsoftTenantIds = @('f8cdef31-a31e-4b4a-93e4-5f571e91255a', '72f988bf-86f1-41af-91ab-2d7cd011db47')
$ownerExpand = '$expand=owners($select=id,userPrincipalName,displayName,accountEnabled)'

if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('EntraAppOwners_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}

try { Connect-GraphIfNeeded -Scopes $requiredScopes }
catch { throw "Unable to connect to Microsoft Graph: $($_.Exception.Message)" }

$newOwner = $null
if (-not [string]::IsNullOrWhiteSpace($AddOwner)) {
    # Resolve the new owner first so a typo fails before the long directory read.
    $ownerUri = '{0}/users/{1}?$select=id,userPrincipalName,accountEnabled' -f $graphV1, [uri]::EscapeDataString($AddOwner)
    try { $newOwner = Invoke-MgGraphRequest -Method GET -Uri $ownerUri -OutputType PSObject -ErrorAction Stop }
    catch { throw "The new owner '$AddOwner' could not be found: $($_.Exception.Message)" }
    if ($newOwner.accountEnabled -ne $true) { throw "The new owner '$AddOwner' is disabled and cannot be used as an owner." }
}

Write-Verbose 'Retrieving app registrations and enterprise applications with their owners.'
try {
    $applications = @(Invoke-GraphPaged -Uri ('{0}/applications?$select=id,appId,displayName,createdDateTime&{1}&$top=999' -f $graphV1, $ownerExpand))
    $spUri = "{0}/servicePrincipals?`$filter=servicePrincipalType eq 'Application'&`$select=id,appId,displayName,createdDateTime,appOwnerOrganizationId&{1}&`$top=999" -f $graphV1, $ownerExpand
    $servicePrincipals = @(Invoke-GraphPaged -Uri $spUri)
}
catch { throw "Failed to list applications or service principals: $($_.Exception.Message)" }

$items = New-Object -TypeName System.Collections.Generic.List[object]; $excludedMicrosoft = 0
foreach ($application in $applications) { $items.Add([PSCustomObject]@{ ObjectType = 'Application'; Source = $application }) }
foreach ($sp in $servicePrincipals) {
    if ($microsoftTenantIds -contains $sp.appOwnerOrganizationId) { $excludedMicrosoft++; continue }
    $items.Add([PSCustomObject]@{ ObjectType = 'ServicePrincipal'; Source = $sp })
}

$rows = New-Object -TypeName System.Collections.Generic.List[object]
foreach ($item in $items) {
    $owners = @($item.Source.owners | Where-Object { $null -ne $_ })
    $disabledOwners = @($owners | Where-Object { $_.accountEnabled -eq $false })
    $finding = 'Ok'
    if ($owners.Count -eq 0) { $finding = 'NoOwners' }
    elseif ($disabledOwners.Count -eq $owners.Count) { $finding = 'AllOwnersDisabled' }
    $ownerNames = foreach ($owner in $owners) {
        $name = $owner.userPrincipalName
        if ([string]::IsNullOrEmpty($name)) { $name = $owner.displayName }
        if ($owner.accountEnabled -eq $false) { $name = '{0} (disabled)' -f $name }
        $name
    }
    $rows.Add([PSCustomObject]@{
        ObjectType         = $item.ObjectType
        Name               = $item.Source.displayName
        AppId              = $item.Source.appId
        ObjectId           = $item.Source.id
        OwnerCount         = $owners.Count
        DisabledOwnerCount = $disabledOwners.Count
        Owners             = (@($ownerNames) -join ';')
        Finding            = $finding
        CreatedDateTime    = ConvertTo-UtcDateTime -Value $item.Source.createdDateTime
        ActionTaken        = 'None'
    })
}

if ($null -ne $newOwner) {
    $ownerReference = @{ '@odata.id' = ('{0}/directoryObjects/{1}' -f $graphV1, $newOwner.id) }
    foreach ($row in @($rows | Where-Object { $_.Finding -ne 'Ok' })) {
        if (-not $PSCmdlet.ShouldProcess(('{0} {1}' -f $row.ObjectType, $row.Name), "Add owner $($newOwner.userPrincipalName)")) { continue }
        $collection = if ($row.ObjectType -eq 'ServicePrincipal') { 'servicePrincipals' } else { 'applications' }
        $refUri = '{0}/{1}/{2}/owners/$ref' -f $graphV1, $collection, $row.ObjectId
        try {
            Invoke-MgGraphRequest -Method POST -Uri $refUri -Body $ownerReference -ContentType 'application/json' -ErrorAction Stop | Out-Null
            $row.ActionTaken = 'OwnerAdded'
        }
        catch { $row.ActionTaken = 'Failed'; Write-Warning "Adding owner to $($row.ObjectType) '$($row.Name)' failed: $($_.Exception.Message)" }
        Start-Sleep -Milliseconds 200
    }
}

$sortedRows = @($rows | Sort-Object -Property Finding, ObjectType, Name)
if ($sortedRows.Count -gt 0) { $sortedRows | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 }
else { Write-Warning 'No app registrations or enterprise applications were found; no CSV was written.' }

Write-Host 'Application owner summary' -ForegroundColor Cyan
Write-Host ('  App registrations       : {0}' -f $applications.Count)
Write-Host ('  Enterprise applications : {0} ({1} Microsoft first-party excluded)' -f ($servicePrincipals.Count - $excludedMicrosoft), $excludedMicrosoft)
Write-Host ('  No owners               : {0}' -f @($sortedRows | Where-Object { $_.Finding -eq 'NoOwners' }).Count) -ForegroundColor Yellow
Write-Host ('  All owners disabled     : {0}' -f @($sortedRows | Where-Object { $_.Finding -eq 'AllOwnersDisabled' }).Count) -ForegroundColor Yellow
Write-Host ('  Ok                      : {0}' -f @($sortedRows | Where-Object { $_.Finding -eq 'Ok' }).Count) -ForegroundColor Green
if ($null -ne $newOwner) { Write-Host ('  Owners added            : {0}' -f @($sortedRows | Where-Object { $_.ActionTaken -eq 'OwnerAdded' }).Count) }
Write-Host ('  Rows exported           : {0} -> {1}' -f $sortedRows.Count, $OutputPath)

if ($PassThru) { $sortedRows }
#endregion Main
