<#
.SYNOPSIS
    Reports soft-deleted users with the days left before permanent deletion, and optionally restores or permanently deletes them.
.DESCRIPTION
    Lists the recycle bin for users through GET /directory/deletedItems/microsoft.graph.user (ConsistencyLevel eventual + $count),
    strips the object-id prefix that Microsoft Entra adds to the UPN of a deleted user, and calculates DaysUntilPermanentDeletion
    (30 days after deletion). The result is exported to CSV. With -Restore (POST /directory/deletedItems/{id}/restore) or
    -PermanentlyDelete (DELETE /directory/deletedItems/{id}) the users named in -UserPrincipalName are processed; both actions
    honour -WhatIf / -Confirm and prompt for confirmation by default.
.PARAMETER UserPrincipalName
    Original UPN(s) of deleted users. Optional filter for the report; required with -Restore or -PermanentlyDelete.
.PARAMETER Restore
    Restores the specified users with their group memberships, licenses and mailbox. Fails when the UPN is meanwhile in use by another object.
.PARAMETER PermanentlyDelete
    Permanently deletes the specified users. This cannot be undone and also purges the mailbox and OneDrive.
.PARAMETER OutputPath
    Path of the CSV report. Defaults to .\Reports\EntraDeletedUsers_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emits the report objects to the pipeline.
.EXAMPLE
    PS> .\Get-EntraDeletedUsers.ps1 -PassThru | Where-Object DaysUntilPermanentDeletion -le 7
    Exports every soft-deleted user and shows the ones that will be purged within a week.
.EXAMPLE
    PS> .\Get-EntraDeletedUsers.ps1 -UserPrincipalName 'jane.doe@contoso.com' -Restore
    Restores Jane's account after confirmation.
.EXAMPLE
    PS> .\Get-EntraDeletedUsers.ps1 -UserPrincipalName 'temp1@contoso.com', 'temp2@contoso.com' -PermanentlyDelete -WhatIf
    Shows which deleted accounts would be purged immediately, without deleting anything.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : User.Read.All (delegated) for the report; User.ReadWrite.All is added with -Restore / -PermanentlyDelete. The least-privileged
                  alternative for both actions is User.DeleteRestore.All; the signed-in admin needs the User Administrator role.
    Category    : Users & authentication
    Changes     : Optional (-Restore / -PermanentlyDelete)
    Notes       : Deleted users are kept for exactly 30 days and then purged automatically. A restore fails when the UPN or a proxy
                  address has been reused; rename the conflicting object first. The recycle bin is also available in the Microsoft
                  Entra admin center under Users > Deleted users.
.LINK
    https://learn.microsoft.com/graph/api/directory-deleteditems-list
.LINK
    https://learn.microsoft.com/graph/api/directory-deleteditems-restore
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High', DefaultParameterSetName = 'Report')]
param(
    [Parameter(ParameterSetName = 'Report', Position = 0)]
    [Parameter(Mandatory = $true, ParameterSetName = 'Restore', Position = 0)]
    [Parameter(Mandatory = $true, ParameterSetName = 'Purge', Position = 0)]
    [string[]]$UserPrincipalName,

    [Parameter(Mandatory = $true, ParameterSetName = 'Restore')]
    [switch]$Restore,

    [Parameter(Mandatory = $true, ParameterSetName = 'Purge')]
    [switch]$PermanentlyDelete,

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
    param([object]$Value)
    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) { return $null }
    if ($Value -is [datetime]) { return $Value.ToUniversalTime() }
    $styles = [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal
    return [datetime]::Parse([string]$Value, [System.Globalization.CultureInfo]::InvariantCulture, $styles)
}
#endregion Helpers

#region Main
$requiredScopes = @('User.Read.All')
if ($Restore -or $PermanentlyDelete) { $requiredScopes += 'User.ReadWrite.All' }
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('EntraDeletedUsers_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}
try { Connect-GraphIfNeeded -Scopes $requiredScopes }
catch { throw "Unable to connect to Microsoft Graph: $($_.Exception.Message)" }
$v1 = 'https://graph.microsoft.com/v1.0'
$uri = "$v1/directory/deletedItems/microsoft.graph.user?`$select=id,displayName,userPrincipalName,mail,userType,deletedDateTime&`$count=true"
try { $deletedUsers = @(Invoke-GraphPaged -Uri $uri -Headers @{ ConsistencyLevel = 'eventual' }) }
catch { throw "Failed to list deleted users: $($_.Exception.Message)" }
Write-Verbose "Found $($deletedUsers.Count) soft-deleted users."

$filter = @()
if ($PSBoundParameters.ContainsKey('UserPrincipalName')) { $filter = @($UserPrincipalName | ForEach-Object { $_.Trim().ToLowerInvariant() }) }
$now = [datetime]::UtcNow
$results = New-Object -TypeName System.Collections.Generic.List[object]
foreach ($item in ($deletedUsers | Sort-Object -Property deletedDateTime)) {
    # Microsoft Entra prefixes the UPN of a deleted user with its object id without dashes (32 hex characters); strip it to get the original UPN.
    $originalUpn = $item.userPrincipalName -replace '^[0-9a-f]{32}', ''
    if ($filter.Count -gt 0 -and $filter -notcontains $originalUpn.ToLowerInvariant() -and $filter -notcontains $item.userPrincipalName.ToLowerInvariant()) { continue }
    $deletedOn = ConvertTo-UtcDateTime -Value $item.deletedDateTime
    $age = 0; $purgeOn = $null
    if ($null -ne $deletedOn) { $age = [int][math]::Floor(($now - $deletedOn).TotalDays); $purgeOn = $deletedOn.AddDays(30) }
    $results.Add([PSCustomObject]@{
        DisplayName                = $item.displayName
        UserPrincipalName          = $originalUpn
        DeletedUserPrincipalName   = $item.userPrincipalName
        Mail                       = $item.mail
        UserType                   = $item.userType
        DeletedDateTime            = $deletedOn
        DaysSinceDeletion          = $age
        DaysUntilPermanentDeletion = [math]::Max(0, 30 - $age)
        PermanentDeletionOn        = $purgeOn
        ActionTaken                = 'None'
        Id                         = $item.id
    })
}
foreach ($upn in $filter) {
    if (@($results | Where-Object { $_.UserPrincipalName -eq $upn -or $_.DeletedUserPrincipalName -eq $upn }).Count -eq 0) { Write-Warning "$upn was not found among the deleted users." }
}
if (($Restore -or $PermanentlyDelete) -and $results.Count -gt 0) {
    $action = 'Restore deleted user'
    if ($PermanentlyDelete) { $action = 'Permanently delete user (cannot be undone)' }
    $processed = 0
    foreach ($row in $results) {
        $processed++
        Write-Progress -Activity $action -Status $row.UserPrincipalName -PercentComplete (($processed / $results.Count) * 100)
        if (-not $PSCmdlet.ShouldProcess($row.UserPrincipalName, $action)) { continue }
        try {
            if ($Restore) {
                Invoke-MgGraphRequest -Method POST -Uri ('{0}/directory/deletedItems/{1}/restore' -f $v1, $row.Id) -ErrorAction Stop | Out-Null
                $row.ActionTaken = 'Restored'
            }
            else {
                Invoke-MgGraphRequest -Method DELETE -Uri ('{0}/directory/deletedItems/{1}' -f $v1, $row.Id) -ErrorAction Stop | Out-Null
                $row.ActionTaken = 'PermanentlyDeleted'
            }
            Start-Sleep -Milliseconds 200
        }
        catch {
            $row.ActionTaken = 'Failed'
            Write-Warning ('{0} failed for {1}: {2}' -f $action, $row.UserPrincipalName, $_.Exception.Message)
        }
    }
    Write-Progress -Activity $action -Completed
}
if ($results.Count -gt 0) { $results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 }
else { Write-Warning 'No matching soft-deleted users were found; no CSV was written.' }
Write-Host 'Deleted users summary' -ForegroundColor Cyan
Write-Host ('  Soft-deleted users in tenant : {0}' -f $deletedUsers.Count)
Write-Host ('  Reported                     : {0}' -f $results.Count)
Write-Host ('  Purged within 7 days         : {0}' -f @($results | Where-Object { $_.DaysUntilPermanentDeletion -le 7 }).Count) -ForegroundColor Yellow
if ($Restore -or $PermanentlyDelete) {
    foreach ($group in ($results | Group-Object -Property ActionTaken | Sort-Object -Property Name)) { Write-Host ('  Action {0,-22}: {1}' -f $group.Name, $group.Count) }
}
Write-Host ('  Report                       : {0}' -f $OutputPath)

if ($PassThru) {
    $results
}
#endregion Main
