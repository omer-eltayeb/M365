<#
.SYNOPSIS
    Reports the Microsoft 365 group expiration policy and the groups that expire soon, with optional renewal or policy enrolment.
.DESCRIPTION
    Reads the tenant group lifecycle policy (GET /groupLifecyclePolicies: lifetime, managed group types, alternate e-mails) and
    lists every Microsoft 365 group whose expirationDateTime lies within -Days days or has already passed, with the owners who
    receive the notifications (ownerless groups fall back to the alternate e-mails). -Renew calls POST /groups/{id}/renew for them;
    -AddToPolicy enrols selected, not yet covered groups (NotCovered) through POST /groupLifecyclePolicies/{id}/addGroup. Exports a CSV.
.PARAMETER GroupName
    One or more display names to include; wildcards are supported. Default: every Microsoft 365 group.
.PARAMETER GroupId
    Object ID of a single Microsoft 365 group.
.PARAMETER Days
    Report groups expiring within this many days (already expired groups are always included). Default 30.
.PARAMETER Renew
    Renew every reported Expired / ExpiringSoon group (extends the expiration by the policy lifetime). Honours -WhatIf / -Confirm.
.PARAMETER AddToPolicy
    Enrol the selected groups that have no expiration date in the lifecycle policy. Requires -GroupName or -GroupId and a policy
    whose managedGroupTypes is Selected. Honours -WhatIf / -Confirm.
.PARAMETER OutputPath
    Path of the CSV report. Defaults to .\Reports\M365GroupExpiration_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emits the report objects to the pipeline.
.EXAMPLE
    PS> .\Get-M365GroupExpirationReport.ps1 -Days 14
    Shows the policy and every Microsoft 365 group expiring within two weeks, with the owners who receive the notifications.
.EXAMPLE
    PS> .\Get-M365GroupExpirationReport.ps1 -GroupName 'Project-*' -Renew -WhatIf
    Lists which Project groups would be renewed without changing anything; drop -WhatIf to renew them after confirmation.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : Group.Read.All, Directory.Read.All (delegated); -Renew adds Group.ReadWrite.All and -AddToPolicy adds
                  Directory.ReadWrite.All (Groups Administrator role).
    Category    : Microsoft 365 Groups governance
    Changes     : Optional (-Renew / -AddToPolicy)
    Notes       : Group expiration requires Microsoft Entra ID P1 licences for the members of covered groups. An expired group is
                  soft-deleted shortly after the date and can be recovered for 30 days (Get-M365DeletedGroupsReport.ps1 -Restore).
                  Active groups are renewed automatically by Microsoft; activity data itself is not exposed here. Dates are UTC.
.LINK
    https://learn.microsoft.com/graph/api/grouplifecyclepolicy-list
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High', DefaultParameterSetName = 'All')]
param(
    [Parameter(ParameterSetName = 'ByName')]
    [string[]]$GroupName,

    [Parameter(ParameterSetName = 'ById')]
    [ValidatePattern('^[0-9a-fA-F-]{36}$')]
    [string]$GroupId,

    [Parameter()]
    [ValidateRange(1, 3650)]
    [int]$Days = 30,

    [Parameter()]
    [switch]$Renew,

    [Parameter()]
    [switch]$AddToPolicy,

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
$graphV1 = 'https://graph.microsoft.com/v1.0'
if ($AddToPolicy -and $PSCmdlet.ParameterSetName -eq 'All') { throw '-AddToPolicy requires -GroupName or -GroupId so that groups are enrolled deliberately.' }
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('M365GroupExpiration_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}

$requiredScopes = @('Group.Read.All', 'Directory.Read.All')
if ($Renew) { $requiredScopes += 'Group.ReadWrite.All' }
if ($AddToPolicy) { $requiredScopes += 'Directory.ReadWrite.All' }
try { Connect-GraphIfNeeded -Scopes $requiredScopes }
catch { throw "Unable to connect to Microsoft Graph: $($_.Exception.Message)" }

# A tenant has at most one group lifecycle policy.
try { $policy = @(Invoke-GraphPaged -Uri "$graphV1/groupLifecyclePolicies") | Select-Object -First 1 }
catch { throw "Failed to read the group lifecycle policy: $($_.Exception.Message)" }
if ($null -eq $policy) { Write-Warning 'No group expiration policy is configured: Microsoft 365 groups never expire in this tenant.' }
elseif ($AddToPolicy -and $policy.managedGroupTypes -ne 'Selected') { throw "-AddToPolicy needs a policy whose managedGroupTypes is Selected (current: $($policy.managedGroupTypes))." }
if ($AddToPolicy -and $null -eq $policy) { throw 'Create a group expiration policy first (Microsoft Entra admin center > Groups > Expiration).' }
$select = 'id,displayName,expirationDateTime,renewedDateTime,resourceProvisioningOptions,groupTypes'
$filter = 'groupTypes/any(c:c eq ''Unified'')'
if ($PSCmdlet.ParameterSetName -eq 'ById') { $filter += " and id eq '$GroupId'" }
try { $groups = @(Invoke-GraphPaged -Uri ('{0}/groups?$filter={1}&$select={2}&$top=999' -f $graphV1, $filter, $select)) }
catch { throw "Failed to list Microsoft 365 groups: $($_.Exception.Message)" }
if ($PSCmdlet.ParameterSetName -eq 'ByName') { $groups = @($groups | Where-Object { $name = $_.displayName; @($GroupName | Where-Object { $name -like $_ }).Count -gt 0 }) }

$results = New-Object -TypeName System.Collections.Generic.List[object]
$nowUtc = [datetime]::UtcNow; $processed = 0
foreach ($group in $groups) {
    $processed++
    Write-Progress -Activity 'Evaluating group expiration' -Status "$processed of $($groups.Count): $($group.displayName)" -PercentComplete (($processed / $groups.Count) * 100)
    $expires = $null; if ($group.expirationDateTime) { $expires = ([datetime]$group.expirationDateTime).ToUniversalTime() }
    $renewed = $null; if ($group.renewedDateTime) { $renewed = ([datetime]$group.renewedDateTime).ToUniversalTime() }
    $daysUntil = $null; if ($null -ne $expires) { $daysUntil = [int][math]::Ceiling(($expires - $nowUtc).TotalDays) }
    if ($null -eq $expires) { if (-not $AddToPolicy) { continue }; $status = 'NotCovered' }
    elseif ($daysUntil -le 0) { $status = 'Expired' }
    elseif ($daysUntil -le $Days) { $status = 'ExpiringSoon' }
    else { continue }

    $owners = @()
    try { $owners = @(@(Invoke-GraphPaged -Uri ('{0}/groups/{1}/owners?$select=userPrincipalName' -f $graphV1, $group.id)).userPrincipalName | Where-Object { $_ }) }
    catch { Write-Warning "Could not read the owners of '$($group.displayName)': $($_.Exception.Message)" }
    $recipients = $owners; if ($owners.Count -eq 0 -and $null -ne $policy) { $recipients = @($policy.alternateNotificationEmails -split ';' | Where-Object { $_ }) }
    $results.Add([PSCustomObject]@{
        DisplayName            = $group.displayName
        Status                 = $status
        ExpirationDateTime     = $expires
        DaysUntilExpiration    = $daysUntil
        RenewedDateTime        = $renewed
        OwnersCount            = $owners.Count
        Owners                 = ($owners -join ';')
        NotificationRecipients = ($recipients -join ';')
        IsTeam                 = (@($group.resourceProvisioningOptions) -contains 'Team')
        ActionTaken            = 'None'
        Id                     = $group.id
    })
    Start-Sleep -Milliseconds 200
}
Write-Progress -Activity 'Evaluating group expiration' -Completed
foreach ($row in $results) {
    try {
        if ($Renew -and $row.Status -ne 'NotCovered' -and $PSCmdlet.ShouldProcess($row.DisplayName, "Renew group expiration (+$($policy.groupLifetimeInDays) days)")) {
            Invoke-MgGraphRequest -Method POST -Uri ('{0}/groups/{1}/renew' -f $graphV1, $row.Id) -ErrorAction Stop | Out-Null
            $row.ActionTaken = 'Renewed'
        }
        elseif ($AddToPolicy -and $row.Status -eq 'NotCovered' -and $PSCmdlet.ShouldProcess($row.DisplayName, 'Add to the group lifecycle policy')) {
            $null = Invoke-MgGraphRequest -Method POST -Uri "$graphV1/groupLifecyclePolicies/$($policy.id)/addGroup" -Body @{ groupId = $row.Id } -ContentType 'application/json' -ErrorAction Stop
            $row.ActionTaken = 'AddedToPolicy'
        }
        else { continue }
        Start-Sleep -Milliseconds 200
    }
    catch { $row.ActionTaken = 'Failed'; Write-Warning "Change on '$($row.DisplayName)' failed: $($_.Exception.Message)" }
}

if ($results.Count -gt 0) { $results | Sort-Object -Property DaysUntilExpiration, DisplayName | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 }
else { Write-Warning "No selected group expires within $Days days; no CSV was written." }
Write-Host 'Group expiration summary' -ForegroundColor Cyan
if ($null -ne $policy) {
    Write-Host ('  Policy                       : {0} days, {1} groups, alternate e-mails: {2}' -f $policy.groupLifetimeInDays, $policy.managedGroupTypes, $policy.alternateNotificationEmails)
}
Write-Host ('  Expiring within {0,3} days     : {1}' -f $Days, @($results | Where-Object { $_.Status -eq 'ExpiringSoon' }).Count) -ForegroundColor Yellow
Write-Host ('  Already expired              : {0}' -f @($results | Where-Object { $_.Status -eq 'Expired' }).Count) -ForegroundColor Yellow
Write-Host ('  Renewed / added to policy    : {0} / {1}' -f @($results | Where-Object { $_.ActionTaken -eq 'Renewed' }).Count, @($results | Where-Object { $_.ActionTaken -eq 'AddedToPolicy' }).Count)
if ($results.Count -gt 0) { Write-Host ('  Report                       : {0}' -f $OutputPath) }
if ($PassThru) { $results }
#endregion Main
