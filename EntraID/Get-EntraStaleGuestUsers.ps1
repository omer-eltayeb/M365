<#
.SYNOPSIS
    Finds guest accounts that never signed in, have been inactive for a number of days, or never accepted their invitation.
.DESCRIPTION
    Lists every guest (userType eq 'Guest') through Microsoft Graph (GET /users with $select=signInActivity) and
    evaluates the most recent interactive or non-interactive sign-in. Guests are flagged as NeverSignedIn,
    Inactive (last sign-in older than -DaysInactive) or PendingInvitation (invitation not accepted after
    -DaysInactive days). The result is exported to CSV. Optionally the flagged accounts can be disabled or
    deleted; both actions honour -WhatIf / -Confirm and prompt for confirmation by default.
.PARAMETER DaysInactive
    Days without a sign-in (or without accepting the invitation) after which a guest is reported. Default 90.
.PARAMETER DisableAccounts
    Disables every flagged guest (PATCH /users/{id} accountEnabled=false). Cannot be combined with -RemoveAccounts.
.PARAMETER RemoveAccounts
    Deletes every flagged guest (DELETE /users/{id}). Deleted users stay recoverable for 30 days. Cannot be combined with -DisableAccounts.
.PARAMETER OutputPath
    Path of the CSV report. Defaults to .\Reports\EntraStaleGuests_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emits the report objects to the pipeline.
.EXAMPLE
    PS> .\Get-EntraStaleGuestUsers.ps1
    Reports guests with no sign-in in the last 90 days plus invitations pending for more than 90 days.
.EXAMPLE
    PS> .\Get-EntraStaleGuestUsers.ps1 -DaysInactive 180 -DisableAccounts -WhatIf
    Shows which guests inactive for 180 days would be disabled, without changing anything.
.EXAMPLE
    PS> .\Get-EntraStaleGuestUsers.ps1 -DaysInactive 365 -RemoveAccounts -OutputPath C:\Temp\RemovedGuests.csv -Verbose
    Deletes guests that have been inactive for a year, asking for confirmation per account, and records the outcome in the CSV.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-03
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : User.Read.All and AuditLog.Read.All for the report. User.ReadWrite.All is requested only with
                  -DisableAccounts or -RemoveAccounts (the signed-in user also needs the User Administrator role).
    Category    : Users & authentication
    Changes     : Optional (-DisableAccounts / -RemoveAccounts)
    Notes       : Reading signInActivity requires Microsoft Entra ID P1 or P2. Sign-ins before April 2020 are not
                  tracked, so very old guests can show as NeverSignedIn. Deleted guests can be restored for 30 days
                  from Microsoft Entra admin center > Users > Deleted users.
.LINK
    https://learn.microsoft.com/graph/api/user-list
.LINK
    https://learn.microsoft.com/graph/api/resources/signinactivity
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High', DefaultParameterSetName = 'Report')]
param(
    [Parameter()]
    [ValidateRange(1, 3650)]
    [int]$DaysInactive = 90,

    [Parameter(ParameterSetName = 'Disable')]
    [switch]$DisableAccounts,

    [Parameter(ParameterSetName = 'Remove')]
    [switch]$RemoveAccounts,

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
    param(
        [Parameter()]
        [object]$Value
    )
    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) { return $null }
    if ($Value -is [datetime]) { return $Value.ToUniversalTime() }
    $styles = [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal
    return [datetime]::Parse([string]$Value, [System.Globalization.CultureInfo]::InvariantCulture, $styles)
}

function Get-GuestDomain {
    <# Returns the guest's home domain from the mail address, falling back to the user_domain#EXT#@tenant UPN format. #>
    param(
        [Parameter()]
        [string]$Mail,

        [Parameter()]
        [string]$UserPrincipalName
    )
    if (-not [string]::IsNullOrWhiteSpace($Mail) -and $Mail.Contains('@')) {
        return $Mail.Split('@')[-1].ToLowerInvariant()
    }
    if ($UserPrincipalName -match '^(.+)_([^_]+)#EXT#@') {
        return $Matches[2].ToLowerInvariant()
    }
    return $null
}
#endregion Helpers

#region Main
$requiredScopes = @('User.Read.All', 'AuditLog.Read.All')
if ($DisableAccounts -or $RemoveAccounts) { $requiredScopes += 'User.ReadWrite.All' }

if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('EntraStaleGuests_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}

try {
    Connect-GraphIfNeeded -Scopes $requiredScopes
}
catch {
    throw "Unable to connect to Microsoft Graph: $($_.Exception.Message)"
}

$selectProperties = 'id,displayName,userPrincipalName,mail,createdDateTime,externalUserState,externalUserStateChangeDateTime,accountEnabled,signInActivity,companyName'
# No $top on purpose: when signInActivity is selected Graph caps the page size (500 instead of 999) and larger pages
# have intermittently come back without signInActivity, so the default page size of 100 is the safe choice.
$uri = "https://graph.microsoft.com/v1.0/users?`$filter=userType eq 'Guest'&`$select=$selectProperties&`$count=true"
Write-Verbose 'Retrieving guest users with sign-in activity.'
try {
    # ConsistencyLevel=eventual together with $count=true enables the advanced query path for the users endpoint.
    $guests = Invoke-GraphPaged -Uri $uri -Headers @{ 'ConsistencyLevel' = 'eventual' }
}
catch {
    throw "Failed to list guest users. signInActivity requires Microsoft Entra ID P1/P2 and AuditLog.Read.All. $($_.Exception.Message)"
}
Write-Verbose "Evaluating $($guests.Count) guest accounts."

$now = [datetime]::UtcNow
$threshold = $now.AddDays(-$DaysInactive)
$results = New-Object -TypeName System.Collections.Generic.List[object]
$processed = 0
foreach ($guest in $guests) {
    $processed++
    if ($processed % 100 -eq 0) {
        Write-Progress -Activity 'Evaluating guest accounts' -Status "$processed of $($guests.Count)" -PercentComplete (($processed / $guests.Count) * 100)
    }
    $created = ConvertTo-UtcDateTime -Value $guest.createdDateTime
    $lastSignIn = $null
    if ($null -ne $guest.signInActivity) {
        $interactive = ConvertTo-UtcDateTime -Value $guest.signInActivity.lastSignInDateTime
        $nonInteractive = ConvertTo-UtcDateTime -Value $guest.signInActivity.lastNonInteractiveSignInDateTime
        # The most recent of the two timestamps counts as "last seen"; both are null when the guest never signed in.
        $lastSignIn = $interactive
        if ($null -ne $nonInteractive -and ($null -eq $lastSignIn -or $nonInteractive -gt $lastSignIn)) { $lastSignIn = $nonInteractive }
    }

    $status = $null
    if ($guest.externalUserState -eq 'PendingAcceptance') {
        if ($null -ne $created -and $created -lt $threshold) { $status = 'PendingInvitation' }
    }
    elseif ($null -eq $lastSignIn) {
        # Recently created guests get the full grace period before they are reported as never signed in.
        if ($null -eq $created -or $created -lt $threshold) { $status = 'NeverSignedIn' }
    }
    elseif ($lastSignIn -lt $threshold) {
        $status = 'Inactive'
    }
    if ($null -eq $status) { continue }

    $daysSinceLastSignIn = $null
    if ($null -ne $lastSignIn) { $daysSinceLastSignIn = [int][math]::Floor(($now - $lastSignIn).TotalDays) }
    $daysSinceCreated = $null
    if ($null -ne $created) { $daysSinceCreated = [int][math]::Floor(($now - $created).TotalDays) }

    $results.Add([PSCustomObject]@{
        DisplayName         = $guest.displayName
        UserPrincipalName   = $guest.userPrincipalName
        Mail                = $guest.mail
        GuestDomain         = Get-GuestDomain -Mail $guest.mail -UserPrincipalName $guest.userPrincipalName
        CompanyName         = $guest.companyName
        Status              = $status
        AccountEnabled      = [bool]$guest.accountEnabled
        ExternalUserState   = $guest.externalUserState
        CreatedDateTime     = $created
        DaysSinceCreated    = $daysSinceCreated
        LastSignInDateTime  = $lastSignIn
        DaysSinceLastSignIn = $daysSinceLastSignIn
        ActionTaken         = 'None'
        Id                  = $guest.id
    })
}
Write-Progress -Activity 'Evaluating guest accounts' -Completed

if (($DisableAccounts -or $RemoveAccounts) -and $results.Count -gt 0) {
    $action = 'Disable guest account'
    if ($RemoveAccounts) { $action = 'Delete guest account (recoverable for 30 days)' }
    $processed = 0
    foreach ($row in $results) {
        $processed++
        Write-Progress -Activity $action -Status $row.UserPrincipalName -PercentComplete (($processed / $results.Count) * 100)
        if ($DisableAccounts -and -not $row.AccountEnabled) {
            $row.ActionTaken = 'AlreadyDisabled'
            continue
        }
        if (-not $PSCmdlet.ShouldProcess($row.UserPrincipalName, $action)) { continue }
        $userUri = 'https://graph.microsoft.com/v1.0/users/{0}' -f $row.Id
        try {
            if ($RemoveAccounts) {
                Invoke-MgGraphRequest -Method DELETE -Uri $userUri -ErrorAction Stop | Out-Null
                $row.ActionTaken = 'Deleted'
            }
            else {
                Invoke-MgGraphRequest -Method PATCH -Uri $userUri -Body @{ accountEnabled = $false } -ContentType 'application/json' -ErrorAction Stop | Out-Null
                $row.ActionTaken = 'Disabled'
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

if ($results.Count -gt 0) {
    $results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
}
else {
    Write-Warning ('No guest accounts exceeded the {0}-day threshold; no CSV was written.' -f $DaysInactive)
}

Write-Host ''
Write-Host 'Stale guest summary' -ForegroundColor Cyan
Write-Host ('  Guests evaluated    : {0}' -f $guests.Count)
Write-Host ('  Flagged (>{0} days) : {1}' -f $DaysInactive, $results.Count) -ForegroundColor Yellow
foreach ($group in ($results | Group-Object -Property Status | Sort-Object -Property Name)) {
    Write-Host ('    {0,-18}: {1}' -f $group.Name, $group.Count)
}
if ($DisableAccounts -or $RemoveAccounts) {
    foreach ($group in ($results | Group-Object -Property ActionTaken | Sort-Object -Property Name)) {
        Write-Host ('    Action {0,-11}: {1}' -f $group.Name, $group.Count)
    }
}
Write-Host ('  Report              : {0}' -f $OutputPath)

if ($PassThru) {
    $results
}
#endregion Main
