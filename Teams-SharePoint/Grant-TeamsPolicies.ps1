<#
.SYNOPSIS
    Bulk-assigns Teams policies to users (one by one or as batch operations) or to a group, with validation and a preview mode.
.DESCRIPTION
    Reads assignments from -InputCsv (UserPrincipalName, PolicyType, PolicyName) or from -UserPrincipalName / -GroupId with
    -PolicyType and -PolicyName, maps the short type to the module cmdlets (Grant-CsTeams<Type>, Grant-CsOnline<Type>,
    Grant-CsTenantDialPlan), checks that each policy exists (Get-Cs*) and skips users that already have it. "Global" or an
    empty PolicyName resets the user to the org-wide default. Nothing is changed unless -Apply is given; every change runs
    inside ShouldProcess (-WhatIf / -Confirm). -UseBatch submits one batch assignment operation per policy (up to 5000 users
    each) and waits for the per-user result. One result object per target is returned.
.PARAMETER InputCsv
    CSV with UserPrincipalName, PolicyType and PolicyName columns (one row per user and policy type).
.PARAMETER UserPrincipalName
    One or more users that receive -PolicyType / -PolicyName.
.PARAMETER GroupId
    Object ID (or e-mail address) of the Microsoft 365 or security group that receives -PolicyType / -PolicyName.
.PARAMETER PolicyType
    Short policy type, for example MeetingPolicy, MessagingPolicy, CallingPolicy, OnlineVoiceRoutingPolicy or TenantDialPlan.
.PARAMETER PolicyName
    Policy to assign. 'Global' or an empty string resets users to the org-wide default or removes the group's assignment.
.PARAMETER Rank
    Precedence of the group policy assignment (1 = highest). When omitted the assignment gets the lowest rank.
.PARAMETER UseBatch
    Assign through the asynchronous batch policy assignment API instead of one Grant-Cs* call per user.
.PARAMETER Apply
    Perform the assignments. Without this switch the script only reports what it would do.
.EXAMPLE
    PS> .\Grant-TeamsPolicies.ps1 -InputCsv .\assignments.csv | Export-Csv .\preview.csv -NoTypeInformation
    Validates policy types, policy names and current assignments and lists what would be granted without changing anything.
.EXAMPLE
    PS> .\Grant-TeamsPolicies.ps1 -GroupId 0f3c3a1e-1111-2222-3333-444455556666 -PolicyType MeetingPolicy -PolicyName 'Kiosk' -Rank 2 -Apply
    Assigns the Kiosk meeting policy to the group with rank 2 after confirmation; add -UseBatch to a CSV run for batch assignment.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, MicrosoftTeams
    Permissions : Teams Administrator (Teams Communications Administrator is sufficient for the voice policy types).
    Category    : Teams administration (MicrosoftTeams module)
    Changes     : Yes
    Notes       : Group assignment uses Grant-Cs<Type> -Group -Rank (the form Microsoft recommends over New-CsGroupPolicyAssignment);
                  AppPermissionPolicy and EmergencyCallRoutingPolicy cannot be group assigned. Batch assignment supports only meeting,
                  messaging, calling, app, channels, update management, emergency, live events, voice routing and dial plan policies.
.LINK
    https://learn.microsoft.com/microsoftteams/assign-policies-users-and-groups
#>
#Requires -Version 5.1
#Requires -Modules MicrosoftTeams

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High', DefaultParameterSetName = 'Csv')]
param(
    [Parameter(Mandatory = $true, ParameterSetName = 'Csv')][ValidateScript({ Test-Path -Path $_ -PathType Leaf })]
    [string]$InputCsv,

    [Parameter(Mandatory = $true, ParameterSetName = 'Users')]
    [string[]]$UserPrincipalName,

    [Parameter(Mandatory = $true, ParameterSetName = 'Group')]
    [string]$GroupId,

    [Parameter(Mandatory = $true, ParameterSetName = 'Users')][Parameter(Mandatory = $true, ParameterSetName = 'Group')]
    [ValidateSet('MeetingPolicy', 'MessagingPolicy', 'CallingPolicy', 'AppPermissionPolicy', 'AppSetupPolicy', 'ChannelsPolicy', 'UpdateManagementPolicy',
        'EventsPolicy', 'OnlineVoiceRoutingPolicy', 'TenantDialPlan', 'OnlineVoicemailPolicy', 'EmergencyCallingPolicy', 'EmergencyCallRoutingPolicy',
        'AudioConferencingPolicy', 'MeetingBroadcastPolicy', 'FeedbackPolicy', 'MobilityPolicy', 'ShiftsPolicy', 'EnhancedEncryptionPolicy', 'IPPhonePolicy')]
    [string]$PolicyType,

    [Parameter(Mandatory = $true, ParameterSetName = 'Users')][Parameter(Mandatory = $true, ParameterSetName = 'Group')]
    [AllowEmptyString()]
    [string]$PolicyName,

    [Parameter(ParameterSetName = 'Group')]
    [int]$Rank,

    [Parameter(ParameterSetName = 'Csv')][Parameter(ParameterSetName = 'Users')]
    [switch]$UseBatch,

    [Parameter()]
    [switch]$Apply
)

$ErrorActionPreference = 'Stop'

#region Helpers
function Connect-TeamsIfNeeded {
    <# Connects to Microsoft Teams PowerShell only when there is no live session. #>
    [CmdletBinding()]
    param()
    $connected = $false
    try { $null = Get-CsTenant -ErrorAction Stop; $connected = $true } catch { $connected = $false }
    if (-not $connected) {
        Write-Verbose 'Connecting to Microsoft Teams PowerShell.'
        Connect-MicrosoftTeams -ErrorAction Stop | Out-Null
    }
}

function Get-PolicyName {
    <# Normalises a policy value (Get-CsOnlineUser UserPolicyDefinition object, legacy "Tag:Name" string or $null) to its name; empty = Global. #>
    param([Parameter()][object]$Value)
    $name = [string]$Value
    if ($null -ne $Value -and $null -ne $Value.PSObject.Properties['Name']) { $name = [string]$Value.Name }
    $name = $name -replace '^Tag:', ''
    if ([string]::IsNullOrWhiteSpace($name)) { return 'Global' }
    return $name
}

function ConvertTo-ResultRow {
    <# One result object per target; CurrentPolicy is only known for users processed one by one. #>
    param($Target, $FullType, $PolicyLabel, $CurrentPolicy, $Result, $Message)
    return [PSCustomObject]@{ Target = $Target; PolicyType = $FullType; PolicyName = $PolicyLabel; CurrentPolicy = $CurrentPolicy; Result = $Result; Message = $Message }
}
#endregion Helpers

#region Main
try { Connect-TeamsIfNeeded } catch { throw "Failed to connect to Microsoft Teams PowerShell: $($_.Exception.Message)" }
$isGroup = ($PSCmdlet.ParameterSetName -eq 'Group')
$previewMessage = 'Preview only; use -Apply to assign'
if ($Apply) { $previewMessage = 'Not confirmed (-WhatIf or declined)' }
$policyCache = @{}
$results = New-Object -TypeName System.Collections.Generic.List[object]
$requests = New-Object -TypeName System.Collections.Generic.List[object]
if ($PSCmdlet.ParameterSetName -eq 'Csv') { $inputRows = @(Import-Csv -Path $InputCsv) }
else {
    $targets = @($UserPrincipalName)
    if ($isGroup) { $targets = @($GroupId) }
    $inputRows = @($targets | ForEach-Object { [PSCustomObject]@{ UserPrincipalName = $_; PolicyType = $PolicyType; PolicyName = $PolicyName } })
}
# Normalise every row into (target, full policy type, policy name); $null as policy name means "reset to Global".
# Online* types and TenantDialPlan keep their names; every other type is prefixed with "Teams" (Grant-CsTeamsMeetingPolicy).
foreach ($inputRow in $inputRows) {
    $shortType = [string]$inputRow.PolicyType
    $target = [string]$inputRow.PolicyName
    if ([string]::IsNullOrWhiteSpace($target) -or $target -eq 'Global') { $target = $null }
    $fullType = "Teams$shortType"
    if ($shortType -like 'Online*' -or $shortType -eq 'TenantDialPlan') { $fullType = $shortType }
    $problem = $null
    if ($null -eq (Get-Command -Name "Grant-Cs$fullType" -ErrorAction SilentlyContinue)) { $problem = "Unknown policy type '$shortType'" }
    elseif ($null -ne $target) {
        $cacheKey = "$fullType|$target"
        if (-not $policyCache.ContainsKey($cacheKey)) {
            try { $policyCache[$cacheKey] = ($null -ne (& "Get-Cs$fullType" -Identity $target -ErrorAction Stop)) } catch { $policyCache[$cacheKey] = $false }
        }
        if (-not $policyCache[$cacheKey]) { $problem = "Policy '$target' does not exist" }
    }
    if ($null -ne $problem) {
        $results.Add((ConvertTo-ResultRow -Target $inputRow.UserPrincipalName -FullType $fullType -PolicyLabel $inputRow.PolicyName -Result 'Failed' -Message $problem))
        continue
    }
    $requests.Add([PSCustomObject]@{ Target = [string]$inputRow.UserPrincipalName; FullType = $fullType; PolicyName = $target })
}
if ($UseBatch) {
    foreach ($batch in @($requests | Group-Object -Property FullType, PolicyName)) {
        $fullType = $batch.Group[0].FullType
        $target = $batch.Group[0].PolicyName
        $label = Get-PolicyName -Value $target
        $identities = @($batch.Group | Select-Object -ExpandProperty Target -Unique)
        for ($offset = 0; $offset -lt $identities.Count; $offset += 5000) {
            $chunk = @($identities[$offset..([Math]::Min($offset + 4999, $identities.Count - 1))])
            if (-not ($Apply -and $PSCmdlet.ShouldProcess("$($chunk.Count) users", "Batch assign $fullType '$label'"))) {
                foreach ($upn in $chunk) { $results.Add((ConvertTo-ResultRow -Target $upn -FullType $fullType -PolicyLabel $label -Result 'WouldGrant' -Message $previewMessage)) }
                continue
            }
            try {
                $operationId = New-CsBatchPolicyAssignmentOperation -PolicyType $fullType -PolicyName $target -Identity $chunk -OperationName "Grant-TeamsPolicies $fullType" -ErrorAction Stop
                $deadline = (Get-Date).AddMinutes(30)
                do {
                    Start-Sleep -Seconds 10
                    $operation = Get-CsBatchPolicyAssignmentOperation -OperationId $operationId -ErrorAction Stop
                } while ($operation.OverallStatus -ne 'Completed' -and (Get-Date) -lt $deadline)
                foreach ($state in @($operation.UserState)) {
                    $outcome = 'Failed'; if ($state.Result -eq 'Success') { $outcome = 'Granted' } elseif ($state.State -ne 'Completed') { $outcome = 'Pending' }
                    $results.Add((ConvertTo-ResultRow -Target $state.Id -FullType $fullType -PolicyLabel $label -Result $outcome -Message "$($state.Result); operation $operationId"))
                }
            }
            catch {
                foreach ($upn in $chunk) { $results.Add((ConvertTo-ResultRow -Target $upn -FullType $fullType -PolicyLabel $label -Result 'Failed' -Message $_.Exception.Message)) }
            }
        }
    }
}
else {
    $counter = 0
    foreach ($request in $requests) {
        $counter++
        Write-Progress -Activity 'Granting Teams policies' -Status "$counter of $($requests.Count): $($request.Target)" -PercentComplete ([int](($counter / $requests.Count) * 100))
        $label = Get-PolicyName -Value $request.PolicyName
        $current = 'n/a'; $outcome = 'WouldGrant'; $message = $previewMessage
        if (-not $isGroup) {
            try { $user = Get-CsOnlineUser -Identity $request.Target -ErrorAction Stop } catch { $user = $null }
            if ($null -eq $user) { $outcome = 'Failed'; $message = 'User not found' }
            else {
                $current = Get-PolicyName -Value $user.($request.FullType)
                if ($current -eq $label) { $outcome = 'Skipped'; $message = 'Already assigned' }
            }
        }
        if ($outcome -eq 'WouldGrant' -and $Apply -and $PSCmdlet.ShouldProcess($request.Target, "Grant $($request.FullType) '$label' (currently '$current')")) {
            # Grant-Cs* cmdlets take -Identity for a user and -Group (plus optional -Rank) for a group policy assignment.
            $grantParams = @{ PolicyName = $request.PolicyName; ErrorAction = 'Stop' }
            if ($isGroup) { $grantParams['Group'] = $request.Target } else { $grantParams['Identity'] = $request.Target }
            if ($isGroup -and $null -ne $request.PolicyName -and $PSBoundParameters.ContainsKey('Rank')) { $grantParams['Rank'] = $Rank }
            try {
                & "Grant-Cs$($request.FullType)" @grantParams | Out-Null
                $outcome = 'Granted'; $message = "Previous: $current"
                if ($isGroup) { $message = 'Group assignment updated' }
            }
            catch { $outcome = 'Failed'; $message = $_.Exception.Message }
        }
        $results.Add((ConvertTo-ResultRow -Target $request.Target -FullType $request.FullType -PolicyLabel $label -CurrentPolicy $current -Result $outcome -Message $message))
    }
    Write-Progress -Activity 'Granting Teams policies' -Completed
}
Write-Host ''
Write-Host 'Teams policy grant summary' -ForegroundColor Cyan
if (-not $Apply) { Write-Host '  Preview mode: no changes were made (use -Apply to assign).' -ForegroundColor Yellow }
foreach ($group in @($results | Group-Object -Property Result | Sort-Object -Property Name)) {
    Write-Host ('  {0,-11}: {1}' -f $group.Name, $group.Count)
}
$results
#endregion Main
