<#
.SYNOPSIS
    Offboards leavers end to end: disables the account, revokes sessions, resets the password, removes groups, manager, MFA methods and licenses.
.DESCRIPTION
    Takes UPNs from -UserPrincipalName or a CSV (UserPrincipalName, optional ManagerUpn and ForwardTo) and runs these Microsoft
    Graph v1.0 steps per user, each skippable with a switch: PATCH accountEnabled=false, POST revokeSignInSessions, PATCH a random
    passwordProfile, DELETE /groups/{id}/members/{userId}/$ref for every group (also removes the user from teams; dynamic and synced
    groups are skipped), DELETE manager/$ref, DELETE every authentication method and finally POST assignLicense to remove the direct
    licenses. With the ExchangeOnlineManagement module the mailbox can first be converted to shared and hidden from the GAL,
    forwarded, given an auto-reply and opened to the manager, so it survives the license removal. Steps that must happen in AD are
    skipped for synced accounts. Every change runs inside ShouldProcess; each step becomes a row (User, Step, Result, Detail).
.PARAMETER UserPrincipalName
    One or more UPNs to offboard.
.PARAMETER InputCsv
    CSV with a UserPrincipalName column and optional ManagerUpn (overrides the manager found in Entra ID) and ForwardTo columns.
.PARAMETER ForwardTo
    SMTP address that receives a copy of new mail (-UserPrincipalName mode; the CSV column wins in CSV mode). Needs Exchange Online.
.PARAMETER SkipDisable
    Do not disable the account.
.PARAMETER SkipRevokeSessions
    Do not revoke refresh tokens and sessions.
.PARAMETER SkipPasswordReset
    Do not set a new random password.
.PARAMETER SkipGroups
    Do not remove group and team memberships.
.PARAMETER SkipLicenses
    Do not remove directly assigned licenses.
.PARAMETER SkipMfaReset
    Do not delete the registered authentication methods (phone, Authenticator, FIDO2, OATH, e-mail, Hello, TAP).
.PARAMETER ConvertMailboxToShared
    Set-Mailbox -Type Shared and hide the mailbox from address lists (Exchange Online).
.PARAMETER AutoReplyMessage
    Text set as internal and external automatic reply (Exchange Online).
.PARAMETER GrantManagerAccess
    Give the manager FullAccess to the mailbox with auto-mapping (Exchange Online).
.PARAMETER OutputPath
    Path of the step results CSV. Defaults to .\Reports\M365UserOffboarding_<timestamp>.csv.
.PARAMETER PassThru
    Also emit the step result objects to the pipeline.
.EXAMPLE
    PS> .\Invoke-M365UserOffboarding.ps1 -UserPrincipalName leaver@contoso.com -WhatIf
    Shows every step that would run for the user, including the groups and authentication methods that would be removed.
.EXAMPLE
    PS> .\Invoke-M365UserOffboarding.ps1 -UserPrincipalName leaver@contoso.com -ConvertMailboxToShared -GrantManagerAccess -AutoReplyMessage 'I have left Contoso.' -Confirm:$false
    Locks the account, strips groups, manager and MFA methods, converts the mailbox to shared with the manager as delegate and then removes the licenses.
.EXAMPLE
    PS> .\Invoke-M365UserOffboarding.ps1 -InputCsv .\Leavers.csv -SkipMfaReset -Confirm:$false -Verbose
    Bulk offboarding without touching authentication methods, with per-step details in the Verbose stream.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication; ExchangeOnlineManagement 3.x only for the mailbox steps
    Permissions : User.ReadWrite.All, Group.ReadWrite.All, Organization.Read.All, UserAuthenticationMethod.ReadWrite.All (unless
                  -SkipMfaReset), User-PasswordProfile.ReadWrite.All (unless -SkipPasswordReset) (delegated); User Administrator plus
                  Authentication Administrator for the MFA step, Exchange Administrator for the mailbox steps.
    Category    : User lifecycle & tenant hygiene
    Changes     : Yes
    Notes       : Licenses are removed last on purpose: a shared mailbox under 50 GB needs no license, while removing the license
                  first starts the 30-day deletion of the mailbox. Group-based licenses and dynamic or synced groups are reported,
                  not changed. Distribution lists need Exchange Online (Remove-DistributionGroupMember is used when connected).
                  OneDrive hand-over is not covered here; use Add-SPOSiteCollectionAdmin.ps1 in the Teams-SharePoint folder.
.LINK
    https://learn.microsoft.com/graph/api/user-revokesigninsessions
.LINK
    https://learn.microsoft.com/graph/api/group-delete-members
.LINK
    https://learn.microsoft.com/graph/api/authentication-list-methods
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High', DefaultParameterSetName = 'Upn')]
param(
    [Parameter(Mandatory = $true, ParameterSetName = 'Upn', Position = 0)]
    [string[]]$UserPrincipalName,

    [Parameter(Mandatory = $true, ParameterSetName = 'Csv')]
    [ValidateScript({ Test-Path -Path $_ -PathType Leaf })]
    [string]$InputCsv,

    [Parameter(ParameterSetName = 'Upn')]
    [string]$ForwardTo,

    [Parameter()] [switch]$SkipDisable,
    [Parameter()] [switch]$SkipRevokeSessions,
    [Parameter()] [switch]$SkipPasswordReset,
    [Parameter()] [switch]$SkipGroups,
    [Parameter()] [switch]$SkipLicenses,
    [Parameter()] [switch]$SkipMfaReset,
    [Parameter()] [switch]$ConvertMailboxToShared,
    [Parameter()] [string]$AutoReplyMessage,
    [Parameter()] [switch]$GrantManagerAccess,
    [Parameter()] [string]$OutputPath,
    [Parameter()] [switch]$PassThru
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

function Connect-ExchangeIfNeeded {
    <# Connects to Exchange Online (or Security & Compliance PowerShell) only when no live session exists. #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [switch]$Compliance
    )
    $connections = @(Get-ConnectionInformation -ErrorAction SilentlyContinue)
    if ($Compliance) {
        $active = @($connections | Where-Object { $_.ConnectionUri -like '*compliance*' -and $_.State -eq 'Connected' })
        if ($active.Count -eq 0) {
            Write-Verbose 'Connecting to Security & Compliance PowerShell.'
            Connect-IPPSSession -ErrorAction Stop
        }
    }
    else {
        $active = @($connections | Where-Object { $_.ConnectionUri -notlike '*compliance*' -and $_.State -eq 'Connected' })
        if ($active.Count -eq 0) {
            Write-Verbose 'Connecting to Exchange Online.'
            Connect-ExchangeOnline -ShowBanner:$false -ErrorAction Stop
        }
    }
}

function Add-StepResult {
    param([string]$User, [string]$Step, [string]$Result, [string]$Detail)
    $script:results.Add([PSCustomObject]@{ User = $User; Step = $Step; Result = $Result; Detail = $Detail })
    Write-Verbose "$User | $Step | $Result | $Detail"
}

function Invoke-LifecycleStep {
    <# Runs one change through the caller's ShouldProcess (so "Yes to All" persists), records a result row and never throws. #>
    param(
        [Parameter(Mandatory = $true)] [System.Management.Automation.PSCmdlet]$Cmdlet,
        [Parameter(Mandatory = $true)] [string]$User,
        [Parameter(Mandatory = $true)] [string]$Step,
        [Parameter(Mandatory = $true)] [string]$Detail,
        [Parameter(Mandatory = $true)] [scriptblock]$Action
    )
    $result = 'Skipped'
    if ($Cmdlet.ShouldProcess($User, "$Step - $Detail")) {
        try { $Detail = [string](& $Action); $result = 'Success' }
        catch { $result = 'Failed'; $Detail = $_.Exception.Message; Write-Warning "$User | $Step failed: $Detail" }
    }
    elseif ($WhatIfPreference) { $result = 'WhatIf' }
    Add-StepResult -User $User -Step $Step -Result $result -Detail $Detail
}

function Get-RandomPassword {
    <# 24 characters from a crypto RNG; nobody needs to know it, it only invalidates the old password. #>
    $alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%&*-_?'
    $bytes = New-Object -TypeName byte[] -ArgumentList 24
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    return -join ($bytes | ForEach-Object { $alphabet[$_ % $alphabet.Length] })
}

# Authentication method types that Graph allows to delete, mapped to their collection segment.
$methodPaths = @{
    '#microsoft.graph.phoneAuthenticationMethod'                   = 'phoneMethods'
    '#microsoft.graph.microsoftAuthenticatorAuthenticationMethod'  = 'microsoftAuthenticatorMethods'
    '#microsoft.graph.fido2AuthenticationMethod'                   = 'fido2Methods'
    '#microsoft.graph.softwareOathAuthenticationMethod'            = 'softwareOathMethods'
    '#microsoft.graph.emailAuthenticationMethod'                   = 'emailMethods'
    '#microsoft.graph.windowsHelloForBusinessAuthenticationMethod' = 'windowsHelloForBusinessMethods'
    '#microsoft.graph.temporaryAccessPassAuthenticationMethod'     = 'temporaryAccessPassMethods'
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('M365UserOffboarding_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}
if ($PSCmdlet.ParameterSetName -eq 'Csv') { $entries = @(Import-Csv -Path $InputCsv) }
else { $entries = @($UserPrincipalName | ForEach-Object { [PSCustomObject]@{ UserPrincipalName = $_; ManagerUpn = ''; ForwardTo = $ForwardTo } }) }

$scopes = @('User.ReadWrite.All', 'Group.ReadWrite.All', 'Organization.Read.All')
if (-not $SkipMfaReset) { $scopes += 'UserAuthenticationMethod.ReadWrite.All' }
if (-not $SkipPasswordReset) { $scopes += 'User-PasswordProfile.ReadWrite.All' }
try { Connect-GraphIfNeeded -Scopes $scopes } catch { throw "Could not connect to Microsoft Graph: $($_.Exception.Message)" }

# Exchange Online is optional: connect only when a mailbox step was requested and the module is installed.
$wantsForward = @($entries | Where-Object { -not [string]::IsNullOrWhiteSpace($_.ForwardTo) }).Count -gt 0
$exoReady = $false
if ($ConvertMailboxToShared -or $GrantManagerAccess -or $wantsForward -or -not [string]::IsNullOrWhiteSpace($AutoReplyMessage)) {
    if ($null -eq (Get-Module -ListAvailable -Name ExchangeOnlineManagement)) {
        Write-Warning 'ExchangeOnlineManagement is not installed; the mailbox steps are skipped.'
    }
    elseif ($WhatIfPreference) { $exoReady = $true }
    else {
        try { Connect-ExchangeIfNeeded; $exoReady = $true } catch { Write-Warning "Exchange Online connection failed, mailbox steps are skipped: $($_.Exception.Message)" }
    }
}

$graphBase = 'https://graph.microsoft.com/v1.0'
$skuNames = @{}
foreach ($sku in (Invoke-GraphPaged -Uri "$graphBase/subscribedSkus?`$select=skuId,skuPartNumber")) { $skuNames[[string]$sku.skuId] = $sku.skuPartNumber }
$script:results = New-Object -TypeName System.Collections.Generic.List[object]
$index = 0
foreach ($entry in $entries) {
    $index++
    $upn = ([string]$entry.UserPrincipalName).Trim()
    if ([string]::IsNullOrWhiteSpace($upn)) { Write-Warning "Row $index has no UserPrincipalName; skipped."; continue }
    Write-Progress -Activity 'Offboarding users' -Status $upn -PercentComplete (($index / $entries.Count) * 100)
    $common = @{ Cmdlet = $PSCmdlet; User = $upn }
    $row = @{ User = $upn }
    try {
        $userUri = "$graphBase/users/$([uri]::EscapeDataString($upn))"
        $account = Invoke-MgGraphRequest -Method GET -Uri ($userUri + '?$select=id,displayName,accountEnabled,onPremisesSyncEnabled,licenseAssignmentStates') -OutputType PSObject
    }
    catch { Add-StepResult @row -Step 'Lookup' -Result 'Failed' -Detail $_.Exception.Message; continue }
    $managerUpn = ([string]$entry.ManagerUpn).Trim()
    if (-not $managerUpn) {
        try { $managerUpn = (Invoke-MgGraphRequest -Method GET -Uri "$userUri/manager?`$select=userPrincipalName" -OutputType PSObject).userPrincipalName }
        catch { $managerUpn = $null }   # 404 = no manager assigned
    }
    $synced = $account.onPremisesSyncEnabled -eq $true
    $syncedNote = 'Synced from on-premises AD - do this in Active Directory'

    if (-not $SkipDisable) {
        if ($synced) { Add-StepResult @row -Step 'DisableAccount' -Result 'Skipped' -Detail $syncedNote }
        elseif (-not $account.accountEnabled) { Add-StepResult @row -Step 'DisableAccount' -Result 'Skipped' -Detail 'Already disabled' }
        else {
            Invoke-LifecycleStep @common -Step 'DisableAccount' -Detail 'Set accountEnabled = false' -Action {
                Invoke-MgGraphRequest -Method PATCH -Uri $userUri -Body '{"accountEnabled":false}' -ContentType 'application/json' | Out-Null; 'Account disabled'
            }
        }
    }
    if (-not $SkipRevokeSessions) {
        Invoke-LifecycleStep @common -Step 'RevokeSessions' -Detail 'Invalidate refresh tokens' -Action {
            Invoke-MgGraphRequest -Method POST -Uri "$userUri/revokeSignInSessions" | Out-Null; 'Sessions revoked'
        }
    }
    if (-not $SkipPasswordReset) {
        if ($synced) { Add-StepResult @row -Step 'ResetPassword' -Result 'Skipped' -Detail $syncedNote }
        else {
            Invoke-LifecycleStep @common -Step 'ResetPassword' -Detail 'Set a random 24-character password' -Action {
                $passwordBody = ConvertTo-Json -InputObject @{ passwordProfile = @{ password = (Get-RandomPassword); forceChangePasswordNextSignIn = $true } }
                Invoke-MgGraphRequest -Method PATCH -Uri $userUri -Body $passwordBody -ContentType 'application/json' | Out-Null; 'Password replaced'
            }
        }
    }
    if (-not $SkipGroups) {
        $groups = Invoke-GraphPaged -Uri "$userUri/memberOf/microsoft.graph.group?`$select=id,displayName,mail,groupTypes,mailEnabled,onPremisesSyncEnabled"
        foreach ($group in $groups) {
            $name = $group.displayName
            if ($group.groupTypes -contains 'DynamicMembership') { Add-StepResult @row -Step 'RemoveFromGroup' -Result 'Skipped' -Detail "$name is dynamic"; continue }
            if ($group.onPremisesSyncEnabled) { Add-StepResult @row -Step 'RemoveFromGroup' -Result 'Skipped' -Detail "$name is synced from on-premises AD"; continue }
            if ($group.mailEnabled -and $group.groupTypes -notcontains 'Unified') {
                # Distribution lists and mail-enabled security groups are Exchange objects; Graph cannot change their members.
                if (-not $exoReady) { Add-StepResult @row -Step 'RemoveFromGroup' -Result 'Skipped' -Detail "$name is a distribution list - connect Exchange Online or remove manually"; continue }
                Invoke-LifecycleStep @common -Step 'RemoveFromGroup' -Detail "$name (distribution list)" -Action {
                    Remove-DistributionGroupMember -Identity $group.mail -Member $upn -BypassSecurityGroupManagerCheck -Confirm:$false -ErrorAction Stop; "Removed from $name"
                }
                continue
            }
            Invoke-LifecycleStep @common -Step 'RemoveFromGroup' -Detail $name -Action {
                Invoke-MgGraphRequest -Method DELETE -Uri "$graphBase/groups/$($group.id)/members/$($account.id)/`$ref" | Out-Null; "Removed from $name"
            }
            Start-Sleep -Milliseconds 200
        }
    }
    if ($managerUpn -and $synced) { Add-StepResult @row -Step 'ClearManager' -Result 'Skipped' -Detail $syncedNote }
    elseif ($managerUpn) {
        Invoke-LifecycleStep @common -Step 'ClearManager' -Detail "Remove manager $managerUpn" -Action {
            Invoke-MgGraphRequest -Method DELETE -Uri "$userUri/manager/`$ref" | Out-Null; 'Manager removed'
        }
    }
    if (-not $SkipMfaReset) {
        $methods = @(Invoke-GraphPaged -Uri "$userUri/authentication/methods" | Where-Object { $methodPaths.ContainsKey([string]$_.'@odata.type') })
        if ($methods.Count -eq 0) { Add-StepResult @row -Step 'RemoveAuthMethods' -Result 'Skipped' -Detail 'No removable methods registered' }
        else {
            Invoke-LifecycleStep @common -Step 'RemoveAuthMethods' -Detail "Delete $($methods.Count) method(s)" -Action {
                foreach ($method in $methods) {
                    Invoke-MgGraphRequest -Method DELETE -Uri "$userUri/authentication/$($methodPaths[[string]$method.'@odata.type'])/$($method.id)" | Out-Null
                }
                "Removed $($methods.Count) method(s)"
            }
        }
    }
    if ($exoReady) {
        if ($ConvertMailboxToShared) {
            Invoke-LifecycleStep @common -Step 'ConvertMailbox' -Detail 'Type Shared, hidden from address lists' -Action {
                Set-Mailbox -Identity $upn -Type Shared -ErrorAction Stop
                Set-Mailbox -Identity $upn -HiddenFromAddressListsEnabled $true -ErrorAction Stop; 'Shared mailbox, hidden from GAL'
            }
        }
        $forwardTo = ([string]$entry.ForwardTo).Trim()
        if ($forwardTo) {
            Invoke-LifecycleStep @common -Step 'ForwardMail' -Detail "Forward to $forwardTo and keep a copy" -Action {
                Set-Mailbox -Identity $upn -ForwardingSmtpAddress $forwardTo -DeliverToMailboxAndForward $true -ErrorAction Stop; "Forwarding to $forwardTo"
            }
        }
        if (-not [string]::IsNullOrWhiteSpace($AutoReplyMessage)) {
            Invoke-LifecycleStep @common -Step 'SetAutoReply' -Detail 'Enable internal and external auto-reply' -Action {
                Set-MailboxAutoReplyConfiguration -Identity $upn -AutoReplyState Enabled -InternalMessage $AutoReplyMessage -ExternalMessage $AutoReplyMessage -ErrorAction Stop; 'Auto-reply enabled'
            }
        }
        if ($GrantManagerAccess -and $managerUpn) {
            Invoke-LifecycleStep @common -Step 'GrantManagerAccess' -Detail "FullAccess for $managerUpn" -Action {
                Add-MailboxPermission -Identity $upn -User $managerUpn -AccessRights FullAccess -InheritanceType All -AutoMapping $true -ErrorAction Stop | Out-Null
                "FullAccess granted to $managerUpn"
            }
        }
    }
    if (-not $SkipLicenses) {
        # Only direct assignments can be removed here; group-based ones follow the group membership removed above.
        $directSkus = @($account.licenseAssignmentStates | Where-Object { $null -eq $_.assignedByGroup } | Select-Object -ExpandProperty skuId -Unique)
        if ($directSkus.Count -eq 0) { Add-StepResult @row -Step 'RemoveLicenses' -Result 'Skipped' -Detail 'No directly assigned licenses' }
        else {
            $names = @($directSkus | ForEach-Object { if ($skuNames.ContainsKey([string]$_)) { $skuNames[[string]$_] } else { $_ } }) -join ', '
            Invoke-LifecycleStep @common -Step 'RemoveLicenses' -Detail $names -Action {
                $body = ConvertTo-Json -InputObject @{ addLicenses = @(); removeLicenses = @($directSkus) } -Depth 3
                Invoke-MgGraphRequest -Method POST -Uri "$userUri/assignLicense" -Body $body -ContentType 'application/json' | Out-Null; "Removed $names"
            }
        }
    }
}
Write-Progress -Activity 'Offboarding users' -Completed

$results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
$counts = foreach ($state in 'Success', 'Failed', 'Skipped', 'WhatIf') { '{0}: {1}' -f $state, @($results | Where-Object { $_.Result -eq $state }).Count }
Write-Host ('Users: {0}  Steps: {1}  {2}' -f $entries.Count, $results.Count, ($counts -join '  ')) -ForegroundColor Cyan
Write-Host "Step results: $OutputPath" -ForegroundColor Cyan
Write-Host 'OneDrive hand-over: run Add-SPOSiteCollectionAdmin.ps1 (Teams-SharePoint) to give the manager access to the personal site.' -ForegroundColor DarkGray
if ($PassThru) { $results }
#endregion Main
