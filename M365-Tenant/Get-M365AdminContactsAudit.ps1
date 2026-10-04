<#
.SYNOPSIS
    Audits who receives tenant notifications and who holds the keys: contact addresses, Global Administrators and emergency access accounts.
.DESCRIPTION
    Reads the technical, security and compliance, marketing and privacy contacts from /organization, the alternate notification
    e-mails of /groupLifecyclePolicies and the reviewers of /policies/adminConsentRequestPolicy, lists every active Global
    Administrator (/roleManagement/directory/roleAssignments) with account state and MFA registration, and searches for emergency
    access (break-glass) accounts by display name. With -IncludeExchange it adds the Exchange Online notification recipients
    (Get-OrganizationConfig, Get-TransportConfig, Get-HostedOutboundSpamFilterPolicy, Get-MalwareFilterPolicy). Every address is
    resolved in the directory and rated: Ok, Empty, PointsToPersonalMailbox, PointsToDisabledUser, External, NoMfa or Review.
    Outputs rows (Area, Setting, Value, Status, Recommendation) to CSV and prints the findings that need action.
.PARAMETER IncludeExchange
    Also audit Exchange Online notification settings (needs the ExchangeOnlineManagement module; skipped with a warning otherwise).
.PARAMETER OutputPath
    Path of the CSV file. Defaults to .\Reports\M365AdminContactsAudit_<timestamp>.csv.
.PARAMETER PassThru
    Also emit the row objects to the pipeline.
.EXAMPLE
    PS> .\Get-M365AdminContactsAudit.ps1
    Audits the Graph-visible contacts, Global Administrators and break-glass accounts and writes the CSV.
.EXAMPLE
    PS> .\Get-M365AdminContactsAudit.ps1 -IncludeExchange -OutputPath C:\Temp\Contacts.csv -Verbose
    Additionally checks the Exchange Online notification recipients and the journaling NDR mailbox.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication; ExchangeOnlineManagement 3.x only for -IncludeExchange
    Permissions : Organization.Read.All, Directory.Read.All, RoleManagement.Read.Directory, User.Read.All, AuditLog.Read.All,
                  Policy.Read.All (delegated); Global Reader covers them. -IncludeExchange needs View-Only Organization Management.
    Category    : User lifecycle & tenant hygiene
    Changes     : No
    Notes       : Without Exchange Online the shared-mailbox test is a heuristic (disabled, unlicensed account = shared mailbox);
                  with -IncludeExchange the real recipient type is used. MFA registration needs Entra ID P1 and shows 'unknown'
                  otherwise. Break-glass detection matches display names containing 'emergency' or 'break glass'; Message Center
                  and service health e-mail preferences are per admin and not exposed through Graph.
.LINK
    https://learn.microsoft.com/graph/api/organization-get
.LINK
    https://learn.microsoft.com/graph/api/adminconsentrequestpolicy-get
.LINK
    https://learn.microsoft.com/entra/identity/role-based-access-control/security-emergency-access
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [Parameter()]
    [switch]$IncludeExchange,

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

function Add-Row {
    param([string]$Area, [string]$Setting, [AllowNull()] $Value, [string]$Status, [string]$Recommendation = '')
    $script:rows.Add([PSCustomObject]@{ Area = $Area; Setting = $Setting; Value = [string]$Value; Status = $Status; Recommendation = $Recommendation })
}

function Get-AddressStatus {
    <# Rates a notification address: groups and shared mailboxes are Ok, personal and disabled user mailboxes are flagged. #>
    param([string]$Address)
    $key = $Address.Trim().ToLowerInvariant()
    if ($script:addressCache.ContainsKey($key)) { return $script:addressCache[$key] }
    $safe = $Address.Trim().Replace("'", "''")
    $user = @(Invoke-GraphPaged -Uri "$graphBase/users?`$filter=mail eq '$safe' or userPrincipalName eq '$safe'&`$select=id,accountEnabled,assignedLicenses") | Select-Object -First 1
    $group = $null
    if ($null -eq $user) { $group = @(Invoke-GraphPaged -Uri "$graphBase/groups?`$filter=mail eq '$safe'&`$select=id,displayName") | Select-Object -First 1 }
    $status = 'External'
    $detail = 'not found in the tenant - external address or mail contact'
    if ($null -ne $group) { $status = 'Ok'; $detail = "group '$($group.displayName)'" }
    elseif ($null -ne $user) {
        $kind = 'user mailbox'
        if ($script:exoReady) {
            $recipient = Get-EXORecipient -ExternalDirectoryObjectId $user.id -ErrorAction SilentlyContinue
            if ($null -ne $recipient) { $kind = [string]$recipient.RecipientTypeDetails }
        }
        elseif (-not $user.accountEnabled -and @($user.assignedLicenses).Count -eq 0) { $kind = 'SharedMailbox' }   # heuristic without Exchange
        if ($kind -match 'Shared|Room|Equipment') { $status = 'Ok'; $detail = $kind }
        elseif (-not $user.accountEnabled) { $status = 'PointsToDisabledUser'; $detail = "disabled account ($kind)" }
        else { $status = 'PointsToPersonalMailbox'; $detail = "enabled $kind - notifications stop when the person leaves" }
    }
    $result = [PSCustomObject]@{ Status = $status; Detail = $detail }
    $script:addressCache[$key] = $result
    return $result
}

function Add-AddressRow {
    <# One row per address (or a single Empty row) for a notification setting. #>
    param([string]$Area, [string]$Setting, [AllowNull()] [object[]]$Addresses, [string]$Recommendation)
    $list = @($Addresses | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
    if ($list.Count -eq 0) { Add-Row -Area $Area -Setting $Setting -Value '' -Status 'Empty' -Recommendation $Recommendation; return }
    foreach ($address in $list) {
        $rating = Get-AddressStatus -Address ([string]$address)
        $note = if ($rating.Status -eq 'Ok') { $rating.Detail } else { "$($rating.Detail). $Recommendation" }
        Add-Row -Area $Area -Setting $Setting -Value $address -Status $rating.Status -Recommendation $note
    }
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('M365AdminContactsAudit_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}
$scopes = @('Organization.Read.All', 'Directory.Read.All', 'RoleManagement.Read.Directory', 'User.Read.All', 'AuditLog.Read.All', 'Policy.Read.All')
try { Connect-GraphIfNeeded -Scopes $scopes } catch { throw "Could not connect to Microsoft Graph: $($_.Exception.Message)" }
$script:exoReady = $false
if ($IncludeExchange) {
    if ($null -eq (Get-Module -ListAvailable -Name ExchangeOnlineManagement)) { Write-Warning 'ExchangeOnlineManagement is not installed; Exchange settings are skipped.' }
    else {
        try { Connect-ExchangeIfNeeded; $script:exoReady = $true } catch { Write-Warning "Exchange Online connection failed; Exchange settings are skipped: $($_.Exception.Message)" }
    }
}
$graphBase = 'https://graph.microsoft.com/v1.0'
$script:rows = New-Object -TypeName System.Collections.Generic.List[object]
$script:addressCache = @{}
$advice = @{
    Shared     = 'Point tenant notifications to a monitored shared mailbox or distribution list.'
    Phone      = 'Microsoft calls this number for urgent security notices.'
    Marketing  = 'Optional; a shared mailbox avoids losing product notices.'
    Privacy    = 'Shown to users behind the privacy statement link; required by many regulators.'
    Lifecycle  = 'Configure Microsoft 365 group expiration so ownerless, unused groups are cleaned up.'
    Consent    = 'Enable the admin consent workflow so users can request app consent instead of being blocked silently.'
    Reviewer   = 'Group or role based reviewer - verify its members.'
    AdminGroup = 'Group or service principal holds Global Administrator - verify members and owners.'
    Disabled   = 'Remove the role from disabled accounts.'
    NoMfa      = 'Register MFA or remove the role; Global Administrators without MFA are the top attack path.'
    TooMany    = 'Microsoft recommends fewer than five Global Administrators; use PIM and least-privileged roles.'
    NoGlass    = 'Create two cloud-only emergency access accounts with Global Administrator, excluded from Conditional Access and monitored.'
    Glass      = 'Emergency accounts must be cloud-only, enabled, Global Administrator, excluded from Conditional Access and alerted on use.'
    Journal    = 'Required when journaling is used; must be a dedicated mailbox that is not journaled itself.'
}

$orgSelect = 'displayName,technicalNotificationMails,securityComplianceNotificationMails,securityComplianceNotificationPhones,marketingNotificationEmails,privacyProfile'
$org = @(Invoke-GraphPaged -Uri "$graphBase/organization?`$select=$orgSelect")[0]
Add-AddressRow -Area 'Organization' -Setting 'Technical notification e-mail' -Addresses $org.technicalNotificationMails -Recommendation $advice.Shared
Add-AddressRow -Area 'Organization' -Setting 'Security and compliance notification e-mail' -Addresses $org.securityComplianceNotificationMails -Recommendation $advice.Shared
$phones = @($org.securityComplianceNotificationPhones | Where-Object { $_ }) -join '; '
Add-Row -Area 'Organization' -Setting 'Security and compliance notification phone' -Value $phones -Status $(if ($phones) { 'Ok' } else { 'Empty' }) -Recommendation $advice.Phone
Add-AddressRow -Area 'Organization' -Setting 'Marketing notification e-mail' -Addresses $org.marketingNotificationEmails -Recommendation $advice.Marketing
Add-AddressRow -Area 'Organization' -Setting 'Privacy contact' -Addresses @($org.privacyProfile.contactEmail) -Recommendation $advice.Privacy

try {
    $lifecycle = @(Invoke-GraphPaged -Uri "$graphBase/groupLifecyclePolicies")
    if ($lifecycle.Count -eq 0) { Add-Row -Area 'Group lifecycle' -Setting 'Expiration policy' -Value 'Not configured' -Status 'Review' -Recommendation $advice.Lifecycle }
    foreach ($policy in $lifecycle) {
        $policyNote = "Ownerless groups ($($policy.managedGroupTypes), $($policy.groupLifetimeInDays) days) send their renewal notices here."
        Add-AddressRow -Area 'Group lifecycle' -Setting 'Alternate notification e-mail' -Addresses @(([string]$policy.alternateNotificationEmails) -split ';') -Recommendation $policyNote
    }
}
catch { Add-Row -Area 'Group lifecycle' -Setting 'Expiration policy' -Value '' -Status 'NoAccess' -Recommendation $_.Exception.Message }

try {
    $consent = Invoke-MgGraphRequest -Method GET -Uri "$graphBase/policies/adminConsentRequestPolicy" -OutputType PSObject
    if (-not $consent.isEnabled) { Add-Row -Area 'Admin consent requests' -Setting 'Workflow' -Value 'Disabled' -Status 'Review' -Recommendation $advice.Consent }
    $consentNote = "Notify reviewers $($consent.notifyReviewers); reminders $($consent.remindersEnabled); requests expire after $($consent.requestDurationInDays) days"
    foreach ($reviewer in @($consent.reviewers)) {
        if ($reviewer.query -notmatch '/users/([0-9a-f-]{36})') {
            Add-Row -Area 'Admin consent requests' -Setting 'Reviewer' -Value $reviewer.query -Status 'Review' -Recommendation $advice.Reviewer
            continue
        }
        $reviewerUser = Invoke-MgGraphRequest -Method GET -Uri "$graphBase/users/$($Matches[1])?`$select=userPrincipalName,accountEnabled" -OutputType PSObject
        $status = if ($reviewerUser.accountEnabled) { 'Ok' } else { 'PointsToDisabledUser' }
        Add-Row -Area 'Admin consent requests' -Setting 'Reviewer' -Value $reviewerUser.userPrincipalName -Status $status -Recommendation $consentNote
    }
}
catch { Add-Row -Area 'Admin consent requests' -Setting 'Workflow' -Value '' -Status 'NoAccess' -Recommendation $_.Exception.Message }

$mfaAvailable = $true
$globalAdmins = @(Invoke-GraphPaged -Uri "$graphBase/roleManagement/directory/roleAssignments?`$filter=roleDefinitionId eq '62e90394-69f5-4237-9190-012177145e10'&`$expand=principal")
foreach ($assignment in $globalAdmins) {
    $principal = $assignment.principal
    if ($principal.'@odata.type' -ne '#microsoft.graph.user') {
        $kind = ([string]$principal.'@odata.type').Replace('#microsoft.graph.', '')
        Add-Row -Area 'Global Administrators' -Setting $principal.displayName -Value $kind -Status 'Review' -Recommendation $advice.AdminGroup
        continue
    }
    $mfa = 'unknown'
    if ($mfaAvailable) {
        try { $mfa = [string](Invoke-MgGraphRequest -Method GET -Uri "$graphBase/reports/authenticationMethods/userRegistrationDetails/$($principal.id)" -OutputType PSObject).isMfaRegistered }
        catch { $mfaAvailable = $false; Write-Warning "MFA registration details are not available (Entra ID P1 and AuditLog.Read.All needed): $($_.Exception.Message)" }
    }
    $status = if (-not $principal.accountEnabled) { 'PointsToDisabledUser' } elseif ($mfa -eq 'False') { 'NoMfa' } else { 'Ok' }
    $note = switch ($status) { 'PointsToDisabledUser' { $advice.Disabled } 'NoMfa' { $advice.NoMfa } default { '' } }
    $value = "mail $($principal.mail); enabled $($principal.accountEnabled); MFA registered $mfa"
    Add-Row -Area 'Global Administrators' -Setting $principal.userPrincipalName -Value $value -Status $status -Recommendation $note
    Start-Sleep -Milliseconds 200
}
if ($globalAdmins.Count -gt 5) { Add-Row -Area 'Global Administrators' -Setting 'Count' -Value $globalAdmins.Count -Status 'Review' -Recommendation $advice.TooMany }

$searchUri = "$graphBase/users?`$search=`"displayName:emergency`" OR `"displayName:break`" OR `"displayName:breakglass`"&`$select=id,displayName,userPrincipalName,accountEnabled,onPremisesSyncEnabled"
$breakGlass = @(Invoke-GraphPaged -Uri $searchUri -Headers @{ ConsistencyLevel = 'eventual' } | Where-Object { $_.displayName -match 'emergency|break.?glass' })
$adminIds = @($globalAdmins | ForEach-Object { $_.principalId })
if ($breakGlass.Count -eq 0) { Add-Row -Area 'Emergency access' -Setting 'Break-glass accounts' -Value 'None found' -Status 'Review' -Recommendation $advice.NoGlass }
foreach ($account in $breakGlass) {
    $isAdmin = $adminIds -contains $account.id
    $cloudOnly = -not $account.onPremisesSyncEnabled
    $status = if ($isAdmin -and $account.accountEnabled -and $cloudOnly) { 'Ok' } else { 'Review' }
    $value = "Global Administrator $isAdmin; enabled $($account.accountEnabled); cloud-only $cloudOnly"
    Add-Row -Area 'Emergency access' -Setting $account.userPrincipalName -Value $value -Status $status -Recommendation $advice.Glass
}

if ($script:exoReady) {
    $orgConfig = Get-OrganizationConfig
    $exoNote = "ExchangeNotificationEnabled is $($orgConfig.ExchangeNotificationEnabled). $($advice.Shared)"
    Add-AddressRow -Area 'Exchange Online' -Setting 'Exchange notification recipients' -Addresses $orgConfig.ExchangeNotificationRecipients -Recommendation $exoNote
    $ndr = [string](Get-TransportConfig).JournalingReportNdrTo
    $ndrStatus = if ($ndr -and $ndr -ne '<>') { (Get-AddressStatus -Address $ndr).Status } else { 'Empty' }
    Add-Row -Area 'Exchange Online' -Setting 'Journaling report NDR mailbox' -Value $ndr -Status $ndrStatus -Recommendation $advice.Journal
    foreach ($policy in @(Get-HostedOutboundSpamFilterPolicy | Where-Object { $_.NotifyOutboundSpam })) {
        Add-AddressRow -Area 'Exchange Online' -Setting "Outbound spam notifications ($($policy.Name))" -Addresses $policy.NotifyOutboundSpamRecipients -Recommendation $advice.Shared
    }
    foreach ($policy in @(Get-MalwareFilterPolicy)) {
        if ($policy.EnableInternalSenderAdminNotifications) {
            Add-AddressRow -Area 'Exchange Online' -Setting "Malware admin notifications, internal ($($policy.Name))" -Addresses @($policy.InternalSenderAdminAddress) -Recommendation $advice.Shared
        }
        if ($policy.EnableExternalSenderAdminNotifications) {
            Add-AddressRow -Area 'Exchange Online' -Setting "Malware admin notifications, external ($($policy.Name))" -Addresses @($policy.ExternalSenderAdminAddress) -Recommendation $advice.Shared
        }
    }
}

$rows | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
$summary = $rows | Group-Object -Property Status | Sort-Object -Property Name | ForEach-Object { '{0}: {1}' -f $_.Name, $_.Count }
Write-Host ("Settings audited: {0}  {1}" -f $rows.Count, ($summary -join '  ')) -ForegroundColor Cyan
foreach ($row in ($rows | Where-Object { $_.Status -notin 'Ok', 'NoAccess' })) {
    Write-Host ('  {0,-22} {1} | {2} = {3}' -f $row.Status, $row.Area, $row.Setting, $row.Value) -ForegroundColor Yellow
}
Write-Host "Report: $OutputPath" -ForegroundColor Cyan
if ($PassThru) { $rows }
#endregion Main
