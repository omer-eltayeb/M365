<#
.SYNOPSIS
    Onboards new hires end to end: creates the account, sets manager, licenses, groups and teams and optionally sends a welcome mail.
.DESCRIPTION
    Takes one user from parameters or many from a CSV with the columns DisplayName, UserPrincipalName, GivenName, Surname,
    JobTitle, Department, UsageLocation, ManagerUpn, LicenseSku, Groups, Teams and SendWelcomeTo (multi-value cells use ';').
    Per user it runs these Microsoft Graph v1.0 steps: POST /users with a generated temporary password (or -InitialPassword) or
    reuse of an existing account (-AllowExisting), PUT manager/$ref, POST assignLicense after checking the free units in
    /subscribedSkus, POST /groups/{id}/members/$ref (dynamic and synced groups are skipped), POST /teams/{id}/members and, with
    -SendWelcomeEmail, POST /me/sendMail with an HTML template. Every change runs inside ShouldProcess (-WhatIf previews,
    -Confirm:$false runs unattended); each step becomes a row (User, Step, Result, Detail) and a failing step never stops the run.
.PARAMETER InputCsv
    CSV with one user per row (columns listed above; only DisplayName and UserPrincipalName are mandatory).
.PARAMETER DisplayName
    Display name of the single user to onboard.
.PARAMETER UserPrincipalName
    UPN of the single user; the part before @ becomes the mailNickname.
.PARAMETER GivenName
    First name.
.PARAMETER Surname
    Last name.
.PARAMETER JobTitle
    Job title.
.PARAMETER Department
    Department.
.PARAMETER UsageLocation
    Two-letter ISO country code; Microsoft requires it before a license can be assigned.
.PARAMETER ManagerUpn
    UPN of the manager.
.PARAMETER LicenseSku
    One or more skuPartNumber values, for example SPE_E3 or EMSPREMIUM.
.PARAMETER Groups
    Display names of security or Microsoft 365 groups to join.
.PARAMETER Teams
    Display names of teams to join.
.PARAMETER SendWelcomeTo
    Address that receives the welcome mail, for example the manager or a private address. Needs -SendWelcomeEmail.
.PARAMETER InitialPassword
    SecureString used as the temporary password instead of a random one (applies to every account created in the run).
.PARAMETER AllowExisting
    Continue with the remaining steps when the UPN already exists instead of reporting a failure.
.PARAMETER SendWelcomeEmail
    Send the welcome mail from the signed-in account to SendWelcomeTo (adds the Mail.Send scope).
.PARAMETER WelcomeTemplatePath
    HTML file whose {DisplayName}, {UserPrincipalName} and {TemporaryPassword} placeholders are replaced.
.PARAMETER PasswordOutputPath
    CSV that receives UserPrincipalName and TemporaryPassword in clear text. Without it the passwords are shown once in the console.
.PARAMETER OutputPath
    Path of the step results CSV. Defaults to .\Reports\M365UserOnboarding_<timestamp>.csv.
.PARAMETER PassThru
    Also emit the step result objects to the pipeline.
.EXAMPLE
    PS> .\Invoke-M365UserOnboarding.ps1 -InputCsv .\NewHires.csv -WhatIf
    Validates the CSV against the tenant (SKUs, groups, teams, existing UPNs) and lists every step that would run.
.EXAMPLE
    PS> .\Invoke-M365UserOnboarding.ps1 -DisplayName 'Dana Vogel' -UserPrincipalName dvogel@contoso.com -UsageLocation DE -ManagerUpn lead@contoso.com -LicenseSku SPE_E3 -Teams Finance -Confirm:$false
    Creates the account, sets the manager, assigns Microsoft 365 E3 and joins the Finance team without prompting; prints the temporary password.
.EXAMPLE
    PS> .\Invoke-M365UserOnboarding.ps1 -InputCsv .\NewHires.csv -SendWelcomeEmail -WelcomeTemplatePath .\Welcome.html -PasswordOutputPath C:\Secure\pw.csv -Confirm:$false
    Bulk onboarding with welcome mails; the temporary passwords go to the protected folder instead of the console.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : User.ReadWrite.All, Group.ReadWrite.All, TeamMember.ReadWrite.All, Organization.Read.All (delegated), plus Mail.Send
                  with -SendWelcomeEmail. User Administrator can create users and assign licenses; adding members to groups and
                  teams the admin does not own needs Groups Administrator or Teams Administrator.
    Category    : User lifecycle & tenant hygiene
    Changes     : Yes
    Notes       : Temporary passwords are 16 random characters and must be changed at first sign-in; the welcome mail carries the
                  password in clear text, so send it to a trusted address. Free units are read once at start, so a long CSV can
                  still exhaust a SKU (Graph then reports the failure in the step row). Group-based licensing is not touched.
.LINK
    https://learn.microsoft.com/graph/api/user-post-users
.LINK
    https://learn.microsoft.com/graph/api/user-assignlicense
.LINK
    https://learn.microsoft.com/graph/api/team-post-members
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High', DefaultParameterSetName = 'Single')]
param(
    [Parameter(Mandatory = $true, ParameterSetName = 'Csv')]
    [ValidateScript({ Test-Path -Path $_ -PathType Leaf })]
    [string]$InputCsv,

    [Parameter(Mandatory = $true, ParameterSetName = 'Single')]
    [string]$DisplayName,

    [Parameter(Mandatory = $true, ParameterSetName = 'Single')]
    [ValidatePattern('^[^@\s]+@[^@\s]+$')]
    [string]$UserPrincipalName,

    [Parameter(ParameterSetName = 'Single')] [string]$GivenName,
    [Parameter(ParameterSetName = 'Single')] [string]$Surname,
    [Parameter(ParameterSetName = 'Single')] [string]$JobTitle,
    [Parameter(ParameterSetName = 'Single')] [string]$Department,
    [Parameter(ParameterSetName = 'Single')] [ValidateLength(2, 2)] [string]$UsageLocation,
    [Parameter(ParameterSetName = 'Single')] [string]$ManagerUpn,
    [Parameter(ParameterSetName = 'Single')] [string[]]$LicenseSku,
    [Parameter(ParameterSetName = 'Single')] [string[]]$Groups,
    [Parameter(ParameterSetName = 'Single')] [string[]]$Teams,
    [Parameter(ParameterSetName = 'Single')] [string]$SendWelcomeTo,

    [Parameter()] [securestring]$InitialPassword,
    [Parameter()] [switch]$AllowExisting,
    [Parameter()] [switch]$SendWelcomeEmail,
    [Parameter()] [string]$WelcomeTemplatePath,
    [Parameter()] [string]$PasswordOutputPath,
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

function Get-TemporaryPassword {
    <# 16 characters from a crypto RNG, four from each of upper, lower, digit and symbol, then shuffled. #>
    $sets = @('ABCDEFGHJKLMNPQRSTUVWXYZ', 'abcdefghijkmnopqrstuvwxyz', '23456789', '!@#$%&*-_?')
    $bytes = New-Object -TypeName byte[] -ArgumentList 16
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    $chars = for ($i = 0; $i -lt 16; $i++) { $set = $sets[$i % 4]; $set[$bytes[$i] % $set.Length] }
    return -join ($chars | Sort-Object -Property { Get-Random })
}

function Add-StepResult {
    param([string]$User, [string]$Step, [string]$Result, [string]$Detail)
    $script:results.Add([PSCustomObject]@{ User = $User; Step = $Step; Result = $Result; Detail = $Detail })
}

function Invoke-GraphChange {
    <# Sends one write request through the caller's ShouldProcess (so "Yes to All" persists), records a result row, never throws. #>
    param(
        [Parameter(Mandatory = $true)] [System.Management.Automation.PSCmdlet]$Cmdlet,
        [Parameter(Mandatory = $true)] [string]$User,
        [Parameter(Mandatory = $true)] [string]$Step,
        [Parameter(Mandatory = $true)] [string]$Detail,
        [Parameter(Mandatory = $true)] [string]$Method,
        [Parameter(Mandatory = $true)] [string]$Uri,
        [Parameter()] [hashtable]$Body
    )
    $result = 'Skipped'
    $response = $null
    if ($Cmdlet.ShouldProcess($User, "$Step - $Detail")) {
        try {
            $request = @{ Method = $Method; Uri = $Uri; OutputType = 'PSObject'; ErrorAction = 'Stop' }
            if ($null -ne $Body) { $request['Body'] = ConvertTo-Json -InputObject $Body -Depth 6; $request['ContentType'] = 'application/json' }
            $response = Invoke-MgGraphRequest @request
            $result = 'Success'
        }
        catch { $result = 'Failed'; $Detail = $_.Exception.Message; Write-Warning "$User | $Step failed: $Detail" }
    }
    elseif ($WhatIfPreference) { $result = 'WhatIf' }
    Add-StepResult -User $User -Step $Step -Result $result -Detail $Detail
    return $response
}

function Split-ListValue {
    param([AllowNull()] $Value)
    return @(([string]$Value) -split ';' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('M365UserOnboarding_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}
if ($PSCmdlet.ParameterSetName -eq 'Csv') { $entries = @(Import-Csv -Path $InputCsv) }
else {
    $entries = @([PSCustomObject]@{
            DisplayName = $DisplayName; UserPrincipalName = $UserPrincipalName; GivenName = $GivenName; Surname = $Surname
            JobTitle = $JobTitle; Department = $Department; UsageLocation = $UsageLocation; ManagerUpn = $ManagerUpn
            LicenseSku = ($LicenseSku -join ';'); Groups = ($Groups -join ';'); Teams = ($Teams -join ';'); SendWelcomeTo = $SendWelcomeTo
        })
}
$template = $null
if ($SendWelcomeEmail) {
    if ([string]::IsNullOrWhiteSpace($WelcomeTemplatePath)) { throw '-SendWelcomeEmail requires -WelcomeTemplatePath.' }
    $template = Get-Content -Path $WelcomeTemplatePath -Raw -ErrorAction Stop
}
$scopes = @('User.ReadWrite.All', 'Group.ReadWrite.All', 'TeamMember.ReadWrite.All', 'Organization.Read.All')
if ($SendWelcomeEmail) { $scopes += 'Mail.Send' }
try { Connect-GraphIfNeeded -Scopes $scopes } catch { throw "Could not connect to Microsoft Graph: $($_.Exception.Message)" }

$graphBase = 'https://graph.microsoft.com/v1.0'
$skus = Invoke-GraphPaged -Uri "$graphBase/subscribedSkus?`$select=skuId,skuPartNumber,prepaidUnits,consumedUnits"
$script:results = New-Object -TypeName System.Collections.Generic.List[object]
$passwords = New-Object -TypeName System.Collections.Generic.List[object]
$plainInitial = $null
if ($null -ne $InitialPassword) { $plainInitial = (New-Object -TypeName System.Net.NetworkCredential -ArgumentList '', $InitialPassword).Password }
$index = 0
foreach ($entry in $entries) {
    $index++
    $upn = ([string]$entry.UserPrincipalName).Trim()
    if ([string]::IsNullOrWhiteSpace($upn)) { Write-Warning "Row $index has no UserPrincipalName; skipped."; continue }
    Write-Progress -Activity 'Onboarding users' -Status $upn -PercentComplete (($index / $entries.Count) * 100)
    $step = @{ Cmdlet = $PSCmdlet; User = $upn }
    $row = @{ User = $upn }
    $password = $null
    $userId = $null
    $safeUpn = $upn.Replace("'", "''")
    $existing = @(Invoke-GraphPaged -Uri "$graphBase/users?`$filter=userPrincipalName eq '$safeUpn'&`$select=id")
    if ($existing.Count -gt 0) {
        if (-not $AllowExisting) { Add-StepResult @row -Step 'CreateUser' -Result 'Failed' -Detail 'UPN already exists (use -AllowExisting)'; continue }
        $userId = $existing[0].id
        Add-StepResult @row -Step 'CreateUser' -Result 'Skipped' -Detail 'Existing account reused'
    }
    else {
        $password = if ($null -ne $plainInitial) { $plainInitial } else { Get-TemporaryPassword }
        $body = @{
            accountEnabled = $true; displayName = [string]$entry.DisplayName; userPrincipalName = $upn; mailNickname = $upn.Split('@')[0]
            passwordProfile = @{ forceChangePasswordNextSignIn = $true; password = $password }
        }
        foreach ($name in 'givenName', 'surname', 'jobTitle', 'department', 'usageLocation') {
            if (-not [string]::IsNullOrWhiteSpace([string]$entry.$name)) { $body[$name] = ([string]$entry.$name).Trim() }
        }
        $created = Invoke-GraphChange @step -Step 'CreateUser' -Detail "Create '$($entry.DisplayName)'" -Method POST -Uri "$graphBase/users" -Body $body
        if ($null -ne $created) {
            $userId = $created.id
            $passwords.Add([PSCustomObject]@{ UserPrincipalName = $upn; TemporaryPassword = $password })
        }
        elseif (-not $WhatIfPreference) { continue }   # creation failed or was declined; the dependent steps make no sense
    }
    $managerUpn = ([string]$entry.ManagerUpn).Trim()
    if ($managerUpn) {
        $safeManager = $managerUpn.Replace("'", "''")
        $manager = @(Invoke-GraphPaged -Uri "$graphBase/users?`$filter=userPrincipalName eq '$safeManager'&`$select=id") | Select-Object -First 1
        if ($null -eq $manager) { Add-StepResult @row -Step 'SetManager' -Result 'Failed' -Detail "$managerUpn not found" }
        else {
            $managerRef = @{ '@odata.id' = "$graphBase/users/$($manager.id)" }
            $null = Invoke-GraphChange @step -Step 'SetManager' -Detail $managerUpn -Method PUT -Uri "$graphBase/users/$userId/manager/`$ref" -Body $managerRef
        }
    }
    foreach ($skuName in (Split-ListValue -Value $entry.LicenseSku)) {
        $sku = $skus | Where-Object { $_.skuPartNumber -eq $skuName } | Select-Object -First 1
        if ($null -eq $sku) { Add-StepResult @row -Step 'AssignLicense' -Result 'Failed' -Detail "$skuName not found in /subscribedSkus"; continue }
        $free = $sku.prepaidUnits.enabled - $sku.consumedUnits
        if ($free -le 0) { Add-StepResult @row -Step 'AssignLicense' -Result 'Failed' -Detail "$skuName has no free units"; continue }
        $licenseBody = @{ addLicenses = @(@{ skuId = $sku.skuId; disabledPlans = @() }); removeLicenses = @() }
        $null = Invoke-GraphChange @step -Step 'AssignLicense' -Detail "$skuName ($free free)" -Method POST -Uri "$graphBase/users/$userId/assignLicense" -Body $licenseBody
    }
    foreach ($kind in 'Groups', 'Teams') {
        $stepName = if ($kind -eq 'Groups') { 'AddToGroup' } else { 'AddToTeam' }
        foreach ($groupName in (Split-ListValue -Value $entry.$kind)) {
            $safeName = $groupName.Replace("'", "''")
            $groupUri = "$graphBase/groups?`$filter=displayName eq '$safeName'&`$select=id,groupTypes,onPremisesSyncEnabled,resourceProvisioningOptions"
            $group = @(Invoke-GraphPaged -Uri $groupUri) | Select-Object -First 1
            if ($null -eq $group) { Add-StepResult @row -Step $stepName -Result 'Failed' -Detail "$groupName not found"; continue }
            if ($group.groupTypes -contains 'DynamicMembership' -or $group.onPremisesSyncEnabled) {
                Add-StepResult @row -Step $stepName -Result 'Skipped' -Detail "$groupName is dynamic or synced from on-premises"; continue
            }
            if ($kind -eq 'Groups') {
                $memberRef = @{ '@odata.id' = "$graphBase/directoryObjects/$userId" }
                $null = Invoke-GraphChange @step -Step $stepName -Detail $groupName -Method POST -Uri "$graphBase/groups/$($group.id)/members/`$ref" -Body $memberRef
                continue
            }
            if ($group.resourceProvisioningOptions -notcontains 'Team') { Add-StepResult @row -Step $stepName -Result 'Failed' -Detail "$groupName is not a team"; continue }
            $member = @{ '@odata.type' = '#microsoft.graph.aadUserConversationMember'; roles = @(); 'user@odata.bind' = "$graphBase/users('$userId')" }
            $null = Invoke-GraphChange @step -Step $stepName -Detail $groupName -Method POST -Uri "$graphBase/teams/$($group.id)/members" -Body $member
        }
    }
    $welcomeTo = ([string]$entry.SendWelcomeTo).Trim()
    if ($SendWelcomeEmail -and $welcomeTo) {
        $passwordText = if ($null -ne $password) { $password } else { 'unchanged (existing account)' }
        $html = $template.Replace('{DisplayName}', [string]$entry.DisplayName).Replace('{UserPrincipalName}', $upn).Replace('{TemporaryPassword}', $passwordText)
        $message = @{
            subject      = 'Welcome - your new Microsoft 365 account'
            body         = @{ contentType = 'HTML'; content = $html }
            toRecipients = @(@{ emailAddress = @{ address = $welcomeTo } })
        }
        $null = Invoke-GraphChange @step -Step 'WelcomeEmail' -Detail "Send to $welcomeTo" -Method POST -Uri "$graphBase/me/sendMail" -Body @{ message = $message; saveToSentItems = $true }
    }
    Start-Sleep -Milliseconds 200
}
Write-Progress -Activity 'Onboarding users' -Completed

$results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
if ($passwords.Count -gt 0 -and [string]::IsNullOrWhiteSpace($PasswordOutputPath)) {
    Write-Warning 'Temporary passwords are shown once and not saved; use -PasswordOutputPath to write them to a file.'
    $passwords | ForEach-Object { Write-Host ('  {0}  {1}' -f $_.UserPrincipalName, $_.TemporaryPassword) -ForegroundColor Yellow }
}
elseif ($passwords.Count -gt 0) {
    $passwords | Export-Csv -Path $PasswordOutputPath -NoTypeInformation -Encoding UTF8
    Write-Warning "Temporary passwords were written in clear text to $PasswordOutputPath - share securely and delete the file."
}
$counts = foreach ($state in 'Success', 'Failed', 'Skipped', 'WhatIf') { '{0}: {1}' -f $state, @($results | Where-Object { $_.Result -eq $state }).Count }
Write-Host ('Users: {0}  Steps: {1}  {2}' -f $entries.Count, $results.Count, ($counts -join '  ')) -ForegroundColor Cyan
Write-Host "Step results: $OutputPath" -ForegroundColor Cyan
if ($PassThru) { $results }
#endregion Main
