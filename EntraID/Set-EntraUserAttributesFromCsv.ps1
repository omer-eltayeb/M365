<#
.SYNOPSIS
    Bulk-updates user profile attributes (job title, department, address, phones, employee data and more) from a CSV file.
.DESCRIPTION
    Reads a CSV with a UserPrincipalName column plus any of the supported attribute columns (displayName, givenName, surname, jobTitle,
    department, companyName, officeLocation, streetAddress, city, state, postalCode, country, usageLocation, mobilePhone, businessPhones
    as a semicolon-separated list, employeeId, employeeType, preferredLanguage). Unknown columns stop the script before any change.
    For each user the current values are read (GET /users/{upn}), unchanged and empty cells are skipped, old and new values are shown,
    and the remaining attributes are written with a single PATCH /users/{id}. Accounts synced from on-premises AD are skipped (only
    usageLocation is cloud-mastered). One result object per attribute change is emitted; -WhatIf / -Confirm are honoured.
.PARAMETER InputCsv
    Path of the CSV file. Column headers are case-insensitive; an empty cell leaves the attribute unchanged.
.EXAMPLE
    PS> .\Set-EntraUserAttributesFromCsv.ps1 -InputCsv C:\Temp\hr-update.csv -WhatIf
    Shows every attribute that would change (old -> new) without updating anything.
.EXAMPLE
    PS> .\Set-EntraUserAttributesFromCsv.ps1 -InputCsv C:\Temp\hr-update.csv -Confirm:$false | Export-Csv C:\Temp\hr-update-result.csv -NoTypeInformation
    Applies all changes without prompting and saves the per-attribute results.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : User.ReadWrite.All (delegated); the signed-in admin needs the User Administrator role.
    Category    : Users & authentication
    Changes     : Yes
    Notes       : Comparison is case-sensitive, so a casing-only correction is applied. Clearing a value is not supported from the CSV
                  (empty means "keep"). usageLocation must be a two-letter ISO country code; employeeId and employeeType need the
                  User Administrator role even though they look like plain profile fields.
.LINK
    https://learn.microsoft.com/graph/api/user-update
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateScript({ Test-Path -Path $_ -PathType Leaf })]
    [string]$InputCsv
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

function New-ChangeRecord {
    <# Builds the per-attribute result object that the script emits. #>
    param([string]$UserPrincipalName, [string]$Attribute, [string]$OldValue, [string]$NewValue, [string]$Result, [string]$ErrorMessage)
    return [PSCustomObject]@{ UserPrincipalName = $UserPrincipalName; Attribute = $Attribute; OldValue = $OldValue; NewValue = $NewValue; Result = $Result; Error = $ErrorMessage }
}
#endregion Helpers

#region Main
$allowed = @('displayName', 'givenName', 'surname', 'jobTitle', 'department', 'companyName', 'officeLocation', 'streetAddress', 'city', 'state',
    'postalCode', 'country', 'usageLocation', 'mobilePhone', 'businessPhones', 'employeeId', 'employeeType', 'preferredLanguage')
$rows = @(Import-Csv -Path $InputCsv)
if ($rows.Count -eq 0) { throw "The file $InputCsv contains no rows." }
$columns = @($rows[0].PSObject.Properties.Name)
if ($columns -notcontains 'UserPrincipalName') { throw "The CSV must contain a 'UserPrincipalName' column." }
$unknown = @($columns | Where-Object { $_ -ne 'UserPrincipalName' -and $allowed -notcontains $_ })
if ($unknown.Count -gt 0) { throw ('Unsupported column(s): {0}. Supported: {1}.' -f ($unknown -join ', '), ($allowed -join ', ')) }
# Take the attribute names from $allowed (not from the header) so the PATCH body uses the exact Graph property casing.
$attributes = @($allowed | Where-Object { $columns -contains $_ })
if ($attributes.Count -eq 0) { throw 'The CSV contains no attribute columns to update.' }
try { Connect-GraphIfNeeded -Scopes @('User.ReadWrite.All') }
catch { throw "Unable to connect to Microsoft Graph: $($_.Exception.Message)" }
$v1 = 'https://graph.microsoft.com/v1.0'
$results = New-Object -TypeName System.Collections.Generic.List[object]
$processed = 0
foreach ($row in $rows) {
    $processed++
    $upn = ([string]$row.UserPrincipalName).Trim()
    Write-Progress -Activity 'Updating user attributes' -Status $upn -PercentComplete (($processed / $rows.Count) * 100)
    if ([string]::IsNullOrWhiteSpace($upn)) { Write-Warning "Row $processed has no UserPrincipalName and is skipped."; continue }
    try {
        $uri = "{0}/users/{1}?`$select=id,onPremisesSyncEnabled,{2}" -f $v1, ($upn -replace '#', '%23'), ($attributes -join ',')
        $user = Invoke-MgGraphRequest -Method GET -Uri $uri -OutputType PSObject -ErrorAction Stop
    }
    catch {
        $results.Add((New-ChangeRecord -UserPrincipalName $upn -Result 'Failed' -ErrorMessage "Lookup failed: $($_.Exception.Message)"))
        Write-Warning ('{0}: lookup failed. {1}' -f $upn, $_.Exception.Message)
        continue
    }
    $body = @{}
    $changes = New-Object -TypeName System.Collections.Generic.List[object]
    foreach ($attribute in $attributes) {
        $newValue = ([string]$row.$attribute).Trim()
        if ([string]::IsNullOrEmpty($newValue)) { continue }
        $patchValue = $newValue
        $oldValue = [string]$user.$attribute
        if ($attribute -eq 'businessPhones') {
            $patchValue = [string[]]@($newValue -split ';' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
            $newValue = $patchValue -join ';'
            $oldValue = @($user.businessPhones) -join ';'
        }
        if ($oldValue -ceq $newValue) { continue }
        $body[$attribute] = $patchValue
        $changes.Add((New-ChangeRecord -UserPrincipalName $upn -Attribute $attribute -OldValue $oldValue -NewValue $newValue -Result 'Pending'))
    }
    if ($changes.Count -eq 0) { $results.Add((New-ChangeRecord -UserPrincipalName $upn -Result 'Unchanged')); continue }
    foreach ($change in $changes) { $results.Add($change) }
    if ($user.onPremisesSyncEnabled) {
        # Only usageLocation is cloud-mastered for synced accounts; every other attribute has to be changed in on-premises AD.
        foreach ($change in @($changes | Where-Object { $_.Attribute -ne 'usageLocation' })) { $change.Result = 'SkippedSynced'; $body.Remove($change.Attribute) }
        if ($body.Count -eq 0) { Write-Warning ('{0} is synced from on-premises AD; change these attributes in Active Directory.' -f $upn); continue }
    }
    $pending = @($changes | Where-Object { $_.Result -eq 'Pending' })
    $summary = ($pending | ForEach-Object { '{0}: "{1}" -> "{2}"' -f $_.Attribute, $_.OldValue, $_.NewValue }) -join ', '
    Write-Verbose ('{0}: {1}' -f $upn, $summary)
    if (-not $PSCmdlet.ShouldProcess($upn, "Update $summary")) { foreach ($change in $pending) { $change.Result = 'WhatIf' }; continue }
    try {
        Invoke-MgGraphRequest -Method PATCH -Uri ('{0}/users/{1}' -f $v1, $user.id) -Body $body -ContentType 'application/json' -ErrorAction Stop | Out-Null
        foreach ($change in $pending) { $change.Result = 'Updated' }
    }
    catch {
        foreach ($change in $pending) { $change.Result = 'Failed'; $change.Error = $_.Exception.Message }
        Write-Warning ('{0}: update failed. {1}' -f $upn, $_.Exception.Message)
    }
    Start-Sleep -Milliseconds 200
}
Write-Progress -Activity 'Updating user attributes' -Completed

Write-Host 'Attribute update summary' -ForegroundColor Cyan
Write-Host ('  Users in file         : {0}' -f $rows.Count)
foreach ($group in ($results | Group-Object -Property Result | Sort-Object -Property Name)) {
    Write-Host ('  {0,-22}: {1}' -f $group.Name, $group.Count)
}
$results
#endregion Main
