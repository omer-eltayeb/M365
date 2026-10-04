<#
.SYNOPSIS
    Checks every Microsoft 365 group name against the tenant naming policy (prefix / suffix pattern and blocked words).
.DESCRIPTION
    Reads PrefixSuffixNamingRequirement and CustomBlockedWordsList from the Group.Unified settings (GET /groupSettings), turns the
    policy into a pattern (literal text is matched as-is, [GroupName] is the free part, attribute tokens such as [Department] match
    anything because the creator is unknown, or the first owner's values with -ResolveOwnerAttributes) and evaluates the display
    name of every Microsoft 365 group (GET /groups). Blocked words are matched case-insensitively as whole words, like Entra ID does.
    Rows list the violations (NoPrefix, NoSuffix, BlockedWord:<word>) and the owners of non-compliant groups. Exports a CSV.
.PARAMETER OnlyNonCompliant
    Export only the groups that violate the policy.
.PARAMETER ResolveOwnerAttributes
    Read the first owner's department, company, office, state, country and job title and use them for the attribute tokens.
    Costs one owners call per group (otherwise owners are read only for non-compliant groups).
.PARAMETER OutputPath
    Path of the CSV report. Defaults to .\Reports\M365GroupNamingCompliance_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emits the report objects to the pipeline.
.EXAMPLE
    PS> .\Get-M365GroupNamingPolicyCompliance.ps1 -OnlyNonCompliant
    Lists the Microsoft 365 groups whose names do not follow the naming policy, with the reason and their owners.
.EXAMPLE
    PS> .\Get-M365GroupNamingPolicyCompliance.ps1 -ResolveOwnerAttributes -OutputPath C:\Temp\Naming.csv -Verbose
    Evaluates all groups, resolving [Department]-style tokens from the first owner, and writes the full report.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : Directory.Read.All, Group.Read.All, User.Read.All (delegated). Global Reader can run it.
    Category    : Microsoft 365 Groups governance
    Changes     : No
    Notes       : The naming policy is enforced only when a group is created or renamed; existing names are never changed, which is
                  why this report exists. It requires Microsoft Entra ID P1 licences for the members of Microsoft 365 groups. Global,
                  Partner Tier 1/2 and User Administrators and Directory Writers are exempt. Prefix and suffix are compared case-insensitively.
.LINK
    https://learn.microsoft.com/entra/identity/users/groups-naming-policy
.LINK
    https://learn.microsoft.com/graph/api/groupsetting-list
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [Parameter()]
    [switch]$OnlyNonCompliant,

    [Parameter()]
    [switch]$ResolveOwnerAttributes,

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

function ConvertTo-NamePattern {
    <# Turns a policy fragment such as 'GRP-[Department]-' into a regex; attribute tokens become the resolved value or a wildcard. #>
    param(
        [Parameter()]
        [AllowEmptyString()]
        [string]$Fragment,

        [Parameter()]
        [hashtable]$Attributes
    )
    $pattern = ''
    foreach ($piece in [regex]::Split($Fragment, '(\[[A-Za-z]+\])')) {
        if ($piece -match '^\[(.+)\]$') {
            $value = $null
            if ($null -ne $Attributes) { $value = $Attributes[$Matches[1]] }
            if ([string]::IsNullOrWhiteSpace($value)) { $pattern += '.*' } else { $pattern += [regex]::Escape($value) }
        }
        else { $pattern += [regex]::Escape($piece) }
    }
    return $pattern
}

function Get-GroupOwnerUser {
    <# Returns the user owners of a group with the profile attributes a naming policy can reference. #>
    param([Parameter(Mandatory = $true)][string]$Id)
    return @(Invoke-GraphPaged -Uri ('{0}/groups/{1}/owners/microsoft.graph.user?$select=userPrincipalName,department,companyName,officeLocation,state,country,jobTitle' -f $graphV1, $Id))
}
#endregion Helpers

#region Main
$graphV1 = 'https://graph.microsoft.com/v1.0'
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('M365GroupNamingCompliance_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}

try { Connect-GraphIfNeeded -Scopes @('Directory.Read.All', 'Group.Read.All', 'User.Read.All') }
catch { throw "Unable to connect to Microsoft Graph: $($_.Exception.Message)" }

try { $setting = @(Invoke-GraphPaged -Uri "$graphV1/groupSettings") | Where-Object { $_.templateId -eq '62375ab9-6b52-47ed-826b-58e47e0e304b' } | Select-Object -First 1 }
catch { throw "Failed to read the group settings: $($_.Exception.Message)" }
$requirement = [string]@($setting.values | Where-Object { $_.name -eq 'PrefixSuffixNamingRequirement' } | Select-Object -First 1).value
$blockedWords = @([string]@($setting.values | Where-Object { $_.name -eq 'CustomBlockedWordsList' } | Select-Object -First 1).value -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
if ([string]::IsNullOrWhiteSpace($requirement) -and $blockedWords.Count -eq 0) { Write-Warning 'No group naming policy (prefix/suffix or blocked words) is configured; nothing to evaluate.'; return }
# Everything before [GroupName] is the prefix, everything after it the suffix; a policy without the token is all prefix.
$parts = $requirement -split '\[GroupName\]', 2
$prefixFragment = $parts[0]
$suffixFragment = ''; if ($parts.Count -gt 1) { $suffixFragment = $parts[1] }

try { $groups = @(Invoke-GraphPaged -Uri ('{0}/groups?$filter=groupTypes/any(c:c eq ''Unified'')&$select=id,displayName&$top=999' -f $graphV1)) }
catch { throw "Failed to list Microsoft 365 groups: $($_.Exception.Message)" }

$results = New-Object -TypeName System.Collections.Generic.List[object]
$processed = 0
foreach ($group in $groups) {
    $processed++
    Write-Progress -Activity 'Evaluating group names' -Status "$processed of $($groups.Count): $($group.displayName)" -PercentComplete (($processed / $groups.Count) * 100)
    $name = [string]$group.displayName
    $owners = @(); $attributes = $null; $calledGraph = $false
    $violations = New-Object -TypeName System.Collections.Generic.List[string]
    try {
        if ($ResolveOwnerAttributes) {
            $owners = Get-GroupOwnerUser -Id $group.id; $calledGraph = $true
            if ($owners.Count -gt 0) {
                $first = $owners[0]
                $attributes = @{ Department = $first.department; Company = $first.companyName; Office = $first.officeLocation }
                $attributes['StateOrProvince'] = $first.state; $attributes['CountryOrRegion'] = $first.country; $attributes['Title'] = $first.jobTitle
            }
        }
        if ($prefixFragment -and -not [regex]::IsMatch($name, '^' + (ConvertTo-NamePattern -Fragment $prefixFragment -Attributes $attributes), 'IgnoreCase')) { $violations.Add('NoPrefix') }
        if ($suffixFragment -and -not [regex]::IsMatch($name, (ConvertTo-NamePattern -Fragment $suffixFragment -Attributes $attributes) + '$', 'IgnoreCase')) { $violations.Add('NoSuffix') }
        foreach ($word in $blockedWords) {
            if ([regex]::IsMatch($name, '(?<![\p{L}\p{N}])' + [regex]::Escape($word) + '(?![\p{L}\p{N}])', 'IgnoreCase')) { $violations.Add("BlockedWord:$word") }
        }
        # Owners matter for follow-up only when the name is wrong, so they are read lazily unless already resolved.
        if ($violations.Count -gt 0 -and -not $ResolveOwnerAttributes) { $owners = Get-GroupOwnerUser -Id $group.id; $calledGraph = $true }
    }
    catch { Write-Warning "Could not fully evaluate '$name': $($_.Exception.Message)" }
    if ($calledGraph) { Start-Sleep -Milliseconds 200 }
    if ($OnlyNonCompliant -and $violations.Count -eq 0) { continue }
    $results.Add([PSCustomObject]@{
        DisplayName = $name
        Compliant   = ($violations.Count -eq 0)
        Violations  = ($violations -join ';')
        Owners      = (@($owners | ForEach-Object { $_.userPrincipalName } | Where-Object { $_ }) -join ';')
        Id          = $group.id
    })
}
Write-Progress -Activity 'Evaluating group names' -Completed
$results | Sort-Object -Property Compliant, DisplayName | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

$nonCompliant = @($results | Where-Object { -not $_.Compliant })
Write-Host 'Naming policy compliance summary' -ForegroundColor Cyan
Write-Host ('  Policy / blocked words       : {0} / {1}' -f $(if ($requirement) { $requirement } else { '(none)' }), $blockedWords.Count)
Write-Host ('  Groups evaluated             : {0}' -f $groups.Count)
Write-Host ('  Non-compliant                : {0}' -f $nonCompliant.Count) -ForegroundColor Yellow
$noPrefix = @($nonCompliant | Where-Object { $_.Violations -like '*NoPrefix*' }).Count; $noSuffix = @($nonCompliant | Where-Object { $_.Violations -like '*NoSuffix*' }).Count
Write-Host ('    NoPrefix / NoSuffix / BlockedWord : {0} / {1} / {2}' -f $noPrefix, $noSuffix, @($nonCompliant | Where-Object { $_.Violations -like '*BlockedWord:*' }).Count)
Write-Host ('  Report                       : {0}' -f $OutputPath)
if ($PassThru) { $results }
#endregion Main
