<#
.SYNOPSIS
    Adds or removes Microsoft Defender for Endpoint device tags in bulk by machine id, device name or CSV.
.DESCRIPTION
    Resolves the target devices through the Defender for Endpoint API and applies POST /machines/{id}/tags with Action Add (or
    Remove with -Remove) for every tag from -Tag and from the optional Tag column of -InputCsv. The current tags of each device
    are read first so tags that are already present (or already absent) are skipped; every change goes through ShouldProcess.
    Outputs one result object per device and tag (DeviceName, MachineId, Tag, Action, Result, Message, TagsAfter).
.PARAMETER TenantId
    Directory (tenant) ID or verified domain of the tenant that hosts the app registration.
.PARAMETER AppCredential
    PSCredential whose user name is the application (client) ID and whose password is the client secret.
.PARAMETER MachineId
    One or more Defender for Endpoint machine ids.
.PARAMETER DeviceName
    One or more device names; matched on computerDnsName exactly first, then as a prefix (so a short host name works).
.PARAMETER InputCsv
    CSV file with a DeviceName column and an optional Tag column; a row's Tag applies to that device in addition to -Tag.
.PARAMETER Tag
    One or more tags to add to (or remove from) every selected device. Tags are case-sensitive in Defender for Endpoint.
.PARAMETER Remove
    Removes the tags instead of adding them.
.EXAMPLE
    PS> $cred = Get-Credential -UserName '<application-id>' -Message 'Client secret'
    PS> .\Set-MDEMachineTags.ps1 -TenantId contoso.onmicrosoft.com -AppCredential $cred -DeviceName 'FIN-PC-01', 'FIN-PC-02' -Tag 'Finance', 'PCI'
    Adds the Finance and PCI tags to both devices after confirmation, skipping tags they already carry.
.EXAMPLE
    PS> .\Set-MDEMachineTags.ps1 -TenantId contoso.onmicrosoft.com -AppCredential $cred -InputCsv .\device-tags.csv -WhatIf
    Shows which tag from the CSV's Tag column would be added to which device without changing anything.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x (REST calls only, no modules)
    Permissions : Application permission Machine.ReadWrite.All (covers the device lookup) granted with admin consent to an app registration.
    Category    : Defender for Endpoint API
    Changes     : Yes
    Notes       : Tags set through the API or portal can be removed this way; tags pushed by the registry/Intune policy or dynamic rules
                  cannot. Rate limit 100 calls per minute and 1,500 per hour; device-group membership rules may re-evaluate on tag change.
.LINK
    https://learn.microsoft.com/defender-endpoint/api/add-or-remove-machine-tags
#>
#Requires -Version 5.1

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $true)]
    [string]$TenantId,

    [Parameter(Mandatory = $true)]
    [pscredential]$AppCredential,

    [Parameter()]
    [string[]]$MachineId,

    [Parameter()]
    [string[]]$DeviceName,

    [Parameter()]
    [string]$InputCsv,

    [Parameter()]
    [string[]]$Tag,

    [Parameter()]
    [switch]$Remove
)

$ErrorActionPreference = 'Stop'
$baseUri = 'https://api.securitycenter.microsoft.com/api'

#region Helpers
function Get-MdeAccessToken {
    <# Acquires an app-only token for the Defender for Endpoint API with the client-credentials flow. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TenantId,

        [Parameter(Mandatory = $true)]
        [pscredential]$AppCredential
    )
    $body = @{
        client_id     = $AppCredential.UserName
        client_secret = $AppCredential.GetNetworkCredential().Password
        scope         = 'https://api.securitycenter.microsoft.com/.default'
        grant_type    = 'client_credentials'
    }
    $tokenUri = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
    $response = Invoke-RestMethod -Method POST -Uri $tokenUri -Body $body -ContentType 'application/x-www-form-urlencoded' -ErrorAction Stop
    return $response.access_token
}

function Invoke-MdeRequest {
    <# Calls the Defender for Endpoint API; GET requests follow @odata.nextLink. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Token,

        [Parameter(Mandatory = $true)]
        [string]$Uri,

        [Parameter()]
        [ValidateSet('GET', 'POST', 'PATCH', 'DELETE')]
        [string]$Method = 'GET',

        [Parameter()]
        [object]$Body
    )
    $headers = @{ Authorization = "Bearer $Token"; 'Content-Type' = 'application/json' }
    if ($Method -ne 'GET') {
        $json = $null
        if ($null -ne $Body) { $json = $Body | ConvertTo-Json -Depth 10 }
        return Invoke-RestMethod -Method $Method -Uri $Uri -Headers $headers -Body $json -ErrorAction Stop
    }
    $results = New-Object -TypeName System.Collections.Generic.List[object]
    $nextLink = $Uri
    while (-not [string]::IsNullOrEmpty($nextLink)) {
        $response = Invoke-RestMethod -Method GET -Uri $nextLink -Headers $headers -ErrorAction Stop
        if ($null -ne $response.PSObject.Properties['value']) { foreach ($item in $response.value) { $results.Add($item) } }
        else { $results.Add($response) }
        $nextLink = $response.'@odata.nextLink'
    }
    return $results
}

function Resolve-MdeMachine {
    <# Resolves -MachineId, -DeviceName and -InputCsv (DeviceName column) to unique machine objects; names match exactly first, then as a prefix. #>
    param([string]$Token, [string[]]$MachineId, [string[]]$DeviceName, [string]$InputCsv)
    $names = @($DeviceName)
    if (-not [string]::IsNullOrWhiteSpace($InputCsv)) { $names += @(Import-Csv -Path $InputCsv | ForEach-Object { $_.DeviceName }) }
    $found = New-Object -TypeName System.Collections.Generic.List[object]
    foreach ($id in @($MachineId | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })) {
        try { $found.Add(@(Invoke-MdeRequest -Token $Token -Uri "$baseUri/machines/$($id.Trim())")[0]) }
        catch { Write-Warning "Machine id '$id' was not found: $($_.Exception.Message)" }
    }
    foreach ($name in @($names | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object { $_.Trim().ToLowerInvariant() } | Select-Object -Unique)) {
        $hits = @()
        foreach ($filter in @("computerDnsName eq '$name'", "startswith(computerDnsName,'$name')")) {
            try { $hits = @(Invoke-MdeRequest -Token $Token -Uri ('{0}/machines?$filter={1}' -f $baseUri, $filter)) }
            catch { Write-Warning "Device lookup '$filter' failed: $($_.Exception.Message)" }
            if ($hits.Count -gt 0) { break }
        }
        if ($hits.Count -eq 0) { Write-Warning "No device matches '$name'."; continue }
        if ($hits.Count -gt 1) { Write-Warning "'$name' matches $($hits.Count) devices: $(@($hits | ForEach-Object { $_.computerDnsName }) -join ', ')" }
        foreach ($machine in $hits) { $found.Add($machine) }
    }
    return @($found | Sort-Object -Property id -Unique)
}
#endregion Helpers

#region Main
if (@($MachineId).Count -eq 0 -and @($DeviceName).Count -eq 0 -and [string]::IsNullOrWhiteSpace($InputCsv)) { throw 'Select the devices with -MachineId, -DeviceName or -InputCsv.' }
$names = @($DeviceName)
$csvTags = @{}
if (-not [string]::IsNullOrWhiteSpace($InputCsv)) {
    foreach ($entry in @(Import-Csv -Path $InputCsv | Where-Object { -not [string]::IsNullOrWhiteSpace($_.DeviceName) })) {
        $key = $entry.DeviceName.Trim().ToLowerInvariant()
        $names += $key
        if ([string]::IsNullOrWhiteSpace($entry.Tag)) { continue }
        if (-not $csvTags.ContainsKey($key)) { $csvTags[$key] = @() }
        $csvTags[$key] += $entry.Tag.Trim()
    }
}
if (@($Tag).Count -eq 0 -and $csvTags.Count -eq 0) { throw 'Specify the tags with -Tag or through a Tag column in the CSV.' }
try { $token = Get-MdeAccessToken -TenantId $TenantId -AppCredential $AppCredential }
catch { throw "Unable to acquire a Defender for Endpoint API token: $($_.Exception.Message)" }
$machines = @(Resolve-MdeMachine -Token $token -MachineId $MachineId -DeviceName $names)
if ($machines.Count -eq 0) { Write-Warning 'No device could be resolved; nothing to do.'; return }

$actionName = $(if ($Remove) { 'Remove' } else { 'Add' })
$rows = New-Object -TypeName System.Collections.Generic.List[object]
foreach ($machine in $machines) {
    $name = [string]$machine.computerDnsName
    $currentTags = @($machine.machineTags)
    # A CSV row's tag only applies to the device it names (exact name or that host name in any DNS suffix), not to other prefix matches.
    $wanted = @($Tag) + @($csvTags.Keys | Where-Object { $name -eq $_ -or $name -like ($_ + '.*') } | ForEach-Object { $csvTags[$_] })
    foreach ($tagValue in @($wanted | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object { $_.Trim() } | Select-Object -Unique)) {
        $row = [PSCustomObject]@{ DeviceName = $name; MachineId = $machine.id; Tag = $tagValue; Action = $actionName; Result = 'Skipped'; Message = $null; TagsAfter = ($currentTags -join ';') }
        $rows.Add($row)
        $present = $currentTags -ccontains $tagValue
        if ($Remove -and -not $present) { $row.Message = 'Tag not present'; continue }
        if (-not $Remove -and $present) { $row.Message = 'Tag already present'; continue }
        if (-not $PSCmdlet.ShouldProcess("$name ($($machine.id))", "$actionName tag '$tagValue'")) { $row.Message = 'Not confirmed (or -WhatIf)'; continue }
        try {
            $updated = Invoke-MdeRequest -Token $token -Uri ('{0}/machines/{1}/tags' -f $baseUri, $machine.id) -Method POST -Body @{ Value = $tagValue; Action = $actionName }
            $currentTags = @($updated.machineTags)
            $row.Result = $(if ($Remove) { 'Removed' } else { 'Added' }); $row.TagsAfter = ($currentTags -join ';')
        }
        catch { $row.Result = 'Failed'; $row.Message = $(if ($_.ErrorDetails) { $_.ErrorDetails.Message } else { $_.Exception.Message }); Write-Warning "${name}: $($row.Message)" }
        Start-Sleep -Milliseconds 200
    }
}

$summary = @($rows | Group-Object -Property Result | Sort-Object -Property Name | ForEach-Object { '{0}={1}' -f $_.Name, $_.Count }) -join ', '
Write-Host ('Defender for Endpoint device tags ({0}): {1} device(s), {2} tag operation(s) - {3}' -f $actionName, $machines.Count, $rows.Count, $summary) -ForegroundColor Cyan
$rows
#endregion Main
