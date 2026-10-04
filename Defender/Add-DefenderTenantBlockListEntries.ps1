<#
.SYNOPSIS
    Bulk-adds block entries (or time-limited allow entries) to the Tenant Allow/Block List from the command line or a CSV file.
.DESCRIPTION
    Adds sender, URL, file hash or IPv6 entries to the Defender for Office 365 Tenant Allow/Block List with
    New-TenantAllowBlockListItems, 20 values per call. Values come from -Entries (one list type) or -InputCsv (columns
    Value, ListType, optional Notes). Each value is syntax-checked for its list type, existing values are skipped and a
    rejected batch is retried one value at a time so a single bad value does not block the others. Block entries expire
    after -ExpireInDays (default 30) unless -NoExpiration is used; -Allow creates allow entries removed 45 days after last
    use (or after -ExpireInDays, 45 maximum) and needs a justification in -Notes. One result object per value is emitted.
.PARAMETER Entries
    Values to add. Sender: addresses or domains (contoso.com, *.top); Url: hosts with optional wildcards and path
    (*.contoso.com/*); FileHash: SHA256 hex string; IP: IPv6 addresses or CIDR ranges.
.PARAMETER ListType
    List that the -Entries belong to: Sender, Url, FileHash or IP.
.PARAMETER InputCsv
    CSV file with columns Value, ListType and optional Notes (a row note overrides -Notes).
.PARAMETER Allow
    Create allow entries instead of block entries. Requires -Notes; -NoExpiration is accepted for IP entries only.
.PARAMETER Notes
    Note stored with the entries, for example the ticket number and reason. Mandatory for allow entries.
.PARAMETER ExpireInDays
    Days until the entries expire (1-90, default 30). Allow entries accept at most 45.
.PARAMETER NoExpiration
    Create entries that never expire (block entries, or IPv6 allow entries).
.EXAMPLE
    PS> .\Add-DefenderTenantBlockListEntries.ps1 -ListType Sender -Entries 'phish@badmail.example', '*.top' -Notes 'INC0012345' -WhatIf
    Shows the sender block entries that would be created with a 30 day expiry without changing anything.
.EXAMPLE
    PS> .\Add-DefenderTenantBlockListEntries.ps1 -InputCsv .\blocks.csv -NoExpiration -Confirm:$false | Where-Object { $_.Status -ne 'Added' }
    Adds every value in the CSV (mixed list types) as a permanent block entry without prompting and shows the values that were not added.
.EXAMPLE
    PS> .\Add-DefenderTenantBlockListEntries.ps1 -ListType Url -Entries 'news.partner.example' -Allow -Notes 'False positive, ticket 4711'
    Creates a URL allow entry that is removed 45 days after it was last used; each batch prompts for confirmation.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, ExchangeOnlineManagement 3.x
    Permissions : Security Administrator (Exchange Online PowerShell session)
    Category    : Email threat operations
    Changes     : Yes
    Notes       : Allow entries created this way cover bulk, spam and phishing verdicts only; malware and high confidence
                  phishing verdicts need an admin submission (Submissions page). New entries take up to 15 minutes to apply.
                  Limits per list: 500 (EOP), 1000 (Defender for Office 365 Plan 1), 5000 allow / 10000 block (Plan 2).
.LINK
    https://learn.microsoft.com/powershell/module/exchange/new-tenantallowblocklistitems
#>
#Requires -Version 5.1
#Requires -Modules ExchangeOnlineManagement

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High', DefaultParameterSetName = 'Entries')]
param(
    [Parameter(Mandatory = $true, ParameterSetName = 'Entries')]
    [string[]]$Entries,

    [Parameter(Mandatory = $true, ParameterSetName = 'Entries')]
    [ValidateSet('Sender', 'Url', 'FileHash', 'IP')]
    [string]$ListType,

    [Parameter(Mandatory = $true, ParameterSetName = 'Csv')]
    [ValidateScript({ Test-Path -Path $_ -PathType Leaf })]
    [string]$InputCsv,

    [Parameter()]
    [switch]$Allow,

    [Parameter()]
    [string]$Notes,

    [Parameter()]
    [ValidateRange(1, 90)]
    [int]$ExpireInDays = 30,

    [Parameter()]
    [switch]$NoExpiration
)

$ErrorActionPreference = 'Stop'

#region Helpers
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

function Test-EntryFormat {
    <# Checks the value syntax for a list type locally; the service rejects a whole batch on the first bad value. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Value,

        [Parameter(Mandatory = $true)]
        [string]$Type
    )
    switch ($Type) {
        'Sender' { return (($Value -match '^[^\s@"<>]+@[A-Za-z0-9.-]+\.[A-Za-z0-9-]{2,}$') -or ($Value -match '^(\*\.)?[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*$' -and $Value -match '\.')) }
        'Url' { return ($Value -notmatch '[\s:@]' -and $Value -match '^[A-Za-z0-9.*~-]+(/\S*)?$' -and $Value -match '\.') }
        'FileHash' { return ($Value -match '^[A-Fa-f0-9]{64}$') }
        'IP' {
            $parts = $Value -split '/'
            if ($parts.Count -gt 2) { return $false }
            if ($parts.Count -eq 2 -and ($parts[1] -notmatch '^\d{1,3}$' -or [int]$parts[1] -lt 1 -or [int]$parts[1] -gt 128)) { return $false }
            $address = $null
            return ([System.Net.IPAddress]::TryParse($parts[0], [ref]$address) -and $address.AddressFamily -eq 'InterNetworkV6')
        }
    }
}
#endregion Helpers

#region Main
if ($Allow) {
    if ([string]::IsNullOrWhiteSpace($Notes)) { throw 'Allow entries require a justification in -Notes (ticket number and why the override is needed).' }
    if ($ExpireInDays -gt 45) { throw 'Allow entries can be valid for at most 45 days: use -ExpireInDays 45 or lower, or omit it to expire 45 days after last use.' }
}
# Microsoft's recommended lifetime for an allow entry is "45 days after last used" unless an explicit expiry is requested (not supported for IP).
$useRemoveAfter = ($Allow -and -not $NoExpiration -and -not $PSBoundParameters.ContainsKey('ExpireInDays'))
$expirationDate = (Get-Date).ToUniversalTime().AddDays($ExpireInDays)
$actionName = $(if ($Allow) { 'Allow' } else { 'Block' })
if ($PSCmdlet.ParameterSetName -eq 'Csv') {
    $candidates = @(Import-Csv -Path $InputCsv -ErrorAction Stop | ForEach-Object { @{ Value = [string]$_.Value; Type = [string]$_.ListType; Note = [string]$_.Notes } })
}
else {
    $candidates = @($Entries | ForEach-Object { @{ Value = $_; Type = $ListType; Note = '' } })
}
if ($candidates.Count -eq 0) { throw 'No values to add were supplied.' }

try {
    Connect-ExchangeIfNeeded
}
catch {
    throw "Unable to connect to Exchange Online: $($_.Exception.Message)"
}
$existing = @{}
$rows = New-Object -TypeName System.Collections.Generic.List[object]
foreach ($candidate in $candidates) {
    $value = ([string]$candidate.Value).Trim()
    $type = @('Sender', 'Url', 'FileHash', 'IP') | Where-Object { $_ -eq ([string]$candidate.Type).Trim() } | Select-Object -First 1
    if ($type -eq 'Url') { $value = $value -replace '^[A-Za-z]+://', '' }
    $note = $(if ([string]::IsNullOrWhiteSpace($candidate.Note)) { $Notes } else { ([string]$candidate.Note).Trim() })
    $expiry = $(if ($NoExpiration) { 'never' } elseif ($useRemoveAfter -and $type -ne 'IP') { '45 days after last use' } else { $expirationDate.ToString('yyyy-MM-dd HH:mm') + ' UTC' })
    $row = [PSCustomObject]@{ Value = $value; ListType = $type; Action = $actionName; Notes = $note; Expiry = $expiry; Status = 'Pending'; Message = $null }
    if ($null -eq $type) { $row.Status = 'InvalidFormat'; $row.Message = "Unknown list type '$($candidate.Type)'" }
    elseif ([string]::IsNullOrWhiteSpace($value) -or -not (Test-EntryFormat -Value $value -Type $type)) { $row.Status = 'InvalidFormat'; $row.Message = "Value does not match the $type entry syntax" }
    elseif ($Allow -and $NoExpiration -and $type -ne 'IP') { $row.Status = 'InvalidFormat'; $row.Message = 'Allow entries without expiry are only supported for IP (IPv6) entries' }
    else {
        if (-not $existing.ContainsKey($type)) {
            try { $existing[$type] = @(Get-TenantAllowBlockListItems -ListType $type -ErrorAction Stop | ForEach-Object { ([string]$_.Value).ToLowerInvariant() }) }
            catch { Write-Warning "Could not read existing $type entries, duplicates will be reported by the service: $($_.Exception.Message)"; $existing[$type] = @() }
        }
        if ($existing[$type] -contains $value.ToLowerInvariant()) { $row.Status = 'AlreadyExists'; $row.Message = 'An entry with this value already exists' }
    }
    $rows.Add($row)
}

foreach ($group in (@($rows | Where-Object { $_.Status -eq 'Pending' }) | Group-Object -Property ListType, Notes)) {
    $items = @($group.Group)
    $type = $items[0].ListType
    $params = @{ ListType = $type; ErrorAction = 'Stop' }
    if ($Allow) { $params['Allow'] = $true } else { $params['Block'] = $true }
    if (-not [string]::IsNullOrWhiteSpace($items[0].Notes)) { $params['Notes'] = $items[0].Notes }
    if ($NoExpiration) { $params['NoExpiration'] = $true } elseif ($useRemoveAfter -and $type -ne 'IP') { $params['RemoveAfter'] = 45 } else { $params['ExpirationDate'] = $expirationDate }
    for ($offset = 0; $offset -lt $items.Count; $offset += 20) {
        $batch = @($items[$offset..([math]::Min($offset + 19, $items.Count - 1))])
        $preview = (@($batch | Select-Object -First 5 -ExpandProperty Value) -join ', ') + $(if ($batch.Count -gt 5) { ', ...' } else { '' })
        if (-not $PSCmdlet.ShouldProcess("$($batch.Count) $type value(s): $preview", "Add $actionName entries to the Tenant Allow/Block List (expiry: $($items[0].Expiry))")) {
            foreach ($row in $batch) { $row.Status = 'Skipped'; $row.Message = 'Not confirmed (or -WhatIf)' }
            continue
        }
        # The whole batch is tried first; a rejected batch is split into single values so the good ones are still added.
        $queue = New-Object -TypeName System.Collections.Generic.Queue[object]
        $queue.Enqueue($batch)
        while ($queue.Count -gt 0) {
            $set = @($queue.Dequeue())
            $params['Entries'] = @($set | Select-Object -ExpandProperty Value)
            try {
                New-TenantAllowBlockListItems @params | Out-Null
                foreach ($row in $set) { $row.Status = 'Added' }
            }
            catch {
                if ($set.Count -gt 1) {
                    Write-Warning "A batch of $($set.Count) $type entries was rejected ($($_.Exception.Message)); retrying one value at a time."
                    foreach ($row in $set) { $queue.Enqueue(@($row)) }
                }
                else { $set[0].Status = 'Failed'; $set[0].Message = $_.Exception.Message }
            }
        }
    }
}
Write-Host ''
Write-Host ('Tenant Allow/Block List - {0} entries ({1} value(s) processed)' -f $actionName, $rows.Count) -ForegroundColor Cyan
foreach ($group in ($rows | Group-Object -Property Status | Sort-Object -Property Name)) {
    $colour = switch ($group.Name) { 'Added' { 'Green' } 'Failed' { 'Red' } 'InvalidFormat' { 'Yellow' } default { 'Gray' } }
    Write-Host ('  {0,-14} {1,6}' -f $group.Name, $group.Count) -ForegroundColor $colour
}

$rows
#endregion Main
