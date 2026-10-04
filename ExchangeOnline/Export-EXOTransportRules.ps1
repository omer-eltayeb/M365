<#
.SYNOPSIS
    Exports every Exchange Online mail flow (transport) rule to JSON files, a CSV summary and a restorable XML collection.
.DESCRIPTION
    Reads all mail flow rules with Get-TransportRule -ResultSize Unlimited and writes them to one export folder: a JSON
    file per rule (the complete rule object), TransportRules.csv (name, state, mode, priority, compact summaries of the
    conditions, exceptions and actions, who changed the rule and when) and TransportRuleCollection.xml produced by
    Export-TransportRuleCollection, which Import-TransportRuleCollection can restore. The CSV flags disabled rules,
    rules still in audit mode and rules that redirect or copy messages to addresses outside the accepted domains.
.PARAMETER OutputFolder
    Folder that receives the JSON files, the CSV and the XML collection. Defaults to .\EXOTransportRulesExport_yyyyMMdd-HHmm
    and is created if missing.
.PARAMETER PassThru
    Also emits the summary objects to the pipeline.
.EXAMPLE
    PS> .\Export-EXOTransportRules.ps1
    Creates .\EXOTransportRulesExport_<timestamp>\ with one JSON file per rule, TransportRules.csv and TransportRuleCollection.xml.
.EXAMPLE
    PS> .\Export-EXOTransportRules.ps1 -OutputFolder C:\Backups\MailFlowRules -PassThru | Where-Object { $_.HasExternalRedirect -or $_.IsAuditMode }
    Exports to the given folder and lists the rules that copy mail to external addresses or are still in audit mode.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, ExchangeOnlineManagement 3.x
    Permissions : Exchange Administrator or Global Reader for the JSON/CSV export; Export-TransportRuleCollection also needs
                  the Transport Rules role (Exchange Administrator, Compliance Management or Records Management).
    Category    : Mail flow & organization
    Changes     : No
    Notes       : Importing the XML with Import-TransportRuleCollection replaces all existing rules, so keep it next to the
                  JSON files as a point-in-time backup. Without the Transport Rules role the XML step is skipped with a
                  warning. Long values (disclaimers, word lists) are truncated to 150 characters in the CSV, not in the JSON.
.LINK
    https://learn.microsoft.com/powershell/module/exchange/get-transportrule
.LINK
    https://learn.microsoft.com/powershell/module/exchange/export-transportrulecollection
#>
#Requires -Version 5.1
#Requires -Modules ExchangeOnlineManagement

[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputFolder,

    [Parameter()]
    [switch]$PassThru
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

function Format-RuleSetting {
    <# Builds "Name=value | Name=value" from the rule properties in $Names that carry a value; nulls, empty lists and $false are skipped. #>
    param(
        [Parameter(Mandatory = $true)]
        [object]$Rule,

        [Parameter()]
        [string[]]$Names
    )
    $parts = @()
    foreach ($name in @($Names)) {
        $value = $Rule.$name
        if ($null -eq $value -or ($value -is [bool] -and -not $value)) { continue }
        if ($value -is [bool]) { $parts += $name; continue }
        $items = @(foreach ($item in @($value)) {
                if ($item -is [System.Collections.IDictionary]) { @(foreach ($key in $item.Keys) { '{0}={1}' -f $key, $item[$key] }) -join ',' }
                else { [string]$item }
            })
        $text = ((@($items | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }) -join ';') -replace '\s+', ' ').Trim()
        if ([string]::IsNullOrEmpty($text)) { continue }
        if ($text.Length -gt 150) { $text = $text.Substring(0, 150) + '...' }
        $parts += '{0}={1}' -f $name, $text
    }
    return ($parts -join ' | ')
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputFolder)) {
    $OutputFolder = Join-Path -Path (Get-Location).Path -ChildPath ('EXOTransportRulesExport_{0}' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
if (-not (Test-Path -Path $OutputFolder)) {
    New-Item -Path $OutputFolder -ItemType Directory -Force | Out-Null
}
# .NET file APIs resolve relative paths against the process directory, not the PowerShell location.
$OutputFolder = (Resolve-Path -Path $OutputFolder).Path

try {
    Connect-ExchangeIfNeeded
}
catch {
    throw "Unable to connect to Exchange Online: $($_.Exception.Message)"
}

try {
    $rules = @(Get-TransportRule -ResultSize Unlimited -ErrorAction Stop | Sort-Object -Property Priority)
    $acceptedDomains = @(Get-AcceptedDomain -ErrorAction Stop | ForEach-Object { ([string]$_.DomainName).ToLowerInvariant() })
}
catch {
    throw "Failed to read the mail flow rules: $($_.Exception.Message)"
}
Write-Verbose "Retrieved $($rules.Count) mail flow rule(s)."

$actionNames = @('RejectMessageReasonText', 'RejectMessageEnhancedStatusCode', 'DeleteMessage', 'Quarantine', 'RedirectMessageTo', 'BlindCopyTo', 'CopyTo',
    'AddToRecipients', 'AddManagerAsRecipientType', 'ModerateMessageByUser', 'ModerateMessageByManager', 'PrependSubject', 'ApplyHtmlDisclaimerText',
    'SetSCL', 'SetHeaderName', 'SetHeaderValue', 'RemoveHeader', 'RouteMessageOutboundConnector', 'RouteMessageOutboundRequireTls', 'StopRuleProcessing',
    'ApplyClassification', 'ApplyRightsProtectionTemplate', 'ApplyOME', 'RemoveOME', 'RemoveOMEv2', 'GenerateIncidentReport', 'GenerateNotification',
    'NotifySender', 'SetAuditSeverity', 'Disconnect', 'SmtpRejectMessageRejectText')
$recipientActions = @('RedirectMessageTo', 'BlindCopyTo', 'CopyTo', 'AddToRecipients')
$summary = New-Object -TypeName System.Collections.Generic.List[object]
$index = 0
foreach ($rule in $rules) {
    $index++
    Write-Progress -Activity 'Exporting mail flow rules' -Status $rule.Name -PercentComplete (($index / $rules.Count) * 100)
    $fileName = '{0:D3}_{1}.json' -f $rule.Priority, ([regex]::Replace([string]$rule.Name, '[\\/:*?"<>|\x00-\x1F]', '_').Trim())
    try {
        $rule | ConvertTo-Json -Depth 6 -WarningAction SilentlyContinue | Set-Content -Path (Join-Path -Path $OutputFolder -ChildPath $fileName) -Encoding UTF8
    }
    catch {
        Write-Warning ('Rule "{0}" could not be saved as JSON: {1}' -f $rule.Name, $_.Exception.Message)
    }

    # Every predicate has an ExceptIf* twin, so the exception property names also give the complete list of condition names.
    $exceptionNames = @($rule.PSObject.Properties.Name | Where-Object { $_ -like 'ExceptIf*' })
    $conditionNames = @($exceptionNames | ForEach-Object { $_.Substring(8) })
    $externalTargets = @()
    foreach ($name in $recipientActions) {
        foreach ($address in @($rule.$name)) {
            if ([string]$address -match '@([^\s>;,\]]+)' -and $acceptedDomains -notcontains $Matches[1].ToLowerInvariant()) { $externalTargets += [string]$address }
        }
    }
    $comments = ([string]$rule.Comments -replace '\s+', ' ').Trim()
    if ($comments.Length -gt 200) { $comments = $comments.Substring(0, 200) + '...' }

    $summary.Add([PSCustomObject]@{
            Name                  = $rule.Name
            State                 = [string]$rule.State
            Mode                  = [string]$rule.Mode
            Priority              = $rule.Priority
            IsDisabled            = ([string]$rule.State -eq 'Disabled')
            IsAuditMode           = ([string]$rule.Mode -ne 'Enforce')
            HasExternalRedirect   = ($externalTargets.Count -gt 0)
            ExternalTargets       = ($externalTargets -join ';')
            Conditions            = Format-RuleSetting -Rule $rule -Names $conditionNames
            Exceptions            = Format-RuleSetting -Rule $rule -Names $exceptionNames
            Actions               = Format-RuleSetting -Rule $rule -Names $actionNames
            SenderAddressLocation = [string]$rule.SenderAddressLocation
            Comments              = $comments
            CreatedBy             = [string]$rule.CreatedBy
            LastModifiedBy        = [string]$rule.LastModifiedBy
            WhenChanged           = $rule.WhenChanged
            Guid                  = [string]$rule.Guid
            JsonFile              = $fileName
        })
}
Write-Progress -Activity 'Exporting mail flow rules' -Completed

if ($summary.Count -gt 0) {
    $summary | Export-Csv -Path (Join-Path -Path $OutputFolder -ChildPath 'TransportRules.csv') -NoTypeInformation -Encoding UTF8
}
else {
    Write-Warning 'No mail flow rules were found; TransportRules.csv was not written.'
}

$xmlExported = $false
if ($rules.Count -gt 0) {
    try {
        # The collection comes back as a byte array (FileData); the same XML is accepted by Import-TransportRuleCollection.
        $collection = Export-TransportRuleCollection -ErrorAction Stop
        [System.IO.File]::WriteAllBytes((Join-Path -Path $OutputFolder -ChildPath 'TransportRuleCollection.xml'), $collection.FileData)
        $xmlExported = $true
    }
    catch {
        Write-Warning "Export-TransportRuleCollection failed (the Transport Rules role is required): $($_.Exception.Message)"
    }
}

$disabledCount = @($summary | Where-Object { $_.IsDisabled }).Count
$externalCount = @($summary | Where-Object { $_.HasExternalRedirect }).Count
Write-Host ''
Write-Host 'Mail flow rule export summary' -ForegroundColor Cyan
Write-Host ('  Rules exported          : {0} (enabled {1}, disabled {2})' -f $summary.Count, ($summary.Count - $disabledCount), $disabledCount)
Write-Host ('  Rules in audit mode     : {0}' -f @($summary | Where-Object { $_.IsAuditMode }).Count)
Write-Host ('  Rules with external copy: {0}' -f $externalCount) -ForegroundColor $(if ($externalCount -gt 0) { 'Yellow' } else { 'Green' })
Write-Host ('  XML collection          : {0}' -f $(if ($xmlExported) { 'TransportRuleCollection.xml' } else { 'not exported' }))
Write-Host ('  Output folder           : {0}' -f $OutputFolder)

if ($PassThru) {
    $summary
}
#endregion Main
