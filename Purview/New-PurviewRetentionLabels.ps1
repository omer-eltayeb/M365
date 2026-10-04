<#
.SYNOPSIS
    Bulk-creates Microsoft Purview retention labels from a CSV file and optionally publishes them in a label policy.
.DESCRIPTION
    Reads -InputCsv, validates every row, skips labels that already exist and creates the rest with New-ComplianceTag
    in Security & Compliance PowerShell, turning the file plan columns into the FilePlanProperty JSON the cmdlet
    expects. With -PublishToPolicy the labels listed in the CSV are published through that retention label policy:
    the policy is created for all Exchange, SharePoint, OneDrive and Microsoft 365 Group locations when missing and
    its rule is created or extended (New/Set-RetentionComplianceRule -PublishComplianceTag). Every change goes through
    ShouldProcess, so -WhatIf previews the plan and -Confirm:$false suppresses the per-label prompts.
.PARAMETER InputCsv
    CSV columns: Name (required), Comment, RetentionAction (Keep | Delete | KeepAndDelete), RetentionDurationDays
    (days or Unlimited), RetentionType (CreationAgeInDays | ModificationAgeInDays | TaggedAgeInDays | EventAgeInDays),
    EventTypeName (required for EventAgeInDays), IsRecordLabel, Regulatory (true/false), ReviewerEmail (';' separated),
    FilePlanDepartment, FilePlanCategory, FilePlanSubCategory, FilePlanAuthority, FilePlanCitation, FilePlanReferenceId.
    Leave all retention columns empty for a classification-only label.
.PARAMETER PublishToPolicy
    Name of the retention label policy that should publish the labels. Created with all locations when missing.
.PARAMETER PassThru
    Emit one result object per CSV row (Name, Status, Detail) to the pipeline.
.EXAMPLE
    PS> .\New-PurviewRetentionLabels.ps1 -InputCsv .\labels.csv -WhatIf
    Validates the CSV and shows which labels would be created, without changing anything.
.EXAMPLE
    PS> .\New-PurviewRetentionLabels.ps1 -InputCsv .\labels.csv -PublishToPolicy 'Finance records' -Confirm:$false -Verbose
    Creates the missing labels and publishes all labels listed in the CSV through the 'Finance records' policy.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, ExchangeOnlineManagement 3.x
    Permissions : Retention Management role (Compliance Administrator or Records Management role group) in Security &
                  Compliance PowerShell
    Category    : Retention & records management
    Changes     : Yes
    Notes       : Regulatory record labels cannot be removed, shortened or deleted once applied to content (the portal only
                  shows the option after Set-RegulatoryComplianceUI -Enabled $true); the script warns before creating one.
                  File plan descriptor values must already exist in the file plan (New-FilePlanPropertyDepartment etc.) and
                  event types must exist (Get-ComplianceRetentionEventType), otherwise the creation fails for that row.
                  Several labels are published through one rule as a comma-separated PublishComplianceTag value; publishing
                  can take up to 24 hours to reach Outlook, SharePoint and OneDrive.
.LINK
    https://learn.microsoft.com/powershell/module/exchangepowershell/new-compliancetag
.LINK
    https://learn.microsoft.com/powershell/module/exchangepowershell/new-retentioncompliancerule
#>
#Requires -Version 5.1
#Requires -Modules ExchangeOnlineManagement

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path -Path $_ -PathType Leaf })]
    [string]$InputCsv,

    [Parameter()]
    [string]$PublishToPolicy,

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
#endregion Helpers

#region Main
$csvRows = @(Import-Csv -Path $InputCsv -ErrorAction Stop)
if ($csvRows.Count -eq 0 -or -not ($csvRows[0].PSObject.Properties.Name -contains 'Name')) {
    throw "The CSV '$InputCsv' is empty or has no 'Name' column."
}

try { Connect-ExchangeIfNeeded -Compliance }
catch { throw "Unable to connect to Security & Compliance PowerShell: $($_.Exception.Message)" }

try { $existingNames = @(Get-ComplianceTag -ErrorAction Stop | ForEach-Object { [string]$_.Name }) }
catch { throw "Failed to read existing retention labels: $($_.Exception.Message)" }
try { $eventTypeNames = @(Get-ComplianceRetentionEventType -ErrorAction Stop | ForEach-Object { [string]$_.Name }) }
catch { $eventTypeNames = @(); Write-Warning "Could not read retention event types; EventTypeName values will not be validated: $($_.Exception.Message)" }

# CSV column -> key name inside the FilePlanProperty JSON ({"Settings":[{"Key":"...","Value":"..."}]}).
$filePlanColumns = [ordered]@{
    FilePlanDepartment = 'FilePlanPropertyDepartment'; FilePlanCategory = 'FilePlanPropertyCategory'; FilePlanSubCategory = 'FilePlanPropertySubcategory'
    FilePlanAuthority = 'FilePlanPropertyAuthority'; FilePlanCitation = 'FilePlanPropertyCitation'; FilePlanReferenceId = 'FilePlanPropertyReferenceId'
}
$results = New-Object -TypeName System.Collections.Generic.List[object]
$rowNumber = 1
foreach ($row in $csvRows) {
    $rowNumber++
    $name = ([string]$row.Name).Trim()
    $action = ([string]$row.RetentionAction).Trim()
    $type = ([string]$row.RetentionType).Trim()
    $durationText = ([string]$row.RetentionDurationDays).Trim()
    $eventTypeName = ([string]$row.EventTypeName).Trim()
    $isRecord = (([string]$row.IsRecordLabel).Trim() -match '^(true|yes|1)$')
    $regulatory = (([string]$row.Regulatory).Trim() -match '^(true|yes|1)$')
    $hasRetention = -not ([string]::IsNullOrWhiteSpace($action) -and [string]::IsNullOrWhiteSpace($type) -and [string]::IsNullOrWhiteSpace($durationText))

    $problems = New-Object -TypeName System.Collections.Generic.List[string]
    $days = 0
    if ([string]::IsNullOrWhiteSpace($name)) { $problems.Add('Name is empty') }
    if ($hasRetention) {
        if ($action -notin @('Keep', 'Delete', 'KeepAndDelete')) { $problems.Add("RetentionAction '$action' is not Keep, Delete or KeepAndDelete") }
        if ($type -notin @('CreationAgeInDays', 'ModificationAgeInDays', 'TaggedAgeInDays', 'EventAgeInDays')) { $problems.Add("RetentionType '$type' is not valid") }
        if ($durationText -ne 'Unlimited' -and (-not [int]::TryParse($durationText, [ref]$days) -or $days -le 0)) { $problems.Add('RetentionDurationDays must be a positive number or Unlimited') }
        if ($type -eq 'EventAgeInDays' -and [string]::IsNullOrWhiteSpace($eventTypeName)) { $problems.Add('EventAgeInDays requires EventTypeName') }
        if ($eventTypeName -and $eventTypeNames.Count -gt 0 -and $eventTypeNames -notcontains $eventTypeName) { $problems.Add("Event type '$eventTypeName' does not exist") }
    }
    if ($regulatory -and -not $isRecord) { $problems.Add('Regulatory requires IsRecordLabel = true') }
    if ($problems.Count -gt 0) {
        Write-Warning "Row $rowNumber ('$name') skipped: $($problems -join '; ')"
        $results.Add([PSCustomObject]@{ Name = $name; Status = 'Invalid'; Detail = ($problems -join '; ') })
        continue
    }
    if ($existingNames -contains $name) {
        $results.Add([PSCustomObject]@{ Name = $name; Status = 'Exists'; Detail = 'Label already exists' })
        continue
    }

    $params = @{ Name = $name; ErrorAction = 'Stop' }
    if (-not [string]::IsNullOrWhiteSpace([string]$row.Comment)) { $params['Comment'] = ([string]$row.Comment).Trim() }
    if ($hasRetention) {
        $params['RetentionAction'] = $action
        $params['RetentionType'] = $type
        $params['RetentionDuration'] = $(if ($durationText -eq 'Unlimited') { 'Unlimited' } else { $days })
        if ($eventTypeName) { $params['EventType'] = $eventTypeName }
    }
    if ($isRecord) { $params['IsRecordLabel'] = $true }
    if ($regulatory) { $params['Regulatory'] = $true; Write-Warning "Label '$name' is a regulatory record label: once applied it can never be removed or shortened." }
    $reviewers = @(([string]$row.ReviewerEmail) -split '[;,]' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    if ($reviewers.Count -gt 0) { $params['ReviewerEmail'] = $reviewers }
    $filePlan = @(foreach ($column in $filePlanColumns.Keys) {
            $value = ([string]$row.$column).Trim()
            if ($value) { [ordered]@{ Key = $filePlanColumns[$column]; Value = $value } }
        })
    if ($filePlan.Count -gt 0) { $params['FilePlanProperty'] = ConvertTo-Json -InputObject @{ Settings = @($filePlan) } -Compress -Depth 5 }

    $description = if ($hasRetention) { "Create retention label ($action, $durationText days, $type)" } else { 'Create classification-only retention label' }
    if ($PSCmdlet.ShouldProcess($name, $description)) {
        try {
            New-ComplianceTag @params | Out-Null
            $existingNames += $name
            $results.Add([PSCustomObject]@{ Name = $name; Status = 'Created'; Detail = $description })
        }
        catch {
            Write-Warning "Failed to create label '$name': $($_.Exception.Message)"
            $results.Add([PSCustomObject]@{ Name = $name; Status = 'Failed'; Detail = $_.Exception.Message })
        }
    }
    else { $results.Add([PSCustomObject]@{ Name = $name; Status = 'Planned'; Detail = $description }) }
}

$publishStatus = 'not requested'
$toPublish = @($results | Where-Object { $_.Status -in @('Created', 'Exists') } | ForEach-Object { $_.Name } | Sort-Object -Unique)
if (-not [string]::IsNullOrWhiteSpace($PublishToPolicy) -and $toPublish.Count -gt 0) {
    $publishStatus = 'skipped'
    try {
        $policy = Get-RetentionCompliancePolicy -Identity $PublishToPolicy -ErrorAction SilentlyContinue
        if ($null -eq $policy -and $PSCmdlet.ShouldProcess($PublishToPolicy, 'Create label policy for all Exchange, SharePoint, OneDrive and Microsoft 365 Group locations')) {
            $policy = New-RetentionCompliancePolicy -Name $PublishToPolicy -ExchangeLocation All -SharePointLocation All -OneDriveLocation All -ModernGroupLocation All -ErrorAction Stop
        }
        if ($null -ne $policy) {
            $rule = @(Get-RetentionComplianceRule -Policy $PublishToPolicy -ErrorAction Stop | Select-Object -First 1)
            if ($rule.Count -gt 0) {
                # Existing rules hold label GUIDs; translate them to names so the merged list is consistent.
                $labelNameByGuid = @{}
                foreach ($label in @(Get-ComplianceTag -ErrorAction Stop)) { $labelNameByGuid[[string]$label.Guid] = [string]$label.Name }
                $current = @(([string]$rule[0].PublishComplianceTag) -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ } |
                        ForEach-Object { if ($labelNameByGuid.ContainsKey($_)) { $labelNameByGuid[$_] } else { $_ } })
                $merged = @($current + $toPublish | Sort-Object -Unique)
                if ($PSCmdlet.ShouldProcess("$PublishToPolicy / $($rule[0].Name)", "Publish labels: $($merged -join ', ')")) {
                    Set-RetentionComplianceRule -Identity $rule[0].Name -PublishComplianceTag ($merged -join ',') -ErrorAction Stop
                    $publishStatus = "updated rule '$($rule[0].Name)' ($($merged.Count) labels)"
                }
            }
            elseif ($PSCmdlet.ShouldProcess($PublishToPolicy, "Create rule publishing: $($toPublish -join ', ')")) {
                New-RetentionComplianceRule -Name "$PublishToPolicy Rule" -Policy $PublishToPolicy -PublishComplianceTag ($toPublish -join ',') -ErrorAction Stop | Out-Null
                $publishStatus = "created rule '$PublishToPolicy Rule' ($($toPublish.Count) labels)"
            }
        }
    }
    catch { Write-Warning "Publishing to '$PublishToPolicy' failed: $($_.Exception.Message)" }
}

Write-Host "`nRetention label creation summary" -ForegroundColor Cyan
foreach ($status in 'Created', 'Planned', 'Exists', 'Invalid', 'Failed') {
    Write-Host ('  {0,-8}: {1}' -f $status, @($results | Where-Object { $_.Status -eq $status }).Count)
}
Write-Host ('  Publish : {0}' -f $publishStatus)

if ($PassThru) {
    $results
}
#endregion Main
