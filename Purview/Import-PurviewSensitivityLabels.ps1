<#
.SYNOPSIS
    Bulk-creates Microsoft Purview sensitivity labels from a CSV file and optionally publishes them in a label policy.
.DESCRIPTION
    Reads a CSV with the columns Name, DisplayName, Tooltip, ParentLabelName, ContentType, EncryptionEnabled,
    EncryptionProtectionType (Template or UserDefined), EncryptionRightsDefinitions, ContentMarkingHeaderText,
    ContentMarkingFooterText and WatermarkText, and creates each label with New-Label (Security & Compliance
    PowerShell): sub-labels are attached to their parent, encryption never expires and allows 30 days offline access,
    and header, footer and watermark markings are enabled whenever text is supplied. Existing labels are skipped.
    Without -Apply the script only validates the file and reports what would be created. -Publish adds the labels to a
    label policy (New-LabelPolicy for all Exchange mailboxes, or Set-LabelPolicy -AddLabels when the policy exists).
.PARAMETER InputCsv
    Path of the CSV file to import. Name and DisplayName are required; every other column is optional.
.PARAMETER Apply
    Create the labels (and the policy with -Publish). Without it the script runs in preview mode; combine with -WhatIf to see each call.
.PARAMETER Publish
    Publish the imported labels (created or already existing) in the label policy named by -PolicyName.
.PARAMETER PolicyName
    Name of the label policy to create or extend. Required with -Publish.
.PARAMETER OutputPath
    Path of the results CSV. Defaults to .\Reports\PurviewLabelImport_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emit the per-row result objects to the pipeline.
.EXAMPLE
    PS> .\Import-PurviewSensitivityLabels.ps1 -InputCsv .\labels.csv
    Validates the file, resolves parents and reports the labels that would be created. Nothing is changed.
.EXAMPLE
    PS> .\Import-PurviewSensitivityLabels.ps1 -InputCsv .\labels.csv -Apply -Publish -PolicyName 'Global label policy' -Confirm:$false
    Creates the missing labels and publishes every label in the file through the named policy without prompting.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, ExchangeOnlineManagement 3.x
    Permissions : Compliance Administrator, Compliance Data Administrator or Information Protection Admin (Security & Compliance PowerShell)
    Category    : Information protection
    Changes     : Yes
    Notes       : Opens a Security & Compliance PowerShell session (Connect-IPPSSession). ContentType accepts combinations of
                  File, Email, Site, UnifiedGroup, PurviewAssets, Teamwork and SchematizedData. EncryptionRightsDefinitions uses
                  "user@contoso.com:VIEW,EDIT;group@contoso.com:VIEW" and is required for Template encryption; UserDefined lets
                  users assign permissions. Tooltip falls back to DisplayName (New-Label requires it). Labels take up to 24 h to appear.
.LINK
    https://learn.microsoft.com/powershell/module/exchange/new-label
.LINK
    https://learn.microsoft.com/powershell/module/exchange/new-labelpolicy
#>
#Requires -Version 5.1
#Requires -Modules ExchangeOnlineManagement

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path -Path $_ -PathType Leaf })]
    [string]$InputCsv,

    [Parameter()]
    [switch]$Apply,

    [Parameter()]
    [switch]$Publish,

    [Parameter()]
    [string]$PolicyName,

    [Parameter()]
    [string]$OutputPath,

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
if ($Publish -and [string]::IsNullOrWhiteSpace($PolicyName)) { throw '-PolicyName is required when -Publish is specified.' }
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('PurviewLabelImport_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}

$rows = @(Import-Csv -Path $InputCsv -ErrorAction Stop)
if ($rows.Count -eq 0) { throw "The input file '$InputCsv' contains no rows." }
foreach ($column in 'Name', 'DisplayName') { if ($null -eq $rows[0].PSObject.Properties[$column]) { throw "The input file must contain a '$column' column." } }

try {
    Connect-ExchangeIfNeeded -Compliance
    $existingLabels = @(Get-Label -ErrorAction Stop)
}
catch {
    throw "Unable to connect to Security & Compliance PowerShell or read the existing labels: $($_.Exception.Message)"
}

# Name -> GUID of existing labels; labels created in this run are added so later rows can reference them as parents.
$labelIds = @{}
foreach ($label in $existingLabels) { $labelIds[([string]$label.Name).ToLowerInvariant()] = [string]$label.Guid }

$results = New-Object -TypeName System.Collections.Generic.List[object]
$index = 0
foreach ($row in $rows) {
    $index++
    $name = ([string]$row.Name).Trim()
    Write-Progress -Activity 'Importing sensitivity labels' -Status ('{0} of {1}: {2}' -f $index, $rows.Count, $name) -PercentComplete (($index / $rows.Count) * 100)
    $result = [PSCustomObject]@{ Name = $name; DisplayName = [string]$row.DisplayName; ParentLabelName = ([string]$row.ParentLabelName).Trim(); Result = $null; Guid = $null; Detail = $null }
    $results.Add($result)
    if ([string]::IsNullOrWhiteSpace($name)) { $result.Result = 'Failed'; $result.Detail = 'Name is empty'; continue }
    if ($labelIds.ContainsKey($name.ToLowerInvariant())) { $result.Result = 'Exists'; $result.Guid = $labelIds[$name.ToLowerInvariant()]; $result.Detail = 'Label already exists'; continue }

    $params = @{ Name = $name; DisplayName = [string]$row.DisplayName; Tooltip = [string]$row.Tooltip; ErrorAction = 'Stop' }
    if ([string]::IsNullOrWhiteSpace($params['Tooltip'])) { $params['Tooltip'] = $params['DisplayName'] }
    if (-not [string]::IsNullOrWhiteSpace($result.ParentLabelName)) {
        if (-not $labelIds.ContainsKey($result.ParentLabelName.ToLowerInvariant())) {
            $result.Result = 'Failed'; $result.Detail = "Parent label '$($result.ParentLabelName)' not found (parents must exist or precede sub-labels)"; continue
        }
        $params['ParentId'] = $labelIds[$result.ParentLabelName.ToLowerInvariant()]
    }
    if (-not [string]::IsNullOrWhiteSpace([string]$row.ContentType)) {
        $params['ContentType'] = ((([string]$row.ContentType) -split '[,;]' | ForEach-Object { $_.Trim() } | Where-Object { $_ }) -join ', ')
    }
    if (([string]$row.EncryptionEnabled) -match '^(true|yes|1)$') {
        $protectionType = ([string]$row.EncryptionProtectionType).Trim()
        if ($protectionType -notin 'Template', 'UserDefined') { $result.Result = 'Failed'; $result.Detail = 'EncryptionProtectionType must be Template or UserDefined'; continue }
        if ($protectionType -eq 'Template' -and [string]::IsNullOrWhiteSpace([string]$row.EncryptionRightsDefinitions)) {
            $result.Result = 'Failed'; $result.Detail = 'Template encryption requires EncryptionRightsDefinitions'; continue
        }
        $params['EncryptionEnabled'] = $true; $params['EncryptionProtectionType'] = $protectionType
        $params['EncryptionContentExpiredOnDateInDaysOrNever'] = 'Never'; $params['EncryptionOfflineAccessDays'] = 30
        if ($protectionType -eq 'Template') { $params['EncryptionRightsDefinitions'] = [string]$row.EncryptionRightsDefinitions } else { $params['EncryptionPromptUser'] = $true }
    }
    foreach ($marking in @(@('ContentMarkingHeaderText', 'ApplyContentMarkingHeader'), @('ContentMarkingFooterText', 'ApplyContentMarkingFooter'), @('WatermarkText', 'ApplyWaterMarking'))) {
        $text = [string]$row.($marking[0])
        if (-not [string]::IsNullOrWhiteSpace($text)) { $params[$marking[1] + 'Enabled'] = $true; $params[$marking[1] + 'Text'] = $text }
    }
    $result.Detail = 'Settings: ' + (($params.Keys | Where-Object { $_ -notin 'Name', 'DisplayName', 'Tooltip', 'ErrorAction' } | Sort-Object) -join ', ')

    if (-not $Apply) { $result.Result = 'Preview'; continue }
    if (-not $PSCmdlet.ShouldProcess($name, 'Create sensitivity label')) { $result.Result = 'Declined'; $result.Detail = 'Declined or -WhatIf'; continue }
    try {
        $created = New-Label @params
        $labelIds[$name.ToLowerInvariant()] = [string]$created.Guid
        $result.Result = 'Created'; $result.Guid = [string]$created.Guid
    }
    catch {
        $result.Result = 'Failed'; $result.Detail = $_.Exception.Message
        Write-Warning "Label '$name' could not be created: $($_.Exception.Message)"
    }
}
Write-Progress -Activity 'Importing sensitivity labels' -Completed
$publishedCount = 0
$publishable = @($results | Where-Object { $_.Result -in 'Created', 'Exists', 'Preview' })
if ($Publish -and $publishable.Count -gt 0) {
    # A sub-label can only be published together with its parent, so parents named in the file are included as well.
    $labelsToPublish = @($publishable | ForEach-Object { $_.Name; $_.ParentLabelName } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique)
    $policyAction = "Create label policy with $($labelsToPublish.Count) label(s) for all Exchange mailboxes"
    # Filtered client-side: Get-LabelPolicy -Identity returns every policy when the name does not exist.
    $policy = Get-LabelPolicy -ErrorAction Stop | Where-Object { $_.Name -eq $PolicyName } | Select-Object -First 1
    if ($null -ne $policy) {
        $currentLabels = @($policy.Labels | ForEach-Object { [string]$_ })
        $labelsToPublish = @($labelsToPublish | Where-Object { $currentLabels -notcontains $_ })
        $policyAction = "Add $($labelsToPublish.Count) label(s) to the existing label policy"
    }
    if (-not $Apply) { Write-Host "Preview: $policyAction '$PolicyName': $($labelsToPublish -join ', ')" -ForegroundColor Yellow }
    elseif ($labelsToPublish.Count -eq 0) { Write-Host "Label policy '$PolicyName' already contains every label from the file." }
    elseif ($PSCmdlet.ShouldProcess($PolicyName, $policyAction)) {
        try {
            if ($null -eq $policy) { New-LabelPolicy -Name $PolicyName -Labels $labelsToPublish -ExchangeLocation All -ErrorAction Stop | Out-Null }
            else { Set-LabelPolicy -Identity $PolicyName -AddLabels $labelsToPublish -ErrorAction Stop }
            $publishedCount = $labelsToPublish.Count
        }
        catch {
            Write-Warning "Publishing to label policy '$PolicyName' failed: $($_.Exception.Message)"
        }
    }
}

$results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
Write-Host ''
Write-Host ('Sensitivity label import summary ({0})' -f $(if ($Apply) { 'applied' } else { 'preview only, use -Apply to create' })) -ForegroundColor Cyan
foreach ($group in ($results | Group-Object -Property Result | Sort-Object -Property Name)) {
    Write-Host ('  {0,-10}: {1}' -f $group.Name, $group.Count) -ForegroundColor $(if ($group.Name -eq 'Failed') { 'Yellow' } else { 'Gray' })
}
if ($Publish) { Write-Host ('  Published : {0} label(s) via policy {1}' -f $publishedCount, $PolicyName) }
Write-Host ('  Report    : {0}' -f $OutputPath)

if ($PassThru) {
    $results
}
#endregion Main
