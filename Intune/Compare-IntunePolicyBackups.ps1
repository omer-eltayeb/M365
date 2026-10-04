<#
.SYNOPSIS
    Compares two Intune policy backup folders created by Export-IntunePolicies.ps1 and reports added, removed and changed policies.
.DESCRIPTION
    Loads every JSON file below the reference and difference folders (one <PolicyType> subfolder per policy type), matches
    the policies by their Graph id (file name as fallback) and compares the documents property by property with a recursive
    helper. Volatile properties (lastModifiedDateTime, createdDateTime, version, @odata.context, assignment ids) are ignored
    so that only real configuration drift is reported as 'path: old -> new'. Works completely offline - no Graph connection
    is needed - which makes it suitable for change reviews, drift detection between tenants and scheduled backup diffs.
    Writes a CSV and optionally emits the rows.
.PARAMETER ReferenceFolder
    Older (baseline) backup folder, for example .\IntuneBackup_20260901-0800.
.PARAMETER DifferenceFolder
    Newer backup folder to compare against the baseline, for example .\IntuneBackup_20261001-0800.
.PARAMETER IncludeUnchanged
    Also list policies without differences (Status Unchanged).
.PARAMETER OutputPath
    CSV path. Defaults to .\Reports\IntunePolicyBackupCompare_yyyyMMdd-HHmm.csv; the folder is created when missing.
.PARAMETER PassThru
    Also emit the comparison objects to the pipeline.
.EXAMPLE
    PS> .\Compare-IntunePolicyBackups.ps1 -ReferenceFolder .\IntuneBackup_20260901-0800 -DifferenceFolder .\IntuneBackup_20261001-0800
    Reports every policy that was added, removed or changed between the two backups.
.EXAMPLE
    PS> .\Compare-IntunePolicyBackups.ps1 -ReferenceFolder D:\Backups\Prod -DifferenceFolder D:\Backups\Test -IncludeUnchanged -PassThru | Out-GridView
    Compares a production export with a test tenant export, including identical policies, and browses the result interactively.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x
    Permissions : None (offline comparison of local JSON files)
    Category    : Compliance, configuration & RBAC
    Changes     : No
    Notes       : Arrays (settings, scheduled actions, assignments) are compared by position, so re-ordering shows up as changes.
                  Backups taken with different PowerShell editions can differ in how dates are serialised ("\/Date(...)\/" on
                  Windows PowerShell 5.1, ISO 8601 on PowerShell 7); compare backups produced by the same edition where possible.
                  ChangedProperties is truncated to 500 characters; ChangedCount always holds the full number of differences.
.LINK
    https://learn.microsoft.com/powershell/module/microsoft.powershell.utility/convertfrom-json
#>
#Requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ReferenceFolder,

    [Parameter(Mandatory = $true)]
    [string]$DifferenceFolder,

    [Parameter()]
    [switch]$IncludeUnchanged,

    [Parameter()]
    [string]$OutputPath,

    [Parameter()]
    [switch]$PassThru
)

$ErrorActionPreference = 'Stop'

#region Helpers
function Get-BackupPolicies {
    <# Loads every JSON file below a backup folder into a hashtable keyed by '<PolicyType>|<id>' (file name when the id is missing). #>
    param([string]$Folder)
    $root = (Resolve-Path -LiteralPath $Folder).ProviderPath
    $map = @{}
    foreach ($file in @(Get-ChildItem -LiteralPath $root -Filter '*.json' -Recurse -File)) {
        try {
            $policy = Get-Content -LiteralPath $file.FullName -Raw -Encoding UTF8 | ConvertFrom-Json
        }
        catch {
            Write-Warning ("Skipping unreadable JSON file '{0}': {1}" -f $file.FullName, $_.Exception.Message)
            continue
        }
        $policyType = $file.DirectoryName.Substring($root.Length).Trim('\', '/')
        if ([string]::IsNullOrEmpty($policyType)) { $policyType = '(root)' }
        $id = [string]$policy.id
        if ([string]::IsNullOrEmpty($id)) { $id = $file.BaseName }
        $name = [string]$policy.displayName
        if ([string]::IsNullOrEmpty($name)) { $name = [string]$policy.name }
        if ([string]::IsNullOrEmpty($name)) { $name = $file.BaseName }
        $map[('{0}|{1}' -f $policyType, $id)] = [PSCustomObject]@{ PolicyType = $policyType; Id = $id; Name = $name; File = $file.FullName; Policy = $policy }
    }
    return $map
}

function Format-JsonValue {
    <# Renders a scalar, object or array as a short single-line string for the change description. #>
    param($Value)
    if ($null -eq $Value) { return '<null>' }
    if ($Value -is [System.Management.Automation.PSCustomObject] -or $Value -is [array]) { $text = [string]($Value | ConvertTo-Json -Compress -Depth 10) }
    else { $text = [string]$Value }
    if ($text.Length -gt 80) { $text = $text.Substring(0, 77) + '...' }
    return $text
}

function Compare-JsonValue {
    <# Recursively compares two deserialised JSON values and records every difference as 'path: old -> new'. #>
    param($Reference, $Difference, [string]$Path, [System.Collections.Generic.List[object]]$Changes)
    $bothObjects = ($Reference -is [System.Management.Automation.PSCustomObject]) -and ($Difference -is [System.Management.Automation.PSCustomObject])
    $bothArrays = ($Reference -is [array]) -and ($Difference -is [array])
    if ($bothObjects) {
        $names = @(@($Reference.PSObject.Properties.Name) + @($Difference.PSObject.Properties.Name) | Sort-Object -Unique)
        foreach ($name in $names) {
            if ($script:ignoredProperties -contains $name) { continue }
            # Assignment ids embed the policy id, so they always differ between a backup and its restored copy.
            if ($name -eq 'id' -and $Path -match '(^|\.)assignments\[\d+\]$') { continue }
            $childPath = $name
            if (-not [string]::IsNullOrEmpty($Path)) { $childPath = '{0}.{1}' -f $Path, $name }
            Compare-JsonValue -Reference $Reference.$name -Difference $Difference.$name -Path $childPath -Changes $Changes
        }
        return
    }
    if ($bothArrays) {
        if ($Reference.Count -ne $Difference.Count) { $Changes.Add(('{0}.Count: {1} -> {2}' -f $Path, $Reference.Count, $Difference.Count)) }
        $shared = [Math]::Min($Reference.Count, $Difference.Count)
        for ($i = 0; $i -lt $shared; $i++) {
            Compare-JsonValue -Reference $Reference[$i] -Difference $Difference[$i] -Path ('{0}[{1}]' -f $Path, $i) -Changes $Changes
        }
        return
    }
    $referenceText = Format-JsonValue -Value $Reference
    $differenceText = Format-JsonValue -Value $Difference
    if ($referenceText -cne $differenceText) { $Changes.Add(('{0}: {1} -> {2}' -f $Path, $referenceText, $differenceText)) }
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('IntunePolicyBackupCompare_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}
foreach ($folder in @($ReferenceFolder, $DifferenceFolder)) {
    if (-not (Test-Path -LiteralPath $folder -PathType Container)) { throw "Backup folder '$folder' does not exist." }
}

$script:ignoredProperties = @('lastModifiedDateTime', 'createdDateTime', 'version', '@odata.context')
$reference = Get-BackupPolicies -Folder $ReferenceFolder
$difference = Get-BackupPolicies -Folder $DifferenceFolder
Write-Verbose ('Reference: {0} policies, difference: {1} policies.' -f $reference.Count, $difference.Count)
$keys = @(@($reference.Keys) + @($difference.Keys) | Sort-Object -Unique)

$results = New-Object -TypeName System.Collections.Generic.List[object]
$index = 0
foreach ($key in $keys) {
    $index++
    Write-Progress -Activity 'Comparing policies' -Status ('{0} of {1}' -f $index, $keys.Count) -PercentComplete ([int](($index / $keys.Count) * 100))
    $referenceItem = $reference[$key]; $differenceItem = $difference[$key]
    $changes = New-Object -TypeName System.Collections.Generic.List[object]
    if ($null -eq $referenceItem) { $status = 'Added'; $item = $differenceItem }
    elseif ($null -eq $differenceItem) { $status = 'Removed'; $item = $referenceItem }
    else {
        $item = $differenceItem
        try {
            Compare-JsonValue -Reference $referenceItem.Policy -Difference $differenceItem.Policy -Path '' -Changes $changes
        }
        catch {
            Write-Warning ("Comparison failed for '{0}': {1}" -f $item.Name, $_.Exception.Message)
            $changes.Add(('<comparison failed: {0}>' -f $_.Exception.Message))
        }
        $status = 'Unchanged'
        if ($changes.Count -gt 0) { $status = 'Changed' }
    }
    if ($status -eq 'Unchanged' -and -not $IncludeUnchanged) { continue }
    $changedText = ($changes -join '; ')
    if ($changedText.Length -gt 500) { $changedText = $changedText.Substring(0, 497) + '...' }
    $results.Add([PSCustomObject]@{
            PolicyType        = $item.PolicyType
            Name              = $item.Name
            Id                = $item.Id
            Status            = $status
            ChangedCount      = $changes.Count
            ChangedProperties = $changedText
            ReferenceFile     = $(if ($null -ne $referenceItem) { $referenceItem.File } else { $null })
            DifferenceFile    = $(if ($null -ne $differenceItem) { $differenceItem.File } else { $null })
        })
}
Write-Progress -Activity 'Comparing policies' -Completed

$results | Sort-Object -Property PolicyType, Status, Name | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
Write-Host ("`nPolicies compared : {0}" -f $keys.Count) -ForegroundColor Cyan
foreach ($group in ($results | Group-Object -Property Status | Sort-Object -Property Name)) {
    $colour = @{ Added = 'Green'; Removed = 'Red'; Changed = 'Yellow'; Unchanged = 'Gray' }[$group.Name]
    Write-Host ('  {0,-10} {1,6}' -f $group.Name, $group.Count) -ForegroundColor $colour
}
if ($results.Count -eq 0) { Write-Host '  No differences found.' -ForegroundColor Green }
Write-Host ('Report saved to {0}' -f $OutputPath) -ForegroundColor Cyan
if ($PassThru) { $results }
#endregion Main
