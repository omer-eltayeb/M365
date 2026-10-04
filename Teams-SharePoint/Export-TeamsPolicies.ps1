<#
.SYNOPSIS
    Exports every Teams policy and tenant configuration definition to JSON and compares the export with a previous one.
.DESCRIPTION
    Runs the Get-Cs* cmdlet of 22 policy types (meeting, messaging, calling, app permission and setup, channels, update
    management, events, live events, audio conferencing, emergency, voice routing, voicemail, dial plan, feedback, mobility,
    Shifts, enhanced encryption, IP phone, files, Cortana) and of 8 tenant-wide configurations (meeting, client, guest
    meeting/messaging/calling, federation, upgrade, dial-in conferencing). Each type is written as <Type>.json in the output
    folder and Index.csv lists the type, the number of instances and their names; cmdlets missing from the installed module
    version are skipped. With -CompareWith the export is diffed against a previous export folder and PolicyDiff.csv lists
    added, removed and changed instances with the property path, old value and new value.
.PARAMETER OutputFolder
    Folder that receives the JSON files, Index.csv and PolicyDiff.csv. Defaults to .\TeamsPoliciesExport_<timestamp>.
.PARAMETER CompareWith
    Path of a previous export folder created by this script. Every <Type>.json found there is compared with the new export.
.PARAMETER PassThru
    Also emit the Index.csv rows (and the PolicyDiff.csv rows when -CompareWith is used) to the pipeline.
.EXAMPLE
    PS> .\Export-TeamsPolicies.ps1
    Writes one JSON file per policy type plus Index.csv to .\TeamsPoliciesExport_<timestamp>\.
.EXAMPLE
    PS> .\Export-TeamsPolicies.ps1 -OutputFolder C:\Backups\TeamsPolicies\2026-10 -CompareWith C:\Backups\TeamsPolicies\2026-09 -Verbose
    Exports the current definitions and writes PolicyDiff.csv with every setting that changed since the September export.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, MicrosoftTeams
    Permissions : Teams Administrator or Global Reader (read-only).
    Category    : Teams administration (MicrosoftTeams module)
    Changes     : No
    Notes       : The JSON files are a configuration snapshot for documentation and change tracking, not a restore format;
                  re-creating a policy still requires the matching New-/Set-Cs* cmdlet. Identities are written as returned
                  by the module ("Global" or "Tag:<name>"); nested objects are serialised up to 10 levels deep.
.LINK
    https://learn.microsoft.com/powershell/module/microsoftteams/get-csteamsmeetingpolicy
.LINK
    https://learn.microsoft.com/powershell/module/microsoftteams/get-cstenantfederationconfiguration
#>
#Requires -Version 5.1
#Requires -Modules MicrosoftTeams

[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputFolder,

    [Parameter()]
    [ValidateScript({ Test-Path -Path $_ -PathType Container })]
    [string]$CompareWith,

    [Parameter()]
    [switch]$PassThru
)

$ErrorActionPreference = 'Stop'

#region Helpers
function Connect-TeamsIfNeeded {
    <# Connects to Microsoft Teams PowerShell only when there is no live session. #>
    [CmdletBinding()]
    param()
    $connected = $false
    try { $null = Get-CsTenant -ErrorAction Stop; $connected = $true } catch { $connected = $false }
    if (-not $connected) {
        Write-Verbose 'Connecting to Microsoft Teams PowerShell.'
        Connect-MicrosoftTeams -ErrorAction Stop | Out-Null
    }
}

function ConvertTo-FlatProperties {
    <# Flattens a deserialised JSON object into "Path = Value" pairs so two exports can be compared setting by setting. #>
    param(
        [Parameter()]
        [object]$InputObject,

        [Parameter()]
        [string]$Prefix = ''
    )
    $result = @{}
    if ($null -eq $InputObject) { $result[$Prefix] = $null; return $result }
    if ($InputObject -is [System.Collections.IList]) {
        $index = 0
        foreach ($item in $InputObject) {
            $flat = ConvertTo-FlatProperties -InputObject $item -Prefix ('{0}[{1}]' -f $Prefix, $index)
            foreach ($key in $flat.Keys) { $result[$key] = $flat[$key] }
            $index++
        }
        if ($index -eq 0) { $result[$Prefix] = '[]' }
        return $result
    }
    if ($InputObject -is [System.Management.Automation.PSCustomObject]) {
        foreach ($property in $InputObject.PSObject.Properties) {
            $path = $property.Name
            if (-not [string]::IsNullOrEmpty($Prefix)) { $path = '{0}.{1}' -f $Prefix, $property.Name }
            $flat = ConvertTo-FlatProperties -InputObject $property.Value -Prefix $path
            foreach ($key in $flat.Keys) { $result[$key] = $flat[$key] }
        }
        return $result
    }
    $result[$Prefix] = [string]$InputObject
    return $result
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputFolder)) {
    $OutputFolder = Join-Path -Path (Get-Location).Path -ChildPath ('TeamsPoliciesExport_{0}' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
if (-not (Test-Path -Path $OutputFolder)) {
    New-Item -Path $OutputFolder -ItemType Directory -Force | Out-Null
}

try { Connect-TeamsIfNeeded } catch { throw "Failed to connect to Microsoft Teams PowerShell: $($_.Exception.Message)" }

$policyCmdlets = @(
    'Get-CsTeamsMeetingPolicy', 'Get-CsTeamsMessagingPolicy', 'Get-CsTeamsCallingPolicy', 'Get-CsTeamsAppPermissionPolicy',
    'Get-CsTeamsAppSetupPolicy', 'Get-CsTeamsChannelsPolicy', 'Get-CsTeamsUpdateManagementPolicy', 'Get-CsTeamsEventsPolicy',
    'Get-CsTeamsMeetingBroadcastPolicy', 'Get-CsTeamsAudioConferencingPolicy', 'Get-CsTeamsEmergencyCallingPolicy',
    'Get-CsTeamsEmergencyCallRoutingPolicy', 'Get-CsOnlineVoiceRoutingPolicy', 'Get-CsOnlineVoicemailPolicy', 'Get-CsTenantDialPlan',
    'Get-CsTeamsFeedbackPolicy', 'Get-CsTeamsMobilityPolicy', 'Get-CsTeamsShiftsPolicy', 'Get-CsTeamsEnhancedEncryptionPolicy',
    'Get-CsTeamsIPPhonePolicy', 'Get-CsTeamsFilesPolicy', 'Get-CsTeamsCortanaPolicy', 'Get-CsTeamsMeetingConfiguration',
    'Get-CsTeamsClientConfiguration', 'Get-CsTeamsGuestMeetingConfiguration', 'Get-CsTeamsGuestMessagingConfiguration',
    'Get-CsTeamsGuestCallingConfiguration', 'Get-CsTenantFederationConfiguration', 'Get-CsTeamsUpgradeConfiguration',
    'Get-CsOnlineDialInConferencingTenantSettings'
)
# Transport / XDS bookkeeping properties carried by the older configuration objects; they are not settings.
$noiseProperties = @('Element', 'Anchor', 'Key', 'ScopeClass', 'PSComputerName', 'RunspaceId')

$indexRows = New-Object -TypeName System.Collections.Generic.List[object]
$diffRows = New-Object -TypeName System.Collections.Generic.List[object]
$skipped = 0; $counter = 0
foreach ($cmdlet in $policyCmdlets) {
    $counter++
    $policyType = $cmdlet -replace '^Get-Cs', ''
    Write-Progress -Activity 'Exporting Teams policies' -Status "$counter of $($policyCmdlets.Count): $policyType" -PercentComplete ([int](($counter / $policyCmdlets.Count) * 100))
    if ($null -eq (Get-Command -Name $cmdlet -ErrorAction SilentlyContinue)) {
        Write-Verbose "Skipping $policyType because $cmdlet is not available in this module version."
        $skipped++
        continue
    }
    try {
        # Identity is rewritten as a plain string so legacy XdsIdentity objects serialise and compare like the modern ones.
        $items = @(& $cmdlet -ErrorAction Stop | Select-Object -Property * -ExcludeProperty $noiseProperties | ForEach-Object {
                if ($null -ne $_.PSObject.Properties['Identity']) { $_.Identity = [string]$_.Identity }
                $_
            } | Sort-Object -Property Identity)
    }
    catch {
        Write-Warning "Skipping ${policyType}: $($_.Exception.Message)"
        $skipped++
        continue
    }
    # -InputObject keeps a single instance as a JSON array so every file has the same shape.
    $json = ConvertTo-Json -InputObject @($items) -Depth 10
    Set-Content -Path (Join-Path -Path $OutputFolder -ChildPath "$policyType.json") -Value $json -Encoding UTF8
    $names = @($items | ForEach-Object { [string]$_.Identity })
    $indexRows.Add([PSCustomObject]@{
            PolicyType = $policyType
            Count      = $items.Count
            Names      = ($names -join ';')
            File       = "$policyType.json"
        })

    if ([string]::IsNullOrWhiteSpace($CompareWith)) { continue }
    $previousFile = Join-Path -Path $CompareWith -ChildPath "$policyType.json"
    if (-not (Test-Path -Path $previousFile)) {
        Write-Verbose "No previous export for $policyType in '$CompareWith'; nothing to compare."
        continue
    }
    $previousMap = @{}
    foreach ($item in @(ConvertFrom-Json -InputObject (Get-Content -Path $previousFile -Raw))) { $previousMap[[string]$item.Identity] = $item }
    $currentMap = @{}
    foreach ($item in @(ConvertFrom-Json -InputObject $json)) { $currentMap[[string]$item.Identity] = $item }

    foreach ($identity in @(@($previousMap.Keys) + @($currentMap.Keys) | Sort-Object -Unique)) {
        if (-not $previousMap.ContainsKey($identity) -or -not $currentMap.ContainsKey($identity)) {
            $change = 'Removed'
            if ($currentMap.ContainsKey($identity)) { $change = 'Added' }
            $diffRows.Add([PSCustomObject]@{ PolicyType = $policyType; Identity = $identity; Change = $change; PropertyPath = $null; OldValue = $null; NewValue = $null })
            continue
        }
        $before = ConvertTo-FlatProperties -InputObject $previousMap[$identity]
        $after = ConvertTo-FlatProperties -InputObject $currentMap[$identity]
        foreach ($path in @(@($before.Keys) + @($after.Keys) | Sort-Object -Unique)) {
            if ([string]$before[$path] -ne [string]$after[$path]) {
                $diffRows.Add([PSCustomObject]@{ PolicyType = $policyType; Identity = $identity; Change = 'Changed'; PropertyPath = $path; OldValue = $before[$path]; NewValue = $after[$path] })
            }
        }
    }
}
Write-Progress -Activity 'Exporting Teams policies' -Completed

$indexPath = Join-Path -Path $OutputFolder -ChildPath 'Index.csv'
$indexRows | Export-Csv -Path $indexPath -NoTypeInformation -Encoding UTF8
$diffPath = Join-Path -Path $OutputFolder -ChildPath 'PolicyDiff.csv'
if ($diffRows.Count -gt 0) { $diffRows | Export-Csv -Path $diffPath -NoTypeInformation -Encoding UTF8 }

$instanceCount = 0
foreach ($indexRow in $indexRows) { $instanceCount += $indexRow.Count }
Write-Host ''
Write-Host 'Teams policy export summary' -ForegroundColor Cyan
Write-Host ('  Policy types exported / skipped : {0} / {1}' -f $indexRows.Count, $skipped)
Write-Host ('  Policy instances                : {0}' -f $instanceCount)
Write-Host ('  Output folder                   : {0}' -f $OutputFolder)
if (-not [string]::IsNullOrWhiteSpace($CompareWith)) {
    $added = @($diffRows | Where-Object { $_.Change -eq 'Added' }).Count
    $removed = @($diffRows | Where-Object { $_.Change -eq 'Removed' }).Count
    $changed = @($diffRows | Where-Object { $_.Change -eq 'Changed' }).Count
    Write-Host ('  Compared with                   : {0}' -f $CompareWith)
    Write-Host ('  Added / removed / changed       : {0} / {1} / {2}' -f $added, $removed, $changed) -ForegroundColor Yellow
    if ($diffRows.Count -gt 0) { Write-Host ('  Differences                     : {0} -> {1}' -f $diffRows.Count, $diffPath) }
}

if ($PassThru) { $indexRows; $diffRows }
#endregion Main
