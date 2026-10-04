<#
.SYNOPSIS
    Restores Intune device configuration, compliance, settings catalog and platform script policies from an Export-IntunePolicies.ps1 backup.
.DESCRIPTION
    Reads the JSON files below <InputFolder>\<PolicyType>\, strips the read-only and tenant-specific properties (id, timestamps,
    version, supportsScopeTags, OData annotations, assignments) and creates each policy as a new object via POST to v1.0
    /deviceManagement/deviceConfigurations, v1.0 /deviceManagement/deviceCompliancePolicies (a 'block immediately' scheduled
    action is added when the backup has none), beta /deviceManagement/configurationPolicies or beta /deviceManagement/deviceManagementScripts.
    Names get a prefix so restored copies never collide with live policies; every creation goes through ShouldProcess, so -WhatIf
    previews the restore and -Confirm:$false runs it unattended. Administrative templates (ADMX) are not supported.
.PARAMETER InputFolder
    Backup folder created by Export-IntunePolicies.ps1 (contains DeviceConfiguration, Compliance, SettingsCatalog, PlatformScript subfolders).
.PARAMETER PolicyType
    One or more policy types to restore: All, DeviceConfiguration, Compliance, SettingsCatalog or PlatformScript. Default: All.
.PARAMETER NamePrefix
    Text placed in front of every restored policy name. Default 'Restored - '; pass '' to keep the original names.
.PARAMETER RestoreAssignments
    Re-create the original assignments (POST /assign with the backed-up targets). The group and filter ids must exist in the tenant.
.EXAMPLE
    PS> .\Import-IntunePolicies.ps1 -InputFolder .\IntuneBackup_20261001-0800 -WhatIf
    Shows which policies would be created from the backup without changing anything.
.EXAMPLE
    PS> .\Import-IntunePolicies.ps1 -InputFolder .\IntuneBackup_20261001-0800 -PolicyType Compliance, SettingsCatalog -RestoreAssignments -Confirm:$false
    Restores the compliance and settings catalog policies including their original group assignments without prompting.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : DeviceManagementConfiguration.ReadWrite.All (delegated) plus an Intune RBAC role such as Policy and Profile Manager
    Category    : Compliance, configuration & RBAC
    Changes     : Yes
    Notes       : Settings catalog policies and platform scripts are created through the beta endpoint, which Microsoft may change
                  without notice. Policies are always created as new objects, never merged into existing ones. Encrypted OMA-URI
                  values, certificates and other secrets are not contained in a backup and must be re-entered after the restore.
                  Assignments referencing groups or filters missing from the target tenant fail with a Graph error; the policy itself is still created.
.LINK
    https://learn.microsoft.com/graph/api/intune-deviceconfig-deviceconfiguration-create
.LINK
    https://learn.microsoft.com/graph/api/intune-deviceconfigv2-devicemanagementconfigurationpolicy-create?view=graph-rest-beta
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $true)]
    [string]$InputFolder,

    [Parameter()]
    [ValidateSet('All', 'DeviceConfiguration', 'Compliance', 'SettingsCatalog', 'PlatformScript')]
    [string[]]$PolicyType = @('All'),

    [Parameter()]
    [string]$NamePrefix = 'Restored - ',

    [Parameter()]
    [switch]$RestoreAssignments
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

function ConvertTo-RestoreBody {
    <# Copies a backed-up object into an ordered hashtable without the read-only properties and OData annotations Graph rejects on POST. #>
    param($Source, [string[]]$Exclude)
    $body = [ordered]@{}
    foreach ($property in $Source.PSObject.Properties) {
        if ($Exclude -contains $property.Name) { continue }
        if ($property.Name -like '*@odata.*' -and $property.Name -ne '@odata.type') { continue }
        $body[$property.Name] = $property.Value
    }
    return $body
}
#endregion Helpers

#region Main
if (-not (Test-Path -LiteralPath $InputFolder -PathType Container)) { throw "Backup folder '$InputFolder' does not exist." }
$graphV1 = 'https://graph.microsoft.com/v1.0/deviceManagement'
$graphBeta = 'https://graph.microsoft.com/beta/deviceManagement'   # beta: settings catalog policies and platform scripts are not exposed in v1.0
$catalog = @(
    [PSCustomObject]@{ Type = 'DeviceConfiguration'; Uri = "$graphV1/deviceConfigurations"; NameProperty = 'displayName'; AssignKey = 'assignments' }
    [PSCustomObject]@{ Type = 'Compliance'; Uri = "$graphV1/deviceCompliancePolicies"; NameProperty = 'displayName'; AssignKey = 'assignments' }
    [PSCustomObject]@{ Type = 'SettingsCatalog'; Uri = "$graphBeta/configurationPolicies"; NameProperty = 'name'; AssignKey = 'assignments' }
    [PSCustomObject]@{ Type = 'PlatformScript'; Uri = "$graphBeta/deviceManagementScripts"; NameProperty = 'displayName'; AssignKey = 'deviceManagementScriptAssignments' }
)
$selectedTypes = $catalog
if ($PolicyType -notcontains 'All') { $selectedTypes = @($catalog | Where-Object { $PolicyType -contains $_.Type }) }
if (Test-Path -LiteralPath (Join-Path -Path $InputFolder -ChildPath 'AdministrativeTemplate')) {
    Write-Warning 'The AdministrativeTemplate folder is skipped: ADMX-backed policies cannot be restored by this script and must be re-created manually.'
}
$stripProperties = @('id', 'createdDateTime', 'lastModifiedDateTime', 'version', 'supportsScopeTags', '@odata.context', 'assignments')

try { Connect-GraphIfNeeded -Scopes @('DeviceManagementConfiguration.ReadWrite.All') } catch { throw "Failed to connect to Microsoft Graph: $($_.Exception.Message)" }

$results = New-Object -TypeName System.Collections.Generic.List[object]
foreach ($entry in $selectedTypes) {
    $typeFolder = Join-Path -Path $InputFolder -ChildPath $entry.Type
    if (-not (Test-Path -LiteralPath $typeFolder)) { Write-Verbose ('No {0} folder in the backup; skipping.' -f $entry.Type); continue }
    $files = @(Get-ChildItem -LiteralPath $typeFolder -Filter '*.json' -File); $index = 0
    foreach ($file in $files) {
        $index++
        Write-Progress -Activity ('Restoring {0}' -f $entry.Type) -Status ('{0} of {1}: {2}' -f $index, $files.Count, $file.Name) -PercentComplete ([int](($index / $files.Count) * 100))
        $result = 'Failed'; $newId = $null; $errorMessage = $null; $assignmentsRestored = 0; $originalName = $file.BaseName; $newName = $null
        try {
            $policy = Get-Content -LiteralPath $file.FullName -Raw -Encoding UTF8 | ConvertFrom-Json
            $originalName = [string]$policy.($entry.NameProperty); $newName = $NamePrefix + $originalName
            $assignments = @($policy.assignments | Where-Object { $null -ne $_.target })
            $body = ConvertTo-RestoreBody -Source $policy -Exclude $stripProperties
            $body[$entry.NameProperty] = $newName
            switch ($entry.Type) {
                'Compliance' {
                    # Graph rejects a compliance policy without a scheduled action, so keep the backed-up rules (minus ids) or add 'block immediately'.
                    $rules = @(foreach ($rule in @($policy.scheduledActionsForRule)) {
                            $actions = @(foreach ($action in @($rule.scheduledActionConfigurations)) { ConvertTo-RestoreBody -Source $action -Exclude @('id') })
                            @{ ruleName = $rule.ruleName; scheduledActionConfigurations = $actions }
                        })
                    $hasBlock = @($rules | ForEach-Object { $_.scheduledActionConfigurations } | Where-Object { $_.actionType -eq 'block' }).Count -gt 0
                    if (-not $hasBlock) {
                        $blockAction = @{ actionType = 'block'; gracePeriodHours = 0; notificationTemplateId = ''; notificationMessageCCList = @() }
                        if ($rules.Count -eq 0) { $rules = @(@{ ruleName = 'PasswordRequired'; scheduledActionConfigurations = @($blockAction) }) }
                        else { $rules[0].scheduledActionConfigurations = @($rules[0].scheduledActionConfigurations) + @($blockAction) }
                    }
                    $body['scheduledActionsForRule'] = $rules
                }
                'SettingsCatalog' {
                    # The create call accepts only the policy header plus settingInstance objects, not the exported setting wrappers.
                    $settings = @(foreach ($setting in @($policy.settings)) {
                            @{ '@odata.type' = '#microsoft.graph.deviceManagementConfigurationSetting'; settingInstance = $setting.settingInstance }
                        })
                    $body = [ordered]@{ name = $newName; description = [string]$policy.description; platforms = $policy.platforms; technologies = $policy.technologies
                        roleScopeTagIds = @($policy.roleScopeTagIds); settings = $settings }
                    $templateId = [string]$policy.templateReference.templateId
                    if (-not [string]::IsNullOrEmpty($templateId)) { $body['templateReference'] = @{ templateId = $templateId } }
                }
            }
            $target = '{0} "{1}" ({2})' -f $entry.Type, $originalName, $file.Name
            if ($PSCmdlet.ShouldProcess($target, ('Create policy "{0}"' -f $newName))) {
                $created = Invoke-MgGraphRequest -Method POST -Uri $entry.Uri -Body ($body | ConvertTo-Json -Depth 50) -ContentType 'application/json' -OutputType PSObject -ErrorAction Stop
                $newId = [string]$created.id; $result = 'Created'
                if ($RestoreAssignments -and $assignments.Count -gt 0) {
                    $assignBody = @{ $entry.AssignKey = @(foreach ($assignment in $assignments) { @{ target = $assignment.target } }) } | ConvertTo-Json -Depth 20
                    Invoke-MgGraphRequest -Method POST -Uri ('{0}/{1}/assign' -f $entry.Uri, $newId) -Body $assignBody -ContentType 'application/json' -ErrorAction Stop | Out-Null
                    $assignmentsRestored = $assignments.Count
                }
                Start-Sleep -Milliseconds 200
            }
            else { $result = 'Skipped'; if ($WhatIfPreference) { $result = 'WhatIf' } }
        }
        catch {
            $errorMessage = $_.Exception.Message
            if ($result -eq 'Created') { $result = 'CreatedWithoutAssignments' }
            Write-Warning ("{0} '{1}' from {2}: {3}" -f $entry.Type, $originalName, $file.Name, $errorMessage)
        }
        $results.Add([PSCustomObject]@{ PolicyType = $entry.Type; SourceFile = $file.Name; OriginalName = $originalName; NewName = $newName; Result = $result
                NewId = $newId; AssignmentsRestored = $assignmentsRestored; Error = $errorMessage })
    }
    Write-Progress -Activity ('Restoring {0}' -f $entry.Type) -Completed
}

Write-Host ("`nBackup folder : {0} ({1} policy files read)" -f $InputFolder, $results.Count) -ForegroundColor Cyan
foreach ($group in ($results | Group-Object -Property Result | Sort-Object -Property Name)) {
    $colour = @{ Created = 'Green'; Failed = 'Red'; CreatedWithoutAssignments = 'Yellow' }[$group.Name]; if (-not $colour) { $colour = 'Gray' }
    Write-Host ('  {0,-26} {1,6}' -f $group.Name, $group.Count) -ForegroundColor $colour
}

$results
#endregion Main
