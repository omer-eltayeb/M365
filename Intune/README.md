# Microsoft Intune scripts

Reporting, troubleshooting and bulk-action scripts for Microsoft Intune: device inventory and compliance, remote actions, policy backup/restore and documentation, app deployment status, Autopilot and enrollment, Windows Update and remediation scripts, security keys (BitLocker/LAPS) and tenant health.

**53 scripts.** Module(s): Microsoft Graph PowerShell SDK (`Microsoft.Graph.Authentication`) - every call goes through `Invoke-MgGraphRequest`.

Every script has full comment-based help (`Get-Help .\<Script>.ps1 -Full`), writes a timestamped CSV to `.\Reports\` by default (`-OutputPath` to choose, `-PassThru` to keep the objects) and is read-only unless the **Changes anything?** column says otherwise - those scripts support `-WhatIf` / `-Confirm`.

## Contents

- [Devices & remote actions](#devices--remote-actions) (15)
- [Compliance, configuration & RBAC](#compliance-configuration--rbac) (14)
- [Apps & app protection](#apps--app-protection) (6)
- [Enrollment & Autopilot](#enrollment--autopilot) (7)
- [Updates & remediations](#updates--remediations) (5)
- [Reporting & platform insights](#reporting--platform-insights) (6)

## Devices & remote actions

| Script | What it does | Permissions / roles | Changes anything? |
|---|---|---|---|
| [Get-IntuneBitLockerRecoveryKeys.ps1](./Get-IntuneBitLockerRecoveryKeys.ps1) | Inventories the BitLocker recovery keys escrowed in Entra ID, joined to the owning device, optionally including the key material for selected devices. | BitLockerKey.ReadBasic.All and Device.Read.All; BitLockerKey.Read.All only with -IncludeKey (delegated). | No |
| [Get-IntuneDeviceComplianceReport.ps1](./Get-IntuneDeviceComplianceReport.ps1) | Inventory and compliance report for all Intune managed devices. | DeviceManagementManagedDevices.Read.All (delegated) plus an Intune RBAC role such as Read Only Operator | No |
| [Get-IntuneDeviceHardwareInventory.ps1](./Get-IntuneDeviceHardwareInventory.ps1) | Builds a per-device hardware inventory (storage, memory, TPM, BIOS, battery, network) for Intune managed devices. | DeviceManagementManagedDevices.Read.All (delegated); Intune Read Only Operator or higher. | No |
| [Get-IntuneDevicesPerUser.ps1](./Get-IntuneDevicesPerUser.ps1) | Groups Intune managed devices by primary user and reports users who own an unusually high number of devices. | DeviceManagementManagedDevices.Read.All (delegated); Intune Read Only Operator or higher. | No |
| [Get-IntuneEncryptionReport.ps1](./Get-IntuneEncryptionReport.ps1) | Reports the encryption state of Intune managed devices and, optionally, whether Windows devices have a BitLocker recovery key escrowed in Entra ID. | DeviceManagementManagedDevices.Read.All; BitLockerKey.ReadBasic.All only with -CheckRecoveryKeys (delegated). | No |
| [Get-IntuneLapsPasswords.ps1](./Get-IntuneLapsPasswords.ps1) | Reports Windows LAPS password backups in Entra ID, flags stale or overdue backups and optionally retrieves the current local administrator password. | DeviceLocalCredential.ReadBasic.All; DeviceLocalCredential.Read.All only with -IncludePasswords (delegated). | No |
| [Get-IntuneOrphanedDevices.ps1](./Get-IntuneOrphanedDevices.ps1) | Reports Intune managed devices whose primary user is missing, deleted from Entra ID or disabled. | DeviceManagementManagedDevices.Read.All and User.Read.All (delegated). | No |
| [Get-IntuneStaleDevices.ps1](./Get-IntuneStaleDevices.ps1) | Reports Intune managed devices that have not synced for a given number of days and can optionally retire or delete them. | Report only: DeviceManagementManagedDevices.Read.All (Intune Read Only Operator). With -RetireDevices / -DeleteDevices: additionally DeviceManagementManagedDevices.PrivilegedOperations.All and DeviceManagementManagedDevices.ReadWrite.All (Intune Administrator or equivalent custom role). | Optional (-RetireDevices / -DeleteDevices) |
| [Invoke-IntuneCollectDiagnostics.ps1](./Invoke-IntuneCollectDiagnostics.ps1) | Triggers the Intune "Collect diagnostics" remote action on selected devices and optionally waits for and downloads the resulting log package. | DeviceManagementManagedDevices.PrivilegedOperations.All and DeviceManagementManagedDevices.Read.All (delegated); Intune RBAC: Collect diagnostics task. | Yes (`-WhatIf` supported) |
| [Invoke-IntuneDeviceAction.ps1](./Invoke-IntuneDeviceAction.ps1) | Sends an Intune remote action (restart, remote lock, shut down, locate, lost mode, key/password rotation, Defender scan) to selected managed devices. | DeviceManagementManagedDevices.PrivilegedOperations.All and DeviceManagementManagedDevices.Read.All; DeviceManagementManagedDevices.ReadWrite.All only for rotateBitLockerKeys (delegated). Intune RBAC: a role with the matching remote task. | Yes (`-WhatIf` supported) |
| [Invoke-IntuneDeviceSync.ps1](./Invoke-IntuneDeviceSync.ps1) | Sends a bulk Intune "Sync" remote action to managed devices selected by name, platform, Entra group or all devices. | DeviceManagementManagedDevices.Read.All and DeviceManagementManagedDevices.PrivilegedOperations.All; GroupMember.Read.All only when -GroupName is used (delegated). Intune RBAC: Help Desk Operator or any role that includes the "Sync devices" remote task. | Yes (`-WhatIf` supported) |
| [Invoke-IntuneDeviceWipe.ps1](./Invoke-IntuneDeviceWipe.ps1) | Offboards selected Intune managed devices with Wipe, Retire, Autopilot Reset or Fresh Start, with a red summary and per-device confirmation. | DeviceManagementManagedDevices.PrivilegedOperations.All and DeviceManagementManagedDevices.Read.All (delegated) | Yes (`-WhatIf` supported) |
| [Rename-IntuneDevices.ps1](./Rename-IntuneDevices.ps1) | Renames selected Intune managed devices from a CSV mapping or a naming pattern with {SERIAL}, {SERIAL8}, {USER} and {OS} tokens. | DeviceManagementManagedDevices.PrivilegedOperations.All and DeviceManagementManagedDevices.Read.All (delegated) | Yes (`-WhatIf` supported) |
| [Set-IntuneDeviceCategoryBulk.ps1](./Set-IntuneDeviceCategoryBulk.ps1) | Assigns an Intune device category to selected managed devices in bulk, skipping devices that already have it. | DeviceManagementManagedDevices.ReadWrite.All (delegated). Intune RBAC: Managed devices > Update (for example Intune Administrator). | Yes (`-WhatIf` supported) |
| [Set-IntuneDevicePrimaryUser.ps1](./Set-IntuneDevicePrimaryUser.ps1) | Sets, clears or auto-assigns (from the last logged-on user) the Intune primary user of selected managed devices. | DeviceManagementManagedDevices.ReadWrite.All and User.Read.All (delegated). | Yes (`-WhatIf` supported) |

## Compliance, configuration & RBAC

| Script | What it does | Permissions / roles | Changes anything? |
|---|---|---|---|
| [Compare-IntunePolicyBackups.ps1](./Compare-IntunePolicyBackups.ps1) | Compares two Intune policy backup folders created by Export-IntunePolicies.ps1 and reports added, removed and changed policies. | None (offline comparison of local JSON files) | No |
| [Export-IntuneEndpointSecurityPolicies.ps1](./Export-IntuneEndpointSecurityPolicies.ps1) | Exports Intune Endpoint security policies (legacy template intents and settings catalog policies) with settings and assignments to JSON. | DeviceManagementConfiguration.Read.All (delegated) plus an Intune RBAC role such as Endpoint Security Manager or Read Only Operator | No |
| [Export-IntunePolicies.ps1](./Export-IntunePolicies.ps1) | Exports Intune configuration, compliance, administrative template and platform script policies to JSON for backup and documentation. | DeviceManagementConfiguration.Read.All (delegated) plus an Intune RBAC role such as Read Only Operator | No |
| [Export-IntuneRbacRoles.ps1](./Export-IntuneRbacRoles.ps1) | Exports Intune RBAC role definitions (permissions) and role assignments (admin groups, scope groups, scope tags) to JSON and CSV. | DeviceManagementRBAC.Read.All, Group.Read.All (delegated) | No |
| [Get-IntuneAssignmentFilters.ps1](./Get-IntuneAssignmentFilters.ps1) | Reports Intune assignment filters with their rules and which policies and apps use them in include or exclude mode. | DeviceManagementConfiguration.Read.All (delegated); DeviceManagementApps.Read.All with -IncludeApps | No |
| [Get-IntuneCompliancePolicyStatusSummary.ps1](./Get-IntuneCompliancePolicyStatusSummary.ps1) | Per-policy compliance status summary (compliant, non-compliant, error, conflict, pending) for every Intune compliance policy. | DeviceManagementConfiguration.Read.All (delegated) plus an Intune RBAC role such as Read Only Operator | No |
| [Get-IntuneConfigurationProfileStatus.ps1](./Get-IntuneConfigurationProfileStatus.ps1) | Deployment status summary (succeeded, failed, error, conflict, pending) for Intune configuration profiles and administrative templates. | DeviceManagementConfiguration.Read.All (delegated) plus an Intune RBAC role such as Read Only Operator | No |
| [Get-IntuneDevicePolicyReport.ps1](./Get-IntuneDevicePolicyReport.ps1) | Reports every configuration profile, compliance policy and (optionally) detected app applied to one or more Intune devices. | DeviceManagementManagedDevices.Read.All (delegated) | No |
| [Get-IntuneNoncompliantDeviceDetails.ps1](./Get-IntuneNoncompliantDeviceDetails.ps1) | Reports the setting-level reasons why Intune managed devices are non-compliant. | DeviceManagementManagedDevices.Read.All (delegated) plus an Intune RBAC role such as Read Only Operator | No |
| [Get-IntunePolicyAssignments.ps1](./Get-IntunePolicyAssignments.ps1) | Builds a "who gets what" assignment matrix for Intune policies and (optionally) apps. | DeviceManagementConfiguration.Read.All, Group.Read.All and, with -IncludeApps, DeviceManagementApps.Read.All (delegated) plus an Intune RBAC role such as Read Only Operator | No |
| [Get-IntuneScopeTagsReport.ps1](./Get-IntuneScopeTagsReport.ps1) | Reports Intune scope tags with their auto-assignment groups and how many policies and apps carry each tag. | DeviceManagementRBAC.Read.All, DeviceManagementConfiguration.Read.All, DeviceManagementApps.Read.All, Group.Read.All (delegated) | No |
| [Get-IntuneUnusedPolicies.ps1](./Get-IntuneUnusedPolicies.ps1) | Finds Intune policies, scripts and (optionally) apps that are not assigned, or are assigned only to empty or deleted groups. | DeviceManagementConfiguration.Read.All, Group.Read.All, GroupMember.Read.All (delegated); DeviceManagementApps.Read.All with -IncludeApps | No |
| [Import-IntunePolicies.ps1](./Import-IntunePolicies.ps1) | Restores Intune device configuration, compliance, settings catalog and platform script policies from an Export-IntunePolicies.ps1 backup. | DeviceManagementConfiguration.ReadWrite.All (delegated) plus an Intune RBAC role such as Policy and Profile Manager | Yes (`-WhatIf` supported) |
| [Search-IntuneSettingsCatalog.ps1](./Search-IntuneSettingsCatalog.ps1) | Searches the Intune settings catalog for settings matching a keyword and reports their definition, category, platform and options. | DeviceManagementConfiguration.Read.All (delegated) | No |

## Apps & app protection

| Script | What it does | Permissions / roles | Changes anything? |
|---|---|---|---|
| [Export-IntuneAppConfigurationPolicies.ps1](./Export-IntuneAppConfigurationPolicies.ps1) | Exports every Intune app configuration policy (managed devices and managed apps) to JSON plus a flattened CSV index. | DeviceManagementApps.Read.All and Group.Read.All (delegated) plus an Intune RBAC role with "Mobile apps" read permission. | No |
| [Export-IntuneApps.ps1](./Export-IntuneApps.ps1) | Exports every Intune app with its assignments to one JSON file per app plus an Apps.csv inventory index. | DeviceManagementApps.Read.All (delegated) plus an Intune RBAC role such as Read Only Operator | No |
| [Get-IntuneAppInstallStatus.ps1](./Get-IntuneAppInstallStatus.ps1) | Install status overview (installed / failed / pending / not applicable) for every assigned Intune app. | DeviceManagementApps.Read.All (delegated) plus an Intune RBAC role such as Read Only Operator | No |
| [Get-IntuneAppProtectionPolicies.ps1](./Get-IntuneAppProtectionPolicies.ps1) | Reports every Intune app protection (MAM) policy for iOS, Android and Windows with its key settings, targeted apps and assignments. | DeviceManagementApps.Read.All and Group.Read.All (delegated) plus an Intune RBAC role with "Managed apps" read permission (for example Read Only Operator). | No |
| [Get-IntuneAppProtectionStatus.ps1](./Get-IntuneAppProtectionStatus.ps1) | Reports the app protection (MAM) status of every managed app registration: user, app, device, last sync, flags and policy gaps. | DeviceManagementApps.Read.All and User.ReadBasic.All (delegated) plus an Intune RBAC role with "Managed apps" read permission. | No |
| [Get-IntuneAppRelationships.ps1](./Get-IntuneAppRelationships.ps1) | Reports Win32 app dependencies and supersedence relationships and flags superseded apps that are still assigned. | DeviceManagementApps.Read.All (delegated) plus an Intune RBAC role with "Mobile apps" read permission. | No |

## Enrollment & Autopilot

| Script | What it does | Permissions / roles | Changes anything? |
|---|---|---|---|
| [Export-AutopilotProfiles.ps1](./Export-AutopilotProfiles.ps1) | Exports Windows Autopilot deployment profiles and Enrollment Status Page profiles to JSON plus two flattened CSV indexes. | DeviceManagementServiceConfig.Read.All, DeviceManagementConfiguration.Read.All and Group.Read.All (delegated); Intune RBAC Read Only Operator. | No |
| [Export-IntuneEnrollmentConfigurations.ps1](./Export-IntuneEnrollmentConfigurations.ps1) | Exports Intune enrollment configurations (restrictions, device limits, ESP, Windows Hello, co-management, notifications) plus Apple ADE and Android Enterprise enrollment profiles. | DeviceManagementServiceConfig.Read.All, DeviceManagementConfiguration.Read.All and Group.Read.All (delegated); Intune RBAC Read Only Operator. | No |
| [Get-AutopilotDeviceReport.ps1](./Get-AutopilotDeviceReport.ps1) | Windows Autopilot registration health report: profile assignment status, enrollment state and last contact per device. | DeviceManagementServiceConfig.Read.All; DeviceManagementManagedDevices.Read.All only with -IncludeManagedDeviceDetails (delegated). Intune RBAC: Read Only Operator or any role with "Enrollment programs" read permission. | No |
| [Get-IntuneConnectorsHealth.ps1](./Get-IntuneConnectorsHealth.ps1) | Health check of Intune connectors and tokens: Apple push certificate, ADE and VPP tokens, Managed Google Play, NDES/certificate connectors, MTD and Autopilot sync. | DeviceManagementServiceConfig.Read.All, DeviceManagementApps.Read.All and DeviceManagementConfiguration.Read.All (delegated). Intune RBAC: Read Only Operator or Intune Administrator. | No |
| [Import-AutopilotDevices.ps1](./Import-AutopilotDevices.ps1) | Imports Windows Autopilot hardware hashes from a Get-WindowsAutopilotInfo CSV, optionally waits for the import result and triggers a sync. | DeviceManagementServiceConfig.ReadWrite.All (delegated). Intune RBAC: Intune Administrator or a role with "Enrollment programs / Create device" permission. | Yes (`-WhatIf` supported) |
| [Remove-AutopilotDevices.ps1](./Remove-AutopilotDevices.ps1) | Deletes Windows Autopilot device identities (by serial, CSV or never-enrolled age) and optionally the matching Intune and Entra ID device objects. | DeviceManagementServiceConfig.ReadWrite.All; plus DeviceManagementManagedDevices.ReadWrite.All with -RemoveIntuneDevice and Device.ReadWrite.All with -RemoveEntraDevice (delegated; Entra deletions need Cloud Device Administrator or Intune Administrator). | Yes (`-WhatIf` supported) |
| [Set-AutopilotDeviceProperties.ps1](./Set-AutopilotDeviceProperties.ps1) | Updates the group tag, assigned user or device name of Windows Autopilot device identities, or removes the assigned user. | DeviceManagementServiceConfig.ReadWrite.All (delegated); User.ReadBasic.All only when -UserPrincipalName or a UserPrincipalName column is used. Intune RBAC: Intune Administrator or "Enrollment programs / Update device". | Yes (`-WhatIf` supported) |

## Updates & remediations

| Script | What it does | Permissions / roles | Changes anything? |
|---|---|---|---|
| [Export-IntuneRemediationScripts.ps1](./Export-IntuneRemediationScripts.ps1) | Exports every Intune remediation (proactive remediation) script package with its detection and remediation scripts, settings and assignments. | DeviceManagementConfiguration.Read.All (delegated) plus an Intune RBAC role such as Read Only Operator | No |
| [Export-IntuneReport.ps1](./Export-IntuneReport.ps1) | Exports any built-in Intune report (Devices, DeviceCompliance, DefenderAgents, update and app install status, ...) to CSV through the Graph export jobs API. | DeviceManagementConfiguration.Read.All, DeviceManagementManagedDevices.Read.All, DeviceManagementApps.Read.All (delegated) plus an Intune RBAC role with the matching read permissions | No |
| [Export-IntuneWindowsUpdatePolicies.ps1](./Export-IntuneWindowsUpdatePolicies.ps1) | Exports Windows update rings, feature update, expedited quality update and driver update profiles with their assignments to JSON and a summary CSV. | DeviceManagementConfiguration.Read.All (delegated) plus an Intune RBAC role such as Read Only Operator | No |
| [Get-IntuneRemediationResults.ps1](./Get-IntuneRemediationResults.ps1) | Reports the run results of Intune remediation (proactive remediation) scripts per package and, optionally, per device. | DeviceManagementConfiguration.Read.All, DeviceManagementManagedDevices.Read.All (delegated) plus an Intune RBAC role | No |
| [Get-IntuneWindowsVersionReport.ps1](./Get-IntuneWindowsVersionReport.ps1) | Reports the Windows feature version, build and patch level (UBR) of every Intune managed Windows device and flags unsupported or outdated builds. | DeviceManagementManagedDevices.Read.All (delegated) plus an Intune RBAC role such as Read Only Operator | No |

## Reporting & platform insights

| Script | What it does | Permissions / roles | Changes anything? |
|---|---|---|---|
| [Get-IntuneAndroidDeviceReport.ps1](./Get-IntuneAndroidDeviceReport.ps1) | Reports every Intune managed Android device with its management mode, OS version and security patch level, flagging outdated, rooted and legacy devices. | DeviceManagementManagedDevices.Read.All (delegated) plus an Intune RBAC role such as Read Only Operator | No |
| [Get-IntuneAppleDeviceReport.ps1](./Get-IntuneAppleDeviceReport.ps1) | Reports every Intune managed iOS, iPadOS and macOS device with its enrollment method, supervision state, MDM certificate expiry and OS version flags. | DeviceManagementManagedDevices.Read.All (delegated) plus an Intune RBAC role such as Read Only Operator | No |
| [Get-IntuneAuditEvents.ps1](./Get-IntuneAuditEvents.ps1) | Exports the Intune audit log (who changed what, when) for the last N days with optional actor, category and activity filters. | DeviceManagementConfiguration.Read.All (delegated) plus an Intune RBAC role with the Audit data > Read permission | No |
| [Get-IntuneCloudPCReport.ps1](./Get-IntuneCloudPCReport.ps1) | Reports every Windows 365 Cloud PC with its status, service plan, provisioning policy and optional connectivity health, and flags Cloud PCs needing attention. | CloudPC.Read.All (delegated) plus an Intune RBAC role such as Cloud PC Reader or Read Only Operator | No |
| [Get-IntuneDefenderAVStatus.ps1](./Get-IntuneDefenderAVStatus.ps1) | Microsoft Defender Antivirus health report for Intune-managed Windows devices. | DeviceManagementManagedDevices.Read.All (delegated) plus an Intune RBAC role such as Read Only Operator | No |
| [Get-IntuneTenantSummary.ps1](./Get-IntuneTenantSummary.ps1) | One-screen Intune tenant health check: enrolment, compliance, policy and app counts, Autopilot, certificate/token expiry and service health. | DeviceManagementManagedDevices.Read.All, DeviceManagementConfiguration.Read.All, DeviceManagementApps.Read.All, DeviceManagementServiceConfig.Read.All, Organization.Read.All, ServiceHealth.Read.All (delegated) | No |

## Quick start

```powershell
# Get-IntuneBitLockerRecoveryKeys.ps1
.\Get-IntuneBitLockerRecoveryKeys.ps1 -DeviceName 'LT-0042' -IncludeKey -PassThru | Format-Table DeviceName, VolumeType, CreatedDateTime, RecoveryKey

# Compare-IntunePolicyBackups.ps1
.\Compare-IntunePolicyBackups.ps1 -ReferenceFolder D:\Backups\Prod -DifferenceFolder D:\Backups\Test -IncludeUnchanged -PassThru | Out-GridView

# Export-IntuneAppConfigurationPolicies.ps1
.\Export-IntuneAppConfigurationPolicies.ps1 -OutputFolder D:\Backups\AppConfig -PassThru | Where-Object { -not $_.Assignments }

# Export-AutopilotProfiles.ps1
.\Export-AutopilotProfiles.ps1 -OutputFolder D:\Backups\Autopilot -PassThru | Format-Table Name, JoinType, DeploymentMode, UserType, AssignedGroups
```

## Notes

- Intune reports work with the **Read Only Operator** or **Help Desk Operator** Intune role; remote actions and policy changes need **Intune Administrator** (or an equivalent custom role with the right permissions).
- Several scripts use the Graph **beta** endpoint because the data is not exposed in v1.0 yet (noted in each header). Beta APIs can change without notice.
- Scripts that call Graph once per device add a short delay to stay within throttling limits; large tenants will take a while.

---

Back to the [repository overview](../README.md).
