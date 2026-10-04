# Microsoft 365 & Intune Admin Scripts

[![PowerShell 5.1 | 7.x](https://img.shields.io/badge/PowerShell-5.1%20%7C%207.x-5391FE?logo=powershell&logoColor=white)](#prerequisites)
[![Microsoft Graph](https://img.shields.io/badge/Microsoft%20Graph-v1.0%20%2F%20beta-0078D4)](https://learn.microsoft.com/graph/overview)
[![Scripts](https://img.shields.io/badge/scripts-365-success)](#script-index)
[![PSScriptAnalyzer](https://github.com/omer-eltayeb/M365/actions/workflows/psscriptanalyzer.yml/badge.svg)](https://github.com/omer-eltayeb/M365/actions/workflows/psscriptanalyzer.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

**365 PowerShell scripts for reporting on, troubleshooting and tidying up Microsoft 365 tenants** - with a strong focus on
**Microsoft Intune** and deep coverage of **Microsoft Entra ID, Microsoft Defender, Exchange Online, Microsoft Purview,
Microsoft Teams, SharePoint Online and tenant-wide administration**.

They come from day-to-day support and consulting work: the questions customers ask most often
("which devices stopped syncing?", "who is forwarding mail outside the company?", "which teams are dead?",
"how many licenses are we wasting?", "who still uses legacy authentication?") turned into repeatable, documented scripts.

Everything is built on the **Microsoft Graph PowerShell SDK** (`Invoke-MgGraphRequest`) and the
**ExchangeOnlineManagement v3** module, with the `MicrosoftTeams` and SharePoint Online management modules where the
Graph API has no equivalent - no deprecated AzureAD / MSOnline modules, no hard-coded tenant details.

## Design principles

| Principle | What it means in practice |
|---|---|
| **Read-only by default** | A script only changes something when you pass an explicit switch (`-RetireDevices`, `-Remediate`, `-DisableAccounts`, ...). Every change supports `-WhatIf` and `-Confirm`. |
| **Least privilege** | Each script requests only the Graph scopes or admin roles it needs and lists them in its help (`.NOTES`) and in the folder README. |
| **Current tooling** | Graph **v1.0** wherever possible; **beta** only where the data lives nowhere else (always called out). REST-backed `Get-EXO*` cmdlets for Exchange. |
| **5.1 and 7.x** | Works in Windows PowerShell 5.1 and PowerShell 7 - no PowerShell 7-only syntax. |
| **Self-documenting** | `Get-Help .\Script.ps1 -Full` works everywhere. Reports land in `.\Reports\` as timestamped CSV files; add `-PassThru` to keep working with the objects in the pipeline. |
| **Consistent** | Same parameter names (`-OutputPath`, `-PassThru`, `-DaysInactive`, `-InputCsv`), same helpers, same summary style - learn one script, you know them all. |

## Repository structure

| Folder | Focus | Scripts |
|---|---|---:|
| [`Intune/`](./Intune) | Device inventory and compliance, remote actions, policy backup/restore, assignment matrix, apps and app protection, Autopilot and enrollment, Windows Update and remediations, BitLocker/LAPS, Cloud PC, tenant health | 53 |
| [`EntraID/`](./EntraID) | Users and authentication methods, groups and devices, sign-in and audit logs, Identity Protection, applications and consent, privileged roles and PIM, governance, tenant security settings | 52 |
| [`Defender/`](./Defender) | Defender XDR alerts and incidents, Secure Score, attack simulation, Defender for Identity, Advanced Hunting, Defender for Endpoint API, Defender for Office 365 policies, quarantine and email authentication | 54 |
| [`ExchangeOnline/`](./ExchangeOnline) | Mailbox lifecycle and holds, sizes and quotas, settings, calendars and rooms, distribution groups, mail flow and message trace, client access and mobile devices, admin audit and migration | 53 |
| [`Purview/`](./Purview) | Sensitivity labels and auto-labeling, DLP, retention and records, eDiscovery and content search, audit log scenarios, insider risk, communication compliance, information barriers | 51 |
| [`Teams-SharePoint/`](./Teams-SharePoint) | Teams inventory and lifecycle, membership and guests, channels, apps and settings, Teams policies and voice, SharePoint sharing and admin, external users, storage, files and sharing links, OneDrive | 51 |
| [`M365-Tenant/`](./M365-Tenant) | Licensing and subscriptions, usage and adoption reports, tenant settings snapshots, service health and Message Center, Microsoft 365 Groups governance, onboarding/offboarding, tenant hygiene | 50 |
| [`Tools/`](./Tools) | Prerequisite installer | 1 |

## Prerequisites

| Requirement | Notes |
|---|---|
| Windows PowerShell 5.1 or PowerShell 7.x | PowerShell 7 is recommended for speed. |
| `Microsoft.Graph.Authentication` | The only Graph module needed - all calls go through `Invoke-MgGraphRequest`, which keeps installs small and avoids cmdlet drift between SDK versions. |
| `ExchangeOnlineManagement` 3.x | Exchange Online, Defender for Office 365 and Purview scripts (modern authentication, REST-backed cmdlets). |
| `MicrosoftTeams` | Teams policy, voice and configuration scripts in `Teams-SharePoint/`. |
| `Microsoft.Online.SharePoint.PowerShell` | SharePoint admin scripts in `Teams-SharePoint/` (Windows only). |
| Permissions | Delegated Graph scopes and admin roles are listed in each script's `.NOTES` and in the folder README. |

Install everything in one go:

```powershell
.\Tools\Install-Prerequisites.ps1 -IncludeDevTools
```

## Getting started

```powershell
# 1. Clone
git clone https://github.com/omer-eltayeb/M365.git
Set-Location .\M365

# 2. Read the help of any script
Get-Help .\Intune\Get-IntuneStaleDevices.ps1 -Full

# 3. Run a report (you are prompted to sign in to Microsoft Graph with the scopes the script needs)
.\Intune\Get-IntuneDeviceComplianceReport.ps1 -OperatingSystem Windows

# 4. Keep working with the objects instead of (or as well as) the CSV
.\Intune\Get-IntuneStaleDevices.ps1 -DaysInactive 120 -PassThru |
    Where-Object { $_.OperatingSystem -eq 'Android' } |
    Format-Table DeviceName, UserPrincipalName, LastSyncDateTime

# 5. Preview a change before making it
.\Intune\Get-IntuneStaleDevices.ps1 -DaysInactive 180 -RetireDevices -WhatIf
```

### Authentication

* **Interactive (default):** each script calls `Connect-MgGraph` / `Connect-ExchangeOnline` / `Connect-MicrosoftTeams` / `Connect-SPOService`
  only when there is no usable session, so you can sign in once and run several scripts in a row.
* **Unattended / app-only:** sign in before running the script and it will reuse the session, for example
  `Connect-MgGraph -ClientId <appId> -TenantId <tenantId> -CertificateThumbprint <thumbprint>` or
  `Connect-ExchangeOnline -AppId <appId> -CertificateThumbprint <thumbprint> -Organization contoso.onmicrosoft.com`.
  `M365-Tenant\New-M365GraphAppRegistrationForAutomation.ps1` creates a ready-to-use app registration with a certificate.
* **Licensing caveats** (sign-in activity needs Microsoft Entra ID P1, PIM eligibility needs P2, Defender data needs the
  relevant Defender service, some audit events need Audit (Premium)) are called out in the `.NOTES` block of the scripts concerned.

## Script index

Legend - **Changes?**: `No` = report only; `Optional (-Switch)` = read-only unless the switch is passed; `Yes` = performs an action (always `-WhatIf`-safe).

<details>
<summary><strong>Microsoft Intune</strong> - 53 scripts (<a href="./Intune/README.md">folder README</a>)</summary>

**Devices & remote actions**

| Script | Purpose | Changes? |
|---|---|---|
| [Get-IntuneBitLockerRecoveryKeys.ps1](./Intune/Get-IntuneBitLockerRecoveryKeys.ps1) | Inventories the BitLocker recovery keys escrowed in Entra ID, joined to the owning device, optionally including the key material for selected devices. | No |
| [Get-IntuneDeviceComplianceReport.ps1](./Intune/Get-IntuneDeviceComplianceReport.ps1) | Inventory and compliance report for all Intune managed devices. | No |
| [Get-IntuneDeviceHardwareInventory.ps1](./Intune/Get-IntuneDeviceHardwareInventory.ps1) | Builds a per-device hardware inventory (storage, memory, TPM, BIOS, battery, network) for Intune managed devices. | No |
| [Get-IntuneDevicesPerUser.ps1](./Intune/Get-IntuneDevicesPerUser.ps1) | Groups Intune managed devices by primary user and reports users who own an unusually high number of devices. | No |
| [Get-IntuneEncryptionReport.ps1](./Intune/Get-IntuneEncryptionReport.ps1) | Reports the encryption state of Intune managed devices and, optionally, whether Windows devices have a BitLocker recovery key escrowed in Entra ID. | No |
| [Get-IntuneLapsPasswords.ps1](./Intune/Get-IntuneLapsPasswords.ps1) | Reports Windows LAPS password backups in Entra ID, flags stale or overdue backups and optionally retrieves the current local administrator password. | No |
| [Get-IntuneOrphanedDevices.ps1](./Intune/Get-IntuneOrphanedDevices.ps1) | Reports Intune managed devices whose primary user is missing, deleted from Entra ID or disabled. | No |
| [Get-IntuneStaleDevices.ps1](./Intune/Get-IntuneStaleDevices.ps1) | Reports Intune managed devices that have not synced for a given number of days and can optionally retire or delete them. | Optional (-RetireDevices / -DeleteDevices) |
| [Invoke-IntuneCollectDiagnostics.ps1](./Intune/Invoke-IntuneCollectDiagnostics.ps1) | Triggers the Intune "Collect diagnostics" remote action on selected devices and optionally waits for and downloads the resulting log package. | Yes (`-WhatIf` supported) |
| [Invoke-IntuneDeviceAction.ps1](./Intune/Invoke-IntuneDeviceAction.ps1) | Sends an Intune remote action (restart, remote lock, shut down, locate, lost mode, key/password rotation, Defender scan) to selected managed devices. | Yes (`-WhatIf` supported) |
| [Invoke-IntuneDeviceSync.ps1](./Intune/Invoke-IntuneDeviceSync.ps1) | Sends a bulk Intune "Sync" remote action to managed devices selected by name, platform, Entra group or all devices. | Yes (`-WhatIf` supported) |
| [Invoke-IntuneDeviceWipe.ps1](./Intune/Invoke-IntuneDeviceWipe.ps1) | Offboards selected Intune managed devices with Wipe, Retire, Autopilot Reset or Fresh Start, with a red summary and per-device confirmation. | Yes (`-WhatIf` supported) |
| [Rename-IntuneDevices.ps1](./Intune/Rename-IntuneDevices.ps1) | Renames selected Intune managed devices from a CSV mapping or a naming pattern with {SERIAL}, {SERIAL8}, {USER} and {OS} tokens. | Yes (`-WhatIf` supported) |
| [Set-IntuneDeviceCategoryBulk.ps1](./Intune/Set-IntuneDeviceCategoryBulk.ps1) | Assigns an Intune device category to selected managed devices in bulk, skipping devices that already have it. | Yes (`-WhatIf` supported) |
| [Set-IntuneDevicePrimaryUser.ps1](./Intune/Set-IntuneDevicePrimaryUser.ps1) | Sets, clears or auto-assigns (from the last logged-on user) the Intune primary user of selected managed devices. | Yes (`-WhatIf` supported) |

**Compliance, configuration & RBAC**

| Script | Purpose | Changes? |
|---|---|---|
| [Compare-IntunePolicyBackups.ps1](./Intune/Compare-IntunePolicyBackups.ps1) | Compares two Intune policy backup folders created by Export-IntunePolicies.ps1 and reports added, removed and changed policies. | No |
| [Export-IntuneEndpointSecurityPolicies.ps1](./Intune/Export-IntuneEndpointSecurityPolicies.ps1) | Exports Intune Endpoint security policies (legacy template intents and settings catalog policies) with settings and assignments to JSON. | No |
| [Export-IntunePolicies.ps1](./Intune/Export-IntunePolicies.ps1) | Exports Intune configuration, compliance, administrative template and platform script policies to JSON for backup and documentation. | No |
| [Export-IntuneRbacRoles.ps1](./Intune/Export-IntuneRbacRoles.ps1) | Exports Intune RBAC role definitions (permissions) and role assignments (admin groups, scope groups, scope tags) to JSON and CSV. | No |
| [Get-IntuneAssignmentFilters.ps1](./Intune/Get-IntuneAssignmentFilters.ps1) | Reports Intune assignment filters with their rules and which policies and apps use them in include or exclude mode. | No |
| [Get-IntuneCompliancePolicyStatusSummary.ps1](./Intune/Get-IntuneCompliancePolicyStatusSummary.ps1) | Per-policy compliance status summary (compliant, non-compliant, error, conflict, pending) for every Intune compliance policy. | No |
| [Get-IntuneConfigurationProfileStatus.ps1](./Intune/Get-IntuneConfigurationProfileStatus.ps1) | Deployment status summary (succeeded, failed, error, conflict, pending) for Intune configuration profiles and administrative templates. | No |
| [Get-IntuneDevicePolicyReport.ps1](./Intune/Get-IntuneDevicePolicyReport.ps1) | Reports every configuration profile, compliance policy and (optionally) detected app applied to one or more Intune devices. | No |
| [Get-IntuneNoncompliantDeviceDetails.ps1](./Intune/Get-IntuneNoncompliantDeviceDetails.ps1) | Reports the setting-level reasons why Intune managed devices are non-compliant. | No |
| [Get-IntunePolicyAssignments.ps1](./Intune/Get-IntunePolicyAssignments.ps1) | Builds a "who gets what" assignment matrix for Intune policies and (optionally) apps. | No |
| [Get-IntuneScopeTagsReport.ps1](./Intune/Get-IntuneScopeTagsReport.ps1) | Reports Intune scope tags with their auto-assignment groups and how many policies and apps carry each tag. | No |
| [Get-IntuneUnusedPolicies.ps1](./Intune/Get-IntuneUnusedPolicies.ps1) | Finds Intune policies, scripts and (optionally) apps that are not assigned, or are assigned only to empty or deleted groups. | No |
| [Import-IntunePolicies.ps1](./Intune/Import-IntunePolicies.ps1) | Restores Intune device configuration, compliance, settings catalog and platform script policies from an Export-IntunePolicies.ps1 backup. | Yes (`-WhatIf` supported) |
| [Search-IntuneSettingsCatalog.ps1](./Intune/Search-IntuneSettingsCatalog.ps1) | Searches the Intune settings catalog for settings matching a keyword and reports their definition, category, platform and options. | No |

**Apps & app protection**

| Script | Purpose | Changes? |
|---|---|---|
| [Export-IntuneAppConfigurationPolicies.ps1](./Intune/Export-IntuneAppConfigurationPolicies.ps1) | Exports every Intune app configuration policy (managed devices and managed apps) to JSON plus a flattened CSV index. | No |
| [Export-IntuneApps.ps1](./Intune/Export-IntuneApps.ps1) | Exports every Intune app with its assignments to one JSON file per app plus an Apps.csv inventory index. | No |
| [Get-IntuneAppInstallStatus.ps1](./Intune/Get-IntuneAppInstallStatus.ps1) | Install status overview (installed / failed / pending / not applicable) for every assigned Intune app. | No |
| [Get-IntuneAppProtectionPolicies.ps1](./Intune/Get-IntuneAppProtectionPolicies.ps1) | Reports every Intune app protection (MAM) policy for iOS, Android and Windows with its key settings, targeted apps and assignments. | No |
| [Get-IntuneAppProtectionStatus.ps1](./Intune/Get-IntuneAppProtectionStatus.ps1) | Reports the app protection (MAM) status of every managed app registration: user, app, device, last sync, flags and policy gaps. | No |
| [Get-IntuneAppRelationships.ps1](./Intune/Get-IntuneAppRelationships.ps1) | Reports Win32 app dependencies and supersedence relationships and flags superseded apps that are still assigned. | No |

**Enrollment & Autopilot**

| Script | Purpose | Changes? |
|---|---|---|
| [Export-AutopilotProfiles.ps1](./Intune/Export-AutopilotProfiles.ps1) | Exports Windows Autopilot deployment profiles and Enrollment Status Page profiles to JSON plus two flattened CSV indexes. | No |
| [Export-IntuneEnrollmentConfigurations.ps1](./Intune/Export-IntuneEnrollmentConfigurations.ps1) | Exports Intune enrollment configurations (restrictions, device limits, ESP, Windows Hello, co-management, notifications) plus Apple ADE and Android Enterprise enrollment profiles. | No |
| [Get-AutopilotDeviceReport.ps1](./Intune/Get-AutopilotDeviceReport.ps1) | Windows Autopilot registration health report: profile assignment status, enrollment state and last contact per device. | No |
| [Get-IntuneConnectorsHealth.ps1](./Intune/Get-IntuneConnectorsHealth.ps1) | Health check of Intune connectors and tokens: Apple push certificate, ADE and VPP tokens, Managed Google Play, NDES/certificate connectors, MTD and Autopilot sync. | No |
| [Import-AutopilotDevices.ps1](./Intune/Import-AutopilotDevices.ps1) | Imports Windows Autopilot hardware hashes from a Get-WindowsAutopilotInfo CSV, optionally waits for the import result and triggers a sync. | Yes (`-WhatIf` supported) |
| [Remove-AutopilotDevices.ps1](./Intune/Remove-AutopilotDevices.ps1) | Deletes Windows Autopilot device identities (by serial, CSV or never-enrolled age) and optionally the matching Intune and Entra ID device objects. | Yes (`-WhatIf` supported) |
| [Set-AutopilotDeviceProperties.ps1](./Intune/Set-AutopilotDeviceProperties.ps1) | Updates the group tag, assigned user or device name of Windows Autopilot device identities, or removes the assigned user. | Yes (`-WhatIf` supported) |

**Updates & remediations**

| Script | Purpose | Changes? |
|---|---|---|
| [Export-IntuneRemediationScripts.ps1](./Intune/Export-IntuneRemediationScripts.ps1) | Exports every Intune remediation (proactive remediation) script package with its detection and remediation scripts, settings and assignments. | No |
| [Export-IntuneReport.ps1](./Intune/Export-IntuneReport.ps1) | Exports any built-in Intune report (Devices, DeviceCompliance, DefenderAgents, update and app install status, ...) to CSV through the Graph export jobs API. | No |
| [Export-IntuneWindowsUpdatePolicies.ps1](./Intune/Export-IntuneWindowsUpdatePolicies.ps1) | Exports Windows update rings, feature update, expedited quality update and driver update profiles with their assignments to JSON and a summary CSV. | No |
| [Get-IntuneRemediationResults.ps1](./Intune/Get-IntuneRemediationResults.ps1) | Reports the run results of Intune remediation (proactive remediation) scripts per package and, optionally, per device. | No |
| [Get-IntuneWindowsVersionReport.ps1](./Intune/Get-IntuneWindowsVersionReport.ps1) | Reports the Windows feature version, build and patch level (UBR) of every Intune managed Windows device and flags unsupported or outdated builds. | No |

**Reporting & platform insights**

| Script | Purpose | Changes? |
|---|---|---|
| [Get-IntuneAndroidDeviceReport.ps1](./Intune/Get-IntuneAndroidDeviceReport.ps1) | Reports every Intune managed Android device with its management mode, OS version and security patch level, flagging outdated, rooted and legacy devices. | No |
| [Get-IntuneAppleDeviceReport.ps1](./Intune/Get-IntuneAppleDeviceReport.ps1) | Reports every Intune managed iOS, iPadOS and macOS device with its enrollment method, supervision state, MDM certificate expiry and OS version flags. | No |
| [Get-IntuneAuditEvents.ps1](./Intune/Get-IntuneAuditEvents.ps1) | Exports the Intune audit log (who changed what, when) for the last N days with optional actor, category and activity filters. | No |
| [Get-IntuneCloudPCReport.ps1](./Intune/Get-IntuneCloudPCReport.ps1) | Reports every Windows 365 Cloud PC with its status, service plan, provisioning policy and optional connectivity health, and flags Cloud PCs needing attention. | No |
| [Get-IntuneDefenderAVStatus.ps1](./Intune/Get-IntuneDefenderAVStatus.ps1) | Microsoft Defender Antivirus health report for Intune-managed Windows devices. | No |
| [Get-IntuneTenantSummary.ps1](./Intune/Get-IntuneTenantSummary.ps1) | One-screen Intune tenant health check: enrolment, compliance, policy and app counts, Autopilot, certificate/token expiry and service health. | No |

</details>

<details>
<summary><strong>Microsoft Entra ID</strong> - 52 scripts (<a href="./EntraID/README.md">folder README</a>)</summary>

**Users & authentication**

| Script | Purpose | Changes? |
|---|---|---|
| [Disable-EntraUserOffboarding.ps1](./EntraID/Disable-EntraUserOffboarding.ps1) | Offboards user identities: disables the account, revokes sessions, resets the password, removes groups, manager, licenses and MFA methods. | Yes (`-WhatIf` supported) |
| [Get-EntraDeletedUsers.ps1](./EntraID/Get-EntraDeletedUsers.ps1) | Reports soft-deleted users with the days left before permanent deletion, and optionally restores or permanently deletes them. | Optional (-Restore / -PermanentlyDelete) |
| [Get-EntraInactiveUsers.ps1](./EntraID/Get-EntraInactiveUsers.ps1) | Reports member accounts with no sign-in for a number of days (or ever) and optionally disables them or revokes their sessions. | Optional (-DisableAccounts / -RevokeSessions) |
| [Get-EntraMFARegistrationReport.ps1](./EntraID/Get-EntraMFARegistrationReport.ps1) | Reports the MFA, passwordless and SSPR registration posture of users in Microsoft Entra ID. | No |
| [Get-EntraPasswordExpiryReport.ps1](./EntraID/Get-EntraPasswordExpiryReport.ps1) | Reports when cloud user passwords expire, based on the domain password validity period and each user's last password change. | No |
| [Get-EntraStaleGuestUsers.ps1](./EntraID/Get-EntraStaleGuestUsers.ps1) | Finds guest accounts that never signed in, have been inactive for a number of days, or never accepted their invitation. | Optional (-DisableAccounts / -RemoveAccounts) |
| [Get-EntraUserAuthenticationMethods.ps1](./EntraID/Get-EntraUserAuthenticationMethods.ps1) | Reports the registered authentication methods (Authenticator, phone, FIDO2, Windows Hello, TAP, etc.) of users and flags password-only accounts. | No |
| [Get-EntraUserInventory.ps1](./EntraID/Get-EntraUserInventory.ps1) | Exports an inventory of Microsoft Entra ID users with licence count, manager, last sign-in and password age. | No |
| [New-EntraTemporaryAccessPass.ps1](./EntraID/New-EntraTemporaryAccessPass.ps1) | Issues Temporary Access Passes (TAP) for one or more users, within the limits of the tenant's TAP policy. | Yes (`-WhatIf` supported) |
| [New-EntraUsersFromCsv.ps1](./EntraID/New-EntraUsersFromCsv.ps1) | Creates Microsoft Entra ID users in bulk from a CSV file, with optional manager, group memberships and license assignment. | Yes (`-WhatIf` supported) |
| [Reset-EntraUserMfa.ps1](./EntraID/Reset-EntraUserMfa.ps1) | Removes all registered MFA / passwordless methods of a user so they must re-register, optionally issuing a Temporary Access Pass. | Yes (`-WhatIf` supported) |
| [Set-EntraUserAttributesFromCsv.ps1](./EntraID/Set-EntraUserAttributesFromCsv.ps1) | Bulk-updates user profile attributes (job title, department, address, phones, employee data and more) from a CSV file. | Yes (`-WhatIf` supported) |

**Groups**

| Script | Purpose | Changes? |
|---|---|---|
| [Add-EntraGroupMembersFromCsv.ps1](./EntraID/Add-EntraGroupMembersFromCsv.ps1) | Adds or removes Microsoft Entra ID group members in bulk from a CSV file. | Yes (`-WhatIf` supported) |
| [Compare-EntraGroupMembership.ps1](./EntraID/Compare-EntraGroupMembership.ps1) | Compares the membership of two Microsoft Entra ID groups (or a group and a CSV list of UPNs) and can synchronise them. | Optional (-Sync) |
| [Export-EntraGroupMembership.ps1](./EntraID/Export-EntraGroupMembership.ps1) | Exports the members (direct or transitive) or the owners of one, several or all Microsoft Entra ID groups to CSV. | No |
| [Get-EntraDynamicGroupRules.ps1](./EntraID/Get-EntraDynamicGroupRules.ps1) | Reports every dynamic membership group in Microsoft Entra ID with its rule, processing state and last evaluation status. | No |
| [Get-EntraGroupInventory.ps1](./EntraID/Get-EntraGroupInventory.ps1) | Inventories every Microsoft Entra ID group with its resolved type, dynamic rule, Teams status and optional member/owner counts. | No |
| [Get-EntraGroupsWithGuests.ps1](./EntraID/Get-EntraGroupsWithGuests.ps1) | Reports Microsoft Entra ID groups (and Teams) that contain guest users, with guest counts, guest domains and owners. | No |
| [Get-EntraNestedGroupsReport.ps1](./EntraID/Get-EntraNestedGroupsReport.ps1) | Reports nested group membership in Microsoft Entra ID (groups that contain other groups), including circular references. | No |
| [Get-EntraOwnerlessAndEmptyGroups.ps1](./EntraID/Get-EntraOwnerlessAndEmptyGroups.ps1) | Finds groups without owners and/or without members, and can assign an owner to the ownerless ones. | Optional (-AddOwner) |

**Devices**

| Script | Purpose | Changes? |
|---|---|---|
| [Get-EntraDeviceInventory.ps1](./EntraID/Get-EntraDeviceInventory.ps1) | Exports an inventory of the device objects in Microsoft Entra ID with join type, management, compliance and owner details. | No |
| [Get-EntraStaleDevices.ps1](./EntraID/Get-EntraStaleDevices.ps1) | Finds Microsoft Entra ID devices that have not signed in for a number of days and can disable or remove them. | Optional (-DisableDevices / -RemoveDevices) |

**Sign-ins, audit & risk**

| Script | Purpose | Changes? |
|---|---|---|
| [Get-EntraConditionalAccessInsights.ps1](./EntraID/Get-EntraConditionalAccessInsights.ps1) | Aggregates how every Conditional Access policy was evaluated in recent sign-ins, including report-only impact and uncovered sign-ins. | No |
| [Get-EntraDirectoryAuditLogs.ps1](./EntraID/Get-EntraDirectoryAuditLogs.ps1) | Exports Microsoft Entra directory audit events (who changed what, when) with initiator, targets and modified properties. | No |
| [Get-EntraFailedSignInSummary.ps1](./EntraID/Get-EntraFailedSignInSummary.ps1) | Summarises failed Microsoft Entra sign-ins by error code, user, application, country and IP, with a password-spray indicator. | No |
| [Get-EntraLegacyAuthSignIns.ps1](./EntraID/Get-EntraLegacyAuthSignIns.ps1) | Finds sign-ins that used legacy authentication protocols (POP3, IMAP4, SMTP, ActiveSync, EWS, MAPI, ...) and whether they succeeded. | No |
| [Get-EntraProvisioningLogs.ps1](./EntraID/Get-EntraProvisioningLogs.ps1) | Exports Microsoft Entra provisioning logs (SCIM / HR-driven user provisioning to SaaS apps) with status, errors and changed attributes. | No |
| [Get-EntraRiskyUsersAndDetections.ps1](./EntraID/Get-EntraRiskyUsersAndDetections.ps1) | Reports Microsoft Entra ID Protection risky users, risk detections and (optionally) risky service principals; can confirm or dismiss a user. | Optional (-ConfirmCompromised / -Dismiss) |
| [Get-EntraSignInLogs.ps1](./EntraID/Get-EntraSignInLogs.ps1) | Exports Microsoft Entra interactive (and optionally non-interactive) sign-in events with Conditional Access and device details. | No |
| [Get-EntraSignInsByLocation.ps1](./EntraID/Get-EntraSignInsByLocation.ps1) | Groups Microsoft Entra sign-ins per user, country, city and IP address and flags unexpected countries and atypical travel. | No |
| [Test-EntraBreakGlassAccounts.ps1](./EntraID/Test-EntraBreakGlassAccounts.ps1) | Validates Microsoft Entra emergency access (break-glass) accounts against Microsoft's recommended configuration. | No |

**Applications & consent**

| Script | Purpose | Changes? |
|---|---|---|
| [Get-EntraAppCredentialExpiry.ps1](./EntraID/Get-EntraAppCredentialExpiry.ps1) | Reports app registration client secrets and certificates that are expired or expiring soon. | No |
| [Get-EntraAppOwnersReport.ps1](./EntraID/Get-EntraAppOwnersReport.ps1) | Reports the owners of every app registration and enterprise application and flags apps without a working owner. | Optional (-AddOwner) |
| [Get-EntraAppPermissionsReport.ps1](./EntraID/Get-EntraAppPermissionsReport.ps1) | Reports every delegated and application permission granted to enterprise applications and flags high-privilege ones. | No |
| [Get-EntraAppRegistrationSecurityAudit.ps1](./EntraID/Get-EntraAppRegistrationSecurityAudit.ps1) | Audits every app registration for risky authentication settings and credential hygiene and reports one row per finding. | No |
| [Get-EntraAppRoleAssignmentsReport.ps1](./EntraID/Get-EntraAppRoleAssignmentsReport.ps1) | Reports which users, groups and service principals are assigned to each enterprise application and in which role. | No |
| [Get-EntraConsentSettingsAndRequests.ps1](./EntraID/Get-EntraConsentSettingsAndRequests.ps1) | Reviews the tenant's user consent, app registration and admin consent workflow settings and exports pending consent requests. | No |
| [Get-EntraSamlCertificateExpiry.ps1](./EntraID/Get-EntraSamlCertificateExpiry.ps1) | Reports the token-signing certificates of SAML enterprise applications that are expired or expiring soon. | No |
| [Get-EntraServicePrincipalInventory.ps1](./EntraID/Get-EntraServicePrincipalInventory.ps1) | Inventories every service principal in the tenant and classifies it by kind, origin and SSO configuration. | No |
| [Get-EntraUnusedEnterpriseApps.ps1](./EntraID/Get-EntraUnusedEnterpriseApps.ps1) | Finds enterprise applications that have not signed in for a given number of days (or never) and can optionally disable them. | Optional (-DisableApps) |

**Roles, governance & tenant policy**

| Script | Purpose | Changes? |
|---|---|---|
| [Export-EntraConditionalAccessPolicies.ps1](./EntraID/Export-EntraConditionalAccessPolicies.ps1) | Backs up every Conditional Access policy to JSON and builds a human-readable CSV summary. | No |
| [Export-EntraPimRoleSettings.ps1](./EntraID/Export-EntraPimRoleSettings.ps1) | Exports the Privileged Identity Management (PIM) role settings (activation, assignment and approval rules) of every Entra directory role. | No |
| [Get-EntraAccessReviewsStatus.ps1](./EntraID/Get-EntraAccessReviewsStatus.ps1) | Reports the status of Microsoft Entra access reviews: definitions, their instances, pending decisions and overdue reviews. | No |
| [Get-EntraAdministrativeUnits.ps1](./EntraID/Get-EntraAdministrativeUnits.ps1) | Reports the Microsoft Entra administrative units with their membership counts, dynamic rules and scoped administrators. | No |
| [Get-EntraCrossTenantAccessPolicy.ps1](./EntraID/Get-EntraCrossTenantAccessPolicy.ps1) | Reports the Microsoft Entra cross-tenant access policy: default settings and every partner-specific configuration. | No |
| [Get-EntraCustomRoleDefinitions.ps1](./EntraID/Get-EntraCustomRoleDefinitions.ps1) | Documents the custom Microsoft Entra directory roles: permissions, state and how many assignments each role has. | No |
| [Get-EntraEntitlementManagementReport.ps1](./EntraID/Get-EntraEntitlementManagementReport.ps1) | Reports Microsoft Entra entitlement management: access packages, their policies and who currently holds an assignment. | No |
| [Get-EntraPimActivationHistory.ps1](./EntraID/Get-EntraPimActivationHistory.ps1) | Reports Privileged Identity Management (PIM) activation and assignment requests for Microsoft Entra directory roles. | No |
| [Get-EntraPrivilegedRoleMembers.ps1](./EntraID/Get-EntraPrivilegedRoleMembers.ps1) | Reports who holds Microsoft Entra directory roles, including active assignments and PIM-eligible assignments. | No |
| [Get-EntraSyncStatusAndErrors.ps1](./EntraID/Get-EntraSyncStatusAndErrors.ps1) | Checks the Microsoft Entra Connect / Cloud Sync health: last sync times, enabled sync features and objects with provisioning errors. | No |
| [Get-EntraTenantSecuritySettings.ps1](./EntraID/Get-EntraTenantSecuritySettings.ps1) | Takes a snapshot of the tenant-wide Microsoft Entra security settings and highlights settings that deserve attention. | No |
| [New-EntraGuestInvitation.ps1](./EntraID/New-EntraGuestInvitation.ps1) | Invites external users as Microsoft Entra B2B guests, in bulk from a list of addresses or a CSV file, and adds them to groups. | Yes (`-WhatIf` supported) |

</details>

<details>
<summary><strong>Microsoft Defender</strong> - 54 scripts (<a href="./Defender/README.md">folder README</a>)</summary>

**Defender XDR alerts & incidents**

| Script | Purpose | Changes? |
|---|---|---|
| [Add-DefenderIncidentComment.ps1](./Defender/Add-DefenderIncidentComment.ps1) | Adds the same analyst comment to one or more Microsoft Defender XDR incidents or alerts. | Yes (`-WhatIf` supported) |
| [Get-DefenderAlertsReport.ps1](./Defender/Get-DefenderAlertsReport.ps1) | Reports alerts from Microsoft Defender XDR (unified alerts API) for the last N days. | No |
| [Get-DefenderAlertsTrend.ps1](./Defender/Get-DefenderAlertsTrend.ps1) | Trends Microsoft Defender XDR alerts over time: volume by severity, source, category and title, MTTR and false-positive rate. | No |
| [Get-DefenderIncidentTimeline.ps1](./Defender/Get-DefenderIncidentTimeline.ps1) | Builds a chronological timeline of one Microsoft Defender XDR incident: alerts, typed evidence and comments. | No |
| [Get-DefenderIncidentsReport.ps1](./Defender/Get-DefenderIncidentsReport.ps1) | Reports Microsoft Defender XDR incidents for triage, including how long each one has been open. | No |
| [Update-DefenderAlerts.ps1](./Defender/Update-DefenderAlerts.ps1) | Bulk-updates Microsoft Defender XDR alerts: status, classification, determination and assignment. | Yes (`-WhatIf` supported) |
| [Update-DefenderIncidents.ps1](./Defender/Update-DefenderIncidents.ps1) | Bulk-updates Microsoft Defender XDR incidents: status, classification, determination, owner and custom tags. | Yes (`-WhatIf` supported) |

**Secure Score**

| Script | Purpose | Changes? |
|---|---|---|
| [Get-DefenderSecureScore.ps1](./Defender/Get-DefenderSecureScore.ps1) | Shows the current Microsoft Secure Score and the improvement actions with the largest remaining point gap. | No |
| [Get-DefenderSecureScoreHistory.ps1](./Defender/Get-DefenderSecureScoreHistory.ps1) | Trends Microsoft Secure Score over the retained daily snapshots and explains score drops at control level. | No |

**Attack simulation training**

| Script | Purpose | Changes? |
|---|---|---|
| [Get-DefenderAttackSimulationUserResults.ps1](./Defender/Get-DefenderAttackSimulationUserResults.ps1) | Reports per-user results of Attack simulation training campaigns and finds repeat offenders across simulations. | No |
| [Get-DefenderAttackSimulations.ps1](./Defender/Get-DefenderAttackSimulations.ps1) | Reports Attack simulation training campaigns with their click, compromise and report rates. | No |

**Defender for Identity**

| Script | Purpose | Changes? |
|---|---|---|
| [Get-DefenderIdentityHealthIssues.ps1](./Defender/Get-DefenderIdentityHealthIssues.ps1) | Reports Microsoft Defender for Identity health issues (sensor and global) with severity, affected domains and fixes. | No |
| [Get-DefenderIdentitySensors.ps1](./Defender/Get-DefenderIdentitySensors.ps1) | Inventories Microsoft Defender for Identity sensors and flags unhealthy, outdated or misconfigured ones. | No |

**Advanced hunting (Graph)**

| Script | Purpose | Changes? |
|---|---|---|
| [Get-DefenderDeviceInventory.ps1](./Defender/Get-DefenderDeviceInventory.ps1) | Exports the Defender for Endpoint device inventory (latest DeviceInfo record per device) with sensor health and onboarding status. | No |
| [Get-DefenderDevicesNotOnboarded.ps1](./Defender/Get-DefenderDevicesNotOnboarded.ps1) | Reconciles Intune-managed Windows, macOS and Linux devices against Defender for Endpoint to find devices that are not onboarded or not reporting. | No |
| [Get-DefenderIdentityLogonHunt.ps1](./Defender/Get-DefenderIdentityLogonHunt.ps1) | Hunts Defender for Identity logon telemetry for password spray sources, NTLM usage and interactive logons by service accounts. | No |
| [Get-DefenderPhishingEmailsHunt.ps1](./Defender/Get-DefenderPhishingEmailsHunt.ps1) | Hunts phishing and malware emails detected by Defender for Office 365, with delivery outcome, policies applied and optional URL clicks. | No |
| [Get-DefenderRemoteLogonsHunt.ps1](./Defender/Get-DefenderRemoteLogonsHunt.ps1) | Hunts remote (RDP and network) logon attempts per device and source IP to surface brute-force patterns and external access. | No |
| [Get-DefenderSecurityRecommendations.ps1](./Defender/Get-DefenderSecurityRecommendations.ps1) | Reports failed Defender Vulnerability Management security configuration checks with impact, risk, remediation and affected device counts. | No |
| [Get-DefenderSoftwareInventory.ps1](./Defender/Get-DefenderSoftwareInventory.ps1) | Exports the Defender Vulnerability Management software inventory with device counts, versions in use and end-of-support status. | No |
| [Get-DefenderSuspiciousPowerShellHunt.ps1](./Defender/Get-DefenderSuspiciousPowerShellHunt.ps1) | Hunts suspicious PowerShell executions (encoded, hidden, download-cradle and Defender-tampering command lines) across onboarded devices. | No |
| [Get-DefenderUsbDeviceUsageHunt.ps1](./Defender/Get-DefenderUsbDeviceUsageHunt.ps1) | Hunts USB drive mounts and removable device connections across onboarded devices, with product, manufacturer and serial number. | No |
| [Get-DefenderVulnerableSoftware.ps1](./Defender/Get-DefenderVulnerableSoftware.ps1) | Reports vulnerable software found by Defender Vulnerability Management: CVEs per software version with CVSS, exploit availability and device counts. | No |
| [Invoke-DefenderHuntingQuery.ps1](./Defender/Invoke-DefenderHuntingQuery.ps1) | Runs any Advanced Hunting KQL query against Microsoft Defender XDR through Microsoft Graph and exports the rows to CSV. | No |

**Defender for Endpoint API**

| Script | Purpose | Changes? |
|---|---|---|
| [Get-MDEExposureScore.ps1](./Defender/Get-MDEExposureScore.ps1) | Shows the Defender Vulnerability Management exposure score, Secure Score for Devices and exposure by device group, with top recommendations. | No |
| [Get-MDEIndicators.ps1](./Defender/Get-MDEIndicators.ps1) | Exports the Microsoft Defender for Endpoint custom indicators (IoCs) with expiry analysis and hygiene flags. | No |
| [Get-MDEMachineActionsHistory.ps1](./Defender/Get-MDEMachineActionsHistory.ps1) | Reports the Microsoft Defender for Endpoint response actions (isolation, scans, packages...) submitted in the last N days. | Optional (-CancelPending) |
| [Get-MDEMachineVulnerabilities.ps1](./Defender/Get-MDEMachineVulnerabilities.ps1) | Reports the vulnerabilities (CVEs) found on devices by Microsoft Defender Vulnerability Management, per device or aggregated per CVE. | No |
| [Get-MDEMachines.ps1](./Defender/Get-MDEMachines.ps1) | Exports the Microsoft Defender for Endpoint device inventory with sensor health, risk and exposure details. | No |
| [Import-MDEIndicators.ps1](./Defender/Import-MDEIndicators.ps1) | Bulk-imports custom indicators (IoCs) into Microsoft Defender for Endpoint from a CSV, or deletes the listed indicators. | Yes (`-WhatIf` supported) |
| [Invoke-MDEAntivirusScan.ps1](./Defender/Invoke-MDEAntivirusScan.ps1) | Starts a Microsoft Defender Antivirus quick or full scan on devices through the Defender for Endpoint API. | Yes (`-WhatIf` supported) |
| [Invoke-MDECollectInvestigationPackage.ps1](./Defender/Invoke-MDECollectInvestigationPackage.ps1) | Collects Microsoft Defender for Endpoint investigation packages from devices and optionally downloads the ZIP files. | Yes (`-WhatIf` supported) |
| [Invoke-MDEIsolateDevice.ps1](./Defender/Invoke-MDEIsolateDevice.ps1) | Isolates devices from the network with Microsoft Defender for Endpoint, or releases them from isolation. | Yes (`-WhatIf` supported) |
| [Invoke-MDERestrictAppExecution.ps1](./Defender/Invoke-MDERestrictAppExecution.ps1) | Restricts app execution on devices with Microsoft Defender for Endpoint (only Microsoft-signed code runs), or lifts the restriction. | Yes (`-WhatIf` supported) |
| [Set-MDEMachineTags.ps1](./Defender/Set-MDEMachineTags.ps1) | Adds or removes Microsoft Defender for Endpoint device tags in bulk by machine id, device name or CSV. | Yes (`-WhatIf` supported) |

**Defender for Office 365 policies**

| Script | Purpose | Changes? |
|---|---|---|
| [Export-DefenderOfficePolicies.ps1](./Defender/Export-DefenderOfficePolicies.ps1) | Backs up every Exchange Online Protection and Defender for Office 365 threat policy to JSON files with an index CSV. | No |
| [Get-DefenderAntiMalwarePolicyReport.ps1](./Defender/Get-DefenderAntiMalwarePolicyReport.ps1) | Reports every anti-malware policy with its scope, common attachments filter, zero-hour auto purge and notification settings. | No |
| [Get-DefenderAntiPhishPolicyReport.ps1](./Defender/Get-DefenderAntiPhishPolicyReport.ps1) | Reports every anti-phishing policy with its scope, phishing threshold, impersonation, spoof and DMARC settings. | No |
| [Get-DefenderAntiSpamPolicyReport.ps1](./Defender/Get-DefenderAntiSpamPolicyReport.ps1) | Reports every inbound anti-spam policy with its scope, verdict actions, bulk threshold, ZAP, allow/block lists and ASF settings. | No |
| [Get-DefenderOutboundSpamPolicyReport.ps1](./Defender/Get-DefenderOutboundSpamPolicyReport.ps1) | Reports every outbound spam policy with its sender scope, automatic forwarding mode, recipient limits and notifications. | No |
| [Get-DefenderPresetSecurityPolicyStatus.ps1](./Defender/Get-DefenderPresetSecurityPolicyStatus.ps1) | Reports whether the Standard, Strict and Built-in protection preset security policies are on and who they cover. | No |
| [Get-DefenderQuarantinePolicies.ps1](./Defender/Get-DefenderQuarantinePolicies.ps1) | Reports every quarantine policy with its decoded end-user permissions, notification settings and the threat policies that use it. | No |
| [Get-DefenderReportSubmissionSettings.ps1](./Defender/Get-DefenderReportSubmissionSettings.ps1) | Explains how users can report suspicious messages (user reported settings) and exports every setting as a Setting/Value CSV. | No |
| [Get-DefenderSafeAttachmentsReport.ps1](./Defender/Get-DefenderSafeAttachmentsReport.ps1) | Reports every Safe Attachments policy with its scope and action, plus the global SharePoint, OneDrive, Teams and Safe Documents settings. | No |
| [Get-DefenderSafeLinksReport.ps1](./Defender/Get-DefenderSafeLinksReport.ps1) | Reports every Safe Links policy with its scope and URL protection settings, and shows who is only covered by Built-in protection. | No |

**Email threat operations**

| Script | Purpose | Changes? |
|---|---|---|
| [Add-DefenderTenantBlockListEntries.ps1](./Defender/Add-DefenderTenantBlockListEntries.ps1) | Bulk-adds block entries (or time-limited allow entries) to the Tenant Allow/Block List from the command line or a CSV file. | Yes (`-WhatIf` supported) |
| [Enable-DefenderDkimForDomains.ps1](./Defender/Enable-DefenderDkimForDomains.ps1) | Prepares, enables or rotates DKIM signing for custom accepted domains and prints the CNAME records the DNS team must publish. | Yes (`-WhatIf` supported) |
| [Get-DefenderEmailAuthenticationStatus.ps1](./Defender/Get-DefenderEmailAuthenticationStatus.ps1) | Scores SPF, DKIM and DMARC for every accepted domain by combining Exchange Online DKIM settings with live DNS lookups. | No |
| [Get-DefenderMailThreatReports.ps1](./Defender/Get-DefenderMailThreatReports.ps1) | Exports the Defender for Office 365 threat protection status as a daily matrix, the mail flow status report and optionally the per-message detail. | No |
| [Get-DefenderQuarantineReport.ps1](./Defender/Get-DefenderQuarantineReport.ps1) | Exports quarantined messages with sender, recipients, verdict, policy, release status and expiry, plus a triage summary. | No |
| [Get-DefenderSpoofIntelligence.ps1](./Defender/Get-DefenderSpoofIntelligence.ps1) | Reports the senders that spoof intelligence allowed or blocked, joined with the spoofed sender overrides, and flags the risky ones. | No |
| [Get-DefenderTenantAllowBlockList.ps1](./Defender/Get-DefenderTenantAllowBlockList.ps1) | Exports the Tenant Allow/Block List (senders, URLs, file hashes, IPv6 addresses and spoofed senders) with expiry and usage flags. | No |
| [Release-DefenderQuarantineMessages.ps1](./Defender/Release-DefenderQuarantineMessages.ps1) | Releases (or deletes) quarantined messages by identity, from a CSV, or by an explicit filter, with safety checks per message. | Yes (`-WhatIf` supported) |
| [Remove-DefenderExpiredAllowBlockEntries.ps1](./Defender/Remove-DefenderExpiredAllowBlockEntries.ps1) | Reports (and with -Remove deletes) expired, aged or explicitly named entries in the Tenant Allow/Block List. | Optional (-Remove) |

</details>

<details>
<summary><strong>Exchange Online</strong> - 53 scripts (<a href="./ExchangeOnline/README.md">folder README</a>)</summary>

**Mailbox lifecycle & compliance**

| Script | Purpose | Changes? |
|---|---|---|
| [Convert-EXOMailboxToShared.ps1](./ExchangeOnline/Convert-EXOMailboxToShared.ps1) | Converts user mailboxes to shared mailboxes (or back to regular) after a licensing and size pre-flight check. | Yes (`-WhatIf` supported) |
| [Enable-EXOArchiveMailboxes.ps1](./ExchangeOnline/Enable-EXOArchiveMailboxes.ps1) | Enables the In-Place Archive (optionally auto-expanding) and assigns a retention policy for mailboxes that lack one. | Yes (`-WhatIf` supported) |
| [Get-EXOArchiveStatusReport.ps1](./ExchangeOnline/Get-EXOArchiveStatusReport.ps1) | Reports In-Place Archive status, size, quota usage and retention policy coverage for Exchange Online mailboxes. | No |
| [Get-EXOHoldsReport.ps1](./ExchangeOnline/Get-EXOHoldsReport.ps1) | Reports every hold applied to Exchange Online mailboxes and decodes the InPlaceHolds identifiers. | No |
| [Get-EXOInactiveMailboxes.ps1](./ExchangeOnline/Get-EXOInactiveMailboxes.ps1) | Finds user (and optionally shared) mailboxes with no activity for a given number of days. | No |
| [Get-EXOMailboxAuditStatus.ps1](./ExchangeOnline/Get-EXOMailboxAuditStatus.ps1) | Reports mailbox auditing status (tenant default, per-mailbox settings, bypass accounts) and can restore the defaults. | Optional (-SetDefaults) |
| [Get-EXOMailboxPlansReport.ps1](./ExchangeOnline/Get-EXOMailboxPlansReport.ps1) | Reports Exchange Online mailbox plans and CAS mailbox plans (the defaults every new mailbox inherits) and can harden them. | Optional (-SetDefaults) |
| [Get-EXOMailboxSizeReport.ps1](./ExchangeOnline/Get-EXOMailboxSizeReport.ps1) | Reports mailbox and archive size, item counts and quota usage for Exchange Online mailboxes. | No |
| [Get-EXOSharedMailboxReport.ps1](./ExchangeOnline/Get-EXOSharedMailboxReport.ps1) | Reports shared (and optionally room/equipment) mailboxes with size, license, delegation and hygiene findings. | No |
| [Get-EXOSoftDeletedMailboxes.ps1](./ExchangeOnline/Get-EXOSoftDeletedMailboxes.ps1) | Reports soft-deleted and inactive mailboxes with purge dates, holds and size, and can restore content into another mailbox. | Optional (-Restore) |
| [Set-EXOLitigationHold.ps1](./ExchangeOnline/Set-EXOLitigationHold.ps1) | Places selected mailboxes on litigation hold (or releases them) with duration, owner and notice details. | Yes (`-WhatIf` supported) |

**Mailbox content & settings**

| Script | Purpose | Changes? |
|---|---|---|
| [Get-EXOEmailAddressReport.ps1](./ExchangeOnline/Get-EXOEmailAddressReport.ps1) | Reports every e-mail address (primary, alias, SIP, SPO, X500) of all Exchange Online recipients with per-domain totals. | No |
| [Get-EXOExternalForwardingReport.ps1](./ExchangeOnline/Get-EXOExternalForwardingReport.ps1) | Finds mail leaving the tenant through mailbox forwarding or inbox rules, and optionally removes it. | Optional (-Remediate) |
| [Get-EXOInboxRulesReport.ps1](./ExchangeOnline/Get-EXOInboxRulesReport.ps1) | Reports inbox rules of Exchange Online mailboxes, flags suspicious rules and can disable them. | Optional (-Disable) |
| [Get-EXOMailboxFolderSizes.ps1](./ExchangeOnline/Get-EXOMailboxFolderSizes.ps1) | Reports the largest folders of Exchange Online mailboxes with item counts, sizes and oldest/newest item dates. | No |
| [Get-EXOMailboxPermissionsReport.ps1](./ExchangeOnline/Get-EXOMailboxPermissionsReport.ps1) | Audits delegated mailbox access: FullAccess, SendAs and SendOnBehalf grants across Exchange Online mailboxes. | No |
| [Get-EXOMailboxRegionalSettings.ps1](./ExchangeOnline/Get-EXOMailboxRegionalSettings.ps1) | Reports language, time zone and date/time format of Exchange Online mailboxes and flags unconfigured or deviating ones. | No |
| [Get-EXOOutOfOfficeReport.ps1](./ExchangeOnline/Get-EXOOutOfOfficeReport.ps1) | Reports automatic reply (out of office) settings of Exchange Online mailboxes and flags stale or risky configurations. | No |
| [Get-EXORecoverableItemsReport.ps1](./ExchangeOnline/Get-EXORecoverableItemsReport.ps1) | Reports Recoverable Items folder usage against quota for Exchange Online mailboxes and optionally starts the Managed Folder Assistant. | Optional (-RunMfa) |
| [Set-EXOAutoReply.ps1](./ExchangeOnline/Set-EXOAutoReply.ps1) | Enables, schedules or disables automatic replies on Exchange Online mailboxes with templated messages, typically for leavers. | Yes (`-WhatIf` supported) |
| [Set-EXOMailboxQuotas.ps1](./ExchangeOnline/Set-EXOMailboxQuotas.ps1) | Sets custom storage quotas and deleted item retention on Exchange Online mailboxes with a before/after report. | Yes (`-WhatIf` supported) |
| [Set-EXOMailboxRegionalSettings.ps1](./ExchangeOnline/Set-EXOMailboxRegionalSettings.ps1) | Sets language, time zone and date/time format on Exchange Online mailboxes, optionally localising default folder names. | Yes (`-WhatIf` supported) |

**Calendar & resource mailboxes**

| Script | Purpose | Changes? |
|---|---|---|
| [Get-EXOCalendarPermissionsReport.ps1](./ExchangeOnline/Get-EXOCalendarPermissionsReport.ps1) | Reports calendar folder permissions on user (and optionally resource) mailboxes and flags over-permissive Default/Anonymous access. | No |
| [Get-EXORoomMailboxReport.ps1](./ExchangeOnline/Get-EXORoomMailboxReport.ps1) | Inventories room and equipment mailboxes with their booking (calendar processing) settings, Places metadata and room list membership. | No |
| [Set-EXODefaultCalendarPermission.ps1](./ExchangeOnline/Set-EXODefaultCalendarPermission.ps1) | Standardises the Default (and optionally Anonymous) calendar permission on user mailboxes. | Yes (`-WhatIf` supported) |
| [Set-EXORoomBookingPolicy.ps1](./ExchangeOnline/Set-EXORoomBookingPolicy.ps1) | Applies a consistent booking policy (calendar processing) and optional Places metadata to room and equipment mailboxes. | Yes (`-WhatIf` supported) |

**Distribution groups**

| Script | Purpose | Changes? |
|---|---|---|
| [Add-EXODistributionGroupMembers.ps1](./ExchangeOnline/Add-EXODistributionGroupMembers.ps1) | Bulk-adds (or, with -Remove, removes) members of distribution groups from a CSV or from parameters, skipping no-op changes. | Yes (`-WhatIf` supported) |
| [Convert-EXODistributionGroupToM365Group.ps1](./ExchangeOnline/Convert-EXODistributionGroupToM365Group.ps1) | Lists distribution groups eligible for upgrade to Microsoft 365 Groups, explains blockers, and optionally submits the upgrade. | Optional (-Upgrade) |
| [Export-EXODistributionGroupMembers.ps1](./ExchangeOnline/Export-EXODistributionGroupMembers.ps1) | Exports the members of distribution groups (optionally expanding nested groups) to one CSV or one CSV per group. | No |
| [Get-EXODistributionGroupReport.ps1](./ExchangeOnline/Get-EXODistributionGroupReport.ps1) | Inventories distribution groups, mail-enabled security groups, room lists and (optionally) dynamic distribution groups. | No |
| [Get-EXODynamicDistributionGroupPreview.ps1](./ExchangeOnline/Get-EXODynamicDistributionGroupPreview.ps1) | Previews dynamic distribution groups: recipient filter, conditional attributes, calculated member count, sample members and an optional recipient test. | No |
| [Get-EXOEmptyAndOwnerlessDistributionGroups.ps1](./ExchangeOnline/Get-EXOEmptyAndOwnerlessDistributionGroups.ps1) | Finds distribution groups that are empty and/or have no valid owner, with optional owner assignment or removal. | Optional (-SetOwner / -RemoveEmpty) |

**Mail flow & organization**

| Script | Purpose | Changes? |
|---|---|---|
| [Export-EXOOrganizationConfig.ps1](./ExchangeOnline/Export-EXOOrganizationConfig.ps1) | Exports the Exchange Online organization and transport configuration as a JSON snapshot plus a key-settings CSV, with optional diff. | No |
| [Export-EXOTransportRules.ps1](./ExchangeOnline/Export-EXOTransportRules.ps1) | Exports every Exchange Online mail flow (transport) rule to JSON files, a CSV summary and a restorable XML collection. | No |
| [Get-EXOAcceptedAndRemoteDomains.ps1](./ExchangeOnline/Get-EXOAcceptedAndRemoteDomains.ps1) | Reports accepted domains and remote domains, flags risky settings and optionally checks each MX record in DNS. | No |
| [Get-EXOConnectorsReport.ps1](./ExchangeOnline/Get-EXOConnectorsReport.ps1) | Inventories inbound and outbound connectors, flags risky configurations and optionally validates outbound connectors. | Optional (-Validate) |
| [Get-EXOJournalAndArchivingConfig.ps1](./ExchangeOnline/Get-EXOJournalAndArchivingConfig.ps1) | Documents journaling, transport limits, archiving and messaging records management (MRM) retention configuration. | No |
| [Get-EXOMailFlowStatusReport.ps1](./ExchangeOnline/Get-EXOMailFlowStatusReport.ps1) | Daily mail flow volumes per event type (good mail, spam, malware, phish, edge blocks, rules) as a pivot table and raw CSV. | No |
| [Get-EXOMessageTrace.ps1](./ExchangeOnline/Get-EXOMessageTrace.ps1) | Runs a message trace for the last 10 days with full paging and exports the results with status and sender/recipient summaries. | No |
| [Get-EXOMessageTraceDetail.ps1](./ExchangeOnline/Get-EXOMessageTraceDetail.ps1) | Shows the event timeline (receive, transport rules, spam / malware verdicts, deliver, fail, defer) of one message per recipient. | No |
| [Get-EXOTopSendersAndRecipients.ps1](./ExchangeOnline/Get-EXOTopSendersAndRecipients.ps1) | Reports the top mail senders and recipients, the top spam and malware targets and the most common malware families. | No |
| [Start-EXOHistoricalSearch.ps1](./ExchangeOnline/Start-EXOHistoricalSearch.ps1) | Submits, lists and waits for historical message trace searches (mail older than 10 days, up to 90 days back). | Yes (`-WhatIf` supported) |

**Client access & mobile devices**

| Script | Purpose | Changes? |
|---|---|---|
| [Export-EXOClientAccessPolicies.ps1](./ExchangeOnline/Export-EXOClientAccessPolicies.ps1) | Exports the OWA, mobile device, authentication and role assignment policies to JSON files with a CSV index and usage counts. | No |
| [Get-EXOCasMailboxProtocolReport.ps1](./ExchangeOnline/Get-EXOCasMailboxProtocolReport.ps1) | Reports which client access protocols (POP, IMAP, SMTP AUTH, ActiveSync, EWS, MAPI, OWA, Outlook clients) each mailbox can use. | No |
| [Get-EXOMobileDevicesReport.ps1](./ExchangeOnline/Get-EXOMobileDevicesReport.ps1) | Reports every mobile device partnership (ActiveSync and Outlook mobile) with owner, platform, access state and last sync. | No |
| [Get-EXOSmtpAuthAndBasicAuthReport.ps1](./ExchangeOnline/Get-EXOSmtpAuthAndBasicAuthReport.ps1) | Reports which mailboxes can still use SMTP AUTH, the authentication policies in force, and how to close the remaining gaps. | No |
| [Remove-EXOStaleMobileDevices.ps1](./ExchangeOnline/Remove-EXOStaleMobileDevices.ps1) | Finds mobile device partnerships that have not synced for a long time and optionally removes them or wipes the account data. | Optional (-Remove) |
| [Set-EXODisableLegacyProtocols.ps1](./ExchangeOnline/Set-EXODisableLegacyProtocols.ps1) | Disables legacy client protocols (POP, IMAP, SMTP AUTH, ActiveSync, EWS) on mailboxes and optionally at the organization level. | Yes (`-WhatIf` supported) |

**Administration, audit & migration**

| Script | Purpose | Changes? |
|---|---|---|
| [Get-EXOAdminChangesAudit.ps1](./ExchangeOnline/Get-EXOAdminChangesAudit.ps1) | Reports the Exchange Online admin cmdlets that were run (who, what, on which object, from where) from the unified audit log. | No |
| [Get-EXOAdminRoleAssignments.ps1](./ExchangeOnline/Get-EXOAdminRoleAssignments.ps1) | Reports who holds Exchange Online admin permissions through role groups and direct management role assignments. | No |
| [Get-EXOMigrationBatchStatus.ps1](./ExchangeOnline/Get-EXOMigrationBatchStatus.ps1) | Reports the status of Exchange Online migration batches and, optionally, of every user inside them. | No |
| [Get-EXONonOwnerMailboxAccess.ps1](./ExchangeOnline/Get-EXONonOwnerMailboxAccess.ps1) | Reports mailbox actions performed by someone other than the mailbox owner (admins and delegates) from the unified audit log. | No |
| [Get-EXOPublicFolderReport.ps1](./ExchangeOnline/Get-EXOPublicFolderReport.ps1) | Reports the public folder hierarchy with sizes, item counts, mail-enabled addresses, stale folders and the public folder mailboxes. | No |

</details>

<details>
<summary><strong>Microsoft Purview</strong> - 51 scripts (<a href="./Purview/README.md">folder README</a>)</summary>

**Information protection**

| Script | Purpose | Changes? |
|---|---|---|
| [Export-PurviewSensitivityLabels.ps1](./Purview/Export-PurviewSensitivityLabels.ps1) | Documents Microsoft Purview sensitivity labels and label policies to CSV and JSON. | No |
| [Get-PurviewAutoLabelingPolicies.ps1](./Purview/Get-PurviewAutoLabelingPolicies.ps1) | Documents Microsoft Purview auto-labeling policies and their rules to CSV and JSON. | No |
| [Get-PurviewIRMConfiguration.ps1](./Purview/Get-PurviewIRMConfiguration.ps1) | Audits the Exchange Online IRM / Azure Rights Management configuration against recommended values. | Optional (-SetRecommended) |
| [Get-PurviewLabelHierarchy.ps1](./Purview/Get-PurviewLabelHierarchy.ps1) | Prints the sensitivity label tree (parents and sub-labels) and exports it with publishing status to CSV. | No |
| [Get-PurviewLabelPolicySettings.ps1](./Purview/Get-PurviewLabelPolicySettings.ps1) | Builds a settings matrix of every sensitivity label policy (mandatory labeling, default labels, scopes, distribution). | No |
| [Get-PurviewLabelUsageFromAudit.ps1](./Purview/Get-PurviewLabelUsageFromAudit.ps1) | Reports sensitivity label activity (applied, changed, removed) from the unified audit log. | No |
| [Get-PurviewOMEConfiguration.ps1](./Purview/Get-PurviewOMEConfiguration.ps1) | Documents Microsoft Purview Message Encryption (OME) branding templates and the transport rules that use them. | Optional (-Set) |
| [Import-PurviewSensitivityLabels.ps1](./Purview/Import-PurviewSensitivityLabels.ps1) | Bulk-creates Microsoft Purview sensitivity labels from a CSV file and optionally publishes them in a label policy. | Yes (`-WhatIf` supported) |
| [New-PurviewCustomSensitiveInfoType.ps1](./Purview/New-PurviewCustomSensitiveInfoType.ps1) | Builds a Purview rule package XML for a custom sensitive information type and optionally uploads it. | Optional (-Create) |
| [Test-PurviewSensitiveInfoType.ps1](./Purview/Test-PurviewSensitiveInfoType.ps1) | Tests which Purview sensitive information types match a text or plain-text file, or lists the available types. | No |

**Data loss prevention**

| Script | Purpose | Changes? |
|---|---|---|
| [Export-PurviewDLPPolicies.ps1](./Purview/Export-PurviewDLPPolicies.ps1) | Documents Microsoft Purview DLP policies and their rules to CSV and JSON. | No |
| [Export-PurviewDlpRulesMatrix.ps1](./Purview/Export-PurviewDlpRulesMatrix.ps1) | Exports a one-row-per-rule matrix of all Purview DLP rules with their conditions, exceptions and actions. | No |
| [Get-PurviewDlpAlertsViaGraph.ps1](./Purview/Get-PurviewDlpAlertsViaGraph.ps1) | Lists Microsoft Purview DLP alerts through the Microsoft Graph security API and optionally resolves them. | Optional (-Resolve) |
| [Get-PurviewDlpIncidentsFromAudit.ps1](./Purview/Get-PurviewDlpIncidentsFromAudit.ps1) | Reports Purview DLP rule matches from the unified audit log for Exchange, SharePoint/OneDrive and endpoint devices. | No |
| [Get-PurviewDlpOverridesAndFalsePositives.ps1](./Purview/Get-PurviewDlpOverridesAndFalsePositives.ps1) | Reports DLP policy-tip overrides and false-positive reports from the unified audit log and highlights rules that need tuning. | No |
| [Get-PurviewDlpPolicyHealth.ps1](./Purview/Get-PurviewDlpPolicyHealth.ps1) | Checks every Purview DLP policy for configuration problems and reports findings with a severity. | No |
| [Get-PurviewEdmSchemas.ps1](./Purview/Get-PurviewEdmSchemas.ps1) | Reports exact data match (EDM) schemas, their fields and the EDM sensitive information types that use them. | No |
| [Get-PurviewEndpointDlpSettings.ps1](./Purview/Get-PurviewEndpointDlpSettings.ps1) | Documents the tenant-wide Endpoint DLP settings (exclusions, restricted apps and browsers, service domains, device groups). | No |
| [Get-PurviewSensitiveInfoTypes.ps1](./Purview/Get-PurviewSensitiveInfoTypes.ps1) | Inventories sensitive information types (SITs), their rule packages and the DLP / auto-labeling rules that use them. | No |
| [Set-PurviewDlpPolicyMode.ps1](./Purview/Set-PurviewDlpPolicyMode.ps1) | Switches Purview DLP policies between test and enforcement modes, in bulk and with a before/after report. | Yes (`-WhatIf` supported) |

**Retention & records management**

| Script | Purpose | Changes? |
|---|---|---|
| [Export-PurviewRetentionLabels.ps1](./Purview/Export-PurviewRetentionLabels.ps1) | Documents Microsoft Purview retention labels, their file plan descriptors and where each label is published or auto-applied. | No |
| [Export-PurviewRetentionPolicies.ps1](./Purview/Export-PurviewRetentionPolicies.ps1) | Documents Microsoft Purview retention policies and their retention rules to CSV and JSON. | No |
| [Get-PurviewAdaptiveScopes.ps1](./Purview/Get-PurviewAdaptiveScopes.ps1) | Reports Microsoft Purview adaptive scopes, their queries and the retention policies that use them. | No |
| [Get-PurviewMailboxHolds.ps1](./Purview/Get-PurviewMailboxHolds.ps1) | Decodes every hold on Exchange Online mailboxes (litigation, eDiscovery, retention policies, label and delay holds) into named rows. | No |
| [Get-PurviewRetentionEvents.ps1](./Purview/Get-PurviewRetentionEvents.ps1) | Reports Purview event-based retention: event types, the labels that depend on them and the retention events raised. | Optional (-NewEvent) |
| [Get-PurviewRetentionLabelUsageFromAudit.ps1](./Purview/Get-PurviewRetentionLabelUsageFromAudit.ps1) | Reports retention label activity (applied, removed, changed, record declared) from the unified audit log. | No |
| [Get-PurviewRetentionLabelsViaGraph.ps1](./Purview/Get-PurviewRetentionLabelsViaGraph.ps1) | Reports Microsoft Purview retention labels (and optionally event types and events) through the Microsoft Graph records management API. | No |
| [Get-PurviewRetentionPolicyDistributionStatus.ps1](./Purview/Get-PurviewRetentionPolicyDistributionStatus.ps1) | Reports the distribution status of Purview retention policies (optionally DLP and label policies) and can retry failed ones. | Optional (-Retry) |
| [New-PurviewRetentionLabels.ps1](./Purview/New-PurviewRetentionLabels.ps1) | Bulk-creates Microsoft Purview retention labels from a CSV file and optionally publishes them in a label policy. | Yes (`-WhatIf` supported) |

**eDiscovery & content search**

| Script | Purpose | Changes? |
|---|---|---|
| [Add-PurviewEDiscoveryCaseMembers.ps1](./Purview/Add-PurviewEDiscoveryCaseMembers.ps1) | Adds, removes or replaces the members of eDiscovery cases, skipping existing members and warning about users outside the eDiscovery Manager role group. | Yes (`-WhatIf` supported) |
| [Export-PurviewContentSearchResults.ps1](./Purview/Export-PurviewContentSearchResults.ps1) | Starts an export of a completed content search and returns the container URL, SAS token and item counts needed to download it. | Yes (`-WhatIf` supported) |
| [Get-PurviewCaseHolds.ps1](./Purview/Get-PurviewCaseHolds.ps1) | Reports every eDiscovery case hold with its locations, rule query and distribution status, flagging holds that need attention. | No |
| [Get-PurviewContentSearchResults.ps1](./Purview/Get-PurviewContentSearchResults.ps1) | Reports Purview content searches with status, item counts and size, optionally with per-location statistics and a result preview. | Optional (-Preview) |
| [Get-PurviewEDiscoveryActivityAudit.ps1](./Purview/Get-PurviewEDiscoveryActivityAudit.ps1) | Reports who did what in eDiscovery and content search (searches, previews, exports, purges, case and hold changes) from the unified audit log. | No |
| [Get-PurviewEDiscoveryCases.ps1](./Purview/Get-PurviewEDiscoveryCases.ps1) | Reports eDiscovery (Standard) and eDiscovery (Premium) cases with members, hold and search counts, and flags stale open cases. | No |
| [Get-PurviewEDiscoveryCasesViaGraph.ps1](./Purview/Get-PurviewEDiscoveryCasesViaGraph.ps1) | Reports eDiscovery (Premium) cases through Microsoft Graph, optionally with custodians, legal holds, searches and review sets. | No |
| [Invoke-PurviewSearchAndPurge.ps1](./Purview/Invoke-PurviewSearchAndPurge.ps1) | Purges the mailbox items found by a completed content search (soft or hard delete), optionally repeating until nothing is left. | Yes (`-WhatIf` supported) |
| [New-PurviewContentSearch.ps1](./Purview/New-PurviewContentSearch.ps1) | Creates and starts a Purview content search from a KQL query or simple mail criteria, optionally waiting for the results. | Yes (`-WhatIf` supported) |

**Audit log scenarios**

| Script | Purpose | Changes? |
|---|---|---|
| [Get-PurviewAuditConfiguration.ps1](./Purview/Get-PurviewAuditConfiguration.ps1) | Reports the Microsoft Purview audit configuration and can switch unified audit log ingestion on. | Optional (-EnableAuditing) |
| [Get-PurviewAuditLogViaGraph.ps1](./Purview/Get-PurviewAuditLogViaGraph.ps1) | Runs a Microsoft Purview audit log search through the Microsoft Graph Audit Search API and exports the records. | No |
| [Search-PurviewAuditAdminRoleChanges.ps1](./Purview/Search-PurviewAuditAdminRoleChanges.ps1) | Reports Entra ID directory role membership changes (and optionally group membership changes) from the unified audit log. | No |
| [Search-PurviewAuditFileActivity.ps1](./Purview/Search-PurviewAuditFileActivity.ps1) | Reports SharePoint and OneDrive file activity (access, download, delete, move, upload) from the unified audit log. | No |
| [Search-PurviewAuditLog.ps1](./Purview/Search-PurviewAuditLog.ps1) | Exports unified audit log records reliably, beyond the 5,000-row limit of a single Search-UnifiedAuditLog call. | No |
| [Search-PurviewAuditMailItemsAccessed.ps1](./Purview/Search-PurviewAuditMailItemsAccessed.ps1) | Reports MailItemsAccessed mailbox audit events (who read which mail, from where) for compromised-account investigations. | No |
| [Search-PurviewAuditSharingEvents.ps1](./Purview/Search-PurviewAuditSharingEvents.ps1) | Reports SharePoint and OneDrive sharing events (invitations, links, permission grants) from the unified audit log. | No |
| [Search-PurviewAuditTeamsActivity.ps1](./Purview/Search-PurviewAuditTeamsActivity.ps1) | Reports Microsoft Teams lifecycle, membership, channel, app and settings events from the unified audit log. | No |
| [Search-PurviewAuditUserTimeline.ps1](./Purview/Search-PurviewAuditUserTimeline.ps1) | Builds a cross-workload activity timeline for one or more users from the unified audit log. | No |

**Risk, compliance & roles**

| Script | Purpose | Changes? |
|---|---|---|
| [Get-PurviewCommunicationCompliancePolicies.ps1](./Purview/Get-PurviewCommunicationCompliancePolicies.ps1) | Documents Microsoft Purview Communication Compliance policies and their rules (reviewers, sampling, conditions). | No |
| [Get-PurviewComplianceRoleGroups.ps1](./Purview/Get-PurviewComplianceRoleGroups.ps1) | Reports Microsoft Purview (Security & Compliance) role groups, their roles and members, plus the eDiscovery case admins. | No |
| [Get-PurviewInformationBarriers.ps1](./Purview/Get-PurviewInformationBarriers.ps1) | Documents information barrier segments, policies and application status, tests a recipient pair and can start policy application. | Optional (-Apply) |
| [Get-PurviewInsiderRiskPolicies.ps1](./Purview/Get-PurviewInsiderRiskPolicies.ps1) | Documents Microsoft Purview Insider Risk Management policies (scenario, mode, scope, time spans, indicators). | No |

</details>

<details>
<summary><strong>Microsoft Teams, SharePoint & OneDrive</strong> - 51 scripts (<a href="./Teams-SharePoint/README.md">folder README</a>)</summary>

**Teams inventory & lifecycle**

| Script | Purpose | Changes? |
|---|---|---|
| [Add-TeamsMembers.ps1](./Teams-SharePoint/Add-TeamsMembers.ps1) | Adds users to teams as owners or members (or removes them) from a CSV file or from parameters, skipping existing memberships. | Yes (`-WhatIf` supported) |
| [Export-TeamsMembership.ps1](./Teams-SharePoint/Export-TeamsMembership.ps1) | Exports the membership of all or selected teams, one row per member with the role Owner, Member or Guest. | No |
| [Get-TeamsAllTeamsReport.ps1](./Teams-SharePoint/Get-TeamsAllTeamsReport.ps1) | Inventories every Microsoft Teams team with owner, member, guest and channel counts, archive state and age. | No |
| [Get-TeamsArchivedTeams.ps1](./Teams-SharePoint/Get-TeamsArchivedTeams.ps1) | Lists archived Microsoft Teams teams and can unarchive them or delete them (with their Microsoft 365 group). | Optional (-Unarchive / -DeleteArchived) |
| [Get-TeamsChannelsReport.ps1](./Teams-SharePoint/Get-TeamsChannelsReport.ps1) | Lists every channel of every team (standard, private, shared) with type, age, email, archive state and optional file size. | No |
| [Get-TeamsGuestAccessReport.ps1](./Teams-SharePoint/Get-TeamsGuestAccessReport.ps1) | Reports which Microsoft Teams teams contain guest users and which external domains they come from. | No |
| [Get-TeamsInactiveTeams.ps1](./Teams-SharePoint/Get-TeamsInactiveTeams.ps1) | Finds Microsoft Teams teams that nobody uses, based on the Teams team activity usage report. | No |
| [Get-TeamsOwnerlessTeams.ps1](./Teams-SharePoint/Get-TeamsOwnerlessTeams.ps1) | Finds teams with no owner, with only disabled owners or with a single owner, and can assign a new owner. | Optional (-AddOwner) |
| [Get-TeamsPrivateAndSharedChannelsReport.ps1](./Teams-SharePoint/Get-TeamsPrivateAndSharedChannelsReport.ps1) | Reports private and shared channels with their owner, member, guest and external member counts and sharing targets. | No |
| [Get-TeamsUserMembership.ps1](./Teams-SharePoint/Get-TeamsUserMembership.ps1) | Lists the teams one or more users belong to, with their role (Owner, Member, Guest) and the team's visibility and archive state. | No |
| [Invoke-TeamsArchiveInactiveTeams.ps1](./Teams-SharePoint/Invoke-TeamsArchiveInactiveTeams.ps1) | Reports teams with no activity for N days and, on request, notifies their owners and archives them. | Optional (-Archive) |
| [Remove-TeamsUserFromAllTeams.ps1](./Teams-SharePoint/Remove-TeamsUserFromAllTeams.ps1) | Offboarding helper: lists every team a user belongs to and, with -Remove, removes the user from all of them. | Optional (-Remove) |

**Teams apps, settings & usage**

| Script | Purpose | Changes? |
|---|---|---|
| [Get-TeamsAppCatalogReport.ps1](./Teams-SharePoint/Get-TeamsAppCatalogReport.ps1) | Reports the Microsoft Teams app catalog: organisation (custom) apps with their versions and publishing state, optionally store and sideloaded apps. | No |
| [Get-TeamsDeviceUsageReport.ps1](./Teams-SharePoint/Get-TeamsDeviceUsageReport.ps1) | Reports which Teams client platforms (Windows, Mac, web, iOS, Android, ...) every user has used and finds web-only and mobile-only users. | No |
| [Get-TeamsInstalledApps.ps1](./Teams-SharePoint/Get-TeamsInstalledApps.ps1) | Inventories the apps installed in Microsoft Teams teams, with version, distribution method and bot flag. | No |
| [Get-TeamsRoomsAndPlaces.ps1](./Teams-SharePoint/Get-TeamsRoomsAndPlaces.ps1) | Inventories meeting rooms (places) with capacity, location, AV devices and room list membership, and flags incomplete room metadata. | No |
| [Get-TeamsTagsReport.ps1](./Teams-SharePoint/Get-TeamsTagsReport.ps1) | Reports the tags defined in Microsoft Teams teams (and their members) and can bulk-create tags from a CSV. | Optional (-CreateFromCsv) |
| [Get-TeamsTeamSettingsReport.ps1](./Teams-SharePoint/Get-TeamsTeamSettingsReport.ps1) | Reports the member, guest, messaging, fun and discovery settings of Microsoft Teams teams and flags deviations from the defaults. | No |
| [Get-TeamsUserActivityReport.ps1](./Teams-SharePoint/Get-TeamsUserActivityReport.ps1) | Reports Microsoft Teams activity per user (messages, calls, meetings, media minutes) and flags inactive and licensed-but-inactive users. | No |
| [New-TeamsFromCsv.ps1](./Teams-SharePoint/New-TeamsFromCsv.ps1) | Creates Microsoft Teams teams in bulk from a CSV file, including owners, members and channels. | Yes (`-WhatIf` supported) |
| [Set-TeamsGuestSettings.ps1](./Teams-SharePoint/Set-TeamsGuestSettings.ps1) | Standardises guest permissions (and optionally member and fun settings) across Microsoft Teams teams. | Yes (`-WhatIf` supported) |

**Teams administration (MicrosoftTeams module)**

| Script | Purpose | Changes? |
|---|---|---|
| [Export-TeamsPolicies.ps1](./Teams-SharePoint/Export-TeamsPolicies.ps1) | Exports every Teams policy and tenant configuration definition to JSON and compares the export with a previous one. | No |
| [Get-TeamsAppPolicies.ps1](./Teams-SharePoint/Get-TeamsAppPolicies.ps1) | Reports the Teams app permission and app setup policies, the org-wide custom app setting and how many users each policy has. | No |
| [Get-TeamsCallQueuesAndAutoAttendants.ps1](./Teams-SharePoint/Get-TeamsCallQueuesAndAutoAttendants.ps1) | Documents every Teams call queue, auto attendant and voice application resource account, with configuration gaps flagged. | No |
| [Get-TeamsExternalAccessConfiguration.ps1](./Teams-SharePoint/Get-TeamsExternalAccessConfiguration.ps1) | Reviews the tenant-wide Teams external access, guest access and anonymous meeting settings against recommended values. | No |
| [Get-TeamsMeetingSettingsReport.ps1](./Teams-SharePoint/Get-TeamsMeetingSettingsReport.ps1) | Reports the security and feature settings of every Teams meeting policy plus the tenant meeting configuration. | No |
| [Get-TeamsPhoneNumberInventory.ps1](./Teams-SharePoint/Get-TeamsPhoneNumberInventory.ps1) | Inventories every Teams phone number with its type, assignment, capabilities, location and PSTN partner. | No |
| [Get-TeamsUserPolicyAssignments.ps1](./Teams-SharePoint/Get-TeamsUserPolicyAssignments.ps1) | Reports the Teams policies directly assigned to each user, finds who has a given policy and optionally exports group assignments. | No |
| [Get-TeamsVoiceEnabledUsers.ps1](./Teams-SharePoint/Get-TeamsVoiceEnabledUsers.ps1) | Reports Enterprise Voice enabled Teams users with their phone number, voice policies, licensing and configuration gaps. | No |
| [Grant-TeamsPolicies.ps1](./Teams-SharePoint/Grant-TeamsPolicies.ps1) | Bulk-assigns Teams policies to users (one by one or as batch operations) or to a group, with validation and a preview mode. | Yes (`-WhatIf` supported) |

**SharePoint administration (SPO module)**

| Script | Purpose | Changes? |
|---|---|---|
| [Add-SPOSiteCollectionAdmin.ps1](./Teams-SharePoint/Add-SPOSiteCollectionAdmin.ps1) | Grants (or with -Remove revokes) site collection administrator rights for an account on selected SharePoint Online sites or OneDrives. | Yes (`-WhatIf` supported) |
| [Export-SPOTenantSettings.ps1](./Teams-SharePoint/Export-SPOTenantSettings.ps1) | Exports all SharePoint Online tenant settings to JSON, assesses the key sharing and security settings and diffs against an earlier export. | No |
| [Get-SPODeletedSitesReport.ps1](./Teams-SharePoint/Get-SPODeletedSitesReport.ps1) | Reports the SharePoint Online sites in the tenant recycle bin with their remaining retention, and optionally restores or purges them. | Optional (-Restore / -PermanentlyDelete) |
| [Get-SPOExternalUsersReport.ps1](./Teams-SharePoint/Get-SPOExternalUsersReport.ps1) | Reports every external (guest) user known to SharePoint Online with age, inviter and domain, and optionally removes selected ones. | Optional (-Remove) |
| [Get-SPOHubSitesReport.ps1](./Teams-SharePoint/Get-SPOHubSitesReport.ps1) | Reports every SharePoint Online hub site with its settings, join permissions, parent hub and associated sites. | No |
| [Get-SPOOneDriveInventory.ps1](./Teams-SharePoint/Get-SPOOneDriveInventory.ps1) | Inventories every OneDrive for Business site with storage, activity and ownership flags, and optionally sets quotas or grants an admin. | Optional (-SetQuota / -GrantAdmin) |
| [Get-SPOOrphanedSites.ps1](./Teams-SharePoint/Get-SPOOrphanedSites.ps1) | Finds SharePoint Online sites without a valid owner, locked sites and dormant sites, and optionally assigns a new owner. | Optional (-SetOwner) |
| [Get-SPOSiteCollectionAdminsReport.ps1](./Teams-SharePoint/Get-SPOSiteCollectionAdminsReport.ps1) | Reports the site collection administrators of every SharePoint Online site and flags sites without a human admin, external admins and admin sprawl. | No |
| [Get-SPOSitesSharingReport.ps1](./Teams-SharePoint/Get-SPOSitesSharingReport.ps1) | Reports the external sharing configuration of every SharePoint Online site and flags sites configured more openly than the tenant. | No |
| [Set-SPOSiteSharing.ps1](./Teams-SharePoint/Set-SPOSiteSharing.ps1) | Sets the external sharing capability, default link settings and domain restrictions on selected SharePoint Online sites. | Yes (`-WhatIf` supported) |

**SharePoint & OneDrive (Graph)**

| Script | Purpose | Changes? |
|---|---|---|
| [Get-OneDriveSharedItemsReport.ps1](./Teams-SharePoint/Get-OneDriveSharedItemsReport.ps1) | Reports every sharing link and direct permission on shared OneDrive files and folders per user, flagging anonymous and external access. | No |
| [Get-OneDriveUsageReport.ps1](./Teams-SharePoint/Get-OneDriveUsageReport.ps1) | Reports OneDrive storage and activity per account and flags dormant OneDrives and OneDrives of deleted users. | No |
| [Get-SPOFileTypeSummary.ps1](./Teams-SharePoint/Get-SPOFileTypeSummary.ps1) | Summarises the files stored in SharePoint sites by extension and by category (Office, PDF, media, archives, code, CAD). | No |
| [Get-SPOLargeFilesReport.ps1](./Teams-SharePoint/Get-SPOLargeFilesReport.ps1) | Finds the largest files in SharePoint sites or OneDrive accounts, optionally with the storage consumed by their version history. | No |
| [Get-SPOListsInventory.ps1](./Teams-SharePoint/Get-SPOListsInventory.ps1) | Inventories the lists and libraries of SharePoint sites with template, visibility, content type settings and optional item and column counts. | No |
| [Get-SPOSharedItemsReport.ps1](./Teams-SharePoint/Get-SPOSharedItemsReport.ps1) | Reports every sharing link and direct permission on shared files and folders in SharePoint sites, flagging anonymous and external access. | No |
| [Get-SPOSiteActivityReport.ps1](./Teams-SharePoint/Get-SPOSiteActivityReport.ps1) | Reports SharePoint activity per user (files viewed, synced, shared internally and externally, pages visited) and flags inactive users and heavy external sharers. | No |
| [Get-SPOSiteFilesInventory.ps1](./Teams-SharePoint/Get-SPOSiteFilesInventory.ps1) | Inventories every file in the document libraries of one or more SharePoint sites with size, age, editor and sharing state. | No |
| [Get-SPOSitePermissionsGraph.ps1](./Teams-SharePoint/Get-SPOSitePermissionsGraph.ps1) | Audits which applications hold Sites.Selected permissions on SharePoint sites, optionally with library-level permissions, and can grant or revoke app access. | Optional (-GrantAppAccess / -RevokePermissionId) |
| [Get-SPOSiteStorageReport.ps1](./Teams-SharePoint/Get-SPOSiteStorageReport.ps1) | Reports SharePoint Online storage consumption per site and flags dormant sites, optionally including OneDrive. | No |
| [Get-SPOSitesInventoryGraph.ps1](./Teams-SharePoint/Get-SPOSitesInventoryGraph.ps1) | Inventories every SharePoint site in the tenant through Microsoft Graph, optionally with library count and storage used. | No |

</details>

<details>
<summary><strong>Microsoft 365 tenant</strong> - 50 scripts (<a href="./M365-Tenant/README.md">folder README</a>)</summary>

**Licensing**

| Script | Purpose | Changes? |
|---|---|---|
| [Convert-M365DirectLicensesToGroup.ps1](./M365-Tenant/Convert-M365DirectLicensesToGroup.ps1) | Migrates direct license assignments of one SKU to group-based licensing without interrupting the users' service. | Optional (-Remove, -AddMissingMembers) |
| [Export-M365SkuCatalog.ps1](./M365-Tenant/Export-M365SkuCatalog.ps1) | Exports the tenant's SKU catalog (with friendly names and consumption) and the service plans inside every SKU. | No |
| [Get-M365CopilotLicenseReport.ps1](./M365-Tenant/Get-M365CopilotLicenseReport.ps1) | Reports Microsoft 365 Copilot license consumption, every licensed user and, optionally, their Copilot usage per app. | No |
| [Get-M365GroupBasedLicensingErrors.ps1](./M365-Tenant/Get-M365GroupBasedLicensingErrors.ps1) | Lists every group that assigns licenses, its processing state and the members whose group-based assignment failed. | Optional (-Reprocess) |
| [Get-M365LicenseAssignmentPaths.ps1](./M365-Tenant/Get-M365LicenseAssignmentPaths.ps1) | Reports how every licensed user received each SKU (direct, group-based or both) together with assignment errors. | No |
| [Get-M365LicenseChangesAudit.ps1](./M365-Tenant/Get-M365LicenseChangesAudit.ps1) | Reports who added or removed which licenses for which users, from the Microsoft Entra directory audit log. | No |
| [Get-M365LicenseReport.ps1](./M365-Tenant/Get-M365LicenseReport.ps1) | Reports Microsoft 365 license consumption per SKU and, optionally, licensed users whose licenses could be reclaimed. | No |
| [Get-M365ServicePlanReport.ps1](./M365-Tenant/Get-M365ServicePlanReport.ps1) | Reports the service plans inside every subscribed SKU and, per user, which plans are disabled or not provisioned. | No |
| [Get-M365SubscriptionsReport.ps1](./M365-Tenant/Get-M365SubscriptionsReport.ps1) | Reports every commercial subscription of the tenant with status, trial flag, renewal/expiry date and SKU consumption. | No |
| [Get-M365UsageLocationReport.ps1](./M365-Tenant/Get-M365UsageLocationReport.ps1) | Finds member users without a usage location, suggests one from their country attribute and optionally sets it. | Optional (-Set) |
| [Set-M365UserLicenses.ps1](./M365-Tenant/Set-M365UserLicenses.ps1) | Assigns and removes Microsoft 365 licenses for one user or a CSV of users, with pre-flight checks and a results CSV. | Yes (`-WhatIf` supported) |

**Usage & adoption reports**

| Script | Purpose | Changes? |
|---|---|---|
| [Export-M365UsageReportsBundle.ps1](./M365-Tenant/Export-M365UsageReportsBundle.ps1) | Downloads a bundle of Microsoft 365 usage detail reports (users, mailboxes, apps, OneDrive, SharePoint, Teams, groups, Viva Engage, activations) as CSV files. | No |
| [Get-M365ActivationsReport.ps1](./M365-Tenant/Get-M365ActivationsReport.ps1) | Reports Microsoft 365 Apps, Project and Visio activations per user and device platform from the Graph usage reports. | No |
| [Get-M365ActiveUsersReport.ps1](./M365-Tenant/Get-M365ActiveUsersReport.ps1) | Reports Microsoft 365 user activity per workload from the Graph usage reports and flags inactive licensed users. | No |
| [Get-M365AppsUsageReport.ps1](./M365-Tenant/Get-M365AppsUsageReport.ps1) | Reports which Microsoft 365 Apps (Outlook, Word, Excel, PowerPoint, OneNote, Teams) and platforms each user actually uses. | No |
| [Get-M365EmailActivityReport.ps1](./M365-Tenant/Get-M365EmailActivityReport.ps1) | Reports Exchange Online email activity per user (sent, received, read, meetings) from the Graph usage reports. | No |
| [Get-M365GroupsActivityReport.ps1](./M365-Tenant/Get-M365GroupsActivityReport.ps1) | Reports Microsoft 365 group activity, membership, guests, owners and storage from the Graph usage reports. | No |
| [Get-M365MailboxUsageReport.ps1](./M365-Tenant/Get-M365MailboxUsageReport.ps1) | Reports Exchange Online mailbox sizes, quotas and archive adoption from the Graph usage reports (no Exchange module needed). | No |
| [Get-M365OneDriveActivityReport.ps1](./M365-Tenant/Get-M365OneDriveActivityReport.ps1) | Reports OneDrive for Business user activity, sync adoption and external sharing from the Graph usage reports. | No |
| [Get-M365VivaEngageActivityReport.ps1](./M365-Tenant/Get-M365VivaEngageActivityReport.ps1) | Reports Viva Engage (Yammer) user activity, communities and device usage from the Graph usage reports. | No |
| [Get-M365WorkloadAdoptionSummary.ps1](./M365-Tenant/Get-M365WorkloadAdoptionSummary.ps1) | Summarises Microsoft 365 adoption per workload (active vs inactive users and the daily active-user trend) from the Graph usage reports. | No |

**Tenant configuration & health**

| Script | Purpose | Changes? |
|---|---|---|
| [Export-M365TenantSettingsSnapshot.ps1](./M365-Tenant/Export-M365TenantSettingsSnapshot.ps1) | Exports a JSON snapshot of tenant-wide Microsoft 365 settings and diffs it against a previous snapshot for change tracking. | No |
| [Get-M365DomainsReport.ps1](./M365-Tenant/Get-M365DomainsReport.ps1) | Reports every domain in the tenant with verification, authentication type, services and password policy, plus DNS and federation details. | No |
| [Get-M365MessageCenterDigest.ps1](./M365-Tenant/Get-M365MessageCenterDigest.ps1) | Exports a digest of Microsoft 365 Message Center posts (CSV and optional HTML) with action deadlines, tags, services and links. | No |
| [Get-M365OrganizationInfo.ps1](./M365-Tenant/Get-M365OrganizationInfo.ps1) | Reports the Microsoft 365 organization profile (contacts, domains, plans, directory quota, MDM authority) with hygiene findings. | No |
| [Get-M365ServiceHealthHistory.ps1](./M365-Tenant/Get-M365ServiceHealthHistory.ps1) | Exports the Microsoft 365 service health history (resolved and open issues) with per-service incident counts and mean time to resolve. | No |
| [Get-M365ServiceHealthReport.ps1](./M365-Tenant/Get-M365ServiceHealthReport.ps1) | Reports current Microsoft 365 service incidents and advisories and, optionally, Message Center changes that need action. | No |
| [Get-M365SharePointTenantSettingsGraph.ps1](./M365-Tenant/Get-M365SharePointTenantSettingsGraph.ps1) | Reports the SharePoint Online tenant settings exposed by Microsoft Graph with a security recommendation per risky setting. | No |
| [Invoke-M365MessageCenterTriage.ps1](./M365-Tenant/Invoke-M365MessageCenterTriage.ps1) | Marks Message Center posts as read/unread, archives/unarchives or favorites/unfavorites them in bulk, by ID or by filter. | Yes (`-WhatIf` supported) |
| [Set-M365ReportConcealedNames.ps1](./M365-Tenant/Set-M365ReportConcealedNames.ps1) | Shows or changes the tenant setting that conceals user, group and site names in Microsoft 365 usage reports. | Optional (-Enable / -Disable) |
| [Set-M365SharePointSharingLevel.ps1](./M365-Tenant/Set-M365SharePointSharingLevel.ps1) | Changes the tenant-wide SharePoint and OneDrive sharing settings through Microsoft Graph, showing the before/after diff first. | Yes (`-WhatIf` supported) |

**Microsoft 365 Groups governance**

| Script | Purpose | Changes? |
|---|---|---|
| [Get-M365DeletedGroupsReport.ps1](./M365-Tenant/Get-M365DeletedGroupsReport.ps1) | Lists soft-deleted Microsoft 365 groups with their remaining recovery window and can restore or purge them. | Optional (-Restore / -PermanentlyDelete) |
| [Get-M365GroupCreationSettings.ps1](./M365-Tenant/Get-M365GroupCreationSettings.ps1) | Reports the tenant-wide Microsoft 365 group settings (Group.Unified) with defaults and recommendations. | No |
| [Get-M365GroupExpirationReport.ps1](./M365-Tenant/Get-M365GroupExpirationReport.ps1) | Reports the Microsoft 365 group expiration policy and the groups that expire soon, with optional renewal or policy enrolment. | Optional (-Renew / -AddToPolicy) |
| [Get-M365GroupGuestSettings.ps1](./M365-Tenant/Get-M365GroupGuestSettings.ps1) | Reports the effective "guests can be added" setting of every Microsoft 365 group and can block or allow guests per group. | Optional (-BlockGuests / -AllowGuests) |
| [Get-M365GroupNamingPolicyCompliance.ps1](./M365-Tenant/Get-M365GroupNamingPolicyCompliance.ps1) | Checks every Microsoft 365 group name against the tenant naming policy (prefix / suffix pattern and blocked words). | No |
| [Get-M365GroupSensitivityLabelReport.ps1](./M365-Tenant/Get-M365GroupSensitivityLabelReport.ps1) | Reports the sensitivity label of every Microsoft 365 group and can apply a label to groups that have none. | Optional (-ApplyLabelId) |
| [Get-M365GroupsReport.ps1](./M365-Tenant/Get-M365GroupsReport.ps1) | Inventories Microsoft 365 groups with lifecycle, ownership, guest, Teams and sensitivity-label details. | No |
| [Set-M365GroupCreationRestriction.ps1](./M365-Tenant/Set-M365GroupCreationRestriction.ps1) | Restricts Microsoft 365 group creation to the members of one group (or re-opens it to everyone) via the Group.Unified settings. | Yes (`-WhatIf` supported) |
| [Set-M365GroupOwners.ps1](./M365-Tenant/Set-M365GroupOwners.ps1) | Adds or removes Microsoft 365 group owners in bulk from a CSV or from -GroupName / -Owners, with last-owner protection. | Yes (`-WhatIf` supported) |

**User lifecycle & tenant hygiene**

| Script | Purpose | Changes? |
|---|---|---|
| [Get-M365AdminContactsAudit.ps1](./M365-Tenant/Get-M365AdminContactsAudit.ps1) | Audits who receives tenant notifications and who holds the keys: contact addresses, Global Administrators and emergency access accounts. | No |
| [Get-M365DirectorySizeSummary.ps1](./M365-Tenant/Get-M365DirectorySizeSummary.ps1) | Quick directory size summary: users, groups, devices, applications, roles, administrative units and the directory quota. | No |
| [Get-M365ExternalCollaborationSummary.ps1](./M365-Tenant/Get-M365ExternalCollaborationSummary.ps1) | One-page executive summary of external collaboration: guests, their domains, groups and teams with guests and the tenant sharing settings. | No |
| [Get-M365TenantHealthScorecard.ps1](./M365-Tenant/Get-M365TenantHealthScorecard.ps1) | One-page tenant health scorecard: identity, security, device, license and service metrics rated Green, Amber or Red. | No |
| [Get-M365UserCrossWorkloadActivity.ps1](./M365-Tenant/Get-M365UserCrossWorkloadActivity.ps1) | Finds truly inactive users by combining Entra sign-in activity with the last Exchange, OneDrive, SharePoint, Teams and Viva Engage activity. | No |
| [Invoke-M365UserOffboarding.ps1](./M365-Tenant/Invoke-M365UserOffboarding.ps1) | Offboards leavers end to end: disables the account, revokes sessions, resets the password, removes groups, manager, MFA methods and licenses. | Yes (`-WhatIf` supported) |
| [Invoke-M365UserOnboarding.ps1](./M365-Tenant/Invoke-M365UserOnboarding.ps1) | Onboards new hires end to end: creates the account, sets manager, licenses, groups and teams and optionally sends a welcome mail. | Yes (`-WhatIf` supported) |
| [New-M365GraphAppRegistrationForAutomation.ps1](./M365-Tenant/New-M365GraphAppRegistrationForAutomation.ps1) | Creates an app registration with certificate credential and Graph application permissions for unattended scripts. | Yes (`-WhatIf` supported) |
| [Send-M365ReportByEmail.ps1](./M365-Tenant/Send-M365ReportByEmail.ps1) | Sends a report by e-mail through Microsoft Graph, with CSV or HTML attachments and an optional inline table built from a CSV. | Yes (`-WhatIf` supported) |
| [Test-M365GraphPermissions.ps1](./M365-Tenant/Test-M365GraphPermissions.ps1) | Diagnoses the current Microsoft Graph session: account, scopes, missing permissions for a script, directory roles and probe calls. | No |

</details>

<details>
<summary><strong>Tools</strong> - 1 scripts (<a href="./Tools/README.md">folder README</a>)</summary>

**Tools**

| Script | Purpose | Changes? |
|---|---|---|
| [Install-Prerequisites.ps1](./Tools/Install-Prerequisites.ps1) | Installs or updates the PowerShell modules required by the scripts in this repository. | Local machine only |

</details>

## Conventions used in every script

* Comment-based help with `.SYNOPSIS`, `.DESCRIPTION`, `.PARAMETER`, `.EXAMPLE`, `.NOTES` (permissions, modules, category, whether it changes anything, caveats) and `.LINK`.
* `[CmdletBinding()]`, typed and validated parameters, `-Verbose` output for the details, `Write-Progress` for long loops.
* `-OutputPath` (timestamped CSV in `.\Reports\` by default) and `-PassThru` on every report.
* Graph paging via `@odata.nextLink`, `$select` to keep payloads small, server-side `$filter` where the API supports it.
* Per-item failures are logged as warnings and never abort a whole run.
* Linted with [PSScriptAnalyzer](https://github.com/PowerShell/PSScriptAnalyzer) in CI using the settings in
  [`PSScriptAnalyzerSettings.psd1`](./PSScriptAnalyzerSettings.psd1).

## Contributing

Issues and pull requests are welcome - see [CONTRIBUTING.md](./CONTRIBUTING.md) for the conventions.
Release notes live in [CHANGELOG.md](./CHANGELOG.md).

## Disclaimer

These scripts are provided **as is**, without warranty of any kind, under the [MIT License](./LICENSE).
Always test in a non-production tenant first and review what a script will do with `-WhatIf` before running any
switch that changes your tenant. They are personal, community contributions and are not official Microsoft tools.

## About the author

**Omer Eltayeb** - Senior Support Engineer for Microsoft Intune, former Microsoft Identity & Security Cloud Solution
Architect, and long-time community trainer (Intune, Microsoft 365 and Azure certifications) for IT communities across
Africa and the Middle East.

* Blog: [www.oeltayeb.com](https://www.oeltayeb.com) - Intune, Entra ID, Defender and Exchange Online deep dives
* LinkedIn: [linkedin.com/in/omer-eltayeb](https://www.linkedin.com/in/omer-eltayeb)
* GitHub: [@omer-eltayeb](https://github.com/omer-eltayeb)

If a script saved you time, a star on the repository is appreciated.
