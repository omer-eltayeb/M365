# Microsoft Entra ID scripts

Identity reporting and lifecycle scripts for Microsoft Entra ID: users and authentication methods, groups and devices, sign-in and audit log analysis, Identity Protection, applications and consent, privileged roles, PIM, governance and tenant-wide security settings.

**52 scripts.** Module(s): Microsoft Graph PowerShell SDK (`Microsoft.Graph.Authentication`).

Every script has full comment-based help (`Get-Help .\<Script>.ps1 -Full`), writes a timestamped CSV to `.\Reports\` by default (`-OutputPath` to choose, `-PassThru` to keep the objects) and is read-only unless the **Changes anything?** column says otherwise - those scripts support `-WhatIf` / `-Confirm`.

## Contents

- [Users & authentication](#users--authentication) (12)
- [Groups](#groups) (8)
- [Devices](#devices) (2)
- [Sign-ins, audit & risk](#sign-ins-audit--risk) (9)
- [Applications & consent](#applications--consent) (9)
- [Roles, governance & tenant policy](#roles-governance--tenant-policy) (12)

## Users & authentication

| Script | What it does | Permissions / roles | Changes anything? |
|---|---|---|---|
| [Disable-EntraUserOffboarding.ps1](./Disable-EntraUserOffboarding.ps1) | Offboards user identities: disables the account, revokes sessions, resets the password, removes groups, manager, licenses and MFA methods. | User.ReadWrite.All, Group.ReadWrite.All (delegated); UserAuthenticationMethod.ReadWrite.All only with -RemoveAuthenticationMethods. User Administrator role. | Yes (`-WhatIf` supported) |
| [Get-EntraDeletedUsers.ps1](./Get-EntraDeletedUsers.ps1) | Reports soft-deleted users with the days left before permanent deletion, and optionally restores or permanently deletes them. | User.Read.All (delegated) for the report; User.ReadWrite.All is added with -Restore / -PermanentlyDelete. The least-privileged alternative for both actions is User.DeleteRestore.All; the signed-in admin needs the User Administrator role. | Optional (-Restore / -PermanentlyDelete) |
| [Get-EntraInactiveUsers.ps1](./Get-EntraInactiveUsers.ps1) | Reports member accounts with no sign-in for a number of days (or ever) and optionally disables them or revokes their sessions. | User.Read.All, AuditLog.Read.All (delegated); User.ReadWrite.All only with -DisableAccounts / -RevokeSessions (User Administrator role). | Optional (-DisableAccounts / -RevokeSessions) |
| [Get-EntraMFARegistrationReport.ps1](./Get-EntraMFARegistrationReport.ps1) | Reports the MFA, passwordless and SSPR registration posture of users in Microsoft Entra ID. | AuditLog.Read.All, UserAuthenticationMethod.Read.All (delegated) plus the Reports Reader, Security Reader or Global Reader role. | No |
| [Get-EntraPasswordExpiryReport.ps1](./Get-EntraPasswordExpiryReport.ps1) | Reports when cloud user passwords expire, based on the domain password validity period and each user's last password change. | User.Read.All, Domain.Read.All (delegated) | No |
| [Get-EntraStaleGuestUsers.ps1](./Get-EntraStaleGuestUsers.ps1) | Finds guest accounts that never signed in, have been inactive for a number of days, or never accepted their invitation. | User.Read.All and AuditLog.Read.All for the report. User.ReadWrite.All is requested only with -DisableAccounts or -RemoveAccounts (the signed-in user also needs the User Administrator role). | Optional (-DisableAccounts / -RemoveAccounts) |
| [Get-EntraUserAuthenticationMethods.ps1](./Get-EntraUserAuthenticationMethods.ps1) | Reports the registered authentication methods (Authenticator, phone, FIDO2, Windows Hello, TAP, etc.) of users and flags password-only accounts. | UserAuthenticationMethod.Read.All, User.Read.All (delegated); GroupMember.Read.All with -GroupName. Authentication Administrator role. | No |
| [Get-EntraUserInventory.ps1](./Get-EntraUserInventory.ps1) | Exports an inventory of Microsoft Entra ID users with licence count, manager, last sign-in and password age. | User.Read.All, AuditLog.Read.All (delegated). AuditLog.Read.All is only used for the sign-in columns. | No |
| [New-EntraTemporaryAccessPass.ps1](./New-EntraTemporaryAccessPass.ps1) | Issues Temporary Access Passes (TAP) for one or more users, within the limits of the tenant's TAP policy. | UserAuthenticationMethod.ReadWrite.All, Policy.Read.All (delegated). Authentication Administrator role; Privileged Authentication Administrator for users that hold admin roles. | Yes (`-WhatIf` supported) |
| [New-EntraUsersFromCsv.ps1](./New-EntraUsersFromCsv.ps1) | Creates Microsoft Entra ID users in bulk from a CSV file, with optional manager, group memberships and license assignment. | User.ReadWrite.All (delegated); Group.ReadWrite.All when Groups is used; Organization.Read.All when LicenseSku is used (User Administrator role). | Yes (`-WhatIf` supported) |
| [Reset-EntraUserMfa.ps1](./Reset-EntraUserMfa.ps1) | Removes all registered MFA / passwordless methods of a user so they must re-register, optionally issuing a Temporary Access Pass. | UserAuthenticationMethod.ReadWrite.All (delegated). Authentication Administrator role; Privileged Authentication Administrator to reset the methods of users that hold admin roles. | Yes (`-WhatIf` supported) |
| [Set-EntraUserAttributesFromCsv.ps1](./Set-EntraUserAttributesFromCsv.ps1) | Bulk-updates user profile attributes (job title, department, address, phones, employee data and more) from a CSV file. | User.ReadWrite.All (delegated); the signed-in admin needs the User Administrator role. | Yes (`-WhatIf` supported) |

## Groups

| Script | What it does | Permissions / roles | Changes anything? |
|---|---|---|---|
| [Add-EntraGroupMembersFromCsv.ps1](./Add-EntraGroupMembersFromCsv.ps1) | Adds or removes Microsoft Entra ID group members in bulk from a CSV file. | GroupMember.ReadWrite.All, User.Read.All, Group.Read.All (delegated) | Yes (`-WhatIf` supported) |
| [Compare-EntraGroupMembership.ps1](./Compare-EntraGroupMembership.ps1) | Compares the membership of two Microsoft Entra ID groups (or a group and a CSV list of UPNs) and can synchronise them. | GroupMember.Read.All; GroupMember.ReadWrite.All with -Sync (delegated) | Optional (-Sync) |
| [Export-EntraGroupMembership.ps1](./Export-EntraGroupMembership.ps1) | Exports the members (direct or transitive) or the owners of one, several or all Microsoft Entra ID groups to CSV. | Group.Read.All, GroupMember.Read.All, User.Read.All (delegated) | No |
| [Get-EntraDynamicGroupRules.ps1](./Get-EntraDynamicGroupRules.ps1) | Reports every dynamic membership group in Microsoft Entra ID with its rule, processing state and last evaluation status. | Group.Read.All, GroupMember.Read.All, User.Read.All (delegated) | No |
| [Get-EntraGroupInventory.ps1](./Get-EntraGroupInventory.ps1) | Inventories every Microsoft Entra ID group with its resolved type, dynamic rule, Teams status and optional member/owner counts. | Group.Read.All (delegated). GroupMember.Read.All is requested only with -IncludeCounts. | No |
| [Get-EntraGroupsWithGuests.ps1](./Get-EntraGroupsWithGuests.ps1) | Reports Microsoft Entra ID groups (and Teams) that contain guest users, with guest counts, guest domains and owners. | Group.Read.All, GroupMember.Read.All, User.Read.All (delegated) | No |
| [Get-EntraNestedGroupsReport.ps1](./Get-EntraNestedGroupsReport.ps1) | Reports nested group membership in Microsoft Entra ID (groups that contain other groups), including circular references. | Group.Read.All, GroupMember.Read.All (delegated) | No |
| [Get-EntraOwnerlessAndEmptyGroups.ps1](./Get-EntraOwnerlessAndEmptyGroups.ps1) | Finds groups without owners and/or without members, and can assign an owner to the ownerless ones. | Group.Read.All and GroupMember.Read.All for the report. Group.ReadWrite.All and User.ReadBasic.All are requested only with -AddOwner (the signed-in user also needs the Groups Administrator role). | Optional (-AddOwner) |

## Devices

| Script | What it does | Permissions / roles | Changes anything? |
|---|---|---|---|
| [Get-EntraDeviceInventory.ps1](./Get-EntraDeviceInventory.ps1) | Exports an inventory of the device objects in Microsoft Entra ID with join type, management, compliance and owner details. | Device.Read.All (delegated) | No |
| [Get-EntraStaleDevices.ps1](./Get-EntraStaleDevices.ps1) | Finds Microsoft Entra ID devices that have not signed in for a number of days and can disable or remove them. | Device.Read.All; Device.ReadWrite.All with -DisableDevices / -RemoveDevices (delegated) | Optional (-DisableDevices / -RemoveDevices) |

## Sign-ins, audit & risk

| Script | What it does | Permissions / roles | Changes anything? |
|---|---|---|---|
| [Get-EntraConditionalAccessInsights.ps1](./Get-EntraConditionalAccessInsights.ps1) | Aggregates how every Conditional Access policy was evaluated in recent sign-ins, including report-only impact and uncovered sign-ins. | AuditLog.Read.All, Policy.Read.All (delegated). | No |
| [Get-EntraDirectoryAuditLogs.ps1](./Get-EntraDirectoryAuditLogs.ps1) | Exports Microsoft Entra directory audit events (who changed what, when) with initiator, targets and modified properties. | AuditLog.Read.All (delegated). | No |
| [Get-EntraFailedSignInSummary.ps1](./Get-EntraFailedSignInSummary.ps1) | Summarises failed Microsoft Entra sign-ins by error code, user, application, country and IP, with a password-spray indicator. | AuditLog.Read.All (delegated). | No |
| [Get-EntraLegacyAuthSignIns.ps1](./Get-EntraLegacyAuthSignIns.ps1) | Finds sign-ins that used legacy authentication protocols (POP3, IMAP4, SMTP, ActiveSync, EWS, MAPI, ...) and whether they succeeded. | AuditLog.Read.All (delegated). | No |
| [Get-EntraProvisioningLogs.ps1](./Get-EntraProvisioningLogs.ps1) | Exports Microsoft Entra provisioning logs (SCIM / HR-driven user provisioning to SaaS apps) with status, errors and changed attributes. | AuditLog.Read.All (delegated). | No |
| [Get-EntraRiskyUsersAndDetections.ps1](./Get-EntraRiskyUsersAndDetections.ps1) | Reports Microsoft Entra ID Protection risky users, risk detections and (optionally) risky service principals; can confirm or dismiss a user. | IdentityRiskyUser.Read.All, IdentityRiskEvent.Read.All (delegated); IdentityRiskyUser.ReadWrite.All with -ConfirmCompromised/-Dismiss; IdentityRiskyServicePrincipal.Read.All with -IncludeServicePrincipals. | Optional (-ConfirmCompromised / -Dismiss) |
| [Get-EntraSignInLogs.ps1](./Get-EntraSignInLogs.ps1) | Exports Microsoft Entra interactive (and optionally non-interactive) sign-in events with Conditional Access and device details. | AuditLog.Read.All, Directory.Read.All (delegated). | No |
| [Get-EntraSignInsByLocation.ps1](./Get-EntraSignInsByLocation.ps1) | Groups Microsoft Entra sign-ins per user, country, city and IP address and flags unexpected countries and atypical travel. | AuditLog.Read.All (delegated). | No |
| [Test-EntraBreakGlassAccounts.ps1](./Test-EntraBreakGlassAccounts.ps1) | Validates Microsoft Entra emergency access (break-glass) accounts against Microsoft's recommended configuration. | User.Read.All, Policy.Read.All, RoleManagement.Read.Directory, UserAuthenticationMethod.Read.All, AuditLog.Read.All, GroupMember.Read.All (delegated). | No |

## Applications & consent

| Script | What it does | Permissions / roles | Changes anything? |
|---|---|---|---|
| [Get-EntraAppCredentialExpiry.ps1](./Get-EntraAppCredentialExpiry.ps1) | Reports app registration client secrets and certificates that are expired or expiring soon. | Application.Read.All (delegated); User.Read.All is added with -IncludeOwners so owner names can be read. Any user with the Application Administrator, Cloud Application Administrator, Global Reader or Security Reader role can run it. | No |
| [Get-EntraAppOwnersReport.ps1](./Get-EntraAppOwnersReport.ps1) | Reports the owners of every app registration and enterprise application and flags apps without a working owner. | Application.Read.All, User.Read.All (delegated); Application.ReadWrite.All is added with -AddOwner. | Optional (-AddOwner) |
| [Get-EntraAppPermissionsReport.ps1](./Get-EntraAppPermissionsReport.ps1) | Reports every delegated and application permission granted to enterprise applications and flags high-privilege ones. | Application.Read.All, Directory.Read.All, DelegatedPermissionGrant.Read.All (delegated) | No |
| [Get-EntraAppRegistrationSecurityAudit.ps1](./Get-EntraAppRegistrationSecurityAudit.ps1) | Audits every app registration for risky authentication settings and credential hygiene and reports one row per finding. | Application.Read.All (delegated) | No |
| [Get-EntraAppRoleAssignmentsReport.ps1](./Get-EntraAppRoleAssignmentsReport.ps1) | Reports which users, groups and service principals are assigned to each enterprise application and in which role. | Application.Read.All, Directory.Read.All (delegated); GroupMember.Read.All is added with -ExpandGroups. | No |
| [Get-EntraConsentSettingsAndRequests.ps1](./Get-EntraConsentSettingsAndRequests.ps1) | Reviews the tenant's user consent, app registration and admin consent workflow settings and exports pending consent requests. | Policy.Read.All, ConsentRequest.Read.All, User.Read.All (delegated) | No |
| [Get-EntraSamlCertificateExpiry.ps1](./Get-EntraSamlCertificateExpiry.ps1) | Reports the token-signing certificates of SAML enterprise applications that are expired or expiring soon. | Application.Read.All (delegated) | No |
| [Get-EntraServicePrincipalInventory.ps1](./Get-EntraServicePrincipalInventory.ps1) | Inventories every service principal in the tenant and classifies it by kind, origin and SSO configuration. | Application.Read.All, Directory.Read.All (delegated); AuditLog.Read.All is added with -IncludeSignInActivity. | No |
| [Get-EntraUnusedEnterpriseApps.ps1](./Get-EntraUnusedEnterpriseApps.ps1) | Finds enterprise applications that have not signed in for a given number of days (or never) and can optionally disable them. | AuditLog.Read.All, Application.Read.All, Directory.Read.All (delegated); Application.ReadWrite.All is added with -DisableApps. | Optional (-DisableApps) |

## Roles, governance & tenant policy

| Script | What it does | Permissions / roles | Changes anything? |
|---|---|---|---|
| [Export-EntraConditionalAccessPolicies.ps1](./Export-EntraConditionalAccessPolicies.ps1) | Backs up every Conditional Access policy to JSON and builds a human-readable CSV summary. | Policy.Read.All, Directory.Read.All, Application.Read.All (delegated), for example as Security Reader, Global Reader or Conditional Access Administrator. | No |
| [Export-EntraPimRoleSettings.ps1](./Export-EntraPimRoleSettings.ps1) | Exports the Privileged Identity Management (PIM) role settings (activation, assignment and approval rules) of every Entra directory role. | RoleManagementPolicy.Read.Directory, RoleManagement.Read.Directory (delegated). | No |
| [Get-EntraAccessReviewsStatus.ps1](./Get-EntraAccessReviewsStatus.ps1) | Reports the status of Microsoft Entra access reviews: definitions, their instances, pending decisions and overdue reviews. | AccessReview.Read.All (delegated); Global Reader, Security Reader or Identity Governance Administrator. | No |
| [Get-EntraAdministrativeUnits.ps1](./Get-EntraAdministrativeUnits.ps1) | Reports the Microsoft Entra administrative units with their membership counts, dynamic rules and scoped administrators. | AdministrativeUnit.Read.All, RoleManagement.Read.Directory, Directory.Read.All (delegated). | No |
| [Get-EntraCrossTenantAccessPolicy.ps1](./Get-EntraCrossTenantAccessPolicy.ps1) | Reports the Microsoft Entra cross-tenant access policy: default settings and every partner-specific configuration. | Policy.Read.All, CrossTenantInformation.ReadBasic.All (delegated); Global Reader or Security Reader. | No |
| [Get-EntraCustomRoleDefinitions.ps1](./Get-EntraCustomRoleDefinitions.ps1) | Documents the custom Microsoft Entra directory roles: permissions, state and how many assignments each role has. | RoleManagement.Read.Directory (delegated); Global Reader or Privileged Role Administrator is sufficient. | No |
| [Get-EntraEntitlementManagementReport.ps1](./Get-EntraEntitlementManagementReport.ps1) | Reports Microsoft Entra entitlement management: access packages, their policies and who currently holds an assignment. | EntitlementManagement.Read.All (delegated); Global Reader or Identity Governance Administrator. | No |
| [Get-EntraPimActivationHistory.ps1](./Get-EntraPimActivationHistory.ps1) | Reports Privileged Identity Management (PIM) activation and assignment requests for Microsoft Entra directory roles. | RoleAssignmentSchedule.Read.Directory, RoleManagement.Read.Directory, Directory.Read.All (delegated). | No |
| [Get-EntraPrivilegedRoleMembers.ps1](./Get-EntraPrivilegedRoleMembers.ps1) | Reports who holds Microsoft Entra directory roles, including active assignments and PIM-eligible assignments. | RoleManagement.Read.Directory, Directory.Read.All; RoleEligibilitySchedule.Read.Directory is added when -IncludeEligible is on (default). A reader role such as Global Reader or Security Reader is sufficient. | No |
| [Get-EntraSyncStatusAndErrors.ps1](./Get-EntraSyncStatusAndErrors.ps1) | Checks the Microsoft Entra Connect / Cloud Sync health: last sync times, enabled sync features and objects with provisioning errors. | Organization.Read.All, OnPremDirectorySynchronization.Read.All, User.Read.All, Group.Read.All, OrgContact.Read.All (delegated); Global Reader or Hybrid Identity Administrator. | No |
| [Get-EntraTenantSecuritySettings.ps1](./Get-EntraTenantSecuritySettings.ps1) | Takes a snapshot of the tenant-wide Microsoft Entra security settings and highlights settings that deserve attention. | Policy.Read.All, Directory.Read.All (delegated); Global Reader or Security Reader is sufficient. | No |
| [New-EntraGuestInvitation.ps1](./New-EntraGuestInvitation.ps1) | Invites external users as Microsoft Entra B2B guests, in bulk from a list of addresses or a CSV file, and adds them to groups. | User.Invite.All, User.Read.All, plus GroupMember.ReadWrite.All when groups are requested (delegated); Guest Inviter role. | Yes (`-WhatIf` supported) |

## Quick start

```powershell
# Disable-EntraUserOffboarding.ps1
.\Disable-EntraUserOffboarding.ps1 -InputCsv C:\Temp\leavers.csv -RemoveLicenses -RemoveAuthenticationMethods -Skip ClearManager -Confirm:$false

# Add-EntraGroupMembersFromCsv.ps1
.\Add-EntraGroupMembersFromCsv.ps1 -CsvPath .\leavers.csv -Remove -Confirm:$false -PassThru | Where-Object { $_.Result -eq 'Failed' }

# Get-EntraDeviceInventory.ps1
.\Get-EntraDeviceInventory.ps1 -JoinType Registered -OperatingSystem Windows -OnlyUnmanaged -PassThru | Sort-Object -Property LastSignInDateTime

# Get-EntraConditionalAccessInsights.ps1
.\Get-EntraConditionalAccessInsights.ps1 -DaysBack 30 -MaxRecords 200000 -PassThru | Where-Object { $_.ReportOnlyFailure -gt 0 }
```

## Notes

- Sign-in activity, the registration report and 30-day sign-in log retention require **Microsoft Entra ID P1**; PIM, Identity Protection, access reviews and entitlement management require **P2** / Microsoft Entra ID Governance.
- Scripts that change identities default to report-only; the action switches (`-DisableAccounts`, `-RemoveDevices`, ...) support `-WhatIf` and prompt per object.
- Advanced queries (`$count`, `$search`, some `$filter` clauses) send the `ConsistencyLevel: eventual` header automatically.

---

Back to the [repository overview](../README.md).
