# Microsoft 365 tenant scripts

Tenant-wide administration: licensing (assignment, group-based licensing, service plans, subscriptions, Copilot), usage and adoption reports, tenant configuration snapshots and settings, service health and Message Center, Microsoft 365 Groups governance, user onboarding/offboarding and tenant hygiene.

**50 scripts.** Module(s): Microsoft Graph PowerShell SDK (`Microsoft.Graph.Authentication`); a few lifecycle scripts optionally use `ExchangeOnlineManagement` when it is installed.

Every script has full comment-based help (`Get-Help .\<Script>.ps1 -Full`), writes a timestamped CSV to `.\Reports\` by default (`-OutputPath` to choose, `-PassThru` to keep the objects) and is read-only unless the **Changes anything?** column says otherwise - those scripts support `-WhatIf` / `-Confirm`.

## Contents

- [Licensing](#licensing) (11)
- [Usage & adoption reports](#usage--adoption-reports) (10)
- [Tenant configuration & health](#tenant-configuration--health) (10)
- [Microsoft 365 Groups governance](#microsoft-365-groups-governance) (9)
- [User lifecycle & tenant hygiene](#user-lifecycle--tenant-hygiene) (10)

## Licensing

| Script | What it does | Permissions / roles | Changes anything? |
|---|---|---|---|
| [Convert-M365DirectLicensesToGroup.ps1](./Convert-M365DirectLicensesToGroup.ps1) | Migrates direct license assignments of one SKU to group-based licensing without interrupting the users' service. | User.Read.All, Group.Read.All, Organization.Read.All (delegated) for the report; -Remove adds User.ReadWrite.All, -AddMissingMembers adds Group.ReadWrite.All. License Administrator plus Groups Administrator (or owner of the group). | Optional (-Remove, -AddMissingMembers) |
| [Export-M365SkuCatalog.ps1](./Export-M365SkuCatalog.ps1) | Exports the tenant's SKU catalog (with friendly names and consumption) and the service plans inside every SKU. | Organization.Read.All (delegated); Global Reader, License Administrator or Billing Administrator. | No |
| [Get-M365CopilotLicenseReport.ps1](./Get-M365CopilotLicenseReport.ps1) | Reports Microsoft 365 Copilot license consumption, every licensed user and, optionally, their Copilot usage per app. | Organization.Read.All, User.Read.All, AuditLog.Read.All (delegated); -IncludeUsage adds Reports.Read.All. Global Reader. | No |
| [Get-M365GroupBasedLicensingErrors.ps1](./Get-M365GroupBasedLicensingErrors.ps1) | Lists every group that assigns licenses, its processing state and the members whose group-based assignment failed. | Group.Read.All, User.Read.All, Organization.Read.All (delegated); -Reprocess adds User.ReadWrite.All. Global Reader or License Administrator can report; -Reprocess needs License Administrator or higher. | Optional (-Reprocess) |
| [Get-M365LicenseAssignmentPaths.ps1](./Get-M365LicenseAssignmentPaths.ps1) | Reports how every licensed user received each SKU (direct, group-based or both) together with assignment errors. | User.Read.All, Group.Read.All, Organization.Read.All (delegated); Global Reader or License Administrator. | No |
| [Get-M365LicenseChangesAudit.ps1](./Get-M365LicenseChangesAudit.ps1) | Reports who added or removed which licenses for which users, from the Microsoft Entra directory audit log. | AuditLog.Read.All, Organization.Read.All (delegated); some tenants also need Directory.Read.All for directoryAudits. Global Reader, Reports Reader or Security Reader can run it. | No |
| [Get-M365LicenseReport.ps1](./Get-M365LicenseReport.ps1) | Reports Microsoft 365 license consumption per SKU and, optionally, licensed users whose licenses could be reclaimed. | Organization.Read.All, User.Read.All (delegated). -IncludeUsers additionally requests AuditLog.Read.All for signInActivity; Global Reader or License Administrator (plus Reports Reader for sign-in data) can run it. | No |
| [Get-M365ServicePlanReport.ps1](./Get-M365ServicePlanReport.ps1) | Reports the service plans inside every subscribed SKU and, per user, which plans are disabled or not provisioned. | Organization.Read.All, User.Read.All (delegated); Global Reader or License Administrator. | No |
| [Get-M365SubscriptionsReport.ps1](./Get-M365SubscriptionsReport.ps1) | Reports every commercial subscription of the tenant with status, trial flag, renewal/expiry date and SKU consumption. | Organization.Read.All (delegated; Directory.Read.All also works). Global Reader or Billing Administrator. | No |
| [Get-M365UsageLocationReport.ps1](./Get-M365UsageLocationReport.ps1) | Finds member users without a usage location, suggests one from their country attribute and optionally sets it. | User.Read.All (delegated); -Set adds User.ReadWrite.All. Global Reader can report; User Administrator can set. | Optional (-Set) |
| [Set-M365UserLicenses.ps1](./Set-M365UserLicenses.ps1) | Assigns and removes Microsoft 365 licenses for one user or a CSV of users, with pre-flight checks and a results CSV. | User.ReadWrite.All, Organization.Read.All (delegated); License Administrator or User Administrator role. | Yes (`-WhatIf` supported) |

## Usage & adoption reports

| Script | What it does | Permissions / roles | Changes anything? |
|---|---|---|---|
| [Export-M365UsageReportsBundle.ps1](./Export-M365UsageReportsBundle.ps1) | Downloads a bundle of Microsoft 365 usage detail reports (users, mailboxes, apps, OneDrive, SharePoint, Teams, groups, Viva Engage, activations) as CSV files. | Reports.Read.All (delegated); plus ReportSettings.Read.All with -IncludeSettingsCheck; Reports Reader or Global Reader role | No |
| [Get-M365ActivationsReport.ps1](./Get-M365ActivationsReport.ps1) | Reports Microsoft 365 Apps, Project and Visio activations per user and device platform from the Graph usage reports. | Reports.Read.All (delegated); Reports Reader or Global Reader role | No |
| [Get-M365ActiveUsersReport.ps1](./Get-M365ActiveUsersReport.ps1) | Reports Microsoft 365 user activity per workload from the Graph usage reports and flags inactive licensed users. | Reports.Read.All (delegated); Reports Reader or Global Reader role | No |
| [Get-M365AppsUsageReport.ps1](./Get-M365AppsUsageReport.ps1) | Reports which Microsoft 365 Apps (Outlook, Word, Excel, PowerPoint, OneNote, Teams) and platforms each user actually uses. | Reports.Read.All (delegated); Reports Reader or Global Reader role | No |
| [Get-M365EmailActivityReport.ps1](./Get-M365EmailActivityReport.ps1) | Reports Exchange Online email activity per user (sent, received, read, meetings) from the Graph usage reports. | Reports.Read.All (delegated); Reports Reader or Global Reader role | No |
| [Get-M365GroupsActivityReport.ps1](./Get-M365GroupsActivityReport.ps1) | Reports Microsoft 365 group activity, membership, guests, owners and storage from the Graph usage reports. | Reports.Read.All (delegated); Reports Reader or Global Reader role | No |
| [Get-M365MailboxUsageReport.ps1](./Get-M365MailboxUsageReport.ps1) | Reports Exchange Online mailbox sizes, quotas and archive adoption from the Graph usage reports (no Exchange module needed). | Reports.Read.All (delegated); Reports Reader or Global Reader role | No |
| [Get-M365OneDriveActivityReport.ps1](./Get-M365OneDriveActivityReport.ps1) | Reports OneDrive for Business user activity, sync adoption and external sharing from the Graph usage reports. | Reports.Read.All (delegated); Reports Reader or Global Reader role | No |
| [Get-M365VivaEngageActivityReport.ps1](./Get-M365VivaEngageActivityReport.ps1) | Reports Viva Engage (Yammer) user activity, communities and device usage from the Graph usage reports. | Reports.Read.All (delegated); Reports Reader or Global Reader role | No |
| [Get-M365WorkloadAdoptionSummary.ps1](./Get-M365WorkloadAdoptionSummary.ps1) | Summarises Microsoft 365 adoption per workload (active vs inactive users and the daily active-user trend) from the Graph usage reports. | Reports.Read.All (delegated); Reports Reader or Global Reader role | No |

## Tenant configuration & health

| Script | What it does | Permissions / roles | Changes anything? |
|---|---|---|---|
| [Export-M365TenantSettingsSnapshot.ps1](./Export-M365TenantSettingsSnapshot.ps1) | Exports a JSON snapshot of tenant-wide Microsoft 365 settings and diffs it against a previous snapshot for change tracking. | Organization.Read.All, SharePointTenantSettings.Read.All, ReportSettings.Read.All, Policy.Read.All, Directory.Read.All, Domain.Read.All, OnPremDirectorySynchronization.Read.All (delegated); OrgSettings-Microsoft365Install.Read.All only with -IncludeBeta. Global Reader can read every area. | No |
| [Get-M365DomainsReport.ps1](./Get-M365DomainsReport.ps1) | Reports every domain in the tenant with verification, authentication type, services and password policy, plus DNS and federation details. | Domain.Read.All (delegated). Global Reader or Domain Name Administrator can read domains and federation settings. | No |
| [Get-M365MessageCenterDigest.ps1](./Get-M365MessageCenterDigest.ps1) | Exports a digest of Microsoft 365 Message Center posts (CSV and optional HTML) with action deadlines, tags, services and links. | ServiceMessage.Read.All (delegated). The signed-in user needs a role that can read the Message Center, for example Message Center Reader, Service Support Administrator or Global Reader. | No |
| [Get-M365OrganizationInfo.ps1](./Get-M365OrganizationInfo.ps1) | Reports the Microsoft 365 organization profile (contacts, domains, plans, directory quota, MDM authority) with hygiene findings. | Organization.Read.All (delegated); User.Read.All only with -ResolveNotificationMails. Any directory reader role (for example Global Reader or Directory Readers) can read /organization. | No |
| [Get-M365ServiceHealthHistory.ps1](./Get-M365ServiceHealthHistory.ps1) | Exports the Microsoft 365 service health history (resolved and open issues) with per-service incident counts and mean time to resolve. | ServiceHealth.Read.All (delegated). The signed-in user needs a role that can see service health, for example Service Support Administrator, Global Reader or any service-specific administrator role. | No |
| [Get-M365ServiceHealthReport.ps1](./Get-M365ServiceHealthReport.ps1) | Reports current Microsoft 365 service incidents and advisories and, optionally, Message Center changes that need action. | ServiceHealth.Read.All (delegated), plus ServiceMessage.Read.All with -IncludeMessageCenter. The signed-in user needs a role that can see service health, for example Service Support Administrator or Global Reader. | No |
| [Get-M365SharePointTenantSettingsGraph.ps1](./Get-M365SharePointTenantSettingsGraph.ps1) | Reports the SharePoint Online tenant settings exposed by Microsoft Graph with a security recommendation per risky setting. | SharePointTenantSettings.Read.All (delegated); the signed-in user needs the SharePoint Administrator or Global Reader role. | No |
| [Invoke-M365MessageCenterTriage.ps1](./Invoke-M365MessageCenterTriage.ps1) | Marks Message Center posts as read/unread, archives/unarchives or favorites/unfavorites them in bulk, by ID or by filter. | ServiceMessage.Read.All and ServiceMessageViewpoint.Write (delegated). The signed-in user needs a role that can read the Message Center, for example Message Center Reader or Service Support Administrator. | Yes (`-WhatIf` supported) |
| [Set-M365ReportConcealedNames.ps1](./Set-M365ReportConcealedNames.ps1) | Shows or changes the tenant setting that conceals user, group and site names in Microsoft 365 usage reports. | ReportSettings.Read.All (delegated) to show the setting; ReportSettings.ReadWrite.All with -Enable or -Disable. The signed-in user needs the Global Administrator or Reports Administrator role to change it. | Optional (-Enable / -Disable) |
| [Set-M365SharePointSharingLevel.ps1](./Set-M365SharePointSharingLevel.ps1) | Changes the tenant-wide SharePoint and OneDrive sharing settings through Microsoft Graph, showing the before/after diff first. | SharePointTenantSettings.ReadWrite.All (delegated); the signed-in user needs the SharePoint Administrator role. | Yes (`-WhatIf` supported) |

## Microsoft 365 Groups governance

| Script | What it does | Permissions / roles | Changes anything? |
|---|---|---|---|
| [Get-M365DeletedGroupsReport.ps1](./Get-M365DeletedGroupsReport.ps1) | Lists soft-deleted Microsoft 365 groups with their remaining recovery window and can restore or purge them. | Group.Read.All (delegated); -Restore / -PermanentlyDelete add Group.ReadWrite.All (Groups Administrator role). | Optional (-Restore / -PermanentlyDelete) |
| [Get-M365GroupCreationSettings.ps1](./Get-M365GroupCreationSettings.ps1) | Reports the tenant-wide Microsoft 365 group settings (Group.Unified) with defaults and recommendations. | Directory.Read.All (delegated; includes reading groups). Global Reader can run it. | No |
| [Get-M365GroupExpirationReport.ps1](./Get-M365GroupExpirationReport.ps1) | Reports the Microsoft 365 group expiration policy and the groups that expire soon, with optional renewal or policy enrolment. | Group.Read.All, Directory.Read.All (delegated); -Renew adds Group.ReadWrite.All and -AddToPolicy adds Directory.ReadWrite.All (Groups Administrator role). | Optional (-Renew / -AddToPolicy) |
| [Get-M365GroupGuestSettings.ps1](./Get-M365GroupGuestSettings.ps1) | Reports the effective "guests can be added" setting of every Microsoft 365 group and can block or allow guests per group. | Group.Read.All, Directory.Read.All (delegated); changes add Group.ReadWrite.All and Directory.ReadWrite.All (Groups Administrator). | Optional (-BlockGuests / -AllowGuests) |
| [Get-M365GroupNamingPolicyCompliance.ps1](./Get-M365GroupNamingPolicyCompliance.ps1) | Checks every Microsoft 365 group name against the tenant naming policy (prefix / suffix pattern and blocked words). | Directory.Read.All, Group.Read.All, User.Read.All (delegated). Global Reader can run it. | No |
| [Get-M365GroupSensitivityLabelReport.ps1](./Get-M365GroupSensitivityLabelReport.ps1) | Reports the sensitivity label of every Microsoft 365 group and can apply a label to groups that have none. | Group.Read.All (delegated); -IncludeCounts adds GroupMember.Read.All, -IncludeSiteUrl adds Sites.Read.All and -ApplyLabelId adds Group.ReadWrite.All (Groups Administrator role; assignedLabels cannot be set app-only). | Optional (-ApplyLabelId) |
| [Get-M365GroupsReport.ps1](./Get-M365GroupsReport.ps1) | Inventories Microsoft 365 groups with lifecycle, ownership, guest, Teams and sensitivity-label details. | Group.Read.All, GroupMember.Read.All, User.Read.All (delegated); Sites.Read.All only with -Include SiteUrl. | No |
| [Set-M365GroupCreationRestriction.ps1](./Set-M365GroupCreationRestriction.ps1) | Restricts Microsoft 365 group creation to the members of one group (or re-opens it to everyone) via the Group.Unified settings. | Directory.ReadWrite.All (delegated); the signed-in user needs the Groups Administrator or Global Administrator role. | Yes (`-WhatIf` supported) |
| [Set-M365GroupOwners.ps1](./Set-M365GroupOwners.ps1) | Adds or removes Microsoft 365 group owners in bulk from a CSV or from -GroupName / -Owners, with last-owner protection. | Group.ReadWrite.All, User.Read.All (delegated); the signed-in user needs the Groups Administrator role. | Yes (`-WhatIf` supported) |

## User lifecycle & tenant hygiene

| Script | What it does | Permissions / roles | Changes anything? |
|---|---|---|---|
| [Get-M365AdminContactsAudit.ps1](./Get-M365AdminContactsAudit.ps1) | Audits who receives tenant notifications and who holds the keys: contact addresses, Global Administrators and emergency access accounts. | Organization.Read.All, Directory.Read.All, RoleManagement.Read.Directory, User.Read.All, AuditLog.Read.All, Policy.Read.All (delegated); Global Reader covers them. -IncludeExchange needs View-Only Organization Management. | No |
| [Get-M365DirectorySizeSummary.ps1](./Get-M365DirectorySizeSummary.ps1) | Quick directory size summary: users, groups, devices, applications, roles, administrative units and the directory quota. | User.Read.All, Group.Read.All, Device.Read.All, Application.Read.All, RoleManagement.Read.Directory, Organization.Read.All, AdministrativeUnit.Read.All (delegated); Global Reader covers all of them. | No |
| [Get-M365ExternalCollaborationSummary.ps1](./Get-M365ExternalCollaborationSummary.ps1) | One-page executive summary of external collaboration: guests, their domains, groups and teams with guests and the tenant sharing settings. | User.Read.All, AuditLog.Read.All, Group.Read.All, GroupMember.Read.All, Policy.Read.All, SharePointTenantSettings.Read.All (delegated); Global Reader covers all of them. | No |
| [Get-M365TenantHealthScorecard.ps1](./Get-M365TenantHealthScorecard.ps1) | One-page tenant health scorecard: identity, security, device, license and service metrics rated Green, Amber or Red. | AuditLog.Read.All, RoleManagement.Read.Directory, SecurityEvents.Read.All, Policy.Read.All, Device.Read.All, User.Read.All, Organization.Read.All, ServiceHealth.Read.All, DeviceManagementManagedDevices.Read.All, Directory.Read.All (delegated); Global Reader plus Security Reader and Intune Read Only Operator cover them. | No |
| [Get-M365UserCrossWorkloadActivity.ps1](./Get-M365UserCrossWorkloadActivity.ps1) | Finds truly inactive users by combining Entra sign-in activity with the last Exchange, OneDrive, SharePoint, Teams and Viva Engage activity. | User.Read.All, AuditLog.Read.All, Reports.Read.All, Organization.Read.All (delegated); Global Reader or Reports Reader plus User Administrator can run it. | No |
| [Invoke-M365UserOffboarding.ps1](./Invoke-M365UserOffboarding.ps1) | Offboards leavers end to end: disables the account, revokes sessions, resets the password, removes groups, manager, MFA methods and licenses. | User.ReadWrite.All, Group.ReadWrite.All, Organization.Read.All, UserAuthenticationMethod.ReadWrite.All (unless -SkipMfaReset), User-PasswordProfile.ReadWrite.All (unless -SkipPasswordReset) (delegated); User Administrator plus Authentication Administrator for the MFA step, Exchange Administrator for the mailbox steps. | Yes (`-WhatIf` supported) |
| [Invoke-M365UserOnboarding.ps1](./Invoke-M365UserOnboarding.ps1) | Onboards new hires end to end: creates the account, sets manager, licenses, groups and teams and optionally sends a welcome mail. | User.ReadWrite.All, Group.ReadWrite.All, TeamMember.ReadWrite.All, Organization.Read.All (delegated), plus Mail.Send with -SendWelcomeEmail. User Administrator can create users and assign licenses; adding members to groups and teams the admin does not own needs Groups Administrator or Teams Administrator. | Yes (`-WhatIf` supported) |
| [New-M365GraphAppRegistrationForAutomation.ps1](./New-M365GraphAppRegistrationForAutomation.ps1) | Creates an app registration with certificate credential and Graph application permissions for unattended scripts. | Application.ReadWrite.All, Directory.Read.All, plus AppRoleAssignment.ReadWrite.All with -GrantAdminConsent (delegated); Application Administrator can create the app, consent needs Privileged Role Administrator. | Yes (`-WhatIf` supported) |
| [Send-M365ReportByEmail.ps1](./Send-M365ReportByEmail.ps1) | Sends a report by e-mail through Microsoft Graph, with CSV or HTML attachments and an optional inline table built from a CSV. | Mail.Send (delegated or application); Mail.Send.Shared is requested in addition when -From is used with a delegated session, and the signed-in user needs Send As (or Send on Behalf) on that mailbox. | Yes (`-WhatIf` supported) |
| [Test-M365GraphPermissions.ps1](./Test-M365GraphPermissions.ps1) | Diagnoses the current Microsoft Graph session: account, scopes, missing permissions for a script, directory roles and probe calls. | Whatever the current session holds (User.Read is requested when no session exists); RoleManagement.Read.Directory with -IncludeEligible. Directory roles need Directory.Read.All or an equivalent scope in the session. | No |

## Quick start

```powershell
# Convert-M365DirectLicensesToGroup.ps1
.\Convert-M365DirectLicensesToGroup.ps1 -Sku SPE_E3 -GroupName 'LIC-M365-E3' -AddMissingMembers -Remove -Confirm:$false

# Export-M365UsageReportsBundle.ps1
.\Export-M365UsageReportsBundle.ps1 -Period D90 -Reports getTeamsUserActivityUserDetail, getTeamsTeamActivityDetail -IncludeSettingsCheck -Zip -OutputFolder C:\Temp\Teams90

# Export-M365TenantSettingsSnapshot.ps1
.\Export-M365TenantSettingsSnapshot.ps1 -OutputFolder C:\Snapshots\2026-10 -CompareWith C:\Snapshots\2026-09 -IncludeBeta

# Get-M365DeletedGroupsReport.ps1
.\Get-M365DeletedGroupsReport.ps1 -GroupName 'Test-*' -PermanentlyDelete -WhatIf
```

## Notes

- Usage reports need the **Reports Reader** (or Global Reader) role; service health and Message Center need **Service Support Administrator** or Global Reader.
- License changes default to report-only where a switch exists; `-WhatIf` works everywhere.
- Friendly SKU names come from a built-in table of common SKUs - unknown SKUs fall back to their part number.

---

Back to the [repository overview](../README.md).
