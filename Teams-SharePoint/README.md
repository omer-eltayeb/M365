# Microsoft Teams, SharePoint & OneDrive scripts

Collaboration governance: team inventory and lifecycle, membership and guests, channels, apps and settings, Teams usage, Teams admin policies and voice, SharePoint site sharing and administration, external users, storage, files and sharing links, OneDrive.

**51 scripts.** Module(s): Microsoft Graph PowerShell SDK for teams, channels, sites, files and usage reports; `MicrosoftTeams` for Teams policies and voice; `Microsoft.Online.SharePoint.PowerShell` for SharePoint admin settings.

Every script has full comment-based help (`Get-Help .\<Script>.ps1 -Full`), writes a timestamped CSV to `.\Reports\` by default (`-OutputPath` to choose, `-PassThru` to keep the objects) and is read-only unless the **Changes anything?** column says otherwise - those scripts support `-WhatIf` / `-Confirm`.

## Contents

- [Teams inventory & lifecycle](#teams-inventory--lifecycle) (12)
- [Teams apps, settings & usage](#teams-apps-settings--usage) (9)
- [Teams administration (MicrosoftTeams module)](#teams-administration-microsoftteams-module) (9)
- [SharePoint administration (SPO module)](#sharepoint-administration-spo-module) (10)
- [SharePoint & OneDrive (Graph)](#sharepoint--onedrive-graph) (11)

## Teams inventory & lifecycle

| Script | What it does | Permissions / roles | Changes anything? |
|---|---|---|---|
| [Add-TeamsMembers.ps1](./Add-TeamsMembers.ps1) | Adds users to teams as owners or members (or removes them) from a CSV file or from parameters, skipping existing memberships. | Group.Read.All, User.Read.All, TeamMember.ReadWrite.All (delegated). Teams Administrator role to change teams the signed-in user does not own. | Yes (`-WhatIf` supported) |
| [Export-TeamsMembership.ps1](./Export-TeamsMembership.ps1) | Exports the membership of all or selected teams, one row per member with the role Owner, Member or Guest. | Group.Read.All, Team.ReadBasic.All, TeamMember.Read.All (delegated); User.Read.All only with -ResolveUsers. Teams Administrator or Global Reader role to read teams the signed-in user is not a member of. | No |
| [Get-TeamsAllTeamsReport.ps1](./Get-TeamsAllTeamsReport.ps1) | Inventories every Microsoft Teams team with owner, member, guest and channel counts, archive state and age. | Group.Read.All, Team.ReadBasic.All, TeamSettings.Read.All, Channel.ReadBasic.All (delegated). The Teams Administrator or Global Reader role lets the signed-in user read teams they are not a member of. | No |
| [Get-TeamsArchivedTeams.ps1](./Get-TeamsArchivedTeams.ps1) | Lists archived Microsoft Teams teams and can unarchive them or delete them (with their Microsoft 365 group). | Group.Read.All, Team.ReadBasic.All (delegated); TeamSettings.ReadWrite.All only with -Unarchive and Group.ReadWrite.All only with -DeleteArchived. Teams Administrator (or Groups Administrator for deletion) role. | Optional (-Unarchive / -DeleteArchived) |
| [Get-TeamsChannelsReport.ps1](./Get-TeamsChannelsReport.ps1) | Lists every channel of every team (standard, private, shared) with type, age, email, archive state and optional file size. | Group.Read.All, Team.ReadBasic.All, Channel.ReadBasic.All (delegated); Files.Read.All only with -IncludeFilesFolder, ChannelMessage.Read.All only with -IncludeLastMessage. Teams Administrator or Global Reader role. | No |
| [Get-TeamsGuestAccessReport.ps1](./Get-TeamsGuestAccessReport.ps1) | Reports which Microsoft Teams teams contain guest users and which external domains they come from. | Group.Read.All, GroupMember.Read.All, User.Read.All (delegated); plus Team.ReadBasic.All and TeamSettings.Read.All when -IncludeTeamSettings is used. Global Reader can run it end to end. | No |
| [Get-TeamsInactiveTeams.ps1](./Get-TeamsInactiveTeams.ps1) | Finds Microsoft Teams teams that nobody uses, based on the Teams team activity usage report. | Reports.Read.All, Group.Read.All (delegated). The Reports Reader or Global Reader role is enough to read usage reports. | No |
| [Get-TeamsOwnerlessTeams.ps1](./Get-TeamsOwnerlessTeams.ps1) | Finds teams with no owner, with only disabled owners or with a single owner, and can assign a new owner. | Group.Read.All, GroupMember.Read.All, User.Read.All (delegated); TeamMember.ReadWrite.All only with -AddOwner. The Teams Administrator role is needed to add owners to teams the signed-in user does not own. | Optional (-AddOwner) |
| [Get-TeamsPrivateAndSharedChannelsReport.ps1](./Get-TeamsPrivateAndSharedChannelsReport.ps1) | Reports private and shared channels with their owner, member, guest and external member counts and sharing targets. | Group.Read.All, Team.ReadBasic.All, Channel.ReadBasic.All, ChannelMember.Read.All (delegated); Files.Read.All only with -IncludeSiteUrl. Teams Administrator or Global Reader role to read channels of teams you are not a member of. | No |
| [Get-TeamsUserMembership.ps1](./Get-TeamsUserMembership.ps1) | Lists the teams one or more users belong to, with their role (Owner, Member, Guest) and the team's visibility and archive state. | User.Read.All, Team.ReadBasic.All, TeamMember.Read.All (delegated). Teams Administrator or Global Reader role to read teams the signed-in user is not a member of. | No |
| [Invoke-TeamsArchiveInactiveTeams.ps1](./Invoke-TeamsArchiveInactiveTeams.ps1) | Reports teams with no activity for N days and, on request, notifies their owners and archives them. | Reports.Read.All, Group.Read.All, Team.ReadBasic.All (delegated); TeamSettings.ReadWrite.All only with -Archive, Mail.Send only with -NotifyOwners. Reports Reader or Global Reader role to read the report, Teams Administrator to archive. | Optional (-Archive) |
| [Remove-TeamsUserFromAllTeams.ps1](./Remove-TeamsUserFromAllTeams.ps1) | Offboarding helper: lists every team a user belongs to and, with -Remove, removes the user from all of them. | User.Read.All, Team.ReadBasic.All, TeamMember.Read.All (delegated); TeamMember.ReadWrite.All only with -Remove. Teams Administrator role to read and change teams the signed-in user is not a member of. | Optional (-Remove) |

## Teams apps, settings & usage

| Script | What it does | Permissions / roles | Changes anything? |
|---|---|---|---|
| [Get-TeamsAppCatalogReport.ps1](./Get-TeamsAppCatalogReport.ps1) | Reports the Microsoft Teams app catalog: organisation (custom) apps with their versions and publishing state, optionally store and sideloaded apps. | AppCatalog.Read.All (delegated). Run as a Teams Administrator: the API works in the user context and only returns the apps the signed-in account is allowed to see under the Teams app permission policies. | No |
| [Get-TeamsDeviceUsageReport.ps1](./Get-TeamsDeviceUsageReport.ps1) | Reports which Teams client platforms (Windows, Mac, web, iOS, Android, ...) every user has used and finds web-only and mobile-only users. | Reports.Read.All (delegated). The Reports Reader, Global Reader or Teams Administrator role is enough. | No |
| [Get-TeamsInstalledApps.ps1](./Get-TeamsInstalledApps.ps1) | Inventories the apps installed in Microsoft Teams teams, with version, distribution method and bot flag. | TeamsAppInstallation.ReadForTeam, Team.ReadBasic.All, Group.Read.All (delegated). Unattended runs would use the application permission TeamsAppInstallation.ReadForTeam.All instead. | No |
| [Get-TeamsRoomsAndPlaces.ps1](./Get-TeamsRoomsAndPlaces.ps1) | Inventories meeting rooms (places) with capacity, location, AV devices and room list membership, and flags incomplete room metadata. | Place.Read.All (delegated). Any Exchange recipient-management or Global Reader role can read places. | No |
| [Get-TeamsTagsReport.ps1](./Get-TeamsTagsReport.ps1) | Reports the tags defined in Microsoft Teams teams (and their members) and can bulk-create tags from a CSV. | TeamworkTag.Read, Team.ReadBasic.All, Group.Read.All (delegated); -CreateFromCsv adds TeamworkTag.ReadWrite and User.Read.All. | Optional (-CreateFromCsv) |
| [Get-TeamsTeamSettingsReport.ps1](./Get-TeamsTeamSettingsReport.ps1) | Reports the member, guest, messaging, fun and discovery settings of Microsoft Teams teams and flags deviations from the defaults. | TeamSettings.Read.All, Team.ReadBasic.All, Group.Read.All (delegated). Global Reader can run it end to end. | No |
| [Get-TeamsUserActivityReport.ps1](./Get-TeamsUserActivityReport.ps1) | Reports Microsoft Teams activity per user (messages, calls, meetings, media minutes) and flags inactive and licensed-but-inactive users. | Reports.Read.All (delegated). The Reports Reader, Global Reader or Teams Administrator role is enough. | No |
| [New-TeamsFromCsv.ps1](./New-TeamsFromCsv.ps1) | Creates Microsoft Teams teams in bulk from a CSV file, including owners, members and channels. | Team.Create, TeamMember.ReadWrite.All, Channel.Create, User.Read.All, Group.Read.All (delegated). The signed-in account must be allowed to create Microsoft 365 groups by the tenant's group creation policy. | Yes (`-WhatIf` supported) |
| [Set-TeamsGuestSettings.ps1](./Set-TeamsGuestSettings.ps1) | Standardises guest permissions (and optionally member and fun settings) across Microsoft Teams teams. | TeamSettings.ReadWrite.All, Group.Read.All (delegated). Teams Administrator or Global Administrator role. | Yes (`-WhatIf` supported) |

## Teams administration (MicrosoftTeams module)

| Script | What it does | Permissions / roles | Changes anything? |
|---|---|---|---|
| [Export-TeamsPolicies.ps1](./Export-TeamsPolicies.ps1) | Exports every Teams policy and tenant configuration definition to JSON and compares the export with a previous one. | Teams Administrator or Global Reader (read-only). | No |
| [Get-TeamsAppPolicies.ps1](./Get-TeamsAppPolicies.ps1) | Reports the Teams app permission and app setup policies, the org-wide custom app setting and how many users each policy has. | Teams Administrator or Global Reader (read-only). | No |
| [Get-TeamsCallQueuesAndAutoAttendants.ps1](./Get-TeamsCallQueuesAndAutoAttendants.ps1) | Documents every Teams call queue, auto attendant and voice application resource account, with configuration gaps flagged. | Teams Communications Administrator, Teams Administrator or Global Reader (read-only). | No |
| [Get-TeamsExternalAccessConfiguration.ps1](./Get-TeamsExternalAccessConfiguration.ps1) | Reviews the tenant-wide Teams external access, guest access and anonymous meeting settings against recommended values. | Teams Administrator or Global Reader (read-only). | No |
| [Get-TeamsMeetingSettingsReport.ps1](./Get-TeamsMeetingSettingsReport.ps1) | Reports the security and feature settings of every Teams meeting policy plus the tenant meeting configuration. | Teams Administrator or Global Reader (read-only). | No |
| [Get-TeamsPhoneNumberInventory.ps1](./Get-TeamsPhoneNumberInventory.ps1) | Inventories every Teams phone number with its type, assignment, capabilities, location and PSTN partner. | Teams Communications Administrator, Teams Administrator or Global Reader (read-only). | No |
| [Get-TeamsUserPolicyAssignments.ps1](./Get-TeamsUserPolicyAssignments.ps1) | Reports the Teams policies directly assigned to each user, finds who has a given policy and optionally exports group assignments. | Teams Administrator or Global Reader (read-only). | No |
| [Get-TeamsVoiceEnabledUsers.ps1](./Get-TeamsVoiceEnabledUsers.ps1) | Reports Enterprise Voice enabled Teams users with their phone number, voice policies, licensing and configuration gaps. | Teams Communications Administrator, Teams Administrator or Global Reader (read-only). | No |
| [Grant-TeamsPolicies.ps1](./Grant-TeamsPolicies.ps1) | Bulk-assigns Teams policies to users (one by one or as batch operations) or to a group, with validation and a preview mode. | Teams Administrator (Teams Communications Administrator is sufficient for the voice policy types). | Yes (`-WhatIf` supported) |

## SharePoint administration (SPO module)

| Script | What it does | Permissions / roles | Changes anything? |
|---|---|---|---|
| [Add-SPOSiteCollectionAdmin.ps1](./Add-SPOSiteCollectionAdmin.ps1) | Grants (or with -Remove revokes) site collection administrator rights for an account on selected SharePoint Online sites or OneDrives. | SharePoint Administrator role. | Yes (`-WhatIf` supported) |
| [Export-SPOTenantSettings.ps1](./Export-SPOTenantSettings.ps1) | Exports all SharePoint Online tenant settings to JSON, assesses the key sharing and security settings and diffs against an earlier export. | SharePoint Administrator role; Global Reader is sufficient for this read-only export. | No |
| [Get-SPODeletedSitesReport.ps1](./Get-SPODeletedSitesReport.ps1) | Reports the SharePoint Online sites in the tenant recycle bin with their remaining retention, and optionally restores or purges them. | SharePoint Administrator role; Global Reader is sufficient for the report. Restore and purge need SharePoint Administrator. | Optional (-Restore / -PermanentlyDelete) |
| [Get-SPOExternalUsersReport.ps1](./Get-SPOExternalUsersReport.ps1) | Reports every external (guest) user known to SharePoint Online with age, inviter and domain, and optionally removes selected ones. | SharePoint Administrator role; Global Reader is sufficient for the report. Removal needs SharePoint Administrator. | Optional (-Remove) |
| [Get-SPOHubSitesReport.ps1](./Get-SPOHubSitesReport.ps1) | Reports every SharePoint Online hub site with its settings, join permissions, parent hub and associated sites. | SharePoint Administrator role; Global Reader is sufficient for this read-only report. | No |
| [Get-SPOOneDriveInventory.ps1](./Get-SPOOneDriveInventory.ps1) | Inventories every OneDrive for Business site with storage, activity and ownership flags, and optionally sets quotas or grants an admin. | SharePoint Administrator role; Global Reader is sufficient for the report. Quota and admin changes need SharePoint Administrator. | Optional (-SetQuota / -GrantAdmin) |
| [Get-SPOOrphanedSites.ps1](./Get-SPOOrphanedSites.ps1) | Finds SharePoint Online sites without a valid owner, locked sites and dormant sites, and optionally assigns a new owner. | SharePoint Administrator role (the owner check reads the site user list); Global Reader works with -SkipOwnerCheck. | Optional (-SetOwner) |
| [Get-SPOSiteCollectionAdminsReport.ps1](./Get-SPOSiteCollectionAdminsReport.ps1) | Reports the site collection administrators of every SharePoint Online site and flags sites without a human admin, external admins and admin sprawl. | SharePoint Administrator role (Get-SPOUser reads the site user list through the admin endpoint); Global Reader may be denied on some sites. | No |
| [Get-SPOSitesSharingReport.ps1](./Get-SPOSitesSharingReport.ps1) | Reports the external sharing configuration of every SharePoint Online site and flags sites configured more openly than the tenant. | SharePoint Administrator role; Global Reader is sufficient for this read-only report. | No |
| [Set-SPOSiteSharing.ps1](./Set-SPOSiteSharing.ps1) | Sets the external sharing capability, default link settings and domain restrictions on selected SharePoint Online sites. | SharePoint Administrator role. | Yes (`-WhatIf` supported) |

## SharePoint & OneDrive (Graph)

| Script | What it does | Permissions / roles | Changes anything? |
|---|---|---|---|
| [Get-OneDriveSharedItemsReport.ps1](./Get-OneDriveSharedItemsReport.ps1) | Reports every sharing link and direct permission on shared OneDrive files and folders per user, flagging anonymous and external access. | Files.Read.All, User.Read.All. Delegated Files.Read.All only reaches OneDrives the signed-in user can already open (for example as a site collection administrator); an app-only session with the application permissions Files.Read.All and User.Read.All is recommended for a tenant-wide scan (connect with Connect-MgGraph first). | No |
| [Get-OneDriveUsageReport.ps1](./Get-OneDriveUsageReport.ps1) | Reports OneDrive storage and activity per account and flags dormant OneDrives and OneDrives of deleted users. | Reports.Read.All (delegated). The Reports Reader or Global Reader role is enough to read usage reports. | No |
| [Get-SPOFileTypeSummary.ps1](./Get-SPOFileTypeSummary.ps1) | Summarises the files stored in SharePoint sites by extension and by category (Office, PDF, media, archives, code, CAD). | Sites.Read.All, Files.Read.All (delegated sees only sites the user can open; app-only recommended tenant-wide). | No |
| [Get-SPOLargeFilesReport.ps1](./Get-SPOLargeFilesReport.ps1) | Finds the largest files in SharePoint sites or OneDrive accounts, optionally with the storage consumed by their version history. | Sites.Read.All, Files.Read.All (delegated sees only sites and OneDrives the user can open; app-only recommended). | No |
| [Get-SPOListsInventory.ps1](./Get-SPOListsInventory.ps1) | Inventories the lists and libraries of SharePoint sites with template, visibility, content type settings and optional item and column counts. | Sites.Read.All (delegated sees only sites the user can open; app-only recommended tenant-wide). | No |
| [Get-SPOSharedItemsReport.ps1](./Get-SPOSharedItemsReport.ps1) | Reports every sharing link and direct permission on shared files and folders in SharePoint sites, flagging anonymous and external access. | Sites.Read.All, Files.Read.All (delegated sees only sites the user can open; app-only recommended tenant-wide). | No |
| [Get-SPOSiteActivityReport.ps1](./Get-SPOSiteActivityReport.ps1) | Reports SharePoint activity per user (files viewed, synced, shared internally and externally, pages visited) and flags inactive users and heavy external sharers. | Reports.Read.All (delegated). The Reports Reader or Global Reader role is enough to read usage reports. | No |
| [Get-SPOSiteFilesInventory.ps1](./Get-SPOSiteFilesInventory.ps1) | Inventories every file in the document libraries of one or more SharePoint sites with size, age, editor and sharing state. | Sites.Read.All, Files.Read.All (delegated sees only sites the user can open; app-only recommended tenant-wide). | No |
| [Get-SPOSitePermissionsGraph.ps1](./Get-SPOSitePermissionsGraph.ps1) | Audits which applications hold Sites.Selected permissions on SharePoint sites, optionally with library-level permissions, and can grant or revoke app access. | Sites.FullControl.All (reading, granting and revoking site permissions all require it; the library permissions alone would work with Sites.Read.All). SharePoint Administrator or Global Administrator role for delegated use. | Optional (-GrantAppAccess / -RevokePermissionId) |
| [Get-SPOSiteStorageReport.ps1](./Get-SPOSiteStorageReport.ps1) | Reports SharePoint Online storage consumption per site and flags dormant sites, optionally including OneDrive. | Reports.Read.All (delegated). The Reports Reader or Global Reader role is enough to read usage reports. | No |
| [Get-SPOSitesInventoryGraph.ps1](./Get-SPOSitesInventoryGraph.ps1) | Inventories every SharePoint site in the tenant through Microsoft Graph, optionally with library count and storage used. | Sites.Read.All. getAllSites is application-only (app-only session); a delegated session falls back to the site search, which returns only the sites the signed-in user can access and no personal sites. | No |

## Quick start

```powershell
# Add-TeamsMembers.ps1
.\Add-TeamsMembers.ps1 -TeamName 'Project Falcon' -Members alex@contoso.com, sam@contoso.com -Role Owner -Confirm:$false

# Get-TeamsAppCatalogReport.ps1
.\Get-TeamsAppCatalogReport.ps1 -IncludeStoreApps -AppName 'Adobe*' -OutputPath C:\Temp\AdobeApps.csv -Verbose

# Export-TeamsPolicies.ps1
.\Export-TeamsPolicies.ps1 -OutputFolder C:\Backups\TeamsPolicies\2026-10 -CompareWith C:\Backups\TeamsPolicies\2026-09 -Verbose

# Add-SPOSiteCollectionAdmin.ps1
.\Add-SPOSiteCollectionAdmin.ps1 -TenantName contoso -Admin former.admin@contoso.com -InputCsv .\sites.csv -Remove -Apply
```

## Notes

- Usage reports (`Reports.Read.All`) lag about 48 hours; if "Display concealed user, group, and site names in all reports" is enabled, names appear hashed.
- The SharePoint Online management shell runs on Windows only and needs the tenant admin URL (`-TenantName contoso`).
- Roles: **Teams Administrator**, **SharePoint Administrator**, **Global Reader** / **Reports Reader** for reports.

---

Back to the [repository overview](../README.md).
