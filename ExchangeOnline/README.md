# Exchange Online scripts

Exchange Online administration: mailbox lifecycle and holds, sizes and quotas, folders and settings, calendars and resource mailboxes, distribution groups, mail flow (transport rules, connectors, message trace, traffic reports), client access protocols, mobile devices, admin roles, audit and migration.

**53 scripts.** Module(s): `ExchangeOnlineManagement` v3 (REST-backed `Get-EXO*` cmdlets wherever they exist).

Every script has full comment-based help (`Get-Help .\<Script>.ps1 -Full`), writes a timestamped CSV to `.\Reports\` by default (`-OutputPath` to choose, `-PassThru` to keep the objects) and is read-only unless the **Changes anything?** column says otherwise - those scripts support `-WhatIf` / `-Confirm`.

## Contents

- [Mailbox lifecycle & compliance](#mailbox-lifecycle--compliance) (11)
- [Mailbox content & settings](#mailbox-content--settings) (11)
- [Calendar & resource mailboxes](#calendar--resource-mailboxes) (4)
- [Distribution groups](#distribution-groups) (6)
- [Mail flow & organization](#mail-flow--organization) (10)
- [Client access & mobile devices](#client-access--mobile-devices) (6)
- [Administration, audit & migration](#administration-audit--migration) (5)

## Mailbox lifecycle & compliance

| Script | What it does | Permissions / roles | Changes anything? |
|---|---|---|---|
| [Convert-EXOMailboxToShared.ps1](./Convert-EXOMailboxToShared.ps1) | Converts user mailboxes to shared mailboxes (or back to regular) after a licensing and size pre-flight check. | Exchange Administrator (or Mail Recipients role) to convert; View-Only Recipients for the pre-flight report | Yes (`-WhatIf` supported) |
| [Enable-EXOArchiveMailboxes.ps1](./Enable-EXOArchiveMailboxes.ps1) | Enables the In-Place Archive (optionally auto-expanding) and assigns a retention policy for mailboxes that lack one. | Exchange Administrator (or Mail Recipients role) for -Enable; View-Only Recipients for the report | Yes (`-WhatIf` supported) |
| [Get-EXOArchiveStatusReport.ps1](./Get-EXOArchiveStatusReport.ps1) | Reports In-Place Archive status, size, quota usage and retention policy coverage for Exchange Online mailboxes. | View-Only Recipients or Global Reader (the report is read-only) | No |
| [Get-EXOHoldsReport.ps1](./Get-EXOHoldsReport.ps1) | Reports every hold applied to Exchange Online mailboxes and decodes the InPlaceHolds identifiers. | View-Only Recipients or Global Reader (the report is read-only) | No |
| [Get-EXOInactiveMailboxes.ps1](./Get-EXOInactiveMailboxes.ps1) | Finds user (and optionally shared) mailboxes with no activity for a given number of days. | View-Only Recipients or Global Reader (the report is read-only) | No |
| [Get-EXOMailboxAuditStatus.ps1](./Get-EXOMailboxAuditStatus.ps1) | Reports mailbox auditing status (tenant default, per-mailbox settings, bypass accounts) and can restore the defaults. | View-Only Configuration + View-Only Recipients (or Global Reader) for the report; Exchange Administrator for -SetDefaults | Optional (-SetDefaults) |
| [Get-EXOMailboxPlansReport.ps1](./Get-EXOMailboxPlansReport.ps1) | Reports Exchange Online mailbox plans and CAS mailbox plans (the defaults every new mailbox inherits) and can harden them. | View-Only Configuration (or Global Reader) for the report; Exchange Administrator for -SetDefaults | Optional (-SetDefaults) |
| [Get-EXOMailboxSizeReport.ps1](./Get-EXOMailboxSizeReport.ps1) | Reports mailbox and archive size, item counts and quota usage for Exchange Online mailboxes. | Exchange Administrator, or View-Only Recipients for the read-only report | No |
| [Get-EXOSharedMailboxReport.ps1](./Get-EXOSharedMailboxReport.ps1) | Reports shared (and optionally room/equipment) mailboxes with size, license, delegation and hygiene findings. | View-Only Recipients or Global Reader (the report is read-only) | No |
| [Get-EXOSoftDeletedMailboxes.ps1](./Get-EXOSoftDeletedMailboxes.ps1) | Reports soft-deleted and inactive mailboxes with purge dates, holds and size, and can restore content into another mailbox. | View-Only Recipients or Global Reader for the report; Exchange Administrator (Recipient Management) for -Restore | Optional (-Restore) |
| [Set-EXOLitigationHold.ps1](./Set-EXOLitigationHold.ps1) | Places selected mailboxes on litigation hold (or releases them) with duration, owner and notice details. | Exchange Administrator with the Legal Hold role (Organization Management or Discovery Management) for -Enable / -Disable; View-Only Recipients for the report | Yes (`-WhatIf` supported) |

## Mailbox content & settings

| Script | What it does | Permissions / roles | Changes anything? |
|---|---|---|---|
| [Get-EXOEmailAddressReport.ps1](./Get-EXOEmailAddressReport.ps1) | Reports every e-mail address (primary, alias, SIP, SPO, X500) of all Exchange Online recipients with per-domain totals. | View-Only Recipients or Global Reader (the report is read-only) | No |
| [Get-EXOExternalForwardingReport.ps1](./Get-EXOExternalForwardingReport.ps1) | Finds mail leaving the tenant through mailbox forwarding or inbox rules, and optionally removes it. | View-Only Recipients for the report; Exchange Administrator (or Mail Recipients role) for -Remediate | Optional (-Remediate) |
| [Get-EXOInboxRulesReport.ps1](./Get-EXOInboxRulesReport.ps1) | Reports inbox rules of Exchange Online mailboxes, flags suspicious rules and can disable them. | View-Only Recipients or Global Reader for the report; Exchange Administrator (Mail Recipients role) for -Disable | Optional (-Disable) |
| [Get-EXOMailboxFolderSizes.ps1](./Get-EXOMailboxFolderSizes.ps1) | Reports the largest folders of Exchange Online mailboxes with item counts, sizes and oldest/newest item dates. | View-Only Recipients or Global Reader (the report is read-only) | No |
| [Get-EXOMailboxPermissionsReport.ps1](./Get-EXOMailboxPermissionsReport.ps1) | Audits delegated mailbox access: FullAccess, SendAs and SendOnBehalf grants across Exchange Online mailboxes. | View-Only Recipients for the report; Exchange Administrator / Recipient Management to act on the findings | No |
| [Get-EXOMailboxRegionalSettings.ps1](./Get-EXOMailboxRegionalSettings.ps1) | Reports language, time zone and date/time format of Exchange Online mailboxes and flags unconfigured or deviating ones. | View-Only Recipients or Global Reader (the report is read-only) | No |
| [Get-EXOOutOfOfficeReport.ps1](./Get-EXOOutOfOfficeReport.ps1) | Reports automatic reply (out of office) settings of Exchange Online mailboxes and flags stale or risky configurations. | View-Only Recipients or Global Reader (the report is read-only) | No |
| [Get-EXORecoverableItemsReport.ps1](./Get-EXORecoverableItemsReport.ps1) | Reports Recoverable Items folder usage against quota for Exchange Online mailboxes and optionally starts the Managed Folder Assistant. | View-Only Recipients or Global Reader for the report; Exchange Administrator (Recipient Management) for -RunMfa | Optional (-RunMfa) |
| [Set-EXOAutoReply.ps1](./Set-EXOAutoReply.ps1) | Enables, schedules or disables automatic replies on Exchange Online mailboxes with templated messages, typically for leavers. | Exchange Administrator (Mail Recipients role) for -Apply; View-Only Recipients for the pre-flight report | Yes (`-WhatIf` supported) |
| [Set-EXOMailboxQuotas.ps1](./Set-EXOMailboxQuotas.ps1) | Sets custom storage quotas and deleted item retention on Exchange Online mailboxes with a before/after report. | Exchange Administrator (Mail Recipients role) for -Apply; View-Only Recipients for the pre-flight report | Yes (`-WhatIf` supported) |
| [Set-EXOMailboxRegionalSettings.ps1](./Set-EXOMailboxRegionalSettings.ps1) | Sets language, time zone and date/time format on Exchange Online mailboxes, optionally localising default folder names. | Exchange Administrator (Mail Recipients role) for -Apply; View-Only Recipients for the pre-flight report | Yes (`-WhatIf` supported) |

## Calendar & resource mailboxes

| Script | What it does | Permissions / roles | Changes anything? |
|---|---|---|---|
| [Get-EXOCalendarPermissionsReport.ps1](./Get-EXOCalendarPermissionsReport.ps1) | Reports calendar folder permissions on user (and optionally resource) mailboxes and flags over-permissive Default/Anonymous access. | View-Only Recipients (Exchange Online) for the report; Mail Recipients role to act on the findings | No |
| [Get-EXORoomMailboxReport.ps1](./Get-EXORoomMailboxReport.ps1) | Inventories room and equipment mailboxes with their booking (calendar processing) settings, Places metadata and room list membership. | View-Only Recipients (Exchange Online) for the report | No |
| [Set-EXODefaultCalendarPermission.ps1](./Set-EXODefaultCalendarPermission.ps1) | Standardises the Default (and optionally Anonymous) calendar permission on user mailboxes. | View-Only Recipients for the report; Mail Recipients role (Recipient Management / Exchange Administrator) for -Apply | Yes (`-WhatIf` supported) |
| [Set-EXORoomBookingPolicy.ps1](./Set-EXORoomBookingPolicy.ps1) | Applies a consistent booking policy (calendar processing) and optional Places metadata to room and equipment mailboxes. | View-Only Recipients for the report; Mail Recipients role (Recipient Management / Exchange Administrator) for -Apply | Yes (`-WhatIf` supported) |

## Distribution groups

| Script | What it does | Permissions / roles | Changes anything? |
|---|---|---|---|
| [Add-EXODistributionGroupMembers.ps1](./Add-EXODistributionGroupMembers.ps1) | Bulk-adds (or, with -Remove, removes) members of distribution groups from a CSV or from parameters, skipping no-op changes. | Distribution Groups role (Recipient Management / Exchange Administrator); View-Only Recipients is enough without -Apply | Yes (`-WhatIf` supported) |
| [Convert-EXODistributionGroupToM365Group.ps1](./Convert-EXODistributionGroupToM365Group.ps1) | Lists distribution groups eligible for upgrade to Microsoft 365 Groups, explains blockers, and optionally submits the upgrade. | View-Only Recipients for the report; Exchange Administrator (Distribution Groups role) for -Upgrade | Optional (-Upgrade) |
| [Export-EXODistributionGroupMembers.ps1](./Export-EXODistributionGroupMembers.ps1) | Exports the members of distribution groups (optionally expanding nested groups) to one CSV or one CSV per group. | View-Only Recipients (Exchange Online) | No |
| [Get-EXODistributionGroupReport.ps1](./Get-EXODistributionGroupReport.ps1) | Inventories distribution groups, mail-enabled security groups, room lists and (optionally) dynamic distribution groups. | View-Only Recipients (Exchange Online) for the report | No |
| [Get-EXODynamicDistributionGroupPreview.ps1](./Get-EXODynamicDistributionGroupPreview.ps1) | Previews dynamic distribution groups: recipient filter, conditional attributes, calculated member count, sample members and an optional recipient test. | View-Only Recipients (Exchange Online) | No |
| [Get-EXOEmptyAndOwnerlessDistributionGroups.ps1](./Get-EXOEmptyAndOwnerlessDistributionGroups.ps1) | Finds distribution groups that are empty and/or have no valid owner, with optional owner assignment or removal. | View-Only Recipients for the report; Distribution Groups role (Recipient Management / Exchange Administrator) for changes | Optional (-SetOwner / -RemoveEmpty) |

## Mail flow & organization

| Script | What it does | Permissions / roles | Changes anything? |
|---|---|---|---|
| [Export-EXOOrganizationConfig.ps1](./Export-EXOOrganizationConfig.ps1) | Exports the Exchange Online organization and transport configuration as a JSON snapshot plus a key-settings CSV, with optional diff. | Exchange Administrator or Global Reader (View-Only Organization Management). | No |
| [Export-EXOTransportRules.ps1](./Export-EXOTransportRules.ps1) | Exports every Exchange Online mail flow (transport) rule to JSON files, a CSV summary and a restorable XML collection. | Exchange Administrator or Global Reader for the JSON/CSV export; Export-TransportRuleCollection also needs the Transport Rules role (Exchange Administrator, Compliance Management or Records Management). | No |
| [Get-EXOAcceptedAndRemoteDomains.ps1](./Get-EXOAcceptedAndRemoteDomains.ps1) | Reports accepted domains and remote domains, flags risky settings and optionally checks each MX record in DNS. | Exchange Administrator or Global Reader (View-Only Organization Management). | No |
| [Get-EXOConnectorsReport.ps1](./Get-EXOConnectorsReport.ps1) | Inventories inbound and outbound connectors, flags risky configurations and optionally validates outbound connectors. | Exchange Administrator or Global Reader for the report; Exchange Administrator (Remote and Accepted Domains role) for -Validate. | Optional (-Validate) |
| [Get-EXOJournalAndArchivingConfig.ps1](./Get-EXOJournalAndArchivingConfig.ps1) | Documents journaling, transport limits, archiving and messaging records management (MRM) retention configuration. | Exchange Administrator or Global Reader (View-Only Organization Management). | No |
| [Get-EXOMailFlowStatusReport.ps1](./Get-EXOMailFlowStatusReport.ps1) | Daily mail flow volumes per event type (good mail, spam, malware, phish, edge blocks, rules) as a pivot table and raw CSV. | Exchange Administrator, Global Reader or Security Reader (View-Only Recipients role). | No |
| [Get-EXOMessageTrace.ps1](./Get-EXOMessageTrace.ps1) | Runs a message trace for the last 10 days with full paging and exports the results with status and sender/recipient summaries. | Message Tracking or View-Only Recipients role (held by Exchange Administrator and Global Reader). | No |
| [Get-EXOMessageTraceDetail.ps1](./Get-EXOMessageTraceDetail.ps1) | Shows the event timeline (receive, transport rules, spam / malware verdicts, deliver, fail, defer) of one message per recipient. | Message Tracking or View-Only Recipients role (held by Exchange Administrator and Global Reader). | No |
| [Get-EXOTopSendersAndRecipients.ps1](./Get-EXOTopSendersAndRecipients.ps1) | Reports the top mail senders and recipients, the top spam and malware targets and the most common malware families. | Exchange Administrator, Global Reader or Security Reader (View-Only Recipients role). | No |
| [Start-EXOHistoricalSearch.ps1](./Start-EXOHistoricalSearch.ps1) | Submits, lists and waits for historical message trace searches (mail older than 10 days, up to 90 days back). | Message Tracking or View-Only Recipients role (held by Exchange Administrator and Global Reader). | Yes (`-WhatIf` supported) |

## Client access & mobile devices

| Script | What it does | Permissions / roles | Changes anything? |
|---|---|---|---|
| [Export-EXOClientAccessPolicies.ps1](./Export-EXOClientAccessPolicies.ps1) | Exports the OWA, mobile device, authentication and role assignment policies to JSON files with a CSV index and usage counts. | View-Only Configuration + View-Only Recipients (or Global Reader) | No |
| [Get-EXOCasMailboxProtocolReport.ps1](./Get-EXOCasMailboxProtocolReport.ps1) | Reports which client access protocols (POP, IMAP, SMTP AUTH, ActiveSync, EWS, MAPI, OWA, Outlook clients) each mailbox can use. | View-Only Recipients + View-Only Configuration (or Global Reader) | No |
| [Get-EXOMobileDevicesReport.ps1](./Get-EXOMobileDevicesReport.ps1) | Reports every mobile device partnership (ActiveSync and Outlook mobile) with owner, platform, access state and last sync. | View-Only Recipients + View-Only Configuration (or Global Reader) | No |
| [Get-EXOSmtpAuthAndBasicAuthReport.ps1](./Get-EXOSmtpAuthAndBasicAuthReport.ps1) | Reports which mailboxes can still use SMTP AUTH, the authentication policies in force, and how to close the remaining gaps. | View-Only Configuration + View-Only Recipients (or Global Reader) | No |
| [Remove-EXOStaleMobileDevices.ps1](./Remove-EXOStaleMobileDevices.ps1) | Finds mobile device partnerships that have not synced for a long time and optionally removes them or wipes the account data. | Exchange Administrator (Organization Client Access role) for -Remove; View-Only Recipients for the report | Optional (-Remove) |
| [Set-EXODisableLegacyProtocols.ps1](./Set-EXODisableLegacyProtocols.ps1) | Disables legacy client protocols (POP, IMAP, SMTP AUTH, ActiveSync, EWS) on mailboxes and optionally at the organization level. | Exchange Administrator (Organization Configuration role for -OrgLevel); View-Only Recipients for the report | Yes (`-WhatIf` supported) |

## Administration, audit & migration

| Script | What it does | Permissions / roles | Changes anything? |
|---|---|---|---|
| [Get-EXOAdminChangesAudit.ps1](./Get-EXOAdminChangesAudit.ps1) | Reports the Exchange Online admin cmdlets that were run (who, what, on which object, from where) from the unified audit log. | Audit Logs or View-Only Audit Logs role (Organization Management / Compliance Management) in Exchange Online | No |
| [Get-EXOAdminRoleAssignments.ps1](./Get-EXOAdminRoleAssignments.ps1) | Reports who holds Exchange Online admin permissions through role groups and direct management role assignments. | View-Only Organization Management (or Global Reader); View-Only Recipients for -CheckAccountStatus | No |
| [Get-EXOMigrationBatchStatus.ps1](./Get-EXOMigrationBatchStatus.ps1) | Reports the status of Exchange Online migration batches and, optionally, of every user inside them. | Migration role (Recipient Management or Organization Management role group), or Exchange Administrator | No |
| [Get-EXONonOwnerMailboxAccess.ps1](./Get-EXONonOwnerMailboxAccess.ps1) | Reports mailbox actions performed by someone other than the mailbox owner (admins and delegates) from the unified audit log. | Audit Logs or View-Only Audit Logs role (Organization Management / Compliance Management) in Exchange Online | No |
| [Get-EXOPublicFolderReport.ps1](./Get-EXOPublicFolderReport.ps1) | Reports the public folder hierarchy with sizes, item counts, mail-enabled addresses, stale folders and the public folder mailboxes. | Public Folders role (Organization Management or Public Folder Management role group) + View-Only Configuration | No |

## Quick start

```powershell
# Convert-EXOMailboxToShared.ps1
.\Convert-EXOMailboxToShared.ps1 -Identity jsmith@contoso.com -ToShared -HideFromAddressList -GrantFullAccessTo manager@contoso.com -NoAutoMapping

# Get-EXOEmailAddressReport.ps1
.\Get-EXOEmailAddressReport.ps1 -Address sales@contoso.com

# Get-EXOCalendarPermissionsReport.ps1
.\Get-EXOCalendarPermissionsReport.ps1 -InputCsv .\Executives.csv -PassThru | Where-Object { $_.Finding }

# Add-EXODistributionGroupMembers.ps1
.\Add-EXODistributionGroupMembers.ps1 -InputCsv .\Leavers.csv -Remove -Apply -Confirm:$false
```

## Notes

- Connect once with `Connect-ExchangeOnline`; the scripts reuse an existing session.
- Per-mailbox loops (folder statistics, inbox rules, calendar permissions) are slow in large tenants - use `-Identity` or `-InputCsv` to scope them.
- Reports need **View-Only Recipients** or **Global Reader**; changes need **Exchange Administrator** (or the specific RBAC role named in the header).

---

Back to the [repository overview](../README.md).
