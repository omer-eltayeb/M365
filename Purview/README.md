# Microsoft Purview scripts

Microsoft Purview compliance scripts: sensitivity labels and auto-labeling, DLP policies and incidents, retention policies and labels, eDiscovery and content search, unified audit log scenarios, insider risk, communication compliance, information barriers and compliance roles.

**51 scripts.** Module(s): `ExchangeOnlineManagement` v3 - Security & Compliance PowerShell (`Connect-IPPSSession`) for policies, Exchange Online for the unified audit log; a few scripts use Microsoft Graph.

Every script has full comment-based help (`Get-Help .\<Script>.ps1 -Full`), writes a timestamped CSV to `.\Reports\` by default (`-OutputPath` to choose, `-PassThru` to keep the objects) and is read-only unless the **Changes anything?** column says otherwise - those scripts support `-WhatIf` / `-Confirm`.

## Contents

- [Information protection](#information-protection) (10)
- [Data loss prevention](#data-loss-prevention) (10)
- [Retention & records management](#retention--records-management) (9)
- [eDiscovery & content search](#ediscovery--content-search) (9)
- [Audit log scenarios](#audit-log-scenarios) (9)
- [Risk, compliance & roles](#risk-compliance--roles) (4)

## Information protection

| Script | What it does | Permissions / roles | Changes anything? |
|---|---|---|---|
| [Export-PurviewSensitivityLabels.ps1](./Export-PurviewSensitivityLabels.ps1) | Documents Microsoft Purview sensitivity labels and label policies to CSV and JSON. | Compliance Administrator, Compliance Data Administrator, Information Protection Reader or Global Reader | No |
| [Get-PurviewAutoLabelingPolicies.ps1](./Get-PurviewAutoLabelingPolicies.ps1) | Documents Microsoft Purview auto-labeling policies and their rules to CSV and JSON. | Compliance Administrator, Compliance Data Administrator or Information Protection Admin; Global Reader is sufficient | No |
| [Get-PurviewIRMConfiguration.ps1](./Get-PurviewIRMConfiguration.ps1) | Audits the Exchange Online IRM / Azure Rights Management configuration against recommended values. | Organization Configuration role (Exchange Online) for Set-IRMConfiguration; View-Only Organization Management is enough for the report | Optional (-SetRecommended) |
| [Get-PurviewLabelHierarchy.ps1](./Get-PurviewLabelHierarchy.ps1) | Prints the sensitivity label tree (parents and sub-labels) and exports it with publishing status to CSV. | Compliance Administrator, Compliance Data Administrator or Information Protection Admin; Global Reader is sufficient | No |
| [Get-PurviewLabelPolicySettings.ps1](./Get-PurviewLabelPolicySettings.ps1) | Builds a settings matrix of every sensitivity label policy (mandatory labeling, default labels, scopes, distribution). | Compliance Administrator, Compliance Data Administrator or Information Protection Admin; Global Reader is sufficient | No |
| [Get-PurviewLabelUsageFromAudit.ps1](./Get-PurviewLabelUsageFromAudit.ps1) | Reports sensitivity label activity (applied, changed, removed) from the unified audit log. | Audit Logs or View-Only Audit Logs role (Exchange Online); Compliance Administrator, Information Protection Admin or Global Reader for label resolution | No |
| [Get-PurviewOMEConfiguration.ps1](./Get-PurviewOMEConfiguration.ps1) | Documents Microsoft Purview Message Encryption (OME) branding templates and the transport rules that use them. | Organization Configuration role (Exchange Online) for -Set; View-Only Organization Management is enough for the report | Optional (-Set) |
| [Import-PurviewSensitivityLabels.ps1](./Import-PurviewSensitivityLabels.ps1) | Bulk-creates Microsoft Purview sensitivity labels from a CSV file and optionally publishes them in a label policy. | Compliance Administrator, Compliance Data Administrator or Information Protection Admin (Security & Compliance PowerShell) | Yes (`-WhatIf` supported) |
| [New-PurviewCustomSensitiveInfoType.ps1](./New-PurviewCustomSensitiveInfoType.ps1) | Builds a Purview rule package XML for a custom sensitive information type and optionally uploads it. | Compliance Administrator or Compliance Data Administrator (Security & Compliance PowerShell) for -Create; none to build the XML | Optional (-Create) |
| [Test-PurviewSensitiveInfoType.ps1](./Test-PurviewSensitiveInfoType.ps1) | Tests which Purview sensitive information types match a text or plain-text file, or lists the available types. | Compliance Administrator, Compliance Data Administrator or Information Protection Admin; Global Reader is sufficient | No |

## Data loss prevention

| Script | What it does | Permissions / roles | Changes anything? |
|---|---|---|---|
| [Export-PurviewDLPPolicies.ps1](./Export-PurviewDLPPolicies.ps1) | Documents Microsoft Purview DLP policies and their rules to CSV and JSON. | Compliance Administrator, Compliance Data Administrator or Global Reader | No |
| [Export-PurviewDlpRulesMatrix.ps1](./Export-PurviewDlpRulesMatrix.ps1) | Exports a one-row-per-rule matrix of all Purview DLP rules with their conditions, exceptions and actions. | Compliance Administrator, Compliance Data Administrator or a role group with View-Only DLP Compliance Management | No |
| [Get-PurviewDlpAlertsViaGraph.ps1](./Get-PurviewDlpAlertsViaGraph.ps1) | Lists Microsoft Purview DLP alerts through the Microsoft Graph security API and optionally resolves them. | Delegated SecurityAlert.Read.All (report) or SecurityAlert.ReadWrite.All (-Resolve) plus Security Reader / Operator | Optional (-Resolve) |
| [Get-PurviewDlpIncidentsFromAudit.ps1](./Get-PurviewDlpIncidentsFromAudit.ps1) | Reports Purview DLP rule matches from the unified audit log for Exchange, SharePoint/OneDrive and endpoint devices. | Audit Logs or View-Only Audit Logs role (Exchange Online); unified audit logging must be enabled | No |
| [Get-PurviewDlpOverridesAndFalsePositives.ps1](./Get-PurviewDlpOverridesAndFalsePositives.ps1) | Reports DLP policy-tip overrides and false-positive reports from the unified audit log and highlights rules that need tuning. | Audit Logs or View-Only Audit Logs role (Exchange Online); unified audit logging must be enabled | No |
| [Get-PurviewDlpPolicyHealth.ps1](./Get-PurviewDlpPolicyHealth.ps1) | Checks every Purview DLP policy for configuration problems and reports findings with a severity. | Compliance Administrator, Compliance Data Administrator or a role group with View-Only DLP Compliance Management | No |
| [Get-PurviewEdmSchemas.ps1](./Get-PurviewEdmSchemas.ps1) | Reports exact data match (EDM) schemas, their fields and the EDM sensitive information types that use them. | Compliance Administrator, Compliance Data Administrator or Global Reader | No |
| [Get-PurviewEndpointDlpSettings.ps1](./Get-PurviewEndpointDlpSettings.ps1) | Documents the tenant-wide Endpoint DLP settings (exclusions, restricted apps and browsers, service domains, device groups). | Compliance Administrator, Compliance Data Administrator or a role group with View-Only DLP Compliance Management | No |
| [Get-PurviewSensitiveInfoTypes.ps1](./Get-PurviewSensitiveInfoTypes.ps1) | Inventories sensitive information types (SITs), their rule packages and the DLP / auto-labeling rules that use them. | Compliance Administrator, Compliance Data Administrator or Global Reader | No |
| [Set-PurviewDlpPolicyMode.ps1](./Set-PurviewDlpPolicyMode.ps1) | Switches Purview DLP policies between test and enforcement modes, in bulk and with a before/after report. | View-Only DLP Compliance Management for the report; DLP Compliance Management (Compliance Administrator) for -Apply | Yes (`-WhatIf` supported) |

## Retention & records management

| Script | What it does | Permissions / roles | Changes anything? |
|---|---|---|---|
| [Export-PurviewRetentionLabels.ps1](./Export-PurviewRetentionLabels.ps1) | Documents Microsoft Purview retention labels, their file plan descriptors and where each label is published or auto-applied. | Retention Management or View-Only Retention Management role (Compliance Administrator, Records Management or Global Reader role groups) in Security & Compliance PowerShell | No |
| [Export-PurviewRetentionPolicies.ps1](./Export-PurviewRetentionPolicies.ps1) | Documents Microsoft Purview retention policies and their retention rules to CSV and JSON. | Retention Management or View-Only Retention Management role (Compliance Administrator, Records Management or Global Reader role groups) in Security & Compliance PowerShell | No |
| [Get-PurviewAdaptiveScopes.ps1](./Get-PurviewAdaptiveScopes.ps1) | Reports Microsoft Purview adaptive scopes, their queries and the retention policies that use them. | Retention Management or View-Only Retention Management role (Compliance Administrator, Records Management or Global Reader role groups) in Security & Compliance PowerShell | No |
| [Get-PurviewMailboxHolds.ps1](./Get-PurviewMailboxHolds.ps1) | Decodes every hold on Exchange Online mailboxes (litigation, eDiscovery, retention policies, label and delay holds) into named rows. | View-Only Recipients (Exchange Online) plus View-Only Retention Management and eDiscovery Manager or View-Only Case in Security & Compliance PowerShell (to resolve policy and case hold names) | No |
| [Get-PurviewRetentionEvents.ps1](./Get-PurviewRetentionEvents.ps1) | Reports Purview event-based retention: event types, the labels that depend on them and the retention events raised. | View-Only Retention Management (report) or Retention Management (-NewEvent) role in Security & Compliance PowerShell; event-based retention requires Microsoft 365 E5 / E5 Compliance licensing | Optional (-NewEvent) |
| [Get-PurviewRetentionLabelUsageFromAudit.ps1](./Get-PurviewRetentionLabelUsageFromAudit.ps1) | Reports retention label activity (applied, removed, changed, record declared) from the unified audit log. | Audit Logs or View-Only Audit Logs role (Exchange Online); View-Only Retention Management for the label lookup. Unified audit logging must be enabled (Get-AdminAuditLogConfig \| Select-Object UnifiedAuditLogIngestionEnabled). | No |
| [Get-PurviewRetentionLabelsViaGraph.ps1](./Get-PurviewRetentionLabelsViaGraph.ps1) | Reports Microsoft Purview retention labels (and optionally event types and events) through the Microsoft Graph records management API. | RecordsManagement.Read.All (delegated; the records management API has no application permissions) | No |
| [Get-PurviewRetentionPolicyDistributionStatus.ps1](./Get-PurviewRetentionPolicyDistributionStatus.ps1) | Reports the distribution status of Purview retention policies (optionally DLP and label policies) and can retry failed ones. | View-Only Retention Management (report) or Retention Management / DLP Compliance Management / Sensitivity Label Administrator (with -Retry) in Security & Compliance PowerShell | Optional (-Retry) |
| [New-PurviewRetentionLabels.ps1](./New-PurviewRetentionLabels.ps1) | Bulk-creates Microsoft Purview retention labels from a CSV file and optionally publishes them in a label policy. | Retention Management role (Compliance Administrator or Records Management role group) in Security & Compliance PowerShell | Yes (`-WhatIf` supported) |

## eDiscovery & content search

| Script | What it does | Permissions / roles | Changes anything? |
|---|---|---|---|
| [Add-PurviewEDiscoveryCaseMembers.ps1](./Add-PurviewEDiscoveryCaseMembers.ps1) | Adds, removes or replaces the members of eDiscovery cases, skipping existing members and warning about users outside the eDiscovery Manager role group. | eDiscovery Manager (member of the case) or eDiscovery Administrator in Security & Compliance PowerShell; reading the role group needs the Role Management or View-Only Configuration role. | Yes (`-WhatIf` supported) |
| [Export-PurviewContentSearchResults.ps1](./Export-PurviewContentSearchResults.ps1) | Starts an export of a completed content search and returns the container URL, SAS token and item counts needed to download it. | eDiscovery Manager role group (Export role) in Security & Compliance PowerShell; case membership for case searches | Yes (`-WhatIf` supported) |
| [Get-PurviewCaseHolds.ps1](./Get-PurviewCaseHolds.ps1) | Reports every eDiscovery case hold with its locations, rule query and distribution status, flagging holds that need attention. | eDiscovery Manager role group (only cases you are a member of) or eDiscovery Administrator (all cases) | No |
| [Get-PurviewContentSearchResults.ps1](./Get-PurviewContentSearchResults.ps1) | Reports Purview content searches with status, item counts and size, optionally with per-location statistics and a result preview. | eDiscovery Manager role group (Compliance Search role; the Preview role for -Preview) in Security & Compliance PowerShell | Optional (-Preview) |
| [Get-PurviewEDiscoveryActivityAudit.ps1](./Get-PurviewEDiscoveryActivityAudit.ps1) | Reports who did what in eDiscovery and content search (searches, previews, exports, purges, case and hold changes) from the unified audit log. | Audit Logs or View-Only Audit Logs role (Exchange Online PowerShell session); unified audit logging must be enabled | No |
| [Get-PurviewEDiscoveryCases.ps1](./Get-PurviewEDiscoveryCases.ps1) | Reports eDiscovery (Standard) and eDiscovery (Premium) cases with members, hold and search counts, and flags stale open cases. | eDiscovery Manager role group (Security & Compliance PowerShell). An eDiscovery Manager only sees the cases they are a member of; an eDiscovery Administrator sees every case. | No |
| [Get-PurviewEDiscoveryCasesViaGraph.ps1](./Get-PurviewEDiscoveryCasesViaGraph.ps1) | Reports eDiscovery (Premium) cases through Microsoft Graph, optionally with custodians, legal holds, searches and review sets. | Delegated eDiscovery.Read.All; the signed-in user must be an eDiscovery Manager (own cases) or eDiscovery Administrator (all cases) in Microsoft Purview. | No |
| [Invoke-PurviewSearchAndPurge.ps1](./Invoke-PurviewSearchAndPurge.ps1) | Purges the mailbox items found by a completed content search (soft or hard delete), optionally repeating until nothing is left. | Search And Purge role (Organization Management or Data Investigator role group) plus eDiscovery Manager for the search | Yes (`-WhatIf` supported) |
| [New-PurviewContentSearch.ps1](./New-PurviewContentSearch.ps1) | Creates and starts a Purview content search from a KQL query or simple mail criteria, optionally waiting for the results. | eDiscovery Manager role group (Compliance Search role) in Security & Compliance PowerShell; case membership for -Case | Yes (`-WhatIf` supported) |

## Audit log scenarios

| Script | What it does | Permissions / roles | Changes anything? |
|---|---|---|---|
| [Get-PurviewAuditConfiguration.ps1](./Get-PurviewAuditConfiguration.ps1) | Reports the Microsoft Purview audit configuration and can switch unified audit log ingestion on. | Exchange Online View-Only Organization Management to report (Organization Management for -EnableAuditing); Purview Audit Logs or Organization Configuration role to read audit retention policies | Optional (-EnableAuditing) |
| [Get-PurviewAuditLogViaGraph.ps1](./Get-PurviewAuditLogViaGraph.ps1) | Runs a Microsoft Purview audit log search through the Microsoft Graph Audit Search API and exports the records. | AuditLogsQuery.Read.All (delegated; a workload-specific AuditLogsQuery-*.Read.All scope also works) plus the Audit Logs or View-Only Audit Logs role in Purview | No |
| [Search-PurviewAuditAdminRoleChanges.ps1](./Search-PurviewAuditAdminRoleChanges.ps1) | Reports Entra ID directory role membership changes (and optionally group membership changes) from the unified audit log. | Audit Logs or View-Only Audit Logs role (Exchange Online / Purview); unified audit log ingestion must be enabled | No |
| [Search-PurviewAuditFileActivity.ps1](./Search-PurviewAuditFileActivity.ps1) | Reports SharePoint and OneDrive file activity (access, download, delete, move, upload) from the unified audit log. | Audit Logs or View-Only Audit Logs role (Exchange Online / Purview); unified audit log ingestion must be enabled | No |
| [Search-PurviewAuditLog.ps1](./Search-PurviewAuditLog.ps1) | Exports unified audit log records reliably, beyond the 5,000-row limit of a single Search-UnifiedAuditLog call. | Audit Logs or View-Only Audit Logs role (Exchange Online / Purview); auditing must be enabled (Get-AdminAuditLogConfig \| Select-Object UnifiedAuditLogIngestionEnabled) | No |
| [Search-PurviewAuditMailItemsAccessed.ps1](./Search-PurviewAuditMailItemsAccessed.ps1) | Reports MailItemsAccessed mailbox audit events (who read which mail, from where) for compromised-account investigations. | Audit Logs or View-Only Audit Logs role (Exchange Online / Purview); unified audit log ingestion must be enabled | No |
| [Search-PurviewAuditSharingEvents.ps1](./Search-PurviewAuditSharingEvents.ps1) | Reports SharePoint and OneDrive sharing events (invitations, links, permission grants) from the unified audit log. | Audit Logs or View-Only Audit Logs role (Exchange Online / Purview); unified audit log ingestion must be enabled | No |
| [Search-PurviewAuditTeamsActivity.ps1](./Search-PurviewAuditTeamsActivity.ps1) | Reports Microsoft Teams lifecycle, membership, channel, app and settings events from the unified audit log. | Audit Logs or View-Only Audit Logs role (Exchange Online / Purview); unified audit log ingestion must be enabled | No |
| [Search-PurviewAuditUserTimeline.ps1](./Search-PurviewAuditUserTimeline.ps1) | Builds a cross-workload activity timeline for one or more users from the unified audit log. | Audit Logs or View-Only Audit Logs role (Exchange Online / Purview); unified audit log ingestion must be enabled | No |

## Risk, compliance & roles

| Script | What it does | Permissions / roles | Changes anything? |
|---|---|---|---|
| [Get-PurviewCommunicationCompliancePolicies.ps1](./Get-PurviewCommunicationCompliancePolicies.ps1) | Documents Microsoft Purview Communication Compliance policies and their rules (reviewers, sampling, conditions). | Communication Compliance or Communication Compliance Admins role group (Supervisory Review Administrator role) in Microsoft Purview | No |
| [Get-PurviewComplianceRoleGroups.ps1](./Get-PurviewComplianceRoleGroups.ps1) | Reports Microsoft Purview (Security & Compliance) role groups, their roles and members, plus the eDiscovery case admins. | Role Management role (Organization Management or Compliance Administrator role group) in Security & Compliance PowerShell; Get-eDiscoveryCaseAdmin needs eDiscovery Manager or Organization Management; -CheckAccountStatus needs Exchange Online View-Only Recipients | No |
| [Get-PurviewInformationBarriers.ps1](./Get-PurviewInformationBarriers.ps1) | Documents information barrier segments, policies and application status, tests a recipient pair and can start policy application. | Compliance Administrator or IB Compliance Management role (Security & Compliance PowerShell); -TestRecipients needs an Exchange Online session with View-Only Recipients or higher | Optional (-Apply) |
| [Get-PurviewInsiderRiskPolicies.ps1](./Get-PurviewInsiderRiskPolicies.ps1) | Documents Microsoft Purview Insider Risk Management policies (scenario, mode, scope, time spans, indicators). | Insider Risk Management or Insider Risk Management Admins role group in Microsoft Purview (Security & Compliance PowerShell) | No |

## Quick start

```powershell
# Export-PurviewSensitivityLabels.ps1
.\Export-PurviewSensitivityLabels.ps1 -PassThru | Where-Object { $_.EncryptionEnabled } | Select-Object DisplayName, ParentLabel, Priority

# Export-PurviewDLPPolicies.ps1
.\Export-PurviewDLPPolicies.ps1 -PassThru | Where-Object { $_.BlockAccess } | Select-Object ParentPolicyName, Name, SensitiveInformation

# Export-PurviewRetentionLabels.ps1
.\Export-PurviewRetentionLabels.ps1 -OutputFolder C:\Docs\Purview\Labels -PassThru | Where-Object { $_.Flags -match 'NotPublished' } | Select-Object Name, RetentionAction, RetentionYears

# Add-PurviewEDiscoveryCaseMembers.ps1
.\Add-PurviewEDiscoveryCaseMembers.ps1 -CaseName 'HR-42' -ReplaceWith hr-lead@contoso.com -Confirm:$false
```

## Notes

- Most scripts open a Security & Compliance PowerShell session; the audit log scripts use the Exchange Online session (`Search-UnifiedAuditLog`).
- Audit retention is 180 days by default (1 year / 10 years with Audit (Premium) retention policies); some events such as `MailItemsAccessed` need Audit (Premium).
- Roles: **Compliance Administrator** / **Compliance Data Administrator** for policy work, **eDiscovery Manager** for cases and searches, **Audit Logs** / **View-Only Audit Logs** for audit searches.

---

Back to the [repository overview](../README.md).
