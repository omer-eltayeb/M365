# Microsoft Defender scripts

Security operations scripts across Microsoft Defender XDR (alerts, incidents, Secure Score, attack simulation, Defender for Identity), Defender for Office 365 (protection policies, quarantine, allow/block lists, email authentication), Advanced Hunting through Microsoft Graph, and the Microsoft Defender for Endpoint API (device inventory, response actions, indicators, vulnerabilities).

**54 scripts.** Module(s): Microsoft Graph PowerShell SDK for XDR, hunting and Secure Score; `ExchangeOnlineManagement` for Defender for Office 365; the Defender for Endpoint REST API (app-only, client credentials) for the `*-MDE*` scripts.

Every script has full comment-based help (`Get-Help .\<Script>.ps1 -Full`), writes a timestamped CSV to `.\Reports\` by default (`-OutputPath` to choose, `-PassThru` to keep the objects) and is read-only unless the **Changes anything?** column says otherwise - those scripts support `-WhatIf` / `-Confirm`.

## Contents

- [Defender XDR alerts & incidents](#defender-xdr-alerts--incidents) (7)
- [Secure Score](#secure-score) (2)
- [Attack simulation training](#attack-simulation-training) (2)
- [Defender for Identity](#defender-for-identity) (2)
- [Advanced hunting (Graph)](#advanced-hunting-graph) (11)
- [Defender for Endpoint API](#defender-for-endpoint-api) (11)
- [Defender for Office 365 policies](#defender-for-office-365-policies) (10)
- [Email threat operations](#email-threat-operations) (9)

## Defender XDR alerts & incidents

| Script | What it does | Permissions / roles | Changes anything? |
|---|---|---|---|
| [Add-DefenderIncidentComment.ps1](./Add-DefenderIncidentComment.ps1) | Adds the same analyst comment to one or more Microsoft Defender XDR incidents or alerts. | SecurityIncident.ReadWrite.All for incidents, SecurityAlert.ReadWrite.All for alerts (delegated); Security Operator or Security Administrator in Microsoft Defender XDR. | Yes (`-WhatIf` supported) |
| [Get-DefenderAlertsReport.ps1](./Get-DefenderAlertsReport.ps1) | Reports alerts from Microsoft Defender XDR (unified alerts API) for the last N days. | SecurityAlert.Read.All (delegated); the signed-in user needs Security Reader, Security Operator or Security Administrator in Microsoft Defender XDR. | No |
| [Get-DefenderAlertsTrend.ps1](./Get-DefenderAlertsTrend.ps1) | Trends Microsoft Defender XDR alerts over time: volume by severity, source, category and title, MTTR and false-positive rate. | SecurityAlert.Read.All (delegated); Security Reader, Security Operator or Security Administrator in Defender XDR. | No |
| [Get-DefenderIncidentTimeline.ps1](./Get-DefenderIncidentTimeline.ps1) | Builds a chronological timeline of one Microsoft Defender XDR incident: alerts, typed evidence and comments. | SecurityIncident.Read.All and SecurityAlert.Read.All (delegated); Security Reader, Security Operator or Security Administrator in Microsoft Defender XDR. | No |
| [Get-DefenderIncidentsReport.ps1](./Get-DefenderIncidentsReport.ps1) | Reports Microsoft Defender XDR incidents for triage, including how long each one has been open. | SecurityIncident.Read.All (delegated); the signed-in user needs Security Reader, Security Operator or Security Administrator in Microsoft Defender XDR. | No |
| [Update-DefenderAlerts.ps1](./Update-DefenderAlerts.ps1) | Bulk-updates Microsoft Defender XDR alerts: status, classification, determination and assignment. | SecurityAlert.ReadWrite.All (delegated); Security Operator or Security Administrator in Defender XDR. | Yes (`-WhatIf` supported) |
| [Update-DefenderIncidents.ps1](./Update-DefenderIncidents.ps1) | Bulk-updates Microsoft Defender XDR incidents: status, classification, determination, owner and custom tags. | SecurityIncident.ReadWrite.All (delegated); Security Operator or Security Administrator in Defender XDR. | Yes (`-WhatIf` supported) |

## Secure Score

| Script | What it does | Permissions / roles | Changes anything? |
|---|---|---|---|
| [Get-DefenderSecureScore.ps1](./Get-DefenderSecureScore.ps1) | Shows the current Microsoft Secure Score and the improvement actions with the largest remaining point gap. | SecurityEvents.Read.All (delegated); the signed-in user needs Security Reader, Security Administrator or Global Reader. | No |
| [Get-DefenderSecureScoreHistory.ps1](./Get-DefenderSecureScoreHistory.ps1) | Trends Microsoft Secure Score over the retained daily snapshots and explains score drops at control level. | SecurityEvents.Read.All (delegated); Security Reader, Security Administrator or Global Reader. | No |

## Attack simulation training

| Script | What it does | Permissions / roles | Changes anything? |
|---|---|---|---|
| [Get-DefenderAttackSimulationUserResults.ps1](./Get-DefenderAttackSimulationUserResults.ps1) | Reports per-user results of Attack simulation training campaigns and finds repeat offenders across simulations. | AttackSimulation.Read.All (+ User.Read.All with -IncludeDepartment); Attack Simulation Administrator or Security Reader. | No |
| [Get-DefenderAttackSimulations.ps1](./Get-DefenderAttackSimulations.ps1) | Reports Attack simulation training campaigns with their click, compromise and report rates. | AttackSimulation.Read.All (delegated); Attack Simulation Administrator, Security Reader or Security Administrator. | No |

## Defender for Identity

| Script | What it does | Permissions / roles | Changes anything? |
|---|---|---|---|
| [Get-DefenderIdentityHealthIssues.ps1](./Get-DefenderIdentityHealthIssues.ps1) | Reports Microsoft Defender for Identity health issues (sensor and global) with severity, affected domains and fixes. | SecurityIdentitiesHealth.Read.All (delegated); Security Reader, Security Operator or Security Administrator. | No |
| [Get-DefenderIdentitySensors.ps1](./Get-DefenderIdentitySensors.ps1) | Inventories Microsoft Defender for Identity sensors and flags unhealthy, outdated or misconfigured ones. | SecurityIdentitiesSensors.Read.All and SecurityIdentitiesHealth.Read.All (delegated); Security Reader, Security Operator or Security Administrator. | No |

## Advanced hunting (Graph)

| Script | What it does | Permissions / roles | Changes anything? |
|---|---|---|---|
| [Get-DefenderDeviceInventory.ps1](./Get-DefenderDeviceInventory.ps1) | Exports the Defender for Endpoint device inventory (latest DeviceInfo record per device) with sensor health and onboarding status. | ThreatHunting.Read.All (delegated); the signed-in user also needs Security Reader or another Defender XDR role with advanced hunting access. | No |
| [Get-DefenderDevicesNotOnboarded.ps1](./Get-DefenderDevicesNotOnboarded.ps1) | Reconciles Intune-managed Windows, macOS and Linux devices against Defender for Endpoint to find devices that are not onboarded or not reporting. | ThreatHunting.Read.All, DeviceManagementManagedDevices.Read.All (delegated); Security Reader or another Defender XDR role with advanced hunting access, plus Intune read access (for example Intune Read Only Operator). | No |
| [Get-DefenderIdentityLogonHunt.ps1](./Get-DefenderIdentityLogonHunt.ps1) | Hunts Defender for Identity logon telemetry for password spray sources, NTLM usage and interactive logons by service accounts. | ThreatHunting.Read.All (delegated); the signed-in user also needs Security Reader or another Defender XDR role with advanced hunting access. | No |
| [Get-DefenderPhishingEmailsHunt.ps1](./Get-DefenderPhishingEmailsHunt.ps1) | Hunts phishing and malware emails detected by Defender for Office 365, with delivery outcome, policies applied and optional URL clicks. | ThreatHunting.Read.All (delegated); the signed-in user also needs Security Reader or another Defender XDR role with advanced hunting access. | No |
| [Get-DefenderRemoteLogonsHunt.ps1](./Get-DefenderRemoteLogonsHunt.ps1) | Hunts remote (RDP and network) logon attempts per device and source IP to surface brute-force patterns and external access. | ThreatHunting.Read.All (delegated); the signed-in user also needs Security Reader or another Defender XDR role with advanced hunting access. | No |
| [Get-DefenderSecurityRecommendations.ps1](./Get-DefenderSecurityRecommendations.ps1) | Reports failed Defender Vulnerability Management security configuration checks with impact, risk, remediation and affected device counts. | ThreatHunting.Read.All (delegated); the signed-in user also needs Security Reader or another Defender XDR role with advanced hunting access. | No |
| [Get-DefenderSoftwareInventory.ps1](./Get-DefenderSoftwareInventory.ps1) | Exports the Defender Vulnerability Management software inventory with device counts, versions in use and end-of-support status. | ThreatHunting.Read.All (delegated); the signed-in user also needs Security Reader or another Defender XDR role with advanced hunting access. | No |
| [Get-DefenderSuspiciousPowerShellHunt.ps1](./Get-DefenderSuspiciousPowerShellHunt.ps1) | Hunts suspicious PowerShell executions (encoded, hidden, download-cradle and Defender-tampering command lines) across onboarded devices. | ThreatHunting.Read.All (delegated); the signed-in user also needs Security Reader or another Defender XDR role with advanced hunting access. | No |
| [Get-DefenderUsbDeviceUsageHunt.ps1](./Get-DefenderUsbDeviceUsageHunt.ps1) | Hunts USB drive mounts and removable device connections across onboarded devices, with product, manufacturer and serial number. | ThreatHunting.Read.All (delegated); the signed-in user also needs Security Reader or another Defender XDR role with advanced hunting access. | No |
| [Get-DefenderVulnerableSoftware.ps1](./Get-DefenderVulnerableSoftware.ps1) | Reports vulnerable software found by Defender Vulnerability Management: CVEs per software version with CVSS, exploit availability and device counts. | ThreatHunting.Read.All (delegated); the signed-in user also needs Security Reader or another Defender XDR role with advanced hunting access. | No |
| [Invoke-DefenderHuntingQuery.ps1](./Invoke-DefenderHuntingQuery.ps1) | Runs any Advanced Hunting KQL query against Microsoft Defender XDR through Microsoft Graph and exports the rows to CSV. | ThreatHunting.Read.All (delegated); the signed-in user also needs Security Reader or another Defender XDR role with advanced hunting access. | No |

## Defender for Endpoint API

| Script | What it does | Permissions / roles | Changes anything? |
|---|---|---|---|
| [Get-MDEExposureScore.ps1](./Get-MDEExposureScore.ps1) | Shows the Defender Vulnerability Management exposure score, Secure Score for Devices and exposure by device group, with top recommendations. | Application permissions Score.Read.All and, for -IncludeRecommendations, SecurityRecommendation.Read.All granted with admin consent to an app registration. | No |
| [Get-MDEIndicators.ps1](./Get-MDEIndicators.ps1) | Exports the Microsoft Defender for Endpoint custom indicators (IoCs) with expiry analysis and hygiene flags. | Application permission Ti.ReadWrite.All (or Ti.Read.All) granted with admin consent to an app registration. | No |
| [Get-MDEMachineActionsHistory.ps1](./Get-MDEMachineActionsHistory.ps1) | Reports the Microsoft Defender for Endpoint response actions (isolation, scans, packages...) submitted in the last N days. | Application permission Machine.Read.All to report; cancelling also needs the permission of the action type (Machine.Isolate, Machine.Scan, Machine.CollectForensics, Machine.RestrictExecution, Machine.LiveResponse...), granted with admin consent. | Optional (-CancelPending) |
| [Get-MDEMachineVulnerabilities.ps1](./Get-MDEMachineVulnerabilities.ps1) | Reports the vulnerabilities (CVEs) found on devices by Microsoft Defender Vulnerability Management, per device or aggregated per CVE. | Application permissions Vulnerability.Read.All and Machine.Read.All granted with admin consent to an app registration. | No |
| [Get-MDEMachines.ps1](./Get-MDEMachines.ps1) | Exports the Microsoft Defender for Endpoint device inventory with sensor health, risk and exposure details. | Application permission Machine.Read.All (WindowsDefenderATP API) granted with admin consent to an app registration. | No |
| [Import-MDEIndicators.ps1](./Import-MDEIndicators.ps1) | Bulk-imports custom indicators (IoCs) into Microsoft Defender for Endpoint from a CSV, or deletes the listed indicators. | Application permission Ti.ReadWrite.All granted with admin consent to an app registration. | Yes (`-WhatIf` supported) |
| [Invoke-MDEAntivirusScan.ps1](./Invoke-MDEAntivirusScan.ps1) | Starts a Microsoft Defender Antivirus quick or full scan on devices through the Defender for Endpoint API. | Application permissions Machine.Scan and Machine.Read.All (device lookup) granted with admin consent to an app registration. | Yes (`-WhatIf` supported) |
| [Invoke-MDECollectInvestigationPackage.ps1](./Invoke-MDECollectInvestigationPackage.ps1) | Collects Microsoft Defender for Endpoint investigation packages from devices and optionally downloads the ZIP files. | Application permissions Machine.CollectForensics and Machine.Read.All (device lookup), admin consent required; the API reference also lists Machine.ReadWrite.All for getPackageUri, grant it as well if the link request is denied. | Yes (`-WhatIf` supported) |
| [Invoke-MDEIsolateDevice.ps1](./Invoke-MDEIsolateDevice.ps1) | Isolates devices from the network with Microsoft Defender for Endpoint, or releases them from isolation. | Application permissions Machine.Isolate and Machine.Read.All (device lookup) granted with admin consent to an app registration. | Yes (`-WhatIf` supported) |
| [Invoke-MDERestrictAppExecution.ps1](./Invoke-MDERestrictAppExecution.ps1) | Restricts app execution on devices with Microsoft Defender for Endpoint (only Microsoft-signed code runs), or lifts the restriction. | Application permissions Machine.RestrictExecution and Machine.Read.All (device lookup) granted with admin consent to an app registration. | Yes (`-WhatIf` supported) |
| [Set-MDEMachineTags.ps1](./Set-MDEMachineTags.ps1) | Adds or removes Microsoft Defender for Endpoint device tags in bulk by machine id, device name or CSV. | Application permission Machine.ReadWrite.All (covers the device lookup) granted with admin consent to an app registration. | Yes (`-WhatIf` supported) |

## Defender for Office 365 policies

| Script | What it does | Permissions / roles | Changes anything? |
|---|---|---|---|
| [Export-DefenderOfficePolicies.ps1](./Export-DefenderOfficePolicies.ps1) | Backs up every Exchange Online Protection and Defender for Office 365 threat policy to JSON files with an index CSV. | Security Administrator or Exchange Administrator; Security Reader or Global Reader is enough for this read-only export | No |
| [Get-DefenderAntiMalwarePolicyReport.ps1](./Get-DefenderAntiMalwarePolicyReport.ps1) | Reports every anti-malware policy with its scope, common attachments filter, zero-hour auto purge and notification settings. | Security Administrator or Exchange Administrator; Security Reader or Global Reader is enough for this read-only report | No |
| [Get-DefenderAntiPhishPolicyReport.ps1](./Get-DefenderAntiPhishPolicyReport.ps1) | Reports every anti-phishing policy with its scope, phishing threshold, impersonation, spoof and DMARC settings. | Security Administrator or Exchange Administrator; Security Reader or Global Reader is enough for this read-only report | No |
| [Get-DefenderAntiSpamPolicyReport.ps1](./Get-DefenderAntiSpamPolicyReport.ps1) | Reports every inbound anti-spam policy with its scope, verdict actions, bulk threshold, ZAP, allow/block lists and ASF settings. | Security Administrator or Exchange Administrator; Security Reader or Global Reader is enough for this read-only report | No |
| [Get-DefenderOutboundSpamPolicyReport.ps1](./Get-DefenderOutboundSpamPolicyReport.ps1) | Reports every outbound spam policy with its sender scope, automatic forwarding mode, recipient limits and notifications. | Security Administrator or Exchange Administrator; Security Reader or Global Reader is enough for this read-only report | No |
| [Get-DefenderPresetSecurityPolicyStatus.ps1](./Get-DefenderPresetSecurityPolicyStatus.ps1) | Reports whether the Standard, Strict and Built-in protection preset security policies are on and who they cover. | Security Administrator or Exchange Administrator; Security Reader or Global Reader is enough for this read-only report | No |
| [Get-DefenderQuarantinePolicies.ps1](./Get-DefenderQuarantinePolicies.ps1) | Reports every quarantine policy with its decoded end-user permissions, notification settings and the threat policies that use it. | Security Administrator or Exchange Administrator; Security Reader or Global Reader is enough for this read-only report | No |
| [Get-DefenderReportSubmissionSettings.ps1](./Get-DefenderReportSubmissionSettings.ps1) | Explains how users can report suspicious messages (user reported settings) and exports every setting as a Setting/Value CSV. | Security Administrator or Exchange Administrator; Security Reader or Global Reader is enough for this read-only report | No |
| [Get-DefenderSafeAttachmentsReport.ps1](./Get-DefenderSafeAttachmentsReport.ps1) | Reports every Safe Attachments policy with its scope and action, plus the global SharePoint, OneDrive, Teams and Safe Documents settings. | Security Administrator or Exchange Administrator; Security Reader or Global Reader is enough for this read-only report | No |
| [Get-DefenderSafeLinksReport.ps1](./Get-DefenderSafeLinksReport.ps1) | Reports every Safe Links policy with its scope and URL protection settings, and shows who is only covered by Built-in protection. | Security Administrator or Exchange Administrator; Security Reader or Global Reader is enough for this read-only report | No |

## Email threat operations

| Script | What it does | Permissions / roles | Changes anything? |
|---|---|---|---|
| [Add-DefenderTenantBlockListEntries.ps1](./Add-DefenderTenantBlockListEntries.ps1) | Bulk-adds block entries (or time-limited allow entries) to the Tenant Allow/Block List from the command line or a CSV file. | Security Administrator (Exchange Online PowerShell session) | Yes (`-WhatIf` supported) |
| [Enable-DefenderDkimForDomains.ps1](./Enable-DefenderDkimForDomains.ps1) | Prepares, enables or rotates DKIM signing for custom accepted domains and prints the CNAME records the DNS team must publish. | Security Administrator or Exchange Administrator (Exchange Online PowerShell session) | Yes (`-WhatIf` supported) |
| [Get-DefenderEmailAuthenticationStatus.ps1](./Get-DefenderEmailAuthenticationStatus.ps1) | Scores SPF, DKIM and DMARC for every accepted domain by combining Exchange Online DKIM settings with live DNS lookups. | Security Reader, Global Reader or View-Only Organization Management (Exchange Online PowerShell session) | No |
| [Get-DefenderMailThreatReports.ps1](./Get-DefenderMailThreatReports.ps1) | Exports the Defender for Office 365 threat protection status as a daily matrix, the mail flow status report and optionally the per-message detail. | Security Reader, Global Reader or Security Administrator (Exchange Online PowerShell session) | No |
| [Get-DefenderQuarantineReport.ps1](./Get-DefenderQuarantineReport.ps1) | Exports quarantined messages with sender, recipients, verdict, policy, release status and expiry, plus a triage summary. | Security Reader, Global Reader or Security Administrator (Exchange Online PowerShell session) | No |
| [Get-DefenderSpoofIntelligence.ps1](./Get-DefenderSpoofIntelligence.ps1) | Reports the senders that spoof intelligence allowed or blocked, joined with the spoofed sender overrides, and flags the risky ones. | Security Reader, Global Reader or Security Administrator (Exchange Online PowerShell session) | No |
| [Get-DefenderTenantAllowBlockList.ps1](./Get-DefenderTenantAllowBlockList.ps1) | Exports the Tenant Allow/Block List (senders, URLs, file hashes, IPv6 addresses and spoofed senders) with expiry and usage flags. | Security Reader, Global Reader or Security Administrator (Exchange Online PowerShell session) | No |
| [Release-DefenderQuarantineMessages.ps1](./Release-DefenderQuarantineMessages.ps1) | Releases (or deletes) quarantined messages by identity, from a CSV, or by an explicit filter, with safety checks per message. | Security Administrator, or the Quarantine Administrator role in Defender for Office 365 (Exchange Online PowerShell session) | Yes (`-WhatIf` supported) |
| [Remove-DefenderExpiredAllowBlockEntries.ps1](./Remove-DefenderExpiredAllowBlockEntries.ps1) | Reports (and with -Remove deletes) expired, aged or explicitly named entries in the Tenant Allow/Block List. | Security Reader or Global Reader for the report; Security Administrator for -Remove | Optional (-Remove) |

## Quick start

```powershell
# Add-DefenderIncidentComment.ps1
.\Add-DefenderIncidentComment.ps1 -AlertId 'da637551227677560813_-961444813' -Comment 'Expected: approved pentest window' -WhatIf

# Get-DefenderSecureScore.ps1
.\Get-DefenderSecureScore.ps1 -PassThru | Where-Object { $_.ImplementationCost -eq 'Low' -and $_.UserImpact -eq 'Low' }

# Get-DefenderAttackSimulationUserResults.ps1
.\Get-DefenderAttackSimulationUserResults.ps1 -SimulationId 'f1b13829-3829-f1b1-2938-b1f12938b1a' -PassThru | Where-Object { $_.IsCompromised } | Select-Object Email, ClickIpAddress

# Get-DefenderIdentityHealthIssues.ps1
.\Get-DefenderIdentityHealthIssues.ps1 -Status all -PassThru | Group-Object -Property DisplayName | Sort-Object -Property Count -Descending
```

## Notes

- Graph security scopes need admin consent; **Security Reader** is enough for reports, **Security Administrator** / **Security Operator** for changes.
- The `*-MDE*` scripts need an app registration with the listed Defender for Endpoint application permissions and a client secret or certificate - see the header of each script.
- Advanced Hunting results are capped at 10,000 rows per query and 30 days of data.

---

Back to the [repository overview](../README.md).
