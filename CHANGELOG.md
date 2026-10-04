# Changelog

All notable changes to this repository are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the scripts use semantic versioning in their `.NOTES` block.

## [1.1.0] - 2026-10-04
### Added
- Expanded every product folder to 50+ scripts (365 scripts in total: Microsoft Intune 53, Microsoft Entra ID 52, Microsoft Defender 54, Exchange Online 53, Microsoft Purview 51, Microsoft Teams, SharePoint & OneDrive 51, Microsoft 365 tenant 50).
- Intune: remote actions, wipe/retire, diagnostics collection, BitLocker and LAPS secrets, hardware inventory, setting-level compliance,
  profile status, unused policies, assignment filters, scope tags, RBAC export, endpoint security export, Settings Catalog search,
  backup compare and restore, app export, app protection policies and status, app configuration, app relationships, connector health,
  Autopilot import/update/remove and profile export, enrollment configurations, Windows Update policies, generic report export,
  Windows version report, remediation scripts and results, audit events, Cloud PC, tenant summary, Android and Apple platform reports.
- Entra ID: user inventory and lifecycle, bulk create/update/offboard, deleted users, password expiry, authentication methods, MFA reset,
  Temporary Access Pass, group inventory and membership tooling, dynamic rules, nested groups, device inventory and clean-up, sign-in
  and audit log analysis, legacy authentication, risky users, provisioning logs, break-glass validation, enterprise app inventory,
  permissions and consent, SAML certificates, app role assignments, app registration security audit, PIM history and settings,
  custom roles, administrative units, access reviews, entitlement management, tenant security settings, cross-tenant access, guest invitations, sync status.
- Defender: Defender for Office 365 policy reports and export, allow/block lists, quarantine, email authentication (SPF/DKIM/DMARC),
  spoof intelligence, threat reports, alert and incident management, incident timeline, alert trends, attack simulation, Secure Score history,
  Defender for Identity health and sensors, Advanced Hunting scenarios, Defender for Endpoint API (machines, actions, isolation, scans,
  investigation packages, app restriction, exposure score, tags, indicators, vulnerabilities), onboarding gap analysis.
- Exchange Online: inactive and shared mailboxes, conversions, archives, holds, auditing, soft-deleted mailboxes, mailbox plans, folder sizes,
  recoverable items, quotas, regional settings, auto-replies, email addresses, inbox rules, calendar permissions, room mailboxes and booking,
  distribution group reports and tooling, transport rules, connectors, domains, message trace, historical search, mail flow reports,
  journaling, organization config, client access protocols, mobile devices, client access policies, admin roles, admin audit, non-owner access, migrations, public folders.
- Purview: auto-labeling, label usage, label import, label hierarchy, IRM/OME, sensitive information types and testing, DLP incidents,
  health, modes, matrix, endpoint settings, EDM, overrides, DLP alerts, retention policies and labels, distribution status, adaptive scopes,
  retention events, mailbox holds, eDiscovery cases, content search, export, search and purge, case holds, case members, eDiscovery audit,
  audit configuration and scenario searches, Graph audit queries, insider risk, communication compliance, information barriers, compliance roles.
- Teams & SharePoint: team reports and lifecycle, ownerless and archived teams, channels, membership tooling, user membership, bulk team creation,
  installed apps and catalog, team settings, usage reports, rooms, tags, Teams policy assignments/export/grant, phone numbers, voice users,
  call queues and auto attendants, external access, app policies, meeting settings, SharePoint sharing and admin reports, external users,
  tenant settings, hub sites, deleted sites, site admins, orphaned sites, OneDrive inventory, Graph site/file/list/sharing/activity reports.
- Tenant: license assignment and paths, group-based licensing errors, service plans, subscriptions, direct-to-group migration, usage location,
  SKU catalog, Copilot licensing, license audit, usage and adoption reports, tenant settings snapshot, organization info, domains,
  SharePoint tenant settings, report privacy, service health history, Message Center digest and triage, Microsoft 365 Groups governance,
  onboarding/offboarding, cross-workload activity, external collaboration summary, tenant scorecard, directory size, automation app registration,
  Graph permission diagnostics, report mailer, admin contacts audit.
### Changed
- Folder READMEs and the root script index are now generated from the script headers (`Category` and `Changes` fields added to `.NOTES`).

## [1.0.0] - 2026-10-03
### Added
- **Intune:** device compliance inventory, stale device clean-up, policy backup to JSON, policy/app assignment matrix,
  app install status, bulk device sync, Autopilot registration health, Defender Antivirus status.
- **Entra ID:** MFA registration posture, stale guest accounts, Conditional Access backup and summary,
  privileged role membership (active and PIM-eligible), app registration credential expiry.
- **Defender:** Secure Score gap analysis, Defender XDR alerts report, incidents report.
- **Exchange Online:** mailbox size and quota report, external forwarding detection (with optional remediation),
  delegated mailbox permissions audit.
- **Purview:** sensitivity label and label policy export, DLP policy and rule export, unified audit log search beyond the 5,000-row limit.
- **Teams & SharePoint:** inactive teams, guest access report, SharePoint and OneDrive storage report.
- **Tenant:** license consumption and waste report, service health and Message Center report.
- **Tooling:** prerequisite installer, PSScriptAnalyzer settings and GitHub Actions lint workflow.
