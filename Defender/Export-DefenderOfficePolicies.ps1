<#
.SYNOPSIS
    Backs up every Exchange Online Protection and Defender for Office 365 threat policy to JSON files with an index CSV.
.DESCRIPTION
    Connects to Exchange Online and exports the tenant's threat policies one policy type per file: anti-phishing,
    inbound anti-spam, outbound spam, anti-malware, Safe Links and Safe Attachments (policies and their rules), the
    global Defender for Office 365 settings (Get-AtpPolicyForO365), connection filter and quarantine policies, the
    preset security policy rules (Standard, Strict and Built-in protection), the DKIM signing configuration and the
    Tenant Allow/Block List entries for senders, URLs and file hashes.
    Every collection is serialised with ConvertTo-Json -Depth 8 to <PolicyType>.json inside -OutputFolder and
    Index.csv lists each file with its object count, object names and export status. Cmdlets that do not exist in
    the tenant (EOP-only tenants have no Safe Links or Safe Attachments cmdlets) produce a warning and are skipped.
    The script is read-only.
.PARAMETER OutputFolder
    Folder that receives the JSON files and Index.csv. Defaults to .\DefenderOfficeExport_yyyyMMdd-HHmm\ (created if missing).
.PARAMETER PassThru
    Also emit the Index.csv rows (PolicyType, FileName, Count, Names, Status) to the pipeline.
.EXAMPLE
    PS> .\Export-DefenderOfficePolicies.ps1
    Exports all policy types into .\DefenderOfficeExport_<timestamp>\ and prints a per-type summary.
.EXAMPLE
    PS> .\Export-DefenderOfficePolicies.ps1 -OutputFolder D:\Backups\MDO\Before-Preset -Verbose
    Exports into a fixed folder, for example before enabling a preset security policy so the settings can be compared afterwards.
.EXAMPLE
    PS> .\Export-DefenderOfficePolicies.ps1 -PassThru | Where-Object { $_.Status -ne 'Exported' }
    Lists the policy types that were skipped (cmdlet not available) or failed.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, ExchangeOnlineManagement 3.x
    Permissions : Security Administrator or Exchange Administrator; Security Reader or Global Reader is enough for this read-only export
    Category    : Defender for Office 365 policies
    Changes     : No
    Notes       : Safe Links, Safe Attachments, Get-AtpPolicyForO365 and the Defender preset rules require Defender for
                  Office 365 Plan 1 or 2; EOP-only tenants still export the anti-spam, anti-malware and anti-phishing
                  basics, quarantine and connection filter policies, DKIM and the Tenant Allow/Block List. The JSON files
                  are a point-in-time baseline for documentation and change comparison (Compare-Object two exports),
                  not a restore package - the objects contain read-only properties that New-*/Set-* cmdlets reject.
.LINK
    https://learn.microsoft.com/defender-office-365/recommended-settings-for-eop-and-office365
.LINK
    https://learn.microsoft.com/powershell/module/exchange/get-tenantallowblocklistitems
#>
#Requires -Version 5.1
#Requires -Modules ExchangeOnlineManagement

[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputFolder,

    [Parameter()]
    [switch]$PassThru
)

$ErrorActionPreference = 'Stop'

#region Helpers
function Connect-ExchangeIfNeeded {
    <# Connects to Exchange Online (or Security & Compliance PowerShell) only when no live session exists. #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [switch]$Compliance
    )
    $connections = @(Get-ConnectionInformation -ErrorAction SilentlyContinue)
    if ($Compliance) {
        $active = @($connections | Where-Object { $_.ConnectionUri -like '*compliance*' -and $_.State -eq 'Connected' })
        if ($active.Count -eq 0) {
            Write-Verbose 'Connecting to Security & Compliance PowerShell.'
            Connect-IPPSSession -ErrorAction Stop
        }
    }
    else {
        $active = @($connections | Where-Object { $_.ConnectionUri -notlike '*compliance*' -and $_.State -eq 'Connected' })
        if ($active.Count -eq 0) {
            Write-Verbose 'Connecting to Exchange Online.'
            Connect-ExchangeOnline -ShowBanner:$false -ErrorAction Stop
        }
    }
}

function Export-JsonFile {
    <# Serialises the raw objects to UTF-8 JSON without a BOM so any tooling can consume the file. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$InputObject,

        [Parameter(Mandatory = $true)]
        [string]$Path
    )
    $json = ConvertTo-Json -InputObject @($InputObject) -Depth 8
    [System.IO.File]::WriteAllText($Path, $json, (New-Object -TypeName System.Text.UTF8Encoding -ArgumentList $false))
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputFolder)) {
    $OutputFolder = Join-Path -Path (Get-Location).Path -ChildPath ('DefenderOfficeExport_{0}' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
if (-not (Test-Path -Path $OutputFolder)) {
    New-Item -Path $OutputFolder -ItemType Directory -Force | Out-Null
}
$OutputFolder = (Resolve-Path -Path $OutputFolder).Path

try {
    Connect-ExchangeIfNeeded
}
catch {
    throw "Unable to connect to Exchange Online: $($_.Exception.Message)"
}

# One entry per export file. Arguments are splatted onto the cmdlet (the Tenant Allow/Block List needs a ListType).
$collections = @(
    @{ Type = 'AntiPhishPolicy'; Command = 'Get-AntiPhishPolicy' }
    @{ Type = 'AntiPhishRule'; Command = 'Get-AntiPhishRule' }
    @{ Type = 'HostedContentFilterPolicy'; Command = 'Get-HostedContentFilterPolicy' }
    @{ Type = 'HostedContentFilterRule'; Command = 'Get-HostedContentFilterRule' }
    @{ Type = 'HostedOutboundSpamFilterPolicy'; Command = 'Get-HostedOutboundSpamFilterPolicy' }
    @{ Type = 'HostedOutboundSpamFilterRule'; Command = 'Get-HostedOutboundSpamFilterRule' }
    @{ Type = 'MalwareFilterPolicy'; Command = 'Get-MalwareFilterPolicy' }
    @{ Type = 'MalwareFilterRule'; Command = 'Get-MalwareFilterRule' }
    @{ Type = 'SafeLinksPolicy'; Command = 'Get-SafeLinksPolicy' }
    @{ Type = 'SafeLinksRule'; Command = 'Get-SafeLinksRule' }
    @{ Type = 'SafeAttachmentPolicy'; Command = 'Get-SafeAttachmentPolicy' }
    @{ Type = 'SafeAttachmentRule'; Command = 'Get-SafeAttachmentRule' }
    @{ Type = 'AtpPolicyForO365'; Command = 'Get-AtpPolicyForO365' }
    @{ Type = 'HostedConnectionFilterPolicy'; Command = 'Get-HostedConnectionFilterPolicy' }
    @{ Type = 'QuarantinePolicy'; Command = 'Get-QuarantinePolicy' }
    @{ Type = 'GlobalQuarantinePolicy'; Command = 'Get-QuarantinePolicy'; Arguments = @{ QuarantinePolicyType = 'GlobalQuarantinePolicy' } }
    @{ Type = 'EOPProtectionPolicyRule'; Command = 'Get-EOPProtectionPolicyRule' }
    @{ Type = 'ATPProtectionPolicyRule'; Command = 'Get-ATPProtectionPolicyRule' }
    @{ Type = 'ATPBuiltInProtectionRule'; Command = 'Get-ATPBuiltInProtectionRule' }
    @{ Type = 'DkimSigningConfig'; Command = 'Get-DkimSigningConfig' }
    @{ Type = 'TenantAllowBlockListSender'; Command = 'Get-TenantAllowBlockListItems'; Arguments = @{ ListType = 'Sender' } }
    @{ Type = 'TenantAllowBlockListUrl'; Command = 'Get-TenantAllowBlockListItems'; Arguments = @{ ListType = 'Url' } }
    @{ Type = 'TenantAllowBlockListFileHash'; Command = 'Get-TenantAllowBlockListItems'; Arguments = @{ ListType = 'FileHash' } }
)

$index = New-Object -TypeName System.Collections.Generic.List[object]
$position = 0
foreach ($collection in $collections) {
    $position++
    Write-Progress -Activity 'Exporting Defender for Office 365 policies' -Status $collection.Type -PercentComplete (($position / $collections.Count) * 100)
    $fileName = '{0}.json' -f $collection.Type
    $items = @()
    $status = 'Exported'

    if ($null -eq (Get-Command -Name $collection.Command -ErrorAction SilentlyContinue)) {
        # The REST module only loads the cmdlets the tenant's licences and the admin's RBAC roles allow.
        Write-Warning ('{0} is not available in this tenant or session (Defender for Office 365 licence or RBAC role missing); {1} skipped.' -f $collection.Command, $collection.Type)
        $status = 'NotAvailable'
        $fileName = $null
    }
    else {
        $arguments = @{}
        if ($null -ne $collection.Arguments) { $arguments = $collection.Arguments }
        try {
            $items = @(& $collection.Command @arguments -ErrorAction Stop)
            Export-JsonFile -InputObject $items -Path (Join-Path -Path $OutputFolder -ChildPath $fileName)
            Write-Verbose ('{0}: {1} object(s) written to {2}' -f $collection.Type, $items.Count, $fileName)
        }
        catch {
            Write-Warning ('{0} failed for {1}: {2}' -f $collection.Command, $collection.Type, $_.Exception.Message)
            $status = 'Failed'
            $fileName = $null
        }
    }

    # Policies have a Name, Tenant Allow/Block List entries a Value and DKIM configs a Domain.
    $names = @(foreach ($item in $items) {
            $label = $null
            foreach ($candidate in 'Name', 'Value', 'Domain', 'Identity') {
                if (-not [string]::IsNullOrWhiteSpace([string]$item.$candidate)) { $label = [string]$item.$candidate; break }
            }
            if ($null -ne $label) { $label }
        })
    $nameText = ($names | Select-Object -First 25) -join '; '
    if ($names.Count -gt 25) { $nameText = '{0}; ... (+{1} more)' -f $nameText, ($names.Count - 25) }

    $index.Add([PSCustomObject]@{
            PolicyType = $collection.Type
            FileName   = $fileName
            Count      = $items.Count
            Names      = $nameText
            Status     = $status
        })
}
Write-Progress -Activity 'Exporting Defender for Office 365 policies' -Completed

$indexPath = Join-Path -Path $OutputFolder -ChildPath 'Index.csv'
$index | Export-Csv -Path $indexPath -NoTypeInformation -Encoding UTF8

$exported = @($index | Where-Object { $_.Status -eq 'Exported' })
$skipped = @($index | Where-Object { $_.Status -eq 'NotAvailable' })
$failed = @($index | Where-Object { $_.Status -eq 'Failed' })

Write-Host ''
Write-Host 'Defender for Office 365 policy export summary' -ForegroundColor Cyan
Write-Host ('  Policy types exported : {0} of {1}' -f $exported.Count, $index.Count)
Write-Host ('  Objects exported      : {0}' -f [int](($exported | Measure-Object -Property Count -Sum).Sum))
Write-Host ('  Not available         : {0}' -f $skipped.Count) -ForegroundColor $(if ($skipped.Count -gt 0) { 'Yellow' } else { 'Green' })
Write-Host ('  Failed                : {0}' -f $failed.Count) -ForegroundColor $(if ($failed.Count -gt 0) { 'Red' } else { 'Green' })
foreach ($row in $exported) {
    Write-Host ('    {0,-32}: {1}' -f $row.PolicyType, $row.Count)
}
Write-Host ('  Output folder         : {0}' -f $OutputFolder)

if ($PassThru) {
    $index
}
#endregion Main
