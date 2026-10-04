<#
.SYNOPSIS
    Reports Purview event-based retention: event types, the labels that depend on them and the retention events raised.
.DESCRIPTION
    Connects to Security & Compliance PowerShell and reads every retention event type (Get-ComplianceRetentionEventType)
    and every retention event (Get-ComplianceRetentionEvent). Retention labels (Get-ComplianceTag) are matched to their
    event type so each type shows how many labels it drives. Writes RetentionEventTypes.csv and RetentionEvents.csv
    into -OutputFolder and prints a summary. With -NewEvent the script first creates a retention event
    (New-ComplianceRetentionEvent) for an event type, asset id and event date, wrapped in ShouldProcess, and the new
    event then appears in the report.
.PARAMETER OutputFolder
    Folder that receives the two CSV files. Defaults to .\PurviewRetentionEvents_yyyyMMdd-HHmm\ (created if missing).
.PARAMETER NewEvent
    Create a retention event before reporting. Requires -EventTypeName, -EventName and -AssetId.
.PARAMETER EventTypeName
    Name of the existing retention event type the new event belongs to.
.PARAMETER EventName
    Display name of the new retention event, for example 'Project Alpine closed'.
.PARAMETER AssetId
    Property:Value pair that identifies the content in SharePoint and OneDrive, for example 'ProductName:Alpine'.
.PARAMETER EventDate
    Date the event occurred; retention periods of matching content start from this date. Defaults to now.
.PARAMETER PassThru
    Also emit the retention event rows to the pipeline.
.EXAMPLE
    PS> .\Get-PurviewRetentionEvents.ps1
    Exports event types (with dependent labels) and retention events to .\PurviewRetentionEvents_<timestamp>\.
.EXAMPLE
    PS> .\Get-PurviewRetentionEvents.ps1 -NewEvent -EventTypeName 'Employee departure' -EventName 'Departure - EMP1234' -AssetId 'EmployeeId:1234' -EventDate '2026-09-30'
    Raises a retention event for the departed employee's content (after confirmation) and then exports the report.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, ExchangeOnlineManagement 3.x
    Permissions : View-Only Retention Management (report) or Retention Management (-NewEvent) role in Security & Compliance
                  PowerShell; event-based retention requires Microsoft 365 E5 / E5 Compliance licensing
    Category    : Retention & records management
    Changes     : Optional (-NewEvent)
    Notes       : Opens a Security & Compliance PowerShell session (Connect-IPPSSession). A retention event only affects
                  content that already carries a label of the matching event type; the AssetId must match a document
                  property (SharePoint/OneDrive) - use -ExchangeAssetIDQuery / -SharePointAssetIDQuery on the cmdlet
                  directly for keyword queries. Events are processed asynchronously and can take up to 7 days to
                  propagate. Events cannot be deleted once created.
.LINK
    https://learn.microsoft.com/powershell/module/exchangepowershell/get-complianceretentionevent
.LINK
    https://learn.microsoft.com/purview/event-driven-retention
#>
#Requires -Version 5.1
#Requires -Modules ExchangeOnlineManagement

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter()]
    [string]$OutputFolder,

    [Parameter()]
    [switch]$NewEvent,

    [Parameter()]
    [string]$EventTypeName,

    [Parameter()]
    [string]$EventName,

    [Parameter()]
    [string]$AssetId,

    [Parameter()]
    [datetime]$EventDate = (Get-Date),

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

function ConvertTo-NameList {
    <# Joins a value or collection of values/objects (using their Name when present) into a ';' separated string. #>
    [CmdletBinding()]
    param([Parameter()][AllowNull()]$Value)
    $names = @(foreach ($item in @($Value)) {
            if ($null -eq $item) { continue }
            if ($null -ne $item.PSObject.Properties['Name'] -and -not [string]::IsNullOrWhiteSpace([string]$item.Name)) { [string]$item.Name } else { [string]$item }
        })
    return ($names -join ';')
}

function Test-EventTypeReference {
    <# True when an EventType value (name or GUID, single value or collection) refers to the given event type. #>
    [CmdletBinding()]
    param(
        [Parameter()][AllowNull()]$Value,
        [Parameter(Mandatory = $true)]$Type
    )
    $tokens = @((ConvertTo-NameList -Value $Value) -split ';' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    return (($tokens -contains [string]$Type.Name) -or ($tokens -contains [string]$Type.Guid))
}
#endregion Helpers

#region Main
if ($NewEvent -and ([string]::IsNullOrWhiteSpace($EventTypeName) -or [string]::IsNullOrWhiteSpace($EventName) -or [string]::IsNullOrWhiteSpace($AssetId))) {
    throw '-NewEvent requires -EventTypeName, -EventName and -AssetId.'
}
if ([string]::IsNullOrWhiteSpace($OutputFolder)) {
    $OutputFolder = Join-Path -Path (Get-Location).Path -ChildPath ('PurviewRetentionEvents_{0}' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
if (-not (Test-Path -Path $OutputFolder)) { New-Item -Path $OutputFolder -ItemType Directory -Force | Out-Null }
$OutputFolder = (Resolve-Path -Path $OutputFolder).Path

try { Connect-ExchangeIfNeeded -Compliance }
catch { throw "Unable to connect to Security & Compliance PowerShell: $($_.Exception.Message)" }

try { $eventTypes = @(Get-ComplianceRetentionEventType -ErrorAction Stop) }
catch { throw "Failed to retrieve retention event types: $($_.Exception.Message)" }
try { $labels = @(Get-ComplianceTag -ErrorAction Stop | Where-Object { -not [string]::IsNullOrWhiteSpace((ConvertTo-NameList -Value $_.EventType)) }) }
catch { throw "Failed to retrieve retention labels: $($_.Exception.Message)" }

$eventCreated = $false
if ($NewEvent) {
    $eventType = @($eventTypes | Where-Object { $_.Name -eq $EventTypeName -or [string]$_.Guid -eq $EventTypeName })
    if ($eventType.Count -eq 0) { throw "Retention event type '$EventTypeName' was not found. Existing types: $(($eventTypes | ForEach-Object { $_.Name }) -join ', ')" }
    $dependentLabels = @($labels | Where-Object { Test-EventTypeReference -Value $_.EventType -Type $eventType[0] })
    if ($dependentLabels.Count -eq 0) { Write-Warning "No retention label uses event type '$($eventType[0].Name)' - the event will not affect any content." }
    $target = "Retention event '$EventName' (type '$($eventType[0].Name)', asset '$AssetId', date $($EventDate.ToString('yyyy-MM-dd')))"
    if ($PSCmdlet.ShouldProcess($target, 'Create retention event')) {
        try {
            New-ComplianceRetentionEvent -Name $EventName -EventType $eventType[0].Name -AssetId $AssetId -EventDateTime $EventDate -ErrorAction Stop | Out-Null
            $eventCreated = $true
            Write-Host "Retention event '$EventName' created." -ForegroundColor Green
        }
        catch { Write-Warning "Failed to create retention event '$EventName': $($_.Exception.Message)" }
    }
}

try { $events = @(Get-ComplianceRetentionEvent -ErrorAction Stop) }
catch { throw "Failed to retrieve retention events: $($_.Exception.Message)" }

$typeRows = New-Object -TypeName System.Collections.Generic.List[object]
foreach ($type in ($eventTypes | Sort-Object -Property Name)) {
    $typeLabels = @($labels | Where-Object { Test-EventTypeReference -Value $_.EventType -Type $type })
    $typeEvents = @($events | Where-Object { Test-EventTypeReference -Value $_.EventType -Type $type })
    $typeRows.Add([PSCustomObject]@{
            Name        = [string]$type.Name
            Guid        = [string]$type.Guid
            Description = [string]$type.Description
            Comment     = [string]$type.Comment
            CreatedBy   = [string]$type.CreatedBy
            WhenCreated = $type.WhenCreated
            WhenChanged = $type.WhenChanged
            LabelCount  = $typeLabels.Count
            Labels      = (@($typeLabels | ForEach-Object { [string]$_.Name } | Sort-Object) -join ';')
            EventCount  = $typeEvents.Count
        })
}

$eventRows = New-Object -TypeName System.Collections.Generic.List[object]
foreach ($event in ($events | Sort-Object -Property EventDateTime -Descending)) {
    $eventRows.Add([PSCustomObject]@{
            Name                   = [string]$event.Name
            Guid                   = [string]$event.Guid
            EventType              = ConvertTo-NameList -Value $event.EventType
            EventDateTime          = $event.EventDateTime
            AssetId                = [string]$event.AssetId
            SharePointAssetIdQuery = [string]$event.SharePointAssetIdQuery
            ExchangeAssetIdQuery   = [string]$event.ExchangeAssetIdQuery
            EventStatus            = [string]$event.EventStatus
            Comment                = [string]$event.Comment
            CreatedBy              = [string]$event.CreatedBy
            WhenCreated            = $event.WhenCreated
        })
}

if ($typeRows.Count -gt 0) { $typeRows | Export-Csv -Path (Join-Path -Path $OutputFolder -ChildPath 'RetentionEventTypes.csv') -NoTypeInformation -Encoding UTF8 }
if ($eventRows.Count -gt 0) { $eventRows | Export-Csv -Path (Join-Path -Path $OutputFolder -ChildPath 'RetentionEvents.csv') -NoTypeInformation -Encoding UTF8 }

$unusedTypes = @($typeRows | Where-Object { $_.LabelCount -eq 0 }).Count
Write-Host "`nEvent-based retention summary" -ForegroundColor Cyan
Write-Host ('  Event types            : {0} ({1} without any label)' -f $typeRows.Count, $unusedTypes) -ForegroundColor $(if ($unusedTypes -gt 0) { 'Yellow' } else { 'Gray' })
Write-Host ('  Event-based labels     : {0}' -f $labels.Count)
$since = (Get-Date).AddDays(-30)
$recentEvents = @($eventRows | Where-Object { $_.WhenCreated -is [datetime] -and $_.WhenCreated -gt $since }).Count
Write-Host ('  Retention events       : {0} ({1} created in the last 30 days)' -f $eventRows.Count, $recentEvents)
if ($NewEvent) { Write-Host ('  New event created      : {0}' -f $eventCreated) }
Write-Host ('  Output folder          : {0}' -f $OutputFolder)

if ($PassThru) {
    $eventRows
}
#endregion Main
