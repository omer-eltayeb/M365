<#
.SYNOPSIS
    Tests which Purview sensitive information types match a text or plain-text file, or lists the available types.
.DESCRIPTION
    Runs Test-DataClassification in Security & Compliance PowerShell against -TextToClassify or the content of a
    plain-text -FilePath and returns one row per matching sensitive information type (SIT) with count, confidence level
    and matched values, masked by default (first and last two characters kept) unless -ShowMatches is used. -ListTypes
    exports the SIT catalogue (Get-DlpSensitiveInformationType) filtered by -Name wildcard instead. Read-only.
.PARAMETER TextToClassify
    Text to classify, for example a sample credit card number or a sentence containing an employee ID.
.PARAMETER FilePath
    Plain-text file (.txt, .csv, .log, .json) whose content is classified. Office, PDF and MSG files are binary and trigger a warning.
.PARAMETER ClassificationNames
    Restrict the test to these sensitive information types (names or GUIDs). Default: every published SIT.
.PARAMETER ShowMatches
    Write the matched values unmasked to the console, CSV and pipeline.
.PARAMETER ListTypes
    List the sensitive information types available in the tenant instead of classifying text.
.PARAMETER Name
    Wildcard filter on the SIT name with -ListTypes, for example 'Credit*' or '*Passport*'. Default '*'.
.PARAMETER OutputPath
    Path of the CSV report. Defaults to .\Reports\PurviewSitTest_yyyyMMdd-HHmm.csv (or PurviewSitCatalog_ with -ListTypes).
.PARAMETER PassThru
    Also emit the result rows to the pipeline.
.EXAMPLE
    PS> .\Test-PurviewSensitiveInfoType.ps1 -TextToClassify 'Card 4111 1111 1111 1111 expires 12/27, SSN 123-45-6789'
    Shows which built-in SITs fire on the sample text, with masked matches, and writes the CSV.
.EXAMPLE
    PS> .\Test-PurviewSensitiveInfoType.ps1 -FilePath .\sample.txt -ClassificationNames 'Contoso Employee ID' -ShowMatches
    Tests a custom SIT against a file and reveals the exact strings it matched - ideal after New-PurviewCustomSensitiveInfoType.ps1.
.EXAMPLE
    PS> .\Test-PurviewSensitiveInfoType.ps1 -ListTypes -Name '*Passport*' -PassThru | Select-Object Name, Publisher, RecommendedConfidence
    Lists every passport-related sensitive information type in the tenant.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, ExchangeOnlineManagement 3.x
    Permissions : Compliance Administrator, Compliance Data Administrator or Information Protection Admin; Global Reader is sufficient
    Category    : Information protection
    Changes     : No
    Notes       : Opens a Security & Compliance PowerShell session (Connect-IPPSSession). Test-DataClassification accepts plain
                  text only; use Test-TextExtraction -FileData to extract text from Office, PDF and MSG files first. Newly created
                  or edited custom SITs can take several minutes to become testable; trainable classifiers are not evaluated.
.LINK
    https://learn.microsoft.com/powershell/module/exchange/test-dataclassification
.LINK
    https://learn.microsoft.com/powershell/module/exchange/get-dlpsensitiveinformationtype
#>
#Requires -Version 5.1
#Requires -Modules ExchangeOnlineManagement

[CmdletBinding(DefaultParameterSetName = 'Text')]
param(
    [Parameter(Mandatory = $true, ParameterSetName = 'Text', Position = 0)]
    [ValidateNotNullOrEmpty()]
    [string]$TextToClassify,

    [Parameter(Mandatory = $true, ParameterSetName = 'File')]
    [ValidateScript({ Test-Path -Path $_ -PathType Leaf })]
    [string]$FilePath,

    [Parameter(ParameterSetName = 'Text')]
    [Parameter(ParameterSetName = 'File')]
    [string[]]$ClassificationNames,

    [Parameter(ParameterSetName = 'Text')]
    [Parameter(ParameterSetName = 'File')]
    [switch]$ShowMatches,

    [Parameter(Mandatory = $true, ParameterSetName = 'List')]
    [switch]$ListTypes,

    [Parameter(ParameterSetName = 'List')]
    [string]$Name = '*',

    [Parameter()]
    [string]$OutputPath,

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

function Get-DetectionValues {
    <# Collects the matched strings from SensitiveInformationDetections; the nesting of its Value members differs between module versions. #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [AllowNull()]
        $Detections
    )
    $values = @()
    foreach ($detection in @($Detections)) {
        if ($null -eq $detection) { continue }
        if ($detection -is [string]) { $values += $detection; continue }
        $inner = $detection.PSObject.Properties['Value']
        if ($null -ne $inner) { $values += @(Get-DetectionValues -Detections $inner.Value) }
    }
    return $values
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $prefix = $(if ($ListTypes) { 'PurviewSitCatalog' } else { 'PurviewSitTest' })
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('{0}_{1}.csv' -f $prefix, (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}

try { Connect-ExchangeIfNeeded -Compliance }
catch { throw "Unable to connect to Security & Compliance PowerShell: $($_.Exception.Message)" }

$rows = New-Object -TypeName System.Collections.Generic.List[object]
if ($ListTypes) {
    try { $types = @(Get-DlpSensitiveInformationType -ErrorAction Stop | Where-Object { $_.Name -like $Name } | Sort-Object -Property Publisher, Name) }
    catch { throw "Get-DlpSensitiveInformationType failed: $($_.Exception.Message)" }
    foreach ($type in $types) {
        $description = [string]$type.Description
        if ($description.Length -gt 160) { $description = $description.Substring(0, 157) + '...' }
        $rows.Add([PSCustomObject]@{
                Name                  = [string]$type.Name
                Publisher             = [string]$type.Publisher
                Type                  = [string]$type.Type
                Description           = $description
                RecommendedConfidence = $type.RecommendedConfidence
                Id                    = [string]$type.Id
            })
    }
    if ($rows.Count -gt 0) { $rows | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 } else { Write-Warning "No sensitive information type matches '$Name'." }
    Write-Host ''
    Write-Host 'Sensitive information type catalogue' -ForegroundColor Cyan
    Write-Host ('  Types matching {0,-12}: {1}' -f "'$Name'", $rows.Count)
    foreach ($group in ($rows | Group-Object -Property Publisher | Sort-Object -Property Count -Descending)) { Write-Host ('    {0,5}  {1}' -f $group.Count, $group.Name) }
    Write-Host ('  Report                      : {0}' -f $OutputPath)
}
else {
    $source = 'Text'
    $text = $TextToClassify
    if ($PSCmdlet.ParameterSetName -eq 'File') {
        $source = (Resolve-Path -Path $FilePath).Path
        # Plain text never contains NUL bytes; Office, PDF and MSG files do, and the classifier would only see garbage.
        if ([System.Array]::IndexOf([System.IO.File]::ReadAllBytes($source), [byte]0) -ge 0) {
            Write-Warning "$FilePath looks like a binary file. Test-DataClassification needs plain text; extract it first with Test-TextExtraction -FileData."
        }
        $text = [System.IO.File]::ReadAllText($source)
    }
    if ([string]::IsNullOrWhiteSpace($text)) { throw 'There is no text to classify.' }

    $testParams = @{ TextToClassify = $text; ErrorAction = 'Stop' }
    if ($PSBoundParameters.ContainsKey('ClassificationNames')) { $testParams['ClassificationNames'] = $ClassificationNames }
    try { $response = Test-DataClassification @testParams }
    catch { throw "Test-DataClassification failed: $($_.Exception.Message)" }

    foreach ($result in @($response.ClassificationResults | Sort-Object -Property ConfidenceLevel, Count -Descending)) {
        $matchValues = @(Get-DetectionValues -Detections $result.SensitiveInformationDetections | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        if (-not $ShowMatches) {
            # Keep the first and last two characters so the report stays shareable but still recognisable.
            $matchValues = @($matchValues | ForEach-Object { if ($_.Length -le 4) { '*' * $_.Length } else { $_.Substring(0, 2) + ('*' * ($_.Length - 4)) + $_.Substring($_.Length - 2) } })
        }
        $rows.Add([PSCustomObject]@{
                ClassificationName = [string]$result.ClassificationName
                Count              = $result.Count
                ConfidenceLevel    = $result.ConfidenceLevel
                Matches            = ($matchValues -join '; ')
                MatchesMasked      = (-not $ShowMatches)
                Source             = $source
            })
    }
    if ($rows.Count -gt 0) { $rows | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 }
    else { Write-Warning 'No sensitive information type matched. New or edited custom SITs can take several minutes to become testable.' }

    Write-Host ''
    Write-Host 'Sensitive information type test' -ForegroundColor Cyan
    Write-Host ('  Input          : {0} ({1:N0} characters)' -f $source, $text.Length)
    Write-Host ('  Types matched  : {0}' -f $rows.Count) -ForegroundColor $(if ($rows.Count -gt 0) { 'Yellow' } else { 'Green' })
    foreach ($row in $rows) { Write-Host ('    {0,-45} count {1,3}  confidence {2,3}  {3}' -f $row.ClassificationName, $row.Count, $row.ConfidenceLevel, $row.Matches) }
    if ($rows.Count -gt 0) { Write-Host ('  Report         : {0}{1}' -f $OutputPath, $(if ($ShowMatches) { ' (contains unmasked matches)' } else { '' })) }
}

if ($PassThru) {
    $rows
}
#endregion Main
