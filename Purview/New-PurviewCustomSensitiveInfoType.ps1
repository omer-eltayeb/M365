<#
.SYNOPSIS
    Builds a Purview rule package XML for a custom sensitive information type and optionally uploads it.
.DESCRIPTION
    Generates a classification rule package (RulePackage / RulePack / Rules schema) for one custom sensitive
    information type: every -Regex becomes a Pattern at -PatternConfidence and, when -Keywords are supplied, a second
    Pattern per regex that also needs a keyword within -ProximityCharacters at -HighConfidence. GUIDs are generated,
    the regular expressions are validated and the XML is written UTF-16 encoded to -OutputXmlPath. -Create uploads it
    with New-DlpSensitiveInformationTypeRulePackage (ShouldProcess) and -Test classifies a sample afterwards.
.PARAMETER Name
    Name of the sensitive information type as shown in the Purview portal and used in DLP / auto-labeling conditions.
.PARAMETER Description
    Description shown in the portal.
.PARAMETER Regex
    One or more regular expressions that identify the primary element, for example '\bEMP-\d{6}\b'.
.PARAMETER PatternConfidence
    Confidence level (1-100) of a regex match without supporting keywords. Default 75.
.PARAMETER Keywords
    Supporting keywords; a regex match with a keyword nearby is reported at -HighConfidence.
.PARAMETER ProximityCharacters
    Distance in characters within which a keyword must appear (patternsProximity). Default 300.
.PARAMETER HighConfidence
    Confidence level (1-100) of a regex match with a keyword nearby; must exceed -PatternConfidence. Default 85.
.PARAMETER Publisher
    Publisher name written into the rule package. Default 'Custom'.
.PARAMETER OutputXmlPath
    Path of the generated XML. Defaults to .\Reports\PurviewSit_<Name>_yyyyMMdd-HHmm.xml.
.PARAMETER Create
    Upload the rule package and create the sensitive information type. Nothing is changed without it.
.PARAMETER Test
    Sample text classified with Test-DataClassification after a successful -Create.
.EXAMPLE
    PS> .\New-PurviewCustomSensitiveInfoType.ps1 -Name 'Contoso Employee ID' -Regex '\bEMP-\d{6}\b' -Keywords 'employee id', 'staff number'
    Validates the regex and writes the rule package XML for review; nothing is uploaded.
.EXAMPLE
    PS> .\New-PurviewCustomSensitiveInfoType.ps1 -Name 'Project Code' -Regex '\bPRJ-[A-Z]{3}-\d{4}\b' -PatternConfidence 65 -Create -Test 'Budget for PRJ-ABC-1234 attached'
    Creates the type after confirmation and immediately tests it against the sample text.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, ExchangeOnlineManagement 3.x
    Permissions : Compliance Administrator or Compliance Data Administrator (Security & Compliance PowerShell) for -Create; none to build the XML
    Category    : Information protection
    Changes     : Optional (-Create)
    Notes       : The classification engine is RE2-based: lookarounds, back-references and lazy quantifiers are not supported and the
                  script warns about them. The package is validated server-side on upload. A new type can take several minutes to
                  replicate before -Test matches. Update an existing package with Set-DlpSensitiveInformationTypeRulePackage.
.LINK
    https://learn.microsoft.com/purview/sit-create-a-custom-sensitive-information-type-in-scc-powershell
.LINK
    https://learn.microsoft.com/powershell/module/exchange/new-dlpsensitiveinformationtyperulepackage
#>
#Requires -Version 5.1
#Requires -Modules ExchangeOnlineManagement

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [string]$Name,
    [Parameter()] [string]$Description = 'Custom sensitive information type created with PowerShell.',
    [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [string[]]$Regex,
    [Parameter()] [ValidateRange(1, 100)] [int]$PatternConfidence = 75,
    [Parameter()] [string[]]$Keywords,
    [Parameter()] [ValidateRange(1, 10000)] [int]$ProximityCharacters = 300,
    [Parameter()] [ValidateRange(1, 100)] [int]$HighConfidence = 85,
    [Parameter()] [string]$Publisher = 'Custom',
    [Parameter()] [string]$OutputXmlPath,
    [Parameter()] [switch]$Create,
    [Parameter()] [string]$Test
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

function Add-XmlElement {
    <# Appends a child element in the rule package namespace, with optional attributes and text, and returns it. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [System.Xml.XmlNode]$Parent,
        [Parameter(Mandatory = $true)] [string]$Name,
        [Parameter()] [hashtable]$Attributes = @{},
        [Parameter()] [string]$Text
    )
    $document = $(if ($Parent -is [System.Xml.XmlDocument]) { $Parent } else { $Parent.OwnerDocument })
    $element = $document.CreateElement($Name, 'http://schemas.microsoft.com/office/2011/mce')
    foreach ($key in $Attributes.Keys) { $element.SetAttribute($key, [string]$Attributes[$key]) }
    if ($PSBoundParameters.ContainsKey('Text')) { $element.InnerText = $Text }
    return $Parent.AppendChild($element)
}
#endregion Helpers

#region Main
foreach ($pattern in $Regex) {
    try { $null = New-Object -TypeName System.Text.RegularExpressions.Regex -ArgumentList $pattern }
    catch { throw "The regular expression '$pattern' does not compile: $($_.Exception.Message)" }
    if ($pattern -match '\(\?<?[=!]|\\[1-9]|[*+?}]\?') { Write-Warning "'$pattern' uses lookaround, back-references or lazy quantifiers, which the Purview classification engine does not support." }
}
$keywordList = @($Keywords | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
if ($keywordList.Count -gt 0 -and $HighConfidence -le $PatternConfidence) { throw 'HighConfidence must be greater than PatternConfidence when keywords are supplied.' }

$safeName = ($Name -replace '[^A-Za-z0-9]+', '_').Trim('_')
if ([string]::IsNullOrWhiteSpace($OutputXmlPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputXmlPath = Join-Path -Path $reportFolder -ChildPath ('PurviewSit_{0}_{1}.xml' -f $safeName, (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputXmlPath -Parent
if ([string]::IsNullOrWhiteSpace($outputFolder)) { $outputFolder = (Get-Location).Path }
if (-not (Test-Path -Path $outputFolder)) { New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null }
# .NET file APIs resolve relative paths against the process directory, not the PowerShell location.
$OutputXmlPath = Join-Path -Path (Resolve-Path -Path $outputFolder).Path -ChildPath (Split-Path -Path $OutputXmlPath -Leaf)

$entityId = [guid]::NewGuid().ToString()
$keywordId = "Keyword_$safeName"
$recommendedConfidence = $(if ($keywordList.Count -gt 0) { $HighConfidence } else { $PatternConfidence })
$doc = New-Object -TypeName System.Xml.XmlDocument
$null = $doc.AppendChild($doc.CreateXmlDeclaration('1.0', 'utf-16', $null))
$package = Add-XmlElement -Parent $doc -Name 'RulePackage'
$rulePack = Add-XmlElement -Parent $package -Name 'RulePack' -Attributes @{ id = [guid]::NewGuid().ToString() }
$null = Add-XmlElement -Parent $rulePack -Name 'Version' -Attributes @{ major = 1; minor = 0; build = 0; revision = 0 }
$null = Add-XmlElement -Parent $rulePack -Name 'Publisher' -Attributes @{ id = [guid]::NewGuid().ToString() }
$details = Add-XmlElement -Parent (Add-XmlElement -Parent $rulePack -Name 'Details' -Attributes @{ defaultLangCode = 'en-us' }) -Name 'LocalizedDetails' -Attributes @{ langcode = 'en-us' }
foreach ($pair in @(@('PublisherName', $Publisher), @('Name', "$Name rule package"), @('Description', $Description))) { $null = Add-XmlElement -Parent $details -Name $pair[0] -Text $pair[1] }

$rules = Add-XmlElement -Parent $package -Name 'Rules'
$entity = Add-XmlElement -Parent $rules -Name 'Entity' -Attributes @{ id = $entityId; patternsProximity = $ProximityCharacters; recommendedConfidence = $recommendedConfidence }
for ($i = 0; $i -lt $Regex.Count; $i++) {
    # A Pattern holds exactly one IdMatch, so each regex gets its own pattern(s); Regex elements follow the Entity inside Rules.
    $regexId = 'Regex_{0}_{1}' -f $safeName, ($i + 1)
    $patternNode = Add-XmlElement -Parent $entity -Name 'Pattern' -Attributes @{ confidenceLevel = $PatternConfidence }
    $null = Add-XmlElement -Parent $patternNode -Name 'IdMatch' -Attributes @{ idRef = $regexId }
    if ($keywordList.Count -gt 0) {
        $patternNode = Add-XmlElement -Parent $entity -Name 'Pattern' -Attributes @{ confidenceLevel = $HighConfidence }
        $null = Add-XmlElement -Parent $patternNode -Name 'IdMatch' -Attributes @{ idRef = $regexId }
        $null = Add-XmlElement -Parent $patternNode -Name 'Match' -Attributes @{ idRef = $keywordId }
    }
    $null = Add-XmlElement -Parent $rules -Name 'Regex' -Attributes @{ id = $regexId } -Text $Regex[$i]
}
if ($keywordList.Count -gt 0) {
    $group = Add-XmlElement -Parent (Add-XmlElement -Parent $rules -Name 'Keyword' -Attributes @{ id = $keywordId }) -Name 'Group' -Attributes @{ matchStyle = 'word' }
    foreach ($keyword in $keywordList) { $null = Add-XmlElement -Parent $group -Name 'Term' -Text $keyword }
}
$resource = Add-XmlElement -Parent (Add-XmlElement -Parent $rules -Name 'LocalizedStrings') -Name 'Resource' -Attributes @{ idRef = $entityId }
foreach ($pair in @(@('Name', $Name), @('Description', $Description))) { $null = Add-XmlElement -Parent $resource -Name $pair[0] -Attributes @{ default = 'true'; langcode = 'en-us' } -Text $pair[1] }

# The declaration says utf-16, so the file must really be UTF-16 encoded or the upload is rejected.
$writerSettings = New-Object -TypeName System.Xml.XmlWriterSettings -Property @{ Indent = $true; Encoding = [System.Text.Encoding]::Unicode }
$writer = [System.Xml.XmlWriter]::Create($OutputXmlPath, $writerSettings)
try { $doc.Save($writer) } finally { $writer.Close() }
Write-Verbose "Rule package written to $OutputXmlPath."

$created = $false
if ($Create) {
    try { Connect-ExchangeIfNeeded -Compliance }
    catch { throw "Unable to connect to Security & Compliance PowerShell: $($_.Exception.Message)" }
    # Filtered client-side: Get-DlpSensitiveInformationType -Identity returns the whole catalogue for unknown names.
    $existing = @(Get-DlpSensitiveInformationType -ErrorAction Stop | Where-Object { $_.Name -eq $Name })
    if ($existing.Count -gt 0) { throw "A sensitive information type named '$Name' already exists. Update it with Set-DlpSensitiveInformationTypeRulePackage instead." }
    if ($PSCmdlet.ShouldProcess($Name, 'Upload the rule package and create the sensitive information type')) {
        try { New-DlpSensitiveInformationTypeRulePackage -FileData ([System.IO.File]::ReadAllBytes($OutputXmlPath)) -ErrorAction Stop | Out-Null; $created = $true }
        catch { Write-Warning "New-DlpSensitiveInformationTypeRulePackage rejected the package: $($_.Exception.Message)" }
    }
}

$testResults = @()
if ($PSBoundParameters.ContainsKey('Test') -and -not $created) { Write-Warning '-Test is only evaluated after the type has been created with -Create.' }
elseif ($PSBoundParameters.ContainsKey('Test')) {
    try { $testResults = @((Test-DataClassification -TextToClassify $Test -ClassificationNames $Name -ErrorAction Stop).ClassificationResults) }
    catch { Write-Warning "Test-DataClassification failed: $($_.Exception.Message)" }
    if ($testResults.Count -eq 0) { Write-Warning 'No match yet. New types take several minutes to replicate; re-test later with Test-PurviewSensitiveInfoType.ps1.' }
}

$keywordText = $(if ($keywordList.Count -gt 0) { ', plus keyword patterns at {0} ({1} keywords within {2} characters)' -f $HighConfidence, $keywordList.Count, $ProximityCharacters } else { '' })
$createdText = $(if ($created) { 'Yes' } elseif ($Create) { 'No (declined, -WhatIf or rejected)' } else { 'No (preview; add -Create to upload)' })
Write-Host ''
Write-Host 'Custom sensitive information type summary' -ForegroundColor Cyan
Write-Host ('  Name          : {0} (entity {1})' -f $Name, $entityId)
Write-Host ('  Patterns      : {0} regex at confidence {1}{2}' -f $Regex.Count, $PatternConfidence, $keywordText)
Write-Host ('  Rule package  : {0}' -f $OutputXmlPath)
Write-Host ('  Created       : {0}' -f $createdText) -ForegroundColor $(if ($created) { 'Green' } else { 'Yellow' })
foreach ($result in $testResults) { Write-Host ('  Test match    : {0} count {1}, confidence {2}' -f $result.ClassificationName, $result.Count, $result.ConfidenceLevel) -ForegroundColor Green }
#endregion Main
