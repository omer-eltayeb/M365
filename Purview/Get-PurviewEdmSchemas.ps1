<#
.SYNOPSIS
    Reports exact data match (EDM) schemas, their fields and the EDM sensitive information types that use them.
.DESCRIPTION
    Connects to Security & Compliance PowerShell, reads every EDM schema (Get-DlpEdmSchema) and parses its EdmSchemaXML
    into one row per field (name, searchable, case-insensitive, ignored delimiters). Custom rule packages
    (Get-DlpSensitiveInformationTypeRulePackage) are scanned for <ExactMatch dataStore="..."> definitions so each field
    shows the EDM sensitive information types that use it, marking the primary (idMatch) element. -ExportXml saves each
    schema as an XML file next to the CSV, ready for editing and re-upload with Set-DlpEdmSchema.
    Writes a CSV and prints a summary. The script is read-only.
.PARAMETER ExportXml
    Also write each schema's XML to EdmSchema_<DataStoreName>.xml in the report folder.
.PARAMETER OutputPath
    Path of the CSV report. Defaults to .\Reports\PurviewEdmSchemas_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emit the field rows to the pipeline.
.EXAMPLE
    PS> .\Get-PurviewEdmSchemas.ps1
    Lists every EDM schema field with its usage and writes the CSV.
.EXAMPLE
    PS> .\Get-PurviewEdmSchemas.ps1 -ExportXml -PassThru | Where-Object { $_.Searchable -and -not $_.UsedBySits }
    Exports the schema XML files and shows searchable fields that no EDM sensitive information type references.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, ExchangeOnlineManagement 3.x
    Permissions : Compliance Administrator, Compliance Data Administrator or Global Reader
    Category    : Data loss prevention
    Changes     : No
    Notes       : Opens a Security & Compliance PowerShell session (Connect-IPPSSession). Schemas only describe the table
                  layout; hashing and uploading the sensitive data itself is done on a workstation with the EDM Upload Agent
                  (EdmUploadAgent.exe /UploadData) by a member of the EDM_DataUploaders group. Up to 10 schemas with
                  32 columns (5 of them searchable) are supported per tenant.
.LINK
    https://learn.microsoft.com/powershell/module/exchange/get-dlpedmschema
.LINK
    https://learn.microsoft.com/purview/sit-learn-about-exact-data-match-based-sits
#>
#Requires -Version 5.1
#Requires -Modules ExchangeOnlineManagement

[CmdletBinding()]
param(
    [Parameter()]
    [switch]$ExportXml,

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

function ConvertTo-RulePackageXml {
    <# Returns the rule package XML as an XmlDocument, from the XML string when present or by decoding the serialized bytes. #>
    param([Parameter(Mandatory = $true)]$Package)
    $document = New-Object -TypeName System.Xml.XmlDocument
    $text = [string]$Package.ClassificationRuleCollectionXml
    if (-not [string]::IsNullOrWhiteSpace($text)) {
        $document.LoadXml($text.TrimStart([char]0xFEFF))
        return $document
    }
    $bytes = $Package.SerializedClassificationRuleCollection
    if ($bytes -is [string]) { $bytes = [Convert]::FromBase64String($bytes) }
    # Loading from a stream lets the XML reader detect the encoding (the service stores UTF-16) from the BOM / declaration.
    $stream = New-Object -TypeName System.IO.MemoryStream -ArgumentList (, [byte[]]$bytes)
    $document.Load($stream)
    return $document
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('PurviewEdmSchemas_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}

try { Connect-ExchangeIfNeeded -Compliance }
catch { throw "Unable to connect to Security & Compliance PowerShell: $($_.Exception.Message)" }

try {
    $schemas = @(Get-DlpEdmSchema -ErrorAction Stop)
    # EDM SITs are always custom, so the large built-in Microsoft Rule Package is skipped.
    $packages = @(Get-DlpSensitiveInformationTypeRulePackage -ErrorAction Stop | Where-Object { $_.RuleCollectionName -ne 'Microsoft Rule Package' })
}
catch { throw "Failed to retrieve EDM schemas or rule packages: $($_.Exception.Message)" }

# One entry per <ExactMatch>: the data store it binds to, the SIT display name and the primary / supporting fields.
$edmSits = New-Object -TypeName System.Collections.Generic.List[object]
foreach ($package in $packages) {
    try { $xml = ConvertTo-RulePackageXml -Package $package }
    catch { Write-Warning ('Could not read rule package {0}: {1}' -f $package.RuleCollectionName, $_.Exception.Message); continue }
    foreach ($match in @($xml.GetElementsByTagName('ExactMatch'))) {
        $id = [string]$match.GetAttribute('id')
        $sitName = $id
        foreach ($resource in @($xml.GetElementsByTagName('Resource'))) {
            if ([string]$resource.GetAttribute('idRef') -eq $id) {
                $nameNode = @($resource.GetElementsByTagName('Name')) | Select-Object -First 1
                if ($null -ne $nameNode) { $sitName = $nameNode.InnerText }
            }
        }
        $edmSits.Add([PSCustomObject]@{
                DataStore  = [string]$match.GetAttribute('dataStore')
                Name       = $sitName
                Package    = [string]$package.RuleCollectionName
                Primary    = @($match.GetElementsByTagName('idMatch') | ForEach-Object { [string]$_.GetAttribute('matches') })
                Supporting = @($match.GetElementsByTagName('match') | ForEach-Object { [string]$_.GetAttribute('matches') })
            })
    }
}

$results = New-Object -TypeName System.Collections.Generic.List[object]
$exported = New-Object -TypeName System.Collections.Generic.List[string]
foreach ($schema in $schemas) {
    $storeName = [string]$schema.DataStoreName
    $xmlText = [string]$schema.EdmSchemaXML
    $fields = @()
    $store = $null
    if ([string]::IsNullOrWhiteSpace($xmlText)) { Write-Warning ('Schema {0} has no EdmSchemaXML content; fields cannot be listed.' -f $storeName) }
    else {
        try {
            $store = ([xml]$xmlText.TrimStart([char]0xFEFF)).EdmSchema.DataStore
            $fields = @($store.Field)
            if ([string]::IsNullOrWhiteSpace($storeName)) { $storeName = [string]$store.GetAttribute('name') }
        }
        catch { Write-Warning ('Could not parse the XML of schema {0}: {1}' -f $storeName, $_.Exception.Message) }
    }
    $storeSits = @($edmSits | Where-Object { $_.DataStore -eq $storeName })
    if ($ExportXml -and -not [string]::IsNullOrWhiteSpace($xmlText)) {
        $xmlPath = Join-Path -Path $outputFolder -ChildPath (('EdmSchema_{0}.xml' -f $storeName) -replace '[\\/:*?"<>|]', '_')
        [System.IO.File]::WriteAllText($xmlPath, $xmlText.TrimStart([char]0xFEFF), (New-Object -TypeName System.Text.UTF8Encoding -ArgumentList $false))
        $exported.Add($xmlPath)
    }
    # A schema without parsable fields still gets one row so it is not missing from the report.
    if ($fields.Count -eq 0) { $fields = @($null) }
    foreach ($field in $fields) {
        $fieldName = ''
        if ($null -ne $field) { $fieldName = [string]$field.GetAttribute('name') }
        $usedBy = @(foreach ($sit in $storeSits) {
                if ($sit.Primary -contains $fieldName) { '{0} (primary)' -f $sit.Name } elseif ($sit.Supporting -contains $fieldName) { $sit.Name }
            })
        $results.Add([PSCustomObject]@{
                Schema            = $storeName
                Version           = [string]$schema.Version
                Field             = $fieldName
                Searchable        = ($null -ne $field -and [string]$field.GetAttribute('searchable') -eq 'true')
                CaseInsensitive   = ($null -ne $field -and [string]$field.GetAttribute('caseInsensitive') -eq 'true')
                IgnoredDelimiters = $(if ($null -ne $field) { [string]$field.GetAttribute('ignoredDelimiters') } else { '' })
                UsedBySits        = ($usedBy -join '; ')
                EdmSitCount       = $storeSits.Count
                SchemaDescription = [string]$schema.Description
                WhenChanged       = $schema.WhenChanged
            })
    }
}

if ($results.Count -gt 0) { $results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 }
else { Write-Warning 'No EDM schemas exist in this tenant. Create one with New-DlpEdmSchema or in the Purview portal.' }

$fieldRows = @($results | Where-Object { $_.Field })
Write-Host 'Purview EDM schema summary' -ForegroundColor Cyan
Write-Host ('  Schemas           : {0}' -f $schemas.Count)
Write-Host ('  Fields            : {0} ({1} searchable)' -f $fieldRows.Count, @($fieldRows | Where-Object { $_.Searchable }).Count)
Write-Host ('  EDM SITs          : {0} in {1} custom rule package(s)' -f $edmSits.Count, $packages.Count)
foreach ($schema in $schemas) {
    $names = @($edmSits | Where-Object { $_.DataStore -eq $schema.DataStoreName } | ForEach-Object { $_.Name })
    Write-Host ('    {0}: {1}' -f $schema.DataStoreName, $(if ($names.Count -gt 0) { $names -join ', ' } else { 'no EDM SIT uses this schema' }))
}
foreach ($path in $exported) { Write-Host ('  Exported          : {0}' -f $path) -ForegroundColor Green }
Write-Host ('  Report            : {0}' -f $OutputPath)
Write-Host '  Data hashing and upload are done with EdmUploadAgent.exe, not PowerShell - see the .LINK article.' -ForegroundColor Yellow

if ($PassThru) { $results }
#endregion Main
