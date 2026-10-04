@{
    # Rules at these severities are reported by the CI workflow; only 'Error' fails the build.
    Severity     = @('Error', 'Warning')

    ExcludeRules = @(
        # The scripts print short, coloured console summaries on purpose.
        'PSAvoidUsingWriteHost',
        # Files are UTF-8 without BOM, which is fine for PowerShell 7 and for GitHub diffs.
        'PSUseBOMForUnicodeEncodedFile'
    )

    Rules        = @{
        PSUseCompatibleSyntax      = @{
            Enable         = $true
            TargetVersions = @('5.1', '7.0')
        }
        PSPlaceOpenBrace           = @{
            Enable             = $true
            OnSameLine         = $true
            NewLineAfter       = $true
            IgnoreOneLineBlock = $true
        }
        PSPlaceCloseBrace          = @{
            Enable             = $true
            NewLineAfter       = $false
            IgnoreOneLineBlock = $true
            NoEmptyLineBefore  = $false
        }
        PSUseConsistentIndentation = @{
            Enable              = $true
            IndentationSize     = 4
            Kind                = 'space'
            PipelineIndentation = 'IncreaseIndentationForFirstPipeline'
        }
        PSUseConsistentWhitespace  = @{
            Enable          = $true
            CheckOpenBrace  = $true
            CheckOpenParen  = $true
            CheckOperator   = $false
            CheckSeparator  = $true
        }
    }
}
