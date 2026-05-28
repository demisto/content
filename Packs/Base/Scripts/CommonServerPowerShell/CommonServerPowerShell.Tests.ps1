BeforeAll {
    . $PSScriptRoot\CommonServerPowerShell.ps1
}


Describe 'Check-DemistoServerRequest' {
    It 'Check that a call to demisto DemistoServerRequest mock works. Should always return an empty response' {
        global:DemistoServerRequest @{} | Should -BeNullOrEmpty
        $demisto.GetAllSupportedCommands() | Should -BeNullOrEmpty
    }
}

Describe 'Check-incidents'{
    It 'Check Incidents creation in a case of more than one incident'{
        $test_incidents = @()
        0..2 | ForEach-Object {
            $test_incidents += [PSCustomObject]@{
                id           = "1111"
                name         = "incident_name"
                type         = "type"
                createdOn    = "2023-05-28T05:57:18.404Z"
            }
        }
        $incidents = @()
        $test_incidents | Foreach-Object {
            $NewAlert = @{
                name = "$($_.type)-$($_.name)"
                occurred = $_.createdOn
                rawJSON = $_ | ConvertTo-JSON -Depth 2
                severity = 1
            }
            $Incidents += $NewAlert
        }
        class DemistoObject {
            DemistoObject () {
            }

            [array] Incidents ($Incidents) {
                # This cmdlet returns a string representing the input object converted to a JSON string.
                $Incidents = $Incidents | ConvertTo-Json -Depth 6 -AsArray
                return $Incidents
            }
        }
        [DemistoObject]$demisto = [DemistoObject]::New()
        $r = $demisto.Incidents($incidents)
        $r.GetType().IsArray | Should -BeTrue
        $incidentArray = $r | ConvertFrom-Json
        $incidentArray.Length | Should -Be 3
    }

    It 'Check Incidents creation in a case of only one incident'{
        $test_incidents = @()
        0..0 | ForEach-Object {
            $test_incidents += [PSCustomObject]@{
                id           = "1111"
                name         = "incident_name"
                type         = "type"
                createdOn    = "2023-05-28T05:57:18.404Z"
            }
        }
        $incidents = @()
        $test_incidents | Foreach-Object {
            $NewAlert = @{
                name = "$($_.type)-$($_.name)"
                occurred = $_.createdOn
                rawJSON = $_ | ConvertTo-JSON -Depth 2
                severity = 1
            }
            $Incidents += $NewAlert
        }
        class DemistoObject {
            DemistoObject () {
            }
            
            [array] Incidents ($Incidents) {
                # This cmdlet returns a string representing the input object converted to a JSON string.
                $Incidents = $Incidents | ConvertTo-Json -Depth 6 -AsArray
                return $Incidents
            }
        }
        [DemistoObject]$demisto = [DemistoObject]::New()
        $r = $demisto.Incidents($incidents)
        $r.GetType().IsArray | Should -BeTrue
        $incidentArray = $r | ConvertFrom-Json
        $incidentArray.Length | Should -Be 1
    }
}

Describe 'Check-UtilityFunctions' {
    It "VersionEqualGreaterThen" {
        class DemistoObject {
            DemistoObject () {
            }

            [array] DemistoVersion () {
                return @{
                    "version" = "6.0.0-build"
                }
            }
        }
        [DemistoObject]$demisto = [DemistoObject]::New()
        DemistoVersionGreaterEqualThen -version "6.0.0"  | Should -BeTrue
        DemistoVersionGreaterEqualThen "5.0.1-build"  | Should -BeTrue
        DemistoVersionGreaterEqualThen -version "6.0.1"  | Should -BeFalse
        DemistoVersionGreaterEqualThen -version "6.0.2-build"  | Should -BeFalse
    }

    It "ArgToList" {
        $r = argToList "a,b,c,2"
        $r.GetType().IsArray | Should -BeTrue
        $r[0] | Should -Be "a"
        $r.Length | Should -Be 4
        $r = argToList '["a","b","c",2]'
        $r.GetType().IsArray | Should -BeTrue
        $r[0] | Should -Be "a"
        $r[3] | Should -Be 2
        $r.Length | Should -Be 4
        $r = argToList @("a","b","c",2)
        $r.GetType().IsArray | Should -BeTrue
        $r[0] | Should -Be "a"
        $r[3] | Should -Be 2
        $r.Length | Should -Be 4
        $r = argToList "a"
        $r.GetType().IsArray | Should -BeTrue
        $r[0] | Should -Be "a"
        $r.Length | Should -Be 1
    }

    It "ReturnOutputs" {
        $msg = "Human readable"
        $r = ReturnOutputs $msg @{Test="test"} @{Raw="raw"}
        $r.ContentsFormat | Should -Be "json"
        $r.HumanReadable | Should -Be $msg
        $r.EntryContext.Test | Should -Be "test"
        $r.Contents.Raw | Should -Be "raw"
        $r = ReturnOutputs $msg
        $r.ContentsFormat | Should -Be "text"
        $r.Contents | Should -Be $msg
    }

    It "ReturnOutputs PsCustomObject" {
        $msg = "Human readable"
        $output = [PsCustomObject]@{Test="test"}
        $raw = [PSCustomObject]@{Raw="raw"}
        $r = ReturnOutputs $msg  $output $raw
        $r.ContentsFormat | Should -Be "json"
        $r.HumanReadable | Should -Be $msg
        $r.EntryContext.Test | Should -Be "test"
        $r.Contents.Raw | Should -Be "raw"
        $r = ReturnOutputs $msg
        $r.ContentsFormat | Should -Be "text"
        $r.Contents | Should -Be $msg
    }

    It "ReturnError simple" {
        $msg = "this is an error"
        $r = ReturnError $msg
        $r.ContentsFormat | Should -Be "text"
        $r.Type | Should -Be 4
        $r.Contents | Should -Be $msg
        $r.EntryContext | Should -BeNullOrEmpty
    }

    Context "FileResult checks" {
        
        BeforeAll {    
            # move into a temp directory which we later on delete from the files created in the  tests         
            $temp_parent = [System.IO.Path]::GetTempPath()
            [string] $temp_dir = [System.Guid]::NewGuid()
            $temp_path = Join-Path $temp_parent $temp_dir
            New-Item -ItemType Directory -Path $temp_path
            Set-Location $temp_path -PassThru
        }

        It "FileResult default" {
            $data = "this is a test"
            $r = FileResult "test.txt" $data
            $r.Type | Should -Be 3
            $r.File | Should -Be "test.txt"
            $inv_id = $demisto.Investigation().id
            Get-Content -Path "${inv_id}_$($r.FileID)" | Should -Be $data
        }

        It "FileResult info" {
            $data = "this is a test"
            # pass $true to indicate that this is a file info entry
            $r = FileResult "test.txt" $data $true
            $r.Type | Should -Be 9
            $r.File | Should -Be "test.txt"
            $inv_id = $demisto.Investigation().id
            Get-Content -Path "${inv_id}_$($r.FileID)" | Should -Be $data
        }

        AfterAll {
            Set-Location -Path - -PassThru
            Remove-Item $temp_path -Recurse
        }
    }
    

    Context "Check log function" {
        BeforeAll {
            Mock DemistoServerLog {}
        }

        It "ReturnError complex" {
            # simulate an error
            Test-JSON "{badjson}" -ErrorAction SilentlyContinue -ErrorVariable err
            $msg = "this is a complex error"
            $r = ReturnError $msg $err @{Failed = $true}
            $r.Contents | Should -Be $msg
            $r.EntryContext.Failed | Should -BeTrue
            # ReturnError call demisto.Error() make sure it was called
            Assert-MockCalled -CommandName DemistoServerLog -Times 2 -ParameterFilter {$level -eq "error"}
            Assert-MockCalled -CommandName DemistoServerLog -Times 1 -ParameterFilter {$msg.Contains("Cannot parse the JSON")}
        }
    }
    Context "TableToMarkdown" {
        BeforeAll {
            $HashTableWithTwoEntries = @(
            [ordered]@{
                Index = '0'
                Name = 'First element'
            },
            [ordered]@{
                Index = '1'
                Name = 'Second element'
            }
            )
            $HashTableWithOneEntry = @(
            [ordered]@{
                Index = '0'
                Name = 'First element'
            })
            $OneElementObject = @()
            ForEach ($object in $HashTableWithOneEntry)
            {
                $OneElementObject += New-Object PSObject -Property $object
            }
            $TwoElementObject = @()
            ForEach ($object in $HashTableWithTwoEntries)
            {
                $TwoElementObject += New-Object PSObject -Property $object
            }
            $hashTable = [ordered]@{"key1" = "value1";"key2" = "value2"}
        }
        It "Empty list without a name" {
            TableToMarkdown @() | Should -Be "**No entries.**`n"
        }
        It "A list with one element and no name" {
            TableToMarkdown $OneElementObject | Should -Be "| Index | Name`n| --- | ---`n| 0 | First element`n"
        }
        It "A list with two elements and no name" {
            TableToMarkdown $TwoElementObject | Should -Be "| Index | Name`n| --- | ---`n| 0 | First element`n| 1 | Second element`n"
        }
        It "Empty list with a name" {
            TableToMarkdown @() "Test Name" | Should -Be "### Test Name`n**No entries.**`n"
        }
        It "A list with two elements and a name" {
            TableToMarkdown $TwoElementObject "Test Name" | Should -Be "### Test Name`n| Index | Name`n| --- | ---`n| 0 | First element`n| 1 | Second element`n"
        }
        It "A list with one elements and a name" {
            TableToMarkdown $OneElementObject "Test Name" | Should -Be "### Test Name`n| Index | Name`n| --- | ---`n| 0 | First element`n"
        }
        It "Check alias to ConvertTo-Markdown" {
            ConvertTo-Markdown @() "Test Name" | Should -Be "### Test Name`n**No entries.**`n"
        }
        It "Check with nested objects" {
            $TwoElementObject += New-Object PSObject -Property ([ordered]@{Index = "2"; Name = $HashTableWithOneEntry})
            TableToMarkdown $TwoElementObject "Test Name" | Should -Be "### Test Name`n| Index | Name`n| --- | ---`n| 0 | First element`n| 1 | Second element`n| 2 | \{`"Index`":`"0`",`"Name`":`"First element`"\}`n"
        }
        It "check with a single hashtable" {
            $hashTable | TableToMarkdown | Should -Be "| key1 | key2`n| --- | ---`n| value1 | value2`n"
        }
        It "Check with a single PSObject" {
            New-Object PSObject -Property $hashTable | TableToMarkdown | Should -Be "| key1 | key2`n| --- | ---`n| value1 | value2`n"
        }
        It "Check with a list of hashtables"{
             $HashTableWithOneEntry | TableToMarkdown | Should -Be "| Index | Name`n| --- | ---`n| 0 | First element`n"
        }
        It "Check with False boolean that is not $null" {
            @{test=$false} | TableToMarkdown | Should -Be "| test`n| ---`n| False`n"
        }
        It "Check with PSObject that nested list"{
            $OneElementObject += New-Object PSObject -Property @{Index=1;Name=@('test1';'test2')}
            $OneElementObject | TableToMarkdown | Should -Be "| Index | Name`n| --- | ---`n| 0 | First element`n| 1 | \[`"test1`",`"test2`"\]`n"
        }
        It "ArrayList object"{
            $ArrLst = [System.Collections.ArrayList]::new()
            $ArrLst.Add("a string")
            $ArrLst.Add("another string")
            $tbl = @{"arraylist" = $ArrLst} | TableToMarkdown
            $tbl | Should -Match "a string"
            $tbl | Should -Match "another string"
        }
    }
    Context "Test stringEscapeMD" {
        It "Escaping special chars"{
            '\ ` * _ { } [ ] ( ) # + - | ! `n `r `r`n' | stringEscapeMD | Should -Be '\\ \` \* \_ \{ \} \[ \] \( \) \# \+ \- \| \! \`n \`r \`r\`n'
        }
    }
}
Describe "Test ParseDateRange"{
        It "Naive Tests" -Tag naive{
            $m_date = Get-Date "2020-11-30T23:30:00.0000000"
            $three_mins = $m_date.AddMinutes(-3)
            $three_hours = $m_date.AddHours(-3)
            $three_days = $m_date.AddDays(-3)
            $three_weeks = $m_date.AddDays(-7 * 3)
            $three_months = $m_date.AddMonths(-3)
            $three_years = $m_date.AddYears(-3)
            Mock -CommandName Get-Date -MockWith {$m_date}
            ParseDateRange("3 minutes") | Should -Be @($three_mins, $m_date)
            ParseDateRange("3 minute") | Should -Be @($three_mins, $m_date)
            ParseDateRange("3 hours") | Should -Be @($three_hours, $m_date)
            ParseDateRange("3 hour") | Should -Be @($three_hours, $m_date)
            ParseDateRange("3 days") | Should -Be @($three_days, $m_date)
            ParseDateRange("3 day") | Should -Be @($three_days, $m_date)
            ParseDateRange("3 week") | Should -Be @($three_weeks, $m_date)
            ParseDateRange("3 weeks") | Should -Be @($three_weeks, $m_date)
            ParseDateRange("3 month") | Should -Be @($three_months, $m_date)
            ParseDateRange("3 months") | Should -Be @($three_months, $m_date)
            ParseDateRange("3 year") | Should -Be @($three_years, $m_date)
            ParseDateRange("3 years") | Should -Be @($three_years, $m_date)
        }
        It "Too many arguments"{
            { ParseDateRange("3 days long") } | Should -Throw
        }
        It "Not a number"{
            { ParseDateRange("lol days") } | Should -Throw
        }
        It "Wrong time unit" {
            { ParseDateRange("3 planets") } | Should -Throw
        }
    }

Describe "Test Remove-SelfReferences" {
<#
Given: Outputs or RawOutputs complicated objects with inner properties.
When: Remove-SelfReferences is called as a part of ReturnOutputs.
Then: Make sure removing self references works as expected.
#>
    It "One self-reference" {
    # (Case 1): Outputs dict containing 1 self-reference. Expect: self-reference removed, otherwise no change.
        $inputDict = [PSCustomObject]@{
            Property1 = "Value1"
            NestedProperty = [PSCustomObject]@{
                NestedProperty1 = "NestedValue1"
                NestedProperty2 = [PSCustomObject]@{
                    DeeplyNestedProperty = [PSCustomObject]@{
                        Deep3 = "DeepValue"
                        Deep4 = "Deep4"
                        }
                    }
                }
            }

        $inputDict.NestedProperty.NestedProperty1 = $inputDict.NestedProperty

        $outDict = Remove-SelfReferences($inputDict)
        $outDict.Property1 | Should -Be "Value1"
        $outDict.NestedProperty.NestedProperty2.DeeplyNestedProperty.Deep3 | Should -Be "DeepValue"
        $outDict.NestedProperty.NestedProperty2.DeeplyNestedProperty.Deep4 | Should -Be "Deep4"

        $outDict.NestedProperty.PSObject.Properties.name -match "NestedProperty1" | Should -Be $false

    }
    It "No self-reference" {
    # (Case 2): Outputs dict containing no self-reference. Expect: no change.
        $inputDict = [PSCustomObject]@{
            Property1 = "Value1"
            NestedProperty = [PSCustomObject]@{
                NestedProperty1 = "NestedValue1"
                NestedProperty2 = [PSCustomObject]@{
                    DeeplyNestedProperty = [PSCustomObject]@{
                        Deep3 = "DeepValue"
                        Deep4 = "Deep4"
                        }
                    }
                }
            }

        $outDict = Remove-SelfReferences($inputDict)
        $outDict.Property1 | Should -Be "Value1"
        $outDict.NestedProperty.NestedProperty1 | Should -Be "NestedValue1"
        $outDict.NestedProperty.NestedProperty2.DeeplyNestedProperty.Deep3 | Should -Be "DeepValue"
        $outDict.NestedProperty.NestedProperty2.DeeplyNestedProperty.Deep4 | Should -Be "Deep4"

    }
    It "Two self-reference" {
    # (Case 3): Outputs dict containing 2 self-references. Expect: both self-references removed, otherwise no change.
        $inputDict = [PSCustomObject]@{
            Property1 = [PSCustomObject]@{
                SelfRef = $null
                OtherProp = 5
            }
            NestedProperty = [PSCustomObject]@{
                NestedProperty1 = "NestedValue1"
                NestedProperty2 = [PSCustomObject]@{
                    DeeplyNestedProperty = [PSCustomObject]@{
                        Deep3 = "DeepValue"
                        Deep4 = "Deep4"
                    }
                }
            }
        }

        $inputDict.NestedProperty.NestedProperty1 = $inputDict.NestedProperty
        $inputDict.Property1.SelfRef = $inputDict.Property1

        $outDict = Remove-SelfReferences($inputDict)
        $outDict.Property1.PSObject.Properties.name -match "SelfRef" | Should -Be $false
        $outDict.NestedProperty.PSObject.Properties.name -match "NestedProperty1" | Should -Be $false

        $outDict.Property1.OtherProp | Should -Be 5
        $outDict.NestedProperty.NestedProperty2.DeeplyNestedProperty.Deep3 | Should -Be "DeepValue"
        $outDict.NestedProperty.NestedProperty2.DeeplyNestedProperty.Deep4 | Should -Be "Deep4"


    }
    It "Deep self-reference" {
    # (Case 4): Outputs dict containing a self-references in a deeper level. Expect: self-reference removed, otherwise no change.
        $inputDict = [PSCustomObject]@{
            Property1 = "Value1"
            NestedProperty = [PSCustomObject]@{
                NestedProperty1 = "NestedValue1"
                NestedProperty2 = [PSCustomObject]@{
                    DeeplyNestedProperty = [PSCustomObject]@{
                        Deep3 = "DeepValue"
                        Deep4 = "Deep4"
                        }
                    }
                }
            }

        $inputDict.NestedProperty.NestedProperty2.DeeplyNestedProperty.Deep4 = $inputDict.NestedProperty

        $outDict = Remove-SelfReferences($inputDict)
        $outDict.NestedProperty.NestedProperty2.DeeplyNestedProperty.PSObject.Properties.name -match "Deep4" | Should -Be $false

        $outDict.Property1 | Should -Be "Value1"
        $outDict.NestedProperty.NestedProperty1 | Should -Be "NestedValue1"
        $outDict.NestedProperty.NestedProperty2.DeeplyNestedProperty.Deep3 | Should -Be "DeepValue"
    }
}

# Module-level shared state used by the UCP `class DemistoObject` redefinition
# pattern. Each It-block sets these before invoking the helper under test.
$script:UcpTestMetadata    = $null
$script:UcpTestCredentials = @{}
$script:UcpTestCalls       = 0
$script:UcpTestLastMethod  = ''
$script:UcpTestCurrentCmd  = ''

Describe 'UCP-Helpers' {
    BeforeEach {
        # Reset module-level state (declared in CommonServerPowerShell.ps1) and
        # the shared test state used by the per-test DemistoObject stubs.
        $script:UcpCredentialsCache       = @{}
        $script:UCP_AUTH_PARAMS_INJECTED = $false
        $script:UcpTestMetadata    = $null
        $script:UcpTestCredentials = @{}
        $script:UcpTestCalls       = 0
        $script:UcpTestLastMethod  = ''
        $script:UcpTestCurrentCmd  = ''
    }

    It 'Is-UcpEnabled returns False when metadata is null' {
        # Given - a DemistoObject whose UnifiedConnectorMetadata returns $null (UCP not configured).
        class DemistoObject {
            DemistoObject () {}
            [object] UnifiedConnectorMetadata () { return $script:UcpTestMetadata }
            [void]   Debug ([object]$m) {}
            [void]   Info  ([object]$m) {}
            [void]   Error ([object]$m) {}
        }
        [DemistoObject]$demisto = [DemistoObject]::New()
        $script:UcpTestMetadata = $null
        # When - Is-UcpEnabled is called.
        # Then - it reports UCP as disabled.
        Is-UcpEnabled | Should -BeFalse
    }

    It 'Is-UcpEnabled returns False when connectionProfiles is empty' {
        # Given - a DemistoObject whose UnifiedConnectorMetadata returns a descriptor with an empty profile list.
        class DemistoObject {
            DemistoObject () {}
            [object] UnifiedConnectorMetadata () { return $script:UcpTestMetadata }
            [void]   Debug ([object]$m) {}
            [void]   Info  ([object]$m) {}
            [void]   Error ([object]$m) {}
        }
        [DemistoObject]$demisto = [DemistoObject]::New()
        $script:UcpTestMetadata = @{ connectionProfiles = @() }
        # When - Is-UcpEnabled is called.
        # Then - it reports UCP as disabled because no auth profiles are present.
        Is-UcpEnabled | Should -BeFalse
    }

    It 'Is-UcpEnabled returns True when connectionProfiles is non-empty' {
        # Given - a DemistoObject whose UnifiedConnectorMetadata returns at least one connection profile.
        class DemistoObject {
            DemistoObject () {}
            [object] UnifiedConnectorMetadata () { return $script:UcpTestMetadata }
            [void]   Debug ([object]$m) {}
            [void]   Info  ([object]$m) {}
            [void]   Error ([object]$m) {}
        }
        [DemistoObject]$demisto = [DemistoObject]::New()
        $script:UcpTestMetadata = @{
            connectionProfiles = @(@{ method_unique_id = 'm1'; capability = 'automation-and-remediation' })
        }
        # When - Is-UcpEnabled is called.
        # Then - it reports UCP as enabled.
        Is-UcpEnabled | Should -BeTrue
    }

    It 'Test-ShouldUseUcpAuth honors the UCP_AUTH_PARAMS_INJECTED flag' {
        # Given - UCP is enabled and the injected-params flag starts off ($false).
        class DemistoObject {
            DemistoObject () {}
            [object] UnifiedConnectorMetadata () { return $script:UcpTestMetadata }
            [void]   Debug ([object]$m) {}
            [void]   Info  ([object]$m) {}
            [void]   Error ([object]$m) {}
        }
        [DemistoObject]$demisto = [DemistoObject]::New()
        $script:UcpTestMetadata = @{
            connectionProfiles = @(@{ method_unique_id = 'm1'; capability = 'automation-and-remediation' })
        }
        # When - Test-ShouldUseUcpAuth is called with the flag off, then on.
        # Then - it returns $true initially, $false once the flag is set.
        Test-ShouldUseUcpAuth | Should -BeTrue
        $script:UCP_AUTH_PARAMS_INJECTED = $true
        Test-ShouldUseUcpAuth | Should -BeFalse
    }

    It 'Resolve-UcpCapability maps known commands and falls back to default' {
        # Given - a DemistoObject whose GetCommand reflects the currently-executing command.
        class DemistoObject {
            DemistoObject () {}
            [string] GetCommand () { return $script:UcpTestCurrentCmd }
            [void]   Debug ([object]$m) {}
            [void]   Info  ([object]$m) {}
            [void]   Error ([object]$m) {}
        }
        [DemistoObject]$demisto = [DemistoObject]::New()
        # When - Resolve-UcpCapability is called with known and unknown command names.
        # Then - the four known collection-and-ingestion commands map to 'collection-and-ingestion'
        #        and any unknown command falls back to the default 'automation-and-remediation'.
        Resolve-UcpCapability -Command 'fetch-incidents'  | Should -Be 'collection-and-ingestion'
        Resolve-UcpCapability -Command 'fetch-assets'     | Should -Be 'collection-and-ingestion'
        Resolve-UcpCapability -Command 'fetch-indicators' | Should -Be 'collection-and-ingestion'
        Resolve-UcpCapability -Command 'fetch-samples'    | Should -Be 'collection-and-ingestion'
        Resolve-UcpCapability -Command 'some-other-cmd'   | Should -Be 'automation-and-remediation'

        # When no explicit command is provided, Resolve-UcpCapability uses $demisto.GetCommand().
        # Then - the result reflects whatever the server reports as the current command.
        $script:UcpTestCurrentCmd = 'fetch-incidents'
        Resolve-UcpCapability | Should -Be 'collection-and-ingestion'
    }

    It 'Get-UcpMethodUniqueId matches by sub_capability first' {
        # Given - two profiles share the same capability but only one matches the requested sub_capability.
        class DemistoObject {
            DemistoObject () {}
            [object] UnifiedConnectorMetadata () { return $script:UcpTestMetadata }
            [void]   Debug ([object]$m) {}
            [void]   Info  ([object]$m) {}
            [void]   Error ([object]$m) {}
        }
        [DemistoObject]$demisto = [DemistoObject]::New()
        $script:UcpTestMetadata = @{
            connectionProfiles = @(
                @{ method_unique_id = 'm1'; capability = 'automation-and-remediation'; sub_capabilities = @() },
                @{ method_unique_id = 'm2'; capability = 'automation-and-remediation'; sub_capabilities = @('salesforce-iam') }
            )
        }
        # When - Get-UcpMethodUniqueId is called with a SubCapability argument.
        # Then - the sub_capability match wins, even though both profiles share the capability.
        Get-UcpMethodUniqueId -SubCapability 'salesforce-iam' | Should -Be 'm2'
    }

    It 'Get-UcpMethodUniqueId matches by capability when sub_capability not given' {
        # Given - two profiles with different capabilities and no sub_capability hint.
        class DemistoObject {
            DemistoObject () {}
            [object] UnifiedConnectorMetadata () { return $script:UcpTestMetadata }
            [string] GetCommand () { return $script:UcpTestCurrentCmd }
            [void]   Debug ([object]$m) {}
            [void]   Info  ([object]$m) {}
            [void]   Error ([object]$m) {}
        }
        [DemistoObject]$demisto = [DemistoObject]::New()
        $script:UcpTestMetadata = @{
            connectionProfiles = @(
                @{ method_unique_id = 'm1'; capability = 'other' },
                @{ method_unique_id = 'm2'; capability = 'automation-and-remediation' }
            )
        }
        # When - Get-UcpMethodUniqueId is called with only a Capability argument.
        # Then - the profile whose capability matches is returned.
        Get-UcpMethodUniqueId -Capability 'automation-and-remediation' | Should -Be 'm2'
    }

    It 'Get-UcpMethodUniqueId falls back to the first profile when nothing matches' {
        # Given - no profile matches either the requested capability or sub_capability.
        class DemistoObject {
            DemistoObject () {}
            [object] UnifiedConnectorMetadata () { return $script:UcpTestMetadata }
            [string] GetCommand () { return $script:UcpTestCurrentCmd }
            [void]   Debug ([object]$m) {}
            [void]   Info  ([object]$m) {}
            [void]   Error ([object]$m) {}
        }
        [DemistoObject]$demisto = [DemistoObject]::New()
        $script:UcpTestMetadata = @{
            connectionProfiles = @(
                @{ method_unique_id = 'm1'; capability = 'other-1' },
                @{ method_unique_id = 'm2'; capability = 'other-2' }
            )
        }
        # When - Get-UcpMethodUniqueId is called with a capability nothing matches.
        # Then - it falls back to the first profile's method_unique_id.
        Get-UcpMethodUniqueId -Capability 'no-such-capability' | Should -Be 'm1'
    }

    It 'Get-UcpCredentials returns $null when UCP is not enabled' {
        # Given - a DemistoObject reporting no UCP metadata.
        class DemistoObject {
            DemistoObject () {}
            [object] UnifiedConnectorMetadata () { return $script:UcpTestMetadata }
            [object] GetUCPCredentials ([string]$id, [bool]$fc) { return $null }
            [string] GetCommand () { return $script:UcpTestCurrentCmd }
            [void]   Debug ([object]$m) {}
            [void]   Info  ([object]$m) {}
            [void]   Error ([object]$m) {}
        }
        [DemistoObject]$demisto = [DemistoObject]::New()
        $script:UcpTestMetadata = $null
        # When - Get-UcpCredentials is called outside of UCP mode.
        # Then - it short-circuits and returns $null without making a credentials request.
        Get-UcpCredentials | Should -BeNullOrEmpty
    }

    It 'Get-UcpCredentials flattens oauth2 credentials and caches them' {
        # Given - UCP returns a nested oauth2 credential dict with a far-future expiry.
        class DemistoObject {
            DemistoObject () {}
            [object] UnifiedConnectorMetadata () { return $script:UcpTestMetadata }
            [object] GetUCPCredentials ([string]$id, [bool]$fc) {
                $script:UcpTestCalls += 1
                $script:UcpTestLastMethod = $id
                if ($script:UcpTestCredentials.Contains($id)) { return $script:UcpTestCredentials[$id] }
                return $null
            }
            [string] GetCommand () { return $script:UcpTestCurrentCmd }
            [void]   Debug ([object]$m) {}
            [void]   Info  ([object]$m) {}
            [void]   Error ([object]$m) {}
        }
        [DemistoObject]$demisto = [DemistoObject]::New()
        $script:UcpTestMetadata = @{
            connectionProfiles = @(@{ method_unique_id = 'm1'; capability = 'automation-and-remediation' })
        }
        $script:UcpTestCredentials = @{
            'm1' = @{
                type   = 'oauth2'
                oauth2 = @{
                    access_token = 'tok-1'
                    token_type   = 'Bearer'
                    expires_at   = ([DateTime]::UtcNow.AddMinutes(10).ToString('o'))
                }
            }
        }

        # When - Get-UcpCredentials is called twice in a row.
        # Then - the first call returns flat oauth2 fields and the second call is served from cache.
        $first = Get-UcpCredentials
        $first.type         | Should -Be 'oauth2'
        $first.access_token | Should -Be 'tok-1'
        $first.token_type   | Should -Be 'Bearer'
        $script:UcpTestCalls | Should -Be 1

        $second = Get-UcpCredentials
        $second.access_token | Should -Be 'tok-1'
        $script:UcpTestCalls | Should -Be 1
    }

    It 'Get-UcpCredentials throws on empty oauth2 access_token' {
        # Given - UCP returns an oauth2 dict with an empty access_token (mis-configured profile).
        class DemistoObject {
            DemistoObject () {}
            [object] UnifiedConnectorMetadata () { return $script:UcpTestMetadata }
            [object] GetUCPCredentials ([string]$id, [bool]$fc) {
                if ($script:UcpTestCredentials.Contains($id)) { return $script:UcpTestCredentials[$id] }
                return $null
            }
            [string] GetCommand () { return $script:UcpTestCurrentCmd }
            [void]   Debug ([object]$m) {}
            [void]   Info  ([object]$m) {}
            [void]   Error ([object]$m) {}
        }
        [DemistoObject]$demisto = [DemistoObject]::New()
        $script:UcpTestMetadata = @{
            connectionProfiles = @(@{ method_unique_id = 'm1'; capability = 'automation-and-remediation' })
        }
        $script:UcpTestCredentials = @{
            'm1' = @{ type = 'oauth2'; oauth2 = @{ access_token = ''; token_type = 'Bearer' } }
        }
        # When - Get-UcpCredentials is called.
        # Then - it fail-fasts with a [UCP] authentication-failed error rather than returning an empty token.
        { Get-UcpCredentials } | Should -Throw -ExpectedMessage '*UCP*'
    }

    It 'Get-UcpCredentials flattens api_key credentials' {
        # Given - UCP returns a nested api_key credential dict.
        class DemistoObject {
            DemistoObject () {}
            [object] UnifiedConnectorMetadata () { return $script:UcpTestMetadata }
            [object] GetUCPCredentials ([string]$id, [bool]$fc) {
                if ($script:UcpTestCredentials.Contains($id)) { return $script:UcpTestCredentials[$id] }
                return $null
            }
            [string] GetCommand () { return $script:UcpTestCurrentCmd }
            [void]   Debug ([object]$m) {}
            [void]   Info  ([object]$m) {}
            [void]   Error ([object]$m) {}
        }
        [DemistoObject]$demisto = [DemistoObject]::New()
        $script:UcpTestMetadata = @{
            connectionProfiles = @(@{ method_unique_id = 'm1'; capability = 'automation-and-remediation' })
        }
        $script:UcpTestCredentials = @{
            'm1' = @{ type = 'api_key'; api_key = @{ key = 'k-1' } }
        }
        # When - Get-UcpCredentials is called.
        # Then - the nested api_key.key is flattened to a top-level `key` field.
        $creds = Get-UcpCredentials
        $creds.type | Should -Be 'api_key'
        $creds.key  | Should -Be 'k-1'
    }

    It 'Get-UcpCredentials flattens plain credentials' {
        # Given - UCP returns a nested plain (username/password) credential dict.
        class DemistoObject {
            DemistoObject () {}
            [object] UnifiedConnectorMetadata () { return $script:UcpTestMetadata }
            [object] GetUCPCredentials ([string]$id, [bool]$fc) {
                if ($script:UcpTestCredentials.Contains($id)) { return $script:UcpTestCredentials[$id] }
                return $null
            }
            [string] GetCommand () { return $script:UcpTestCurrentCmd }
            [void]   Debug ([object]$m) {}
            [void]   Info  ([object]$m) {}
            [void]   Error ([object]$m) {}
        }
        [DemistoObject]$demisto = [DemistoObject]::New()
        $script:UcpTestMetadata = @{
            connectionProfiles = @(@{ method_unique_id = 'm1'; capability = 'automation-and-remediation' })
        }
        $script:UcpTestCredentials = @{
            'm1' = @{ type = 'plain'; plain = @{ username = 'u1'; password = 'p1' } }
        }
        # When - Get-UcpCredentials is called.
        # Then - the nested plain.username and plain.password are flattened to top-level fields.
        $creds = Get-UcpCredentials
        $creds.type     | Should -Be 'plain'
        $creds.username | Should -Be 'u1'
        $creds.password | Should -Be 'p1'
    }

    It 'Get-UcpCredentials preserves extra fields beyond the standard credential keys' {
        # Given - a UCP 'plain' profile that carries additional connection fields (certificate,
        # app_id, organization, url, custom_flag) alongside the standard username/password.
        # This mirrors the EWS Extension Online PowerShell V3 / ps_demo connector where the
        # connection profile binds certificate + organization + app_id + url through the plain
        # auth profile.
        class DemistoObject {
            DemistoObject () {}
            [object] UnifiedConnectorMetadata () { return $script:UcpTestMetadata }
            [object] GetUCPCredentials ([string]$id, [bool]$fc) {
                if ($script:UcpTestCredentials.Contains($id)) { return $script:UcpTestCredentials[$id] }
                return $null
            }
            [string] GetCommand () { return $script:UcpTestCurrentCmd }
            [void]   Debug ([object]$m) {}
            [void]   Info  ([object]$m) {}
            [void]   Error ([object]$m) {}
        }
        [DemistoObject]$demisto = [DemistoObject]::New()
        $script:UcpTestMetadata = @{
            connectionProfiles = @(@{ method_unique_id = 'm1'; capability = 'automation-and-remediation' })
        }
        $script:UcpTestCredentials = @{
            'm1' = @{
                type         = 'plain'
                # Extra fields at the top level of the credentials object.
                certificate  = 'BASE64-CERT-DATA'
                app_id       = 'app-xyz'
                organization = 'contoso.onmicrosoft.com'
                url          = 'https://outlook.office365.com'
                custom_flag  = $true
                plain        = @{
                    username = 'u1'
                    password = 'p1'
                    # Extra fields nested under the type-specific sub-object.
                    nested_extra = 'kept'
                }
            }
        }
        # When - Get-UcpCredentials is called.
        # Then - the standard plain fields plus all extra fields (from both top level and the
        #        nested 'plain' sub-object) are present on the flattened result.
        $creds = Get-UcpCredentials
        $creds.type         | Should -Be 'plain'
        $creds.username     | Should -Be 'u1'
        $creds.password     | Should -Be 'p1'
        $creds.certificate  | Should -Be 'BASE64-CERT-DATA'
        $creds.app_id       | Should -Be 'app-xyz'
        $creds.organization | Should -Be 'contoso.onmicrosoft.com'
        $creds.url          | Should -Be 'https://outlook.office365.com'
        $creds.custom_flag  | Should -Be $true
        $creds.nested_extra | Should -Be 'kept'
    }

    It 'Invalidate-UcpCredentialsCache forces a re-fetch on the next call' {
        # Given - one credentials fetch has already populated the client-side TTL cache.
        class DemistoObject {
            DemistoObject () {}
            [object] UnifiedConnectorMetadata () { return $script:UcpTestMetadata }
            [object] GetUCPCredentials ([string]$id, [bool]$fc) {
                $script:UcpTestCalls += 1
                if ($script:UcpTestCredentials.Contains($id)) { return $script:UcpTestCredentials[$id] }
                return $null
            }
            [string] GetCommand () { return $script:UcpTestCurrentCmd }
            [void]   Debug ([object]$m) {}
            [void]   Info  ([object]$m) {}
            [void]   Error ([object]$m) {}
        }
        [DemistoObject]$demisto = [DemistoObject]::New()
        $script:UcpTestMetadata = @{
            connectionProfiles = @(@{ method_unique_id = 'm1'; capability = 'automation-and-remediation' })
        }
        $script:UcpTestCredentials = @{
            'm1' = @{ type = 'api_key'; api_key = @{ key = 'k-1' } }
        }

        Get-UcpCredentials | Out-Null
        $script:UcpTestCalls | Should -Be 1

        # When - Invalidate-UcpCredentialsCache is called and Get-UcpCredentials runs again.
        # Then - the second call hits the server again (call counter increments to 2).
        Invalidate-UcpCredentialsCache -methodUniqueId 'm1'
        Get-UcpCredentials | Out-Null
        $script:UcpTestCalls | Should -Be 2
    }
}

# Direct unit tests for DemistoObject.UnifiedConnectorMetadata - exercising the
# normalization branches: array unwrap, hashtable passthrough, IDictionary copy,
# PSCustomObject conversion, $null and unrecognized-type fallback.
#
# We test the production method by reaching into the real [DemistoObject]
# instance ($demisto, created when CommonServerPowerShell.ps1 is dot-sourced)
# and overriding only its ServerRequest method per test via Add-Member -Force.
# This lets the production UnifiedConnectorMetadata() run unchanged against
# stubbed transport responses, which is exactly what the AI reviewer asked for.
Describe 'UCP-DemistoObject-UnifiedConnectorMetadata' {
    BeforeEach {
        # Override ServerRequest on the real $demisto instance. Each It sets
        # $script:UcpDoNextResponse to whatever it wants ServerRequest to return.
        $script:UcpDoNextResponse = $null
        Add-Member -InputObject $demisto -MemberType ScriptMethod -Name 'ServerRequest' `
            -Force -Value { param($Cmd) return $script:UcpDoNextResponse }
    }

    It 'returns @{} when ServerRequest returns $null' {
        # Given - ServerRequest yields $null (no UCP metadata on the server).
        $script:UcpDoNextResponse = $null
        # When - UnifiedConnectorMetadata is called.
        # Then - it returns an empty hashtable rather than $null, so callers can index safely.
        $result = $demisto.UnifiedConnectorMetadata()
        $result | Should -BeOfType ([hashtable])
        $result.Count | Should -Be 0
    }

    It 'passes a hashtable response through unchanged' {
        # Given - ServerRequest already returns a hashtable.
        $script:UcpDoNextResponse = @{ connectionProfiles = @(@{ method_unique_id = 'm1' }); connectorId = 'c-1' }
        # When - UnifiedConnectorMetadata is called.
        # Then - the hashtable is returned intact and is still a hashtable.
        $result = $demisto.UnifiedConnectorMetadata()
        $result | Should -BeOfType ([hashtable])
        $result.connectorId       | Should -Be 'c-1'
        $result.connectionProfiles[0].method_unique_id | Should -Be 'm1'
    }

    It 'converts an ordered IDictionary to a hashtable' {
        # Given - ServerRequest returns an ordered dictionary (a real IDictionary that is not a hashtable).
        $script:UcpDoNextResponse = [ordered]@{ connectorId = 'c-2'; connectionProfiles = @(@{ method_unique_id = 'm2' }) }
        # When - UnifiedConnectorMetadata is called.
        # Then - the result is normalized to a hashtable, preserving all keys/values.
        $result = $demisto.UnifiedConnectorMetadata()
        $result | Should -BeOfType ([hashtable])
        $result.connectorId       | Should -Be 'c-2'
        $result.connectionProfiles[0].method_unique_id | Should -Be 'm2'
    }

    It 'converts a PSCustomObject (typical JSON-parse result) to a hashtable' {
        # Given - ServerRequest returns a PSCustomObject (what ConvertFrom-Json produces by default).
        $script:UcpDoNextResponse = [PSCustomObject]@{
            connectorId        = 'c-3'
            connectionProfiles = @([PSCustomObject]@{ method_unique_id = 'm3' })
        }
        # When - UnifiedConnectorMetadata is called.
        # Then - all PSObject properties are copied into a hashtable.
        $result = $demisto.UnifiedConnectorMetadata()
        $result | Should -BeOfType ([hashtable])
        $result.connectorId       | Should -Be 'c-3'
        $result.connectionProfiles[0].method_unique_id | Should -Be 'm3'
    }

    It 'unwraps a 1-element array wrapping a hashtable' {
        # Given - ServerRequest returns the metadata wrapped in a 1-element array (PowerShell can do this when
        # only one element is returned through the pipeline).
        $script:UcpDoNextResponse = @(, @{ connectorId = 'c-4' })
        # When - UnifiedConnectorMetadata is called.
        # Then - the array is unwrapped before the type-checks run, so the inner hashtable is returned.
        $result = $demisto.UnifiedConnectorMetadata()
        $result | Should -BeOfType ([hashtable])
        $result.connectorId | Should -Be 'c-4'
    }

    It 'unwraps a 1-element array wrapping a PSCustomObject' {
        # Given - ServerRequest returns the metadata as a PSCustomObject wrapped in a 1-element array.
        $script:UcpDoNextResponse = @(, [PSCustomObject]@{ connectorId = 'c-5' })
        # When - UnifiedConnectorMetadata is called.
        # Then - the array is unwrapped first, then the PSCustomObject is normalized to a hashtable.
        $result = $demisto.UnifiedConnectorMetadata()
        $result | Should -BeOfType ([hashtable])
        $result.connectorId | Should -Be 'c-5'
    }

    It 'returns @{} for an unrecognized response type' {
        # Given - ServerRequest returns a scalar integer the normalizer doesn't recognize (not array, hashtable,
        # IDictionary, or PSCustomObject).
        $script:UcpDoNextResponse = 42
        # When - UnifiedConnectorMetadata is called.
        # Then - the normalizer falls back to an empty hashtable rather than throwing or returning the scalar.
        $result = $demisto.UnifiedConnectorMetadata()
        $result | Should -BeOfType ([hashtable])
        $result.Count | Should -Be 0
    }
}