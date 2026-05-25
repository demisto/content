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

    It 'Test-UcpEnabled returns False when metadata is null' {
        class DemistoObject {
            DemistoObject () {}
            [object] UnifiedConnectorMetadata () { return $script:UcpTestMetadata }
            [void]   Debug ([object]$m) {}
            [void]   Info  ([object]$m) {}
            [void]   Error ([object]$m) {}
        }
        [DemistoObject]$demisto = [DemistoObject]::New()
        $script:UcpTestMetadata = $null
        Test-UcpEnabled | Should -BeFalse
    }

    It 'Test-UcpEnabled returns False when connectionProfiles is empty' {
        class DemistoObject {
            DemistoObject () {}
            [object] UnifiedConnectorMetadata () { return $script:UcpTestMetadata }
            [void]   Debug ([object]$m) {}
            [void]   Info  ([object]$m) {}
            [void]   Error ([object]$m) {}
        }
        [DemistoObject]$demisto = [DemistoObject]::New()
        $script:UcpTestMetadata = @{ connectionProfiles = @() }
        Test-UcpEnabled | Should -BeFalse
    }

    It 'Test-UcpEnabled returns True when connectionProfiles is non-empty' {
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
        Test-UcpEnabled | Should -BeTrue
    }

    It 'Test-ShouldUseUcpAuth honors the UCP_AUTH_PARAMS_INJECTED flag' {
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
        Test-ShouldUseUcpAuth | Should -BeTrue
        $script:UCP_AUTH_PARAMS_INJECTED = $true
        Test-ShouldUseUcpAuth | Should -BeFalse
    }

    It 'Resolve-UcpCapability maps known commands and falls back to default' {
        class DemistoObject {
            DemistoObject () {}
            [string] GetCommand () { return $script:UcpTestCurrentCmd }
            [void]   Debug ([object]$m) {}
            [void]   Info  ([object]$m) {}
            [void]   Error ([object]$m) {}
        }
        [DemistoObject]$demisto = [DemistoObject]::New()
        Resolve-UcpCapability -Command 'fetch-incidents' | Should -Be 'collection-and-ingestion'
        Resolve-UcpCapability -Command 'fetch-assets'    | Should -Be 'collection-and-ingestion'
        Resolve-UcpCapability -Command 'some-other-cmd'  | Should -Be 'automation-and-remediation'

        # Falls back to $demisto.GetCommand() when not given
        $script:UcpTestCurrentCmd = 'fetch-incidents'
        Resolve-UcpCapability | Should -Be 'collection-and-ingestion'
    }

    It 'Get-UcpMethodUniqueId matches by sub_capability first' {
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
        Get-UcpMethodUniqueId -SubCapability 'salesforce-iam' | Should -Be 'm2'
    }

    It 'Get-UcpMethodUniqueId matches by capability when sub_capability not given' {
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
        Get-UcpMethodUniqueId -Capability 'automation-and-remediation' | Should -Be 'm2'
    }

    It 'Get-UcpMethodUniqueId falls back to the first profile when nothing matches' {
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
        Get-UcpMethodUniqueId -Capability 'no-such-capability' | Should -Be 'm1'
    }

    It 'Get-UcpCredentials returns $null when UCP is not enabled' {
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
        Get-UcpCredentials | Should -BeNullOrEmpty
    }

    It 'Get-UcpCredentials flattens oauth2 credentials and caches them' {
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

        $first = Get-UcpCredentials
        $first.type         | Should -Be 'oauth2'
        $first.access_token | Should -Be 'tok-1'
        $first.token_type   | Should -Be 'Bearer'
        $script:UcpTestCalls | Should -Be 1

        # Second call - should hit the cache, no extra GetUCPCredentials request.
        $second = Get-UcpCredentials
        $second.access_token | Should -Be 'tok-1'
        $script:UcpTestCalls | Should -Be 1
    }

    It 'Get-UcpCredentials throws on empty oauth2 access_token' {
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
        { Get-UcpCredentials } | Should -Throw -ExpectedMessage '*UCP*'
    }

    It 'Get-UcpCredentials flattens api_key credentials' {
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
        $creds = Get-UcpCredentials
        $creds.type | Should -Be 'api_key'
        $creds.key  | Should -Be 'k-1'
    }

    It 'Get-UcpCredentials flattens plain credentials' {
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
        $creds = Get-UcpCredentials
        $creds.type     | Should -Be 'plain'
        $creds.username | Should -Be 'u1'
        $creds.password | Should -Be 'p1'
    }

    It 'Invalidate-UcpCredentialsCache forces a re-fetch on the next call' {
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

        Invalidate-UcpCredentialsCache -methodUniqueId 'm1'
        Get-UcpCredentials | Out-Null
        $script:UcpTestCalls | Should -Be 2
    }
}