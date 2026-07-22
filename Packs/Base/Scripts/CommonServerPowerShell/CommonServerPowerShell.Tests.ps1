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

# ================================================================================
# UCP (Unified Connector Platform / ConnectUs) param interpolation tests.
# Parity with CommonServerPython_test.py UCP suites (TestUcpInterpolation,
# TestUcpInterpolationPassthroughDeep, get_ucp_credentials / invalidate tests).
# ================================================================================

Describe "Test ConvertFrom-UcpParamMap" {
    It "Parses a canonical comma-separated string into ordered pairs" {
        $pairs = ConvertFrom-UcpParamMap -ParamMap 'username:credentials.identifier,password:credentials.password'
        @($pairs).Count | Should -Be 2
        $pairs[0].FieldId | Should -Be 'username'
        $pairs[0].Destination | Should -Be 'credentials.identifier'
        $pairs[1].FieldId | Should -Be 'password'
        $pairs[1].Destination | Should -Be 'credentials.password'
    }

    It "Skips empty and malformed (no-colon) entries" {
        $pairs = ConvertFrom-UcpParamMap -ParamMap 'good:dest, ,nocolon,empty:'
        @($pairs).Count | Should -Be 1
        $pairs[0].FieldId | Should -Be 'good'
        $pairs[0].Destination | Should -Be 'dest'
    }

    It "Returns empty for `$null input" {
        @(ConvertFrom-UcpParamMap -ParamMap $null).Count | Should -Be 0
    }

    It "Returns empty for empty-string input" {
        @(ConvertFrom-UcpParamMap -ParamMap '').Count | Should -Be 0
    }

    It "Trims whitespace around field id and destination" {
        $pairs = ConvertFrom-UcpParamMap -ParamMap ' a : b.c '
        @($pairs).Count | Should -Be 1
        $pairs[0].FieldId | Should -Be 'a'
        $pairs[0].Destination | Should -Be 'b.c'
    }

    It "Splits only on the first colon (dotted destinations preserved)" {
        $pairs = ConvertFrom-UcpParamMap -ParamMap 'tenant:credentials.connection.tenant.slug'
        $pairs[0].FieldId | Should -Be 'tenant'
        $pairs[0].Destination | Should -Be 'credentials.connection.tenant.slug'
    }
}

Describe "Test Set-UcpByPath" {
    It "Places a value at a single-segment path" {
        $target = [ordered]@{}
        Set-UcpByPath -Target $target -Path 'dest' -Value 'v'
        $target['dest'] | Should -Be 'v'
    }

    It "Creates intermediate dicts for a dotted path" {
        $target = [ordered]@{}
        Set-UcpByPath -Target $target -Path 'credentials.identifier' -Value 'alice'
        $target['credentials']['identifier'] | Should -Be 'alice'
    }

    It "Folds two paths sharing a parent into one nested dict" {
        $target = [ordered]@{}
        Set-UcpByPath -Target $target -Path 'credentials.identifier' -Value 'alice'
        Set-UcpByPath -Target $target -Path 'credentials.password' -Value 's3cr3t'
        $target['credentials']['identifier'] | Should -Be 'alice'
        $target['credentials']['password'] | Should -Be 's3cr3t'
    }

    It "Empty path is a no-op (existing keys preserved)" {
        $target = [ordered]@{ keep = 1 }
        Set-UcpByPath -Target $target -Path '' -Value 'x'
        $target['keep'] | Should -Be 1
        $target.Contains('') | Should -Be $false
    }

    It "Overwrites a non-dict intermediate with a dict" {
        $target = [ordered]@{ a = 'scalar' }
        Set-UcpByPath -Target $target -Path 'a.b' -Value 2
        $target['a']['b'] | Should -Be 2
    }
}

Describe "Test Merge-UcpDeep" {
    It "Recursively merges nested dicts, preserving siblings" {
        $target = [ordered]@{ credentials = [ordered]@{ identifier = 'original'; password = 'old'; field3 = 'value' } }
        $source = [ordered]@{ credentials = [ordered]@{ identifier = 'new'; password = 'fresh' } }
        Merge-UcpDeep -Target $target -Source $source | Out-Null
        $target['credentials']['identifier'] | Should -Be 'new'
        $target['credentials']['password'] | Should -Be 'fresh'
        $target['credentials']['field3'] | Should -Be 'value'
    }

    It "Incoming value wins on a scalar conflict" {
        $target = [ordered]@{ a = 1; b = 2 }
        $source = [ordered]@{ a = 99 }
        Merge-UcpDeep -Target $target -Source $source | Out-Null
        $target['a'] | Should -Be 99
        $target['b'] | Should -Be 2
    }

    It "A dict overwrites a scalar" {
        $target = [ordered]@{ a = 'scalar' }
        $source = [ordered]@{ a = [ordered]@{ nested = 1 } }
        Merge-UcpDeep -Target $target -Source $source | Out-Null
        $target['a']['nested'] | Should -Be 1
    }

    It "A scalar overwrites a dict" {
        $target = [ordered]@{ a = [ordered]@{ nested = 1 } }
        $source = [ordered]@{ a = 'scalar' }
        Merge-UcpDeep -Target $target -Source $source | Out-Null
        $target['a'] | Should -Be 'scalar'
    }

    It "Adds keys present only in the source" {
        $target = [ordered]@{ a = 1 }
        $source = [ordered]@{ b = 2 }
        Merge-UcpDeep -Target $target -Source $source | Out-Null
        $target['a'] | Should -Be 1
        $target['b'] | Should -Be 2
    }
}

Describe "Test Select-UcpProfiles" {
    It "Selects the single profile matching the capability" {
        $profiles = @(
            [ordered]@{ capability = 'cap-a'; method_unique_id = 'A' },
            [ordered]@{ capability = 'cap-b'; method_unique_id = 'B' }
        )
        $result = @(Select-UcpProfiles -Profiles $profiles -Capability 'cap-a')
        $result.Count | Should -Be 1
        $result[0]['method_unique_id'] | Should -Be 'A'
    }

    It "Selects all profiles matching the capability" {
        $profiles = @(
            [ordered]@{ capability = 'cap-x'; method_unique_id = 'A' },
            [ordered]@{ capability = 'cap-x'; method_unique_id = 'B' }
        )
        $result = @(Select-UcpProfiles -Profiles $profiles -Capability 'cap-x')
        $result.Count | Should -Be 2
        $result[0]['method_unique_id'] | Should -Be 'A'
        $result[1]['method_unique_id'] | Should -Be 'B'
    }

    It "Falls back to the first profile with an interpolation_mapping when no capability matches" {
        $profiles = @(
            [ordered]@{ capability = 'other'; method_unique_id = 'A' },
            [ordered]@{ capability = 'other'; method_unique_id = 'B'; metadata = [ordered]@{ xsoar = [ordered]@{ interpolation_mapping = 'u:x' } } }
        )
        $result = @(Select-UcpProfiles -Profiles $profiles -Capability 'no-match')
        $result.Count | Should -Be 1
        $result[0]['method_unique_id'] | Should -Be 'B'
    }

    It "Returns empty for an empty profile list" {
        @(Select-UcpProfiles -Profiles @() -Capability 'cap').Count | Should -Be 0
    }
}

Describe "Test ConvertFrom-UcpCredentials" {
    It "Flattens a plain envelope (type -> inner dict)" {
        $envelope = [ordered]@{ type = 'plain'; plain = [ordered]@{ username = 'alice'; password = 's3cr3t' } }
        $flat = ConvertFrom-UcpCredentials -Credentials $envelope
        $flat['username'] | Should -Be 'alice'
        $flat['password'] | Should -Be 's3cr3t'
    }

    It "Descends into the 'parameters' sub-dict for a passthrough envelope" {
        $envelope = [ordered]@{ type = 'passthrough'; passthrough = [ordered]@{ parameters = [ordered]@{ username = 'bob'; token = 'tok' } } }
        $flat = ConvertFrom-UcpCredentials -Credentials $envelope
        $flat['username'] | Should -Be 'bob'
        $flat['token'] | Should -Be 'tok'
    }
}

Describe "Test Resolve-UcpCapability" {
    It "Maps a known command to its capability" {
        Resolve-UcpCapability -Command 'fetch-incidents' | Should -Be 'fetch-issues'
    }

    It "Falls back to the default capability for an unknown command" {
        Resolve-UcpCapability -Command 'some-random-command' | Should -Be 'automation-and-remediation'
    }
}

Describe "Test Build-UcpParams" {
    It "Folds flat fields into a credentials dict via interpolation_mapping" {
        Mock Get-UcpCredentials { return [ordered]@{ type = 'plain'; plain = [ordered]@{ username = 'alice'; password = 's3cr3t' } } }
        $meta = [ordered]@{
            connectionProfiles = @(
                [ordered]@{
                    capability        = 'automation-and-remediation'
                    method_unique_id  = 'A'
                    metadata          = [ordered]@{ xsoar = [ordered]@{ interpolation_mapping = 'username:credentials.identifier,password:credentials.password' } }
                }
            )
        }
        $result = Build-UcpParams -ConnectorMetadata $meta -Capability 'automation-and-remediation'
        $result['credentials']['identifier'] | Should -Be 'alice'
        $result['credentials']['password'] | Should -Be 's3cr3t'
    }

    It "Only interpolates profiles matching the capability" {
        Mock Get-UcpCredentials { return [ordered]@{ type = 'plain'; plain = [ordered]@{ k = 'COLLECTOR' } } }
        $meta = [ordered]@{
            connectionProfiles = @(
                [ordered]@{ capability = 'cap-a'; method_unique_id = 'A'; metadata = [ordered]@{ xsoar = [ordered]@{ interpolation_mapping = 'u:credentials.identifier' } } },
                [ordered]@{ capability = 'cap-b'; method_unique_id = 'B'; metadata = [ordered]@{ xsoar = [ordered]@{ interpolation_mapping = 'k:credentials.password' } } }
            )
        }
        $result = Build-UcpParams -ConnectorMetadata $meta -Capability 'cap-b'
        $result['credentials']['password'] | Should -Be 'COLLECTOR'
        $result['credentials'].Contains('identifier') | Should -Be $false
    }

    It "Merges values from multiple active profiles" {
        Mock Get-UcpCredentials {
            param($MethodUniqueId, $Body)
            if ($MethodUniqueId -eq 'A') { return [ordered]@{ type = 'plain'; plain = [ordered]@{ u = 'alice' } } }
            return [ordered]@{ type = 'plain'; plain = [ordered]@{ p = 'pw' } }
        }
        $meta = [ordered]@{
            connectionProfiles = @(
                [ordered]@{ capability = 'x'; method_unique_id = 'A'; metadata = [ordered]@{ xsoar = [ordered]@{ interpolation_mapping = 'u:credentials.identifier' } } },
                [ordered]@{ capability = 'x'; method_unique_id = 'B'; metadata = [ordered]@{ xsoar = [ordered]@{ interpolation_mapping = 'p:credentials.password' } } }
            )
        }
        $result = Build-UcpParams -ConnectorMetadata $meta -Capability 'x'
        $result['credentials']['identifier'] | Should -Be 'alice'
        $result['credentials']['password'] | Should -Be 'pw'
    }

    It "Last profile wins on a destination conflict" {
        Mock Get-UcpCredentials {
            param($MethodUniqueId, $Body)
            if ($MethodUniqueId -eq 'A') { return [ordered]@{ type = 'plain'; plain = [ordered]@{ v = 'first' } } }
            return [ordered]@{ type = 'plain'; plain = [ordered]@{ v = 'second' } }
        }
        $meta = [ordered]@{
            connectionProfiles = @(
                [ordered]@{ capability = 'x'; method_unique_id = 'A'; metadata = [ordered]@{ xsoar = [ordered]@{ interpolation_mapping = 'v:dest' } } },
                [ordered]@{ capability = 'x'; method_unique_id = 'B'; metadata = [ordered]@{ xsoar = [ordered]@{ interpolation_mapping = 'v:dest' } } }
            )
        }
        $result = Build-UcpParams -ConnectorMetadata $meta -Capability 'x'
        $result['dest'] | Should -Be 'second'
    }

    It "Skips fields with a missing (null) value" {
        Mock Get-UcpCredentials { return [ordered]@{ type = 'plain'; plain = [ordered]@{ present = 1 } } }
        $meta = [ordered]@{
            connectionProfiles = @(
                [ordered]@{ capability = 'x'; method_unique_id = 'A'; metadata = [ordered]@{ xsoar = [ordered]@{ interpolation_mapping = 'present:a,absent:b' } } }
            )
        }
        $result = Build-UcpParams -ConnectorMetadata $meta -Capability 'x'
        $result['a'] | Should -Be 1
        $result.Contains('b') | Should -Be $false
    }

    It "Returns empty when metadata is missing" {
        $result = Build-UcpParams -ConnectorMetadata $null -Capability 'x'
        @($result.Keys).Count | Should -Be 0
    }

    It "Returns empty when no profile carries an interpolation_mapping" {
        $meta = [ordered]@{ connectionProfiles = @([ordered]@{ capability = 'x'; method_unique_id = 'A' }) }
        $result = Build-UcpParams -ConnectorMetadata $meta -Capability 'x'
        @($result.Keys).Count | Should -Be 0
    }

    It "Resolves the capability automatically when not provided" {
        Mock Get-UcpCredentials { return [ordered]@{ type = 'plain'; plain = [ordered]@{ k = 'tok' } } }
        Mock Resolve-UcpCapability { return 'fetch-issues' }
        $meta = [ordered]@{
            connectionProfiles = @(
                [ordered]@{ capability = 'fetch-issues'; method_unique_id = 'A'; metadata = [ordered]@{ xsoar = [ordered]@{ interpolation_mapping = 'k:credentials.password' } } }
            )
        }
        $result = Build-UcpParams -ConnectorMetadata $meta -Capability $null
        $result['credentials']['password'] | Should -Be 'tok'
    }

    It "Performs deep, multi-level interpolation for a passthrough profile" {
        $mapping = (
            "username:credentials.identifier," +
            "app_password:credentials.password," +
            "bitbucket_email:credentials.metadata.email," +
            "account_id:credentials.metadata.accountId," +
            "api_token:credentials.metadata.token," +
            "client_key:credentials.oauth.consumerKey," +
            "client_secret:credentials.oauth.consumerSecret," +
            "base_url:credentials.connection.host," +
            "auth_scheme:credentials.connection.scheme," +
            "tenant:credentials.connection.tenant.slug"
        )
        Mock Get-UcpCredentials {
            return [ordered]@{
                type        = 'passthrough'
                passthrough = [ordered]@{
                    parameters = [ordered]@{
                        username        = 'alice'
                        app_password    = 's3cr3t'
                        bitbucket_email = 'you@example.com'
                        account_id      = '557058:abc'
                        api_token       = 'tok-123'
                        client_key      = 'ck'
                        client_secret   = 'cs'
                        base_url        = 'host-value'
                        auth_scheme     = 'basic'
                        tenant          = 'my-tenant'
                    }
                }
            }
        }
        $meta = [ordered]@{
            connectionProfiles = @(
                [ordered]@{
                    capability       = 'automation-and-remediation'
                    method_unique_id = 'pt-method-1'
                    type             = 'passthrough'
                    metadata         = [ordered]@{ xsoar = [ordered]@{ interpolation_mapping = $mapping } }
                }
            )
        }
        $result = Build-UcpParams -ConnectorMetadata $meta -Capability 'automation-and-remediation'
        $creds = $result['credentials']
        $creds['identifier'] | Should -Be 'alice'
        $creds['password'] | Should -Be 's3cr3t'
        $creds['metadata']['email'] | Should -Be 'you@example.com'
        $creds['metadata']['accountId'] | Should -Be '557058:abc'
        $creds['metadata']['token'] | Should -Be 'tok-123'
        $creds['oauth']['consumerKey'] | Should -Be 'ck'
        $creds['oauth']['consumerSecret'] | Should -Be 'cs'
        $creds['connection']['host'] | Should -Be 'host-value'
        $creds['connection']['scheme'] | Should -Be 'basic'
        $creds['connection']['tenant']['slug'] | Should -Be 'my-tenant'
    }
}

Describe "Test Get-UcpCredentials cache" {
    BeforeEach {
        $script:UcpCredsCache.Clear()
    }
    AfterEach {
        $script:UcpCredsCache.Clear()
    }

    It "Serves a fresh (far-future expiry) cache entry without re-fetching" {
        $creds = [ordered]@{ type = 'oauth2'; oauth2 = [ordered]@{ access_token = 'cached' } }
        $future = ([double][System.DateTimeOffset]::UtcNow.ToUnixTimeSeconds()) + 3600
        $script:UcpCredsCache['abc123'] = @{ result = $creds; expiry = $future }
        $result = Get-UcpCredentials -MethodUniqueId 'abc123'
        $result['oauth2']['access_token'] | Should -Be 'cached'
    }

    It "Serves a `$null-expiry entry indefinitely" {
        $creds = [ordered]@{ type = 'api_key'; api_key = [ordered]@{ key = 'k' } }
        $script:UcpCredsCache['key123'] = @{ result = $creds; expiry = $null }
        $result = Get-UcpCredentials -MethodUniqueId 'key123'
        $result['api_key']['key'] | Should -Be 'k'
    }
}

Describe "Test Clear-UcpCredentialEntry" {
    BeforeEach {
        $script:UcpCredsCache.Clear()
    }
    AfterEach {
        $script:UcpCredsCache.Clear()
    }

    It "Removes the specified cache entry" {
        $script:UcpCredsCache['abc123'] = @{ result = @{}; expiry = $null }
        Clear-UcpCredentialEntry -MethodUniqueId 'abc123'
        $script:UcpCredsCache.ContainsKey('abc123') | Should -Be $false
    }

    It "Does not raise for a non-existent key" {
        { Clear-UcpCredentialEntry -MethodUniqueId 'nope' } | Should -Not -Throw
    }

    It "Only removes the specified key, leaving others intact" {
        $script:UcpCredsCache['key1'] = @{ result = @{}; expiry = $null }
        $script:UcpCredsCache['key2'] = @{ result = @{}; expiry = $null }
        Clear-UcpCredentialEntry -MethodUniqueId 'key1'
        $script:UcpCredsCache.ContainsKey('key1') | Should -Be $false
        $script:UcpCredsCache.ContainsKey('key2') | Should -Be $true
    }
}

Describe "Test Invoke-UcpParamInterpolation" {
    BeforeEach {
        $script:UcpAuthParamsInjected = $false
    }
    AfterEach {
        $script:UcpAuthParamsInjected = $false
    }

    It "Sets the injected flag and merges interpolated params into the merge target" {
        Mock Build-UcpParams { return [ordered]@{ credentials = [ordered]@{ identifier = 'alice'; password = 's3cr3t' } } }
        $meta = [ordered]@{ connectionProfiles = @([ordered]@{ capability = 'automation-and-remediation'; method_unique_id = 'A' }) }

        $result = Invoke-UcpParamInterpolation -ConnectorMetadata $meta

        $result | Should -Be $true
        $script:UcpAuthParamsInjected | Should -Be $true
        # Merge target is $demisto._ucpParamsMergeTarget(); the interpolated
        # credentials must be observable through Params().
        $demisto.Params()['credentials']['identifier'] | Should -Be 'alice'
        $demisto.Params()['credentials']['password'] | Should -Be 's3cr3t'
    }

    It "Is a no-op (flag stays false) when no params are produced" {
        Mock Build-UcpParams { return [ordered]@{} }
        $meta = [ordered]@{ connectionProfiles = @([ordered]@{ capability = 'automation-and-remediation'; method_unique_id = 'A' }) }

        $result = Invoke-UcpParamInterpolation -ConnectorMetadata $meta

        $result | Should -Be $false
        $script:UcpAuthParamsInjected | Should -Be $false
    }
}