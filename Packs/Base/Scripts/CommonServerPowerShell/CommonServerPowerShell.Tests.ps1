BeforeAll {
    . $PSScriptRoot\CommonServerPowerShell.ps1
}


Describe 'Check-DemistoServerRequest' {
    It 'Check that a call to demisto DemistoServerRequest mock works. Should always return an empty response' {
        global:DemistoServerRequest @{} | Should -BeNullOrEmpty
        $demisto.GetAllSupportedCommands() | Should -BeNullOrEmpty
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