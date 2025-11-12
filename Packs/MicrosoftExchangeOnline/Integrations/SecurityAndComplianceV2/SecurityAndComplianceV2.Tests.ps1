BeforeAll {
    . $PSScriptRoot\demistomock.ps1
    . $PSScriptRoot\SecurityAndComplianceV2.ps1
    
        class MockClient {
            [psobject] NewSearch($name, $param2, $kql, $description, $bool1, $locations, $p1, $p2, $p3, $errAction) {
                return @{ Name = $name; Status = "NotStarted"}
            }
    
            [void] StartSearch($name) {
                $script:SearchStarted = $true
            }
    
            [psobject] GetSearch($name) {
                return @{ Name = $name; Status = "Completed"; Items = 2 }
            }
    
            [psobject] GetSearchAction($name, $errAction) {
                return $null
            }
    
            [psobject] NewSearchAction($a, $b, $c, $d, $e, $f, $g, $h, $i, $j) {
                return @{ Status = "Starting" }
            }
        }
        $mockClient = [MockClient]::new()
    }    


Describe 'StringRegexParse' {
    Context "SuccesResults" {
        It "No SuccesResults" {
            $string = ''
            $parsed_object = ParseSuccessResults $string -1
            $parsed_object | Should -Be $null
        }

        It "Single SuccesResults" {
            $string = "{Location: user@onmicrosoft.com, Item count: 1, Total size: 2}"
            $expected_object = @{
                "Location" = "user@onmicrosoft.com"
                "ItemsCount" = 1
                "Size" = 2
            }
            $parsed_object = ParseSuccessResults $string 1

            Compare-Object $expected_object $parsed_object -Property Location, ItemsCount, Size, Count | Should -Be $null
        }

        It "Multiple SuccesResults" {
            $string = "{Location: user1@onmicrosoft.com, Item count: 1, Total size: 2}
            {Location: user2@onmicrosoft.com, Item count: 3, Total size: 4}
            {Location: user3@onmicrosoft.com, Item count: 5, Total size: 6}"
            $expected_objects = @(@{
                "Location" = "user1@onmicrosoft.com"
                "ItemsCount" = 1
                "Size" = 2
            },
            @{
                "Location" = "user2@onmicrosoft.com"
                "ItemsCount" = 3
                "Size" = 4
            },
            @{
                "Location" = "user3@onmicrosoft.com"
                "ItemsCount" = 5
                "Size" = 6
            }
            )

            $parsed_objects = ParseSuccessResults $string 3

            for ($i = 0; $i -lt $expected_objects.Count; $i++) {
                Compare-Object $expected_objects[$i] $parsed_objects[$i] -Property Location, ItemsCount, Size, Count | Should -Be $null
            }
        }
    }

    Context "Results" {
        It "No Results" {
            $string = ''
            $parsed_object = ParseResults $string
            $parsed_object | Should -Be $null
        }
        # for preview result
        It "Single Results Preview" {
            $string = "{Location: user@onmicrosoft.com; Sender: user; Subject: xxx xxx; Type: Email; Size: 1; Received Time: 5/14/2020 6:45:31 PM; Data Link: data}"
            $expected_object = @{
                "Location" = "user@onmicrosoft.com"
                "Sender" = "user"
                "Subject" = "xxx xxx"
                "Type" = "Email"
                "Size" = 1
                "ReceivedTime" = "5/14/2020 6:45:31 PM"
                "DataLink" = "data"
            }

            $parsed_object = ParseResults $string 1 "Preview"

            Compare-Object $expected_object $parsed_object -Property Location, Sender, Subject, Type, ReceivedTime ,Size, DataLink, Count | Should -Be $null
        }

        It "Multiple Results Preview" {
            $string = "{Location: user1@onmicrosoft.com; Sender: user one; Subject: xxx xxx; Type: Email; Size: 1; Received Time: 5/14/2020 6:45:31 PM; Data Link: data1,
                Location: user2@onmicrosoft.com; Sender: user two; Subject: yyy yyy; Type: Email; Size: 2; Received Time: 5/14/2020 6:45:32 PM; Data Link: data2,
                Location: user3@onmicrosoft.com; Sender: user three; Subject: zzz zzz; Type: Email; Size: 3; Received Time: 5/14/2020 6:45:33 PM; Data Link: data3/data}"
            $expected_objects = @(@{
                "Location" = "user1@onmicrosoft.com"
                "Sender" = "user one"
                "Subject" = "xxx xxx"
                "Type" = "Email"
                "Size" = 1
                "ReceivedTime" = "5/14/2020 6:45:31 PM"
                "DataLink" = "data1"
            },
            @{
                "Location" = "user2@onmicrosoft.com"
                "Sender" = "user two"
                "Subject" = "yyy yyy"
                "Type" = "Email"
                "Size" = 2
                "ReceivedTime" = "5/14/2020 6:45:32 PM"
                "DataLink" = "data2"
            },
            @{
                "Location" = "user3@onmicrosoft.com"
                "Sender" = "user three"
                "Subject" = "zzz zzz"
                "Type" = "Email"
                "Size" = 3
                "ReceivedTime" = "5/14/2020 6:45:33 PM"
                "DataLink" = "data3/data"
            }
            )

            $parsed_objects = ParseResults $string 3 "Preview"

            for ($i = 0; $i -lt $expected_objects.Count; $i++) {
                Compare-Object $expected_objects[$i] $parsed_objects[$i] -Property Location, Sender, Subject, Type, ReceivedTime ,Size, DataLink, Count | Should -Be $null
            }
        }
        # for Purge result
        It "Single Results Purge" {
            $string = "{Location: testp@demistodev.onmicrosoft.com; Item count: 10; Total size: 2890210; Failed count: 0; }"
            $expected_object = @{
                "Location" = "testp@demistodev.onmicrosoft.com"
                "ItemCount" = 10
                "TotalSize" = 2890210
                "FailedCount" = 0
            }

            $parsed_object = ParseResults $string 1 "Purge"

            Compare-Object $expected_object $parsed_object -Property Location
        }

        It "Multiple Results Purge" {
            $string = "Details:{Location: testp@demistodev.onmicrosoft.com; Item count: 10; Total size: 2890210; Failed count: 0; ,
                        Location: aaaaa@demistodev.onmicrosoft.com; Item count: 10; Total size: 2814884; Failed count: 0; ,
                        Location: FileTestTeam@demistodev.onmicrosoft.com; Item count: 10; Total size: 2791289; Failed count: 0; }"
                        ""
            $expected_objects = @(@{
                "Location" = "testp@demistodev.onmicrosoft.com"
                "ItemCount" = 10
                "TotalSize" = 2890210
                "FailedCount" = 0
            },
            @{
                "Location" = "aaaaa@demistodev.onmicrosoft.com"
                "ItemCount" = 10
                "TotalSize" = 2814884
                "FailedCount" = 0
            },
            @{
                "Location" = "FileTestTeam@demistodev.onmicrosoft.com"
                "ItemCount" = 10
                "TotalSize" = 2791289
                "FailedCount" = 0
            }
            )

            $parsed_objects = ParseResults $string 3 "Purge"

            for ($i = 0; $i -lt $expected_objects.Count; $i++) {
                Compare-Object $expected_objects[$i] $parsed_objects[$i] -Property Location
            }
        }
    }
}

Describe 'GetShortHash' {
    Context "Hashing basics" {
        It "Returns a hash of the requested length" {
            $input = "hello world"
            $length = 12
            $hash = GetShortHash $input $length

            $hash.Length | Should -Be $length
        }
        It "Returns the same hash for the same input" {
            $input = "repeatable"
            $hash1 = GetShortHash $input
            $hash2 = GetShortHash $input

            $hash1 | Should -Be $hash2
        }
        It "Returns different hashes for different input" {
            $input1 = "input one"
            $input2 = "input two"
            $hash1 = GetShortHash $input1
            $hash2 = GetShortHash $input2

            $hash1 | Should -Not -Be $hash2
        }
    }
}

Describe 'MakeSearchName' {
    Context "Override name is provided" {
        It "Returns the override name directly" {
            $result = MakeSearchName "<abc@domain.com>" @("Mailbox1") "CustomName"
            $result | Should -Be "CustomName"
        }
    }

    Context "ExchangeLocation is 'All'" {
        It "Strips angle brackets and returns only base name" {
            $result = MakeSearchName "<abc@domain.com>" @("All","Mailbox1")
            $result | Should -Be "abc@domain.com"
        }
    }

    Context "ExchangeLocation is a specific mailbox or list" {
        It "Returns different hashes for different locations" {
            $name1 = MakeSearchName "<abc@domain.com>" @("Mailbox1")
            $name2 = MakeSearchName "<abc@domain.com>" @("Mailbox2")

            $name1 | Should -Not -Be $name2
        }
        It "Returns same hash for same location input order" {
            $name1 = MakeSearchName "<abc@domain.com>" @("Mailbox1", "Mailbox2")
            $name2 = MakeSearchName "<abc@domain.com>" @("Mailbox1", "Mailbox2")

            $name1 | Should -Be $name2
        }
    }
}

Describe 'SearchAndDeleteEmailCommand' {
    Context "Initial run - search creation" {
        It "Creates and starts a new search" {
            $kwargs = @{
                polling_first_run = $true
                force = $false
                internet_message_id = "<abc@domain.com>"
                exchange_location = @("All")
            }

            $result = SearchAndDeleteEmailCommand -client $mockClient -kwargs $kwargs

            $result[2].Name | Should -Match "abc@domain.com"
            $result[3].search_name | Should -Be $result[2].Name
        }
    }

}
