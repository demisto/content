BeforeAll {
    . $PSScriptRoot\demistomock.ps1
    . $PSScriptRoot\SecurityAndCompliance.ps1
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

        It "Single Results" {
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

            $parsed_object = ParseResults $string 1

            Compare-Object $expected_object $parsed_object -Property Location, Sender, Subject, Type, ReceivedTime ,Size, DataLink, Count | Should -Be $null
        }

        It "Multiple Results" {
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

            $parsed_objects = ParseResults $string 3

            for ($i = 0; $i -lt $expected_objects.Count; $i++) {
                Compare-Object $expected_objects[$i] $parsed_objects[$i] -Property Location, Sender, Subject, Type, ReceivedTime ,Size, DataLink, Count | Should -Be $null
            }
        }
    }
}