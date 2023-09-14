Describe "SearchAuditLogCommand Tests" {
    BeforeAll {
        . "$PSScriptRoot/MicrosoftPolicyAndComplianceAuditLog.ps1"
        . "$PSScriptRoot/CommonServerPowerShell.ps1"
        
        Mock Connect-ExchangeOnline
        Mock Disconnect-ExchangeOnline
        Mock Get-Date {"Thursday, July 13, 2023 3:14:32 PM"}
        Mock New-Object

        $mockedClient = [ExchangeOnlinePowershellV3Client]::new(
            "app_id",
            "organization",
            [System.Convert]::ToBase64String(
                [System.Text.Encoding]::UTF8.GetBytes(
                    "certificate")),
            (ConvertTo-SecureString "password" -AsPlainText -Force)
        )

        $command_arguments = @{
            start_date = "2023-01-01"
            end_date = "2023-01-31"
            free_text = "search query"
            record_type = "Type1"
            ip_addresses = @("192.168.0.1", "192.168.0.2")
            operations = @("Op1", "Op2")
            user_ids = @("user1", "user2")
            result_size = 0
        }
    }


    Context "When the search returns results" {
        It "Should output the audit log entries and context" {
            function Search-UnifiedAuditLog {
                param (
                    [string]$StartDate,
                    [string]$EndDate,
                    [string]$RecordType,
                    [string]$FreeText,
                    [String[]]$Operations,
                    [String[]]$IPAddresses,
                    [String[]]$UserIds,
                    [int]$ResultSize
                )
                
                $StartDate | Should -Be "Thursday, July 13, 2023 3:14:32 PM"
                $EndDate | Should -Be "Thursday, July 13, 2023 3:14:32 PM"
                $RecordType | Should -Be "Type1"
                $FreeText | Should -Be "search query"
                $IPAddresses | Should -Be @("192.168.0.1", "192.168.0.2")
                $operations | Should -Be @("Op1", "Op2")
                $UserIds | Should -Be @("user1", "user2")
                $ResultSize | Should -Be 5000

                return ,@{AuditData = Get-Content "test_data/audit_log.json" -Raw}
            }

            $human_readable, $entry_context, $raw_response = SearchAuditLogCommand $mockedClient $command_arguments

            $human_readable | Should -Be (Get-Content "test_data/human_readable.md" -Raw)
            $entry_context["O365AuditLog(val.Id === obj.Id)"][0].Workload | Should -Be "AzureActiveDirectory"
            $entry_context["O365AuditLog(val.Id === obj.Id)"][0].UserId | Should -Be "someone@somecompany.onmicrosoft.com"
            $raw_response[0].Workload | Should -Be "AzureActiveDirectory"
            $raw_response[0].UserId | Should -Be "someone@somecompany.onmicrosoft.com"
        }
    }

    Context "When the search returns no results" {
        It "Should output an empty audit log message" {
            function Search-UnifiedAuditLog {}

            $result = SearchAuditLogCommand $mockedClient $command_arguments

            $result[0] | Should -Be "Audit log from $(Get-Date) to $(Get-Date) is empty"
            $result[1] | Should -BeNull
            $result[2] | Should -BeNull
        }
    }

    Context "When an invalid start_date is provided" {
        It "Should throw an error" {
            $command_arguments.start_date = "gibberish"
            
            { SearchAuditLogCommand $mockedClient $command_arguments } |
                Should -Throw "start_date ('gibberish') is not a date range or a valid date "
        }
    }
}
