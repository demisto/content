# [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseDeclaredVarsMoreThanAssignments", "", Justification="Known issue in pester")]
# [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidTrailingWhitespace", "", Justification="Ignore")]
# [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidUsingWriteHost", "", Justification="Ignore")]
# Param()

$AUDIT_LOG_JSON = Get-Content "test_data/audit_log.json" -Raw | ConvertFrom-Json

# BeforeAll {
#     . "$PSScriptRoot/MicrosoftPolicyAndComplianceAuditLog.ps1"
#     Mock Connect-ExchangeOnline
#     Mock Disconnect-ExchangeOnline
# }

# $temp = Get-Content "test_data/audit_log.json" -Raw | ConvertFrom-Json
# Describe "SearchAuditLogCommand" {
#     It "With correct params" {
#         function Search-UnifiedAuditLog {
#             param (
#                 [string]$start_date,
#                 [string]$end_date,
#                 [string]$free_text,
#                 [string]$record_type,
#                 [String[]]$ip_addresses,
#                 [String[]]$operations,
#                 [String[]]$user_ids,
#                 [int]$result_size
#             )
#             return $AUDIT_LOG_JSON
#         }
#         Mock Get-Date {return "Wednesday, July 12, 2023 9:58:19 AM"}
#         $certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList [Text.Encoding]::Default.GetBytes("aaaaa=")
#         $password = ConvertTo-SecureString "password"  -AsPlainText -Force
#         $client = [ExchangeOnlinePowershellV3Client]::new("url", "app_id", "organization", $certificate, $password)
#         ($human_readable, $entry_context, $raw_response) = SearchAuditLogCommand $client
#         ($human_readable, $entry_context, $raw_response) | Should -Be ($temp, $null, $null)
#     }
# }

Describe "SearchAuditLogCommand Tests" {
    BeforeAll {
        . "$PSScriptRoot/MicrosoftPolicyAndComplianceAuditLog.ps1"
        Mock Connect-ExchangeOnline
        Mock Disconnect-ExchangeOnline
        function Search-UnifiedAuditLog {
            param (
                [string]$start_date,
                [string]$end_date,
                [string]$free_text,
                [string]$record_type,
                [String[]]$ip_addresses,
                [String[]]$operations,
                [String[]]$user_ids,
                [int]$result_size
            )
            return $AUDIT_LOG_JSON
        }
        
        $mockedClient = [ExchangeOnlinePowershellV3Client]::new(
            "https://example.com",
            "app_id",
            "organization",
            "base64encodedcertificate",
            (ConvertTo-SecureString "password" -AsPlainText -Force)
        )
    }
    
    
        Context "When the search returns results" {
            It "Should output the audit log entries and context" {
                # Arrange
    
                $command_arguments = @{
                    start_date = "2023-01-01"
                    end_date = "2023-01-31"
                    free_text = "search query"
                    record_type = "Type1"
                    ip_addresses = @("192.168.0.1", "192.168.0.2")
                    operations = @("Op1", "Op2")
                    user_ids = @("user1", "user2")
                    result_size = 100
                }
    
                # Act
                $result = SearchAuditLogCommand $mockedClient $command_arguments
    
                # Assert
                $result[0] | Should -Be "Expected human-readable output"
                $result[1]["$script:INTEGRATION_ENTRY_CONTEXT(val.Id === obj.Id)"][0].Id | Should -Be 1
                $result[1]["$script:INTEGRATION_ENTRY_CONTEXT(val.Id === obj.Id)"][0].EventName | Should -Be "Event 1"
                $result[1]["$script:INTEGRATION_ENTRY_CONTEXT(val.Id === obj.Id)"][1].Id | Should -Be 2
                $result[1]["$script:INTEGRATION_ENTRY_CONTEXT(val.Id === obj.Id)"][1].EventName | Should -Be "Event 2"
                $result[2][0].Id | Should -Be 1
                $result[2][0].EventName | Should -Be "Event 1"
                $result[2][1].Id | Should -Be 2
                $result[2][1].EventName | Should -Be "Event 2"
            }
        }
    
        Context "When the search returns no results" {
            It "Should output an empty audit log message" {
    
                $command_arguments = @{
                    start_date = "2023-01-01"
                    end_date = "2023-01-31"
                }
    
                # Act
                $result = SearchAuditLogCommand $mockedClient $command_arguments
    
                # Assert
                $result[0] | Should -Be "Audit log from 2023-01-01 to 2023-01-31 is empty"
                $result[1] | Should -BeNull
                $result[2] | Should -BeNull
            }
        }
    
        Context "When an invalid start_date is provided" {
            It "Should throw an error" {
                    { SearchAuditLogCommand $mockedClient $command_arguments } | Should -Throw "start_date"
            }
        }
    }
    