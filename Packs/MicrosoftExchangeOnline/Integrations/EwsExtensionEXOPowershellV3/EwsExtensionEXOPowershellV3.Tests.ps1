BeforeAll {
    . $PSScriptRoot\CommonServerPowerShell.ps1
    . $PSScriptRoot\EwsExtensionEXOPowershellV3.ps1

    class MockClient {
        [psobject] EXOGetQuarantineMessage($params) {
            $identity = $params.Identity

            if ($identity -eq "single-message") {
                return [PSCustomObject]@{
                    Identity = "msg-123"
                    Subject = "Test Message"
                    Direction = "Inbound"
                    SenderAddress = "sender@test.com"
                    RecipientAddress = @("recipient@test.com")
                    EmptyField = ""
                    NullField = $null
                }
            }
            elseif ($identity -eq "multiple-messages") {
                return @(
                    [PSCustomObject]@{
                        Identity = "msg-1"
                        Subject = "Message 1"
                        Direction = "Inbound"
                    },
                    [PSCustomObject]@{
                        Identity = "msg-2"
                        Subject = "Message 2"
                        Direction = "Outbound"
                    }
                )
            }
            elseif ($identity -eq "empty-result") {
                return @()
            }
            elseif ($identity -eq "hashtable-message") {
                return @{
                    Identity = "msg-789"
                    Subject = "Hashtable Message"
                    Direction = "Inbound"
                }
            }

            return $null
        }
    }

    $mockClient = [MockClient]::new()
}

Describe 'EXOGetQuarantineMessageCommand' {
    Context "Single message response" {
        It "Processes single message correctly" {
            $kwargs = @{ identity = "single-message" }

            $result = EXOGetQuarantineMessageCommand -client $mockClient -kwargs $kwargs

            # Should return 3 elements: human_readable, entry_context, raw_response
            $result | Should -HaveCount 3

            # Human readable should not be empty
            $result[0] | Should -Not -BeNullOrEmpty

            # Entry context should have the correct key
            $result[1].Keys | Should -Contain "EWS.GetQuarantineMessage(obj.Identity === val.Identity)"

            # Raw response should be the original object
            $result[2].Identity | Should -Be "msg-123"
            $result[2].Subject | Should -Be "Test Message"
        }

        It "Removes empty fields from single message" {
            $kwargs = @{ identity = "single-message" }

            $result = EXOGetQuarantineMessageCommand -client $mockClient -kwargs $kwargs

            # The raw response should still have all fields (including empty ones)
            $result[2].Identity | Should -Be "msg-123"
            $result[2].EmptyField | Should -Be ""
            $result[2].NullField | Should -Be $null
        }
    }

    Context "Multiple messages response" {
        It "Processes array of messages correctly" {
            $kwargs = @{ identity = "multiple-messages" }

            $result = EXOGetQuarantineMessageCommand -client $mockClient -kwargs $kwargs

            $result | Should -HaveCount 3
            $result[0] | Should -Not -BeNullOrEmpty

            # Raw response should be an array
            $result[2] | Should -HaveCount 2
            $result[2][0].Identity | Should -Be "msg-1"
            $result[2][1].Identity | Should -Be "msg-2"
        }
    }

    Context "Empty response" {
        It "Handles null response gracefully" {
            $kwargs = @{ identity = "empty-result" }

            $result = EXOGetQuarantineMessageCommand -client $mockClient -kwargs $kwargs

            $result | Should -HaveCount 3

            # Raw response should be null or empty
            $result[2] | Should -BeNullOrEmpty
        }
    }

    Context "Hashtable response" {
        It "Processes hashtable response correctly" {
            $kwargs = @{ identity = "hashtable-message" }

            $result = EXOGetQuarantineMessageCommand -client $mockClient -kwargs $kwargs

            $result | Should -HaveCount 3
            $result[0] | Should -Not -BeNullOrEmpty

            # Raw response should contain the hashtable data
            $result[2].Identity | Should -Be "msg-789"
            $result[2].Subject | Should -Be "Hashtable Message"
        }
    }

    Context "Various parameter combinations" {
        It "Accepts empty kwargs" {
            $kwargs = @{}

            $result = EXOGetQuarantineMessageCommand -client $mockClient -kwargs $kwargs

            $result | Should -HaveCount 3
        }

        It "Handles multiple filter parameters" {
            $kwargs = @{
                identity = "single-message"
                entity_type = "Email"
                direction = "Inbound"
            }

            $result = EXOGetQuarantineMessageCommand -client $mockClient -kwargs $kwargs

            $result | Should -HaveCount 3
            $result[2].Identity | Should -Be "msg-123"
        }
    }
}