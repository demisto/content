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

        [psobject] CreateMailFlowRule($cmd_params) {
            # Echo back the received params plus a few server-populated fields so tests can
            # assert the parameter mapping/casting and the output shape.
            return [PSCustomObject]@{
                Name                         = $cmd_params.Name
                State                        = "Enabled"
                Mode                         = $cmd_params.Mode
                Priority                     = $cmd_params.Priority
                IsRuleConfigurationSupported = $true
                Comments                     = $cmd_params.Comments
                Guid                         = "00000000-0000-0000-0000-000000000001"
                From                         = $cmd_params.From
                SentTo                       = $cmd_params.SentTo
                Quarantine                   = $cmd_params.Quarantine
                DeleteMessage                = $cmd_params.DeleteMessage
                RejectMessageReasonText      = $cmd_params.RejectMessageReasonText
                StopRuleProcessing           = $cmd_params.StopRuleProcessing
            }
        }

        [psobject] UpdateMailFlowRule($cmd_params) {
            # Echo back the received params so tests can assert the parameter mapping/casting.
            # Set-TransportRule returns no output in reality, but we return the params here to
            # allow the test to verify what was sent to the cmdlet.
            return [PSCustomObject]@{
                Identity   = $cmd_params.Identity
                Mode       = $cmd_params.Mode
                Priority   = $cmd_params.Priority
                Comments   = $cmd_params.Comments
                From       = $cmd_params.From
                SentTo     = $cmd_params.SentTo
                Quarantine = $cmd_params.Quarantine
            }
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

Describe 'NewMailFlowRuleCommand' {
    Context "Valid create with a single action" {
        It "Creates a rule and returns the expected output shape" {
            $kwargs = @{ name = "Test-Rule"; quarantine = "true" }

            $result = NewMailFlowRuleCommand -client $mockClient -kwargs $kwargs

            # Should return 3 elements: human_readable, entry_context, raw_response
            $result | Should -HaveCount 3

            # Human readable should not be empty
            $result[0] | Should -Not -BeNullOrEmpty

            # Raw response should carry the created rule
            $result[2].Name | Should -Be "Test-Rule"
            $result[2].Quarantine | Should -Be $true
        }
    }

    Context "Argument mapping and type casting" {
        It "Maps snake_case args to PowerShell params and casts types" {
            $kwargs = @{
                name       = "Mapping-Rule"
                priority   = "5"
                from       = "a@test.com,b@test.com"
                sent_to    = "c@test.com"
                comments   = "hello"
                quarantine = "true"
            }

            $result = NewMailFlowRuleCommand -client $mockClient -kwargs $kwargs

            # priority cast to int
            $result[2].Priority | Should -Be 5
            $result[2].Priority | Should -BeOfType [int]

            # from / sent_to cast to arrays
            $result[2].From | Should -HaveCount 2
            $result[2].From[0] | Should -Be "a@test.com"
            $result[2].SentTo | Should -HaveCount 1

            # quarantine cast to boolean
            $result[2].Quarantine | Should -Be $true

            $result[2].Comments | Should -Be "hello"
        }
    }

    Context "Missing action validation" {
        It "Returns an error and does not call the client when no action is provided" {
            Mock ReturnError {}

            $kwargs = @{ name = "No-Action-Rule"; subject_contains_words = "test" }

            $result = NewMailFlowRuleCommand -client $mockClient -kwargs $kwargs

            # ReturnError should be invoked exactly once
            Should -Invoke ReturnError -Times 1 -Exactly

            # The command returns nothing after the validation error
            $result | Should -BeNullOrEmpty
        }
    }

    Context "Default extended_output (false)" {
        It "Returns the curated subset context under the Guid-keyed path" {
            $kwargs = @{ name = "Subset-Rule"; quarantine = "true"; extended_output = "false" }

            $result = NewMailFlowRuleCommand -client $mockClient -kwargs $kwargs

            $result | Should -HaveCount 3
            $result[1].Keys | Should -Contain "EWS.MailFlowRules(obj.Guid === val.Guid)"
        }
    }

    Context "Extended output (true)" {
        It "Returns the full response context under the Guid-keyed path" {
            $kwargs = @{ name = "Full-Rule"; quarantine = "true"; extended_output = "true" }

            $result = NewMailFlowRuleCommand -client $mockClient -kwargs $kwargs

            $result | Should -HaveCount 3
            $result[1].Keys | Should -Contain "EWS.MailFlowRules(obj.Guid === val.Guid)"

            # Full response context is the parsed raw response object (carries the Guid).
            $result[1]["EWS.MailFlowRules(obj.Guid === val.Guid)"].Guid | Should -Be "00000000-0000-0000-0000-000000000001"
        }
    }
}

Describe 'SetMailFlowRuleCommand' {
    Context "Valid update" {
        It "Updates a rule and returns the expected output shape" {
            $kwargs = @{ identity = "Test-Rule"; priority = "2" }

            $result = SetMailFlowRuleCommand -client $mockClient -kwargs $kwargs

            # Should return 3 elements: human_readable, entry_context, raw_response
            $result | Should -HaveCount 3

            # Human readable should be the success message referencing the identity
            $result[0] | Should -BeLike "*Test-Rule*"
            $result[0] | Should -BeLike "*updated successfully*"
        }
    }

    Context "No context output" {
        It "Returns an empty entry context" {
            $kwargs = @{ identity = "Test-Rule"; comments = "changed" }

            $result = SetMailFlowRuleCommand -client $mockClient -kwargs $kwargs

            # Set-TransportRule produces no context output.
            $result[1] | Should -BeOfType [hashtable]
            $result[1].Keys | Should -HaveCount 0
        }
    }

    Context "Argument mapping and type casting" {
        It "Maps identity and casts types before calling the client" {
            $kwargs = @{
                identity = "Mapping-Rule"
                priority = "7"
                from     = "a@test.com,b@test.com"
                comments = "hello"
            }

            $result = SetMailFlowRuleCommand -client $mockClient -kwargs $kwargs

            # raw_response echoes what was sent to the client
            $result[2].Identity | Should -Be "Mapping-Rule"
            $result[2].Priority | Should -Be 7
            $result[2].Priority | Should -BeOfType [int]
            $result[2].From | Should -HaveCount 2
            $result[2].Comments | Should -Be "hello"
        }
    }

    Context "Update without action arguments" {
        It "Does not require an action (unlike create)" {
            $kwargs = @{ identity = "No-Action-Update"; mode = "Enforce" }

            $result = SetMailFlowRuleCommand -client $mockClient -kwargs $kwargs

            $result | Should -HaveCount 3
            $result[2].Mode | Should -Be "Enforce"
        }
    }
}

Describe 'Entry ID parameter loading and merging' {
    Context "MergeEntryIdParams" {
        It "Adds file parameters that are not already present in cmd_params" {
            $cmd_params = @{ Name = "My Rule" }
            $params_from_file = @{ Comments = "From file"; StopRuleProcessing = $true }

            $merged = MergeEntryIdParams $cmd_params $params_from_file

            $merged.Name | Should -Be "My Rule"
            $merged.Comments | Should -Be "From file"
            $merged.StopRuleProcessing | Should -Be $true
        }

        It "Gives precedence to explicit command arguments over file values" {
            $cmd_params = @{ Comments = "Explicit comment" }
            $params_from_file = @{ Comments = "From file" }

            $merged = MergeEntryIdParams $cmd_params $params_from_file

            # The explicit argument value must win.
            $merged.Comments | Should -Be "Explicit comment"
        }

        It "Returns cmd_params unchanged when the file map is empty" {
            $cmd_params = @{ Name = "My Rule" }
            $params_from_file = @{}

            $merged = MergeEntryIdParams $cmd_params $params_from_file

            $merged.Keys | Should -HaveCount 1
            $merged.Name | Should -Be "My Rule"
        }
    }


    Context "End-to-end entry_id merging via NewMailFlowRuleCommand" {
        It "Merges file parameters into the client call, with explicit args winning" {
            # Mock the file-loading helper so this test focuses on the merge behavior
            # inside NewMailFlowRuleCommand, independent of the $demisto file API.
            Mock GetMailFlowRuleParamsFromEntryId {
                return @{ Comments = "From file"; StopRuleProcessing = $true }
            }

            # Explicit comments should win over the file value; StopRuleProcessing comes from the file.
            $kwargs = @{ name = "Merged Rule"; quarantine = "true"; comments = "Explicit comment"; entry_id = "12@34" }

            $result = NewMailFlowRuleCommand -client $mockClient -kwargs $kwargs

            $result | Should -HaveCount 3
            # raw_response echoes the params sent to the client (MockClient.CreateMailFlowRule).
            $result[2].Comments | Should -Be "Explicit comment"
            $result[2].StopRuleProcessing | Should -Be $true
        }
    }
}