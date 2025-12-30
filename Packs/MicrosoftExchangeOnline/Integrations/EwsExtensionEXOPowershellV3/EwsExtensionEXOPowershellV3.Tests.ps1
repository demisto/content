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
                return $null
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

Describe 'Test-IsEmptyValue' {
    Context "Null values" {
        It "Returns true for null" {
            $result = Test-IsEmptyValue $null
            $result | Should -Be $true
        }
    }
    
    Context "String values" {
        It "Returns true for empty string" {
            $result = Test-IsEmptyValue ""
            $result | Should -Be $true
        }
        
        It "Returns true for whitespace string" {
            $result = Test-IsEmptyValue "   "
            $result | Should -Be $true
        }
        
        It "Returns false for non-empty string" {
            $result = Test-IsEmptyValue "hello"
            $result | Should -Be $false
        }
    }
    
    Context "Collection values" {
        It "Returns true for empty array" {
            $result = Test-IsEmptyValue @()
            $result | Should -Be $true
        }
        
        It "Returns false for non-empty array" {
            $result = Test-IsEmptyValue @(1, 2, 3)
            $result | Should -Be $false
        }
    }
    
    Context "Numeric and boolean values" {
        It "Returns false for zero" {
            $result = Test-IsEmptyValue 0
            $result | Should -Be $false
        }
        
        It "Returns false for false boolean" {
            $result = Test-IsEmptyValue $false
            $result | Should -Be $false
        }
        
        It "Returns false for true boolean" {
            $result = Test-IsEmptyValue $true
            $result | Should -Be $false
        }
    }
}

Describe 'Remove-EmptyItems' {
    Context "PSCustomObject input" {
        It "Removes null properties" {
            $input = [PSCustomObject]@{
                ValidProp = "value"
                NullProp = $null
            }
            
            $result = Remove-EmptyItems $input
            
            $result.Keys | Should -Contain "ValidProp"
            $result.Keys | Should -Not -Contain "NullProp"
            $result["ValidProp"] | Should -Be "value"
        }
        
        It "Removes empty string properties" {
            $input = [PSCustomObject]@{
                ValidProp = "value"
                EmptyString = ""
                WhitespaceString = "   "
            }
            
            $result = Remove-EmptyItems $input
            
            $result.Keys | Should -Contain "ValidProp"
            $result.Keys | Should -Not -Contain "EmptyString"
            $result.Keys | Should -Not -Contain "WhitespaceString"
        }
        
        It "Removes empty array properties" {
            $input = [PSCustomObject]@{
                ValidProp = "value"
                EmptyArray = @()
                ValidArray = @(1, 2, 3)
            }
            
            $result = Remove-EmptyItems $input
            
            $result.Keys | Should -Contain "ValidProp"
            $result.Keys | Should -Contain "ValidArray"
            $result.Keys | Should -Not -Contain "EmptyArray"
            $result["ValidArray"] | Should -HaveCount 3
        }
        
        It "Keeps zero and false values" {
            $input = [PSCustomObject]@{
                ZeroValue = 0
                FalseValue = $false
            }
            
            $result = Remove-EmptyItems $input
            
            $result.Keys | Should -Contain "ZeroValue"
            $result.Keys | Should -Contain "FalseValue"
            $result["ZeroValue"] | Should -Be 0
            $result["FalseValue"] | Should -Be $false
        }
    }
    
    Context "Hashtable input" {
        It "Removes null properties from hashtable" {
            $input = @{
                ValidProp = "value"
                NullProp = $null
                EmptyString = ""
            }
            
            $result = Remove-EmptyItems $input
            
            $result.Keys | Should -Contain "ValidProp"
            $result.Keys | Should -Not -Contain "NullProp"
            $result.Keys | Should -Not -Contain "EmptyString"
        }
        
        It "Handles complex hashtable with mixed values" {
            $input = @{
                Name = "Test"
                NullValue = $null
                EmptyString = ""
                WhitespaceString = "   "
                EmptyArray = @()
                ValidNumber = 42
                ValidArray = @(1, 2, 3)
                ZeroValue = 0
            }
            
            $result = Remove-EmptyItems $input
            
            $result.Keys | Should -Contain "Name"
            $result.Keys | Should -Contain "ValidNumber"
            $result.Keys | Should -Contain "ValidArray"
            $result.Keys | Should -Contain "ZeroValue"
            $result.Keys | Should -Not -Contain "NullValue"
            $result.Keys | Should -Not -Contain "EmptyString"
            $result.Keys | Should -Not -Contain "WhitespaceString"
            $result.Keys | Should -Not -Contain "EmptyArray"
            $result["ZeroValue"] | Should -Be 0
        }
    }
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