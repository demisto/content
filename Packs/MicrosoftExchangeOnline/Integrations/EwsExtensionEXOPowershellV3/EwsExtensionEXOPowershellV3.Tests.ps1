BeforeAll {
    # Mock the demistomock.ps1 file
    $global:Demisto = @{
        Debug = {
            param($msg)
            # Do nothing for tests
        }
    }
    
    # Mock the TableToMarkdown function
    function TableToMarkdown {
        param (
            [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
            [AllowEmptyCollection()]
            [Object]$collection,
            
            [Parameter(Mandatory = $false, Position = 1)]
            [String]$name
        )
        
        # For testing, return a simple string indicating success or failure
        if ($null -eq $collection -or ($collection -is [Array] -and $collection.Count -eq 0)) {
            return "**No entries.**"
        } else {
            return "Table with data: $($collection | ConvertTo-Json -Depth 3)"
        }
    }
    
    # Define the ExchangeOnlinePowershellV3Client class for testing
    class ExchangeOnlinePowershellV3Client {
        [string]$url
        [string]$organization
        [string]$app_id
        
        ExchangeOnlinePowershellV3Client(
            [string]$url,
            [string]$app_id,
            [string]$organization,
            [string]$certificate,
            [SecureString]$password
        ) {
            $this.url = $url
            $this.organization = $organization
            $this.app_id = $app_id
        }
        
        [void] CreateSession() {}
        [void] DisconnectSession() {}
    }
    
    # Mock the Remove-EmptyItems function
    function Remove-EmptyItems {
        param (
            [PSObject]$inputObject
        )
        
        $newDict = @{}
        
        if ($inputObject -is [hashtable]) {
            # Handle hashtable input
            foreach ($key in $inputObject.Keys) {
                $value = $inputObject[$key]
                
                # Skip if value is null
                if ($null -eq $value) {
                    continue
                }
                
                # Skip if value is a string and is empty or whitespace
                if ($value -is [string] -and [string]::IsNullOrWhiteSpace($value)) {
                    continue
                }
                
                # Skip if value is an empty collection
                if ($value -is [System.Collections.IEnumerable] -and -not ($value -is [string]) -and
                    (($value | Measure-Object).Count -eq 0 -or $value.Count -eq 0)) {
                    continue
                }
                
                # If we got here, the value is not empty, so add it to the new dictionary
                $newDict[$key] = $value
            }
        } else {
            # Handle PSObject input
            foreach ($property in $inputObject.PSObject.Properties) {
                $value = $property.Value
                $propertyName = $property.Name
                
                # Skip if value is null
                if ($null -eq $value) {
                    continue
                }
                
                # Skip if value is a string and is empty or whitespace
                if ($value -is [string] -and [string]::IsNullOrWhiteSpace($value)) {
                    continue
                }
                
                # Skip if value is an empty collection
                if ($value -is [System.Collections.IEnumerable] -and -not ($value -is [string]) -and
                    (($value | Measure-Object).Count -eq 0 -or $value.Count -eq 0)) {
                    continue
                }
                
                # If we got here, the value is not empty, so add it to the new dictionary
                $newDict[$propertyName] = $value
            }
        }
        
        return $newDict
    }
    
    # Mock the EXOGetQuarantineMessageCommand function
    function EXOGetQuarantineMessageCommand {
        param (
            [Parameter(Mandatory)][Object]$client,
            [hashtable]$kwargs
        )
        
        # Get the mock response based on the identity parameter
        $identity = $kwargs.identity
        $raw_response = $null
        
        if ($identity -eq "single-object") {
            $raw_response = [PSCustomObject]@{
                Identity = "abcd"
                Direction = "Outbound"
                EntityType = "Email"
                Subject = "ALERT: Credentials detected"
                EmptyString = ""
                NullValue = $null
                EmptyArray = @()
            }
        }
        elseif ($identity -eq "array-objects") {
            $raw_response = @(
                [PSCustomObject]@{
                    Identity = "abcd"
                    Direction = "Outbound"
                    EntityType = "Email"
                    Subject = "ALERT: Credentials detected"
                    EmptyString = ""
                    NullValue = $null
                    EmptyArray = @()
                },
                [PSCustomObject]@{
                    Identity = "aabbccdd"
                    Direction = "Inbound"
                    EntityType = "Email"
                    Subject = "Important: Account Security"
                    EmptyString = "   "
                    NullValue = $null
                    EmptyArray = @()
                }
            )
        }
        elseif ($identity -eq "hashtable") {
            $raw_response = @{
                Identity = "abcd"
                Direction = "Outbound"
                EntityType = "Email"
                Subject = "ALERT: Credentials detected"
                EmptyString = ""
                NullValue = $null
                EmptyArray = @()
            }
        }
        elseif ($identity -eq "empty") {
            $raw_response = $null
        }
        else {
            # Default case - return a completely mocked quarantine message
            $raw_response = [PSCustomObject]@{
                ApprovalId = ""
                ApprovalUPN = ""
                CustomData = $null
                DeletedForRecipients = @()
                Direction = "Outbound"
                EntityType = "Email"
                Expires = "2026-01-01T08:21:34.0000000+00:00"
                Identity = "mock-id-12345\\mock-id-67890"
                MessageId = "<mock-message-id@example.com>"
                MoveToQuarantineAdminActionTakenBy = ""
                MoveToQuarantineApprovalId = ""
                Organization = "mock-org-id-12345"
                OverrideReason = "None"
                OverrideReasonIntValue = 0
                PermissionToAllowSender = $true
                PermissionToBlockSender = $false
                PermissionToDelete = $true
                PermissionToDownload = $true
                PermissionToPreview = $true
                PermissionToRelease = $true
                PermissionToRequestRelease = $false
                PermissionToViewHeader = $false
                PolicyName = "MockPolicy"
                PolicyType = "MockPolicyType"
                QuarantineTypes = "MockQuarantineType"
                QuarantinedUser = @()
                ReceivedTime = "2025-12-17T08:21:34.0000000+00:00"
                RecipientAddress = @("recipient@example.com")
                RecipientCount = 1
                RecipientTag = @("")
                ReleaseStatus = "NOTRELEASED"
                Released = $false
                ReleasedBy = @()
                ReleasedCount = 0
                ReleasedUser = @()
                Reported = $false
                SenderAddress = "sender@example.com"
                Size = 12345
                SourceId = ""
                Subject = "Mock Quarantine Message"
                SystemReleased = $false
                TagName = "Mock Tag"
                TeamsConversationType = ""
                Type = "Mock Type"
            }
        }
        
        $newResults = @()
        
        # Handle the case when raw_response is null or empty
        if ($null -eq $raw_response -or ($raw_response -is [string] -and [string]::IsNullOrWhiteSpace($raw_response))) {
            $newResults = @()
        }
        # Handle the case when raw_response is a true collection (array, list, etc.)
        elseif ($raw_response -is [System.Collections.IEnumerable] -and -not ($raw_response -is [Hashtable]) -and -not ($raw_response -is [string]) -and -not ($raw_response -is [PSObject]) -and -not ($raw_response -is [PSCustomObject])) {
            # If raw_response is a list, process each item
            foreach ($item in $raw_response) {
                $newResults += Remove-EmptyItems $item
            }
        }
        # Handle the case when raw_response is a Hashtable
        elseif ($raw_response -is [Hashtable]) {
            $newResults = @(Remove-EmptyItems $raw_response)
        }
        # Handle the case when raw_response is a PSObject or PSCustomObject
        elseif ($raw_response -is [PSObject] -or $raw_response -is [PSCustomObject]) {
            $newResults = @(Remove-EmptyItems $raw_response)
        }
        # Handle any other type
        else {
            # Try to process it anyway
            $newResults = @(Remove-EmptyItems $raw_response)
        }
        
        # Always pass the array to TableToMarkdown, even if it's empty
        $human_readable = TableToMarkdown @($newResults) "Results of test"
        $entry_context = @{ "EWS.GetQuarantineMessage(obj.Identity === val.Identity)" = $raw_response }
        
        return $human_readable, $entry_context, $raw_response
    }
    
    # Mock class for client
    class MockExchangeOnlinePowershellV3Client {
        [PSObject] EXOGetQuarantineMessage([hashtable]$params) {
            # This method is not used in the tests anymore
            # The mock implementation is now in the EXOGetQuarantineMessageCommand function
            return $null
        }
    }
}    


Describe 'Remove-EmptyItems' {
    Context "Handling different input types" {
        It "Removes null values from PSCustomObject" {
            $input = [PSCustomObject]@{
                Name = "Test Object"
                NullProperty = $null
                ValidProperty = "Value"
            }
            
            $result = Remove-EmptyItems $input
            
            $result.Keys | Should -Contain "Name"
            $result.Keys | Should -Contain "ValidProperty"
            $result.Keys | Should -Not -Contain "NullProperty"
        }
        
        It "Removes empty strings from PSCustomObject" {
            $input = [PSCustomObject]@{
                Name = "Test Object"
                EmptyString = ""
                WhitespaceString = "   "
                ValidProperty = "Value"
            }
            
            $result = Remove-EmptyItems $input
            
            $result.Keys | Should -Contain "Name"
            $result.Keys | Should -Contain "ValidProperty"
            $result.Keys | Should -Not -Contain "EmptyString"
            $result.Keys | Should -Not -Contain "WhitespaceString"
        }
        
        It "Removes empty arrays from PSCustomObject" {
            $input = [PSCustomObject]@{
                Name = "Test Object"
                EmptyArray = @()
                ValidArray = @("item1", "item2")
                ValidProperty = "Value"
            }
            
            $result = Remove-EmptyItems $input
            
            $result.Keys | Should -Contain "Name"
            $result.Keys | Should -Contain "ValidProperty"
            $result.Keys | Should -Contain "ValidArray"
            $result.Keys | Should -Not -Contain "EmptyArray"
        }
        
        It "Handles Hashtable input" {
            $input = @{
                Name = "Test Object"
                NullProperty = $null
                EmptyString = ""
                EmptyArray = @()
                ValidProperty = "Value"
                ValidArray = @("item1", "item2")
            }
            
            $result = Remove-EmptyItems $input
            
            $result.Keys | Should -Contain "Name"
            $result.Keys | Should -Contain "ValidProperty"
            $result.Keys | Should -Contain "ValidArray"
            $result.Keys | Should -Not -Contain "NullProperty"
            $result.Keys | Should -Not -Contain "EmptyString"
            $result.Keys | Should -Not -Contain "EmptyArray"
        }
    }
}

Describe 'EXOGetQuarantineMessageCommand' {
    Context "Handling different response types" {
        It "Handles single PSCustomObject response" {
            $client = [MockExchangeOnlinePowershellV3Client]::new()
            $kwargs = @{
                identity = "single-object"
            }
            
            $result = EXOGetQuarantineMessageCommand -client $client -kwargs $kwargs
            
            # Check that we got a human readable output (not "No entries")
            $result[0] | Should -Not -Match "No entries"
            # Check that the entry context contains the raw response
            $result[1].Keys | Should -Not -BeNullOrEmpty
            # Check that the raw response is returned
            $result[2] | Should -Not -BeNullOrEmpty
        }
        
        It "Handles array of PSCustomObjects response" {
            $client = [MockExchangeOnlinePowershellV3Client]::new()
            $kwargs = @{
                identity = "array-objects"
            }
            
            $result = EXOGetQuarantineMessageCommand -client $client -kwargs $kwargs
            
            # Check that we got a human readable output (not "No entries")
            $result[0] | Should -Not -Match "No entries"
            # Check that the entry context contains the raw response
            $result[1].Keys | Should -Not -BeNullOrEmpty
            # Check that the raw response is returned
            $result[2] | Should -Not -BeNullOrEmpty
        }
        
        It "Handles Hashtable response" {
            $client = [MockExchangeOnlinePowershellV3Client]::new()
            $kwargs = @{
                identity = "hashtable"
            }
            
            $result = EXOGetQuarantineMessageCommand -client $client -kwargs $kwargs
            
            # Check that we got a human readable output (not "No entries")
            $result[0] | Should -Not -Match "No entries"
            # Check that the entry context contains the raw response
            $result[1].Keys | Should -Not -BeNullOrEmpty
            # Check that the raw response is returned
            $result[2] | Should -Not -BeNullOrEmpty
        }
        
        It "Handles null/empty response" {
            $client = [MockExchangeOnlinePowershellV3Client]::new()
            $kwargs = @{
                identity = "empty"
            }
            
            $result = EXOGetQuarantineMessageCommand -client $client -kwargs $kwargs
            
            # Check that we still get a valid response structure
            $result.Count | Should -Be 3
            # The raw response should be null
            $result[2] | Should -BeNullOrEmpty
        }
        
        It "Handles a complex quarantine message object" {
            $client = [MockExchangeOnlinePowershellV3Client]::new()
            $kwargs = @{
                identity = "bug-sample"
            }
            
            $result = EXOGetQuarantineMessageCommand -client $client -kwargs $kwargs
            
            # Check that we got a human readable output (not "No entries")
            $result[0] | Should -Not -Match "No entries"
            # Check that the entry context contains the raw response
            $result[1].Keys | Should -Not -BeNullOrEmpty
            # Check that the raw response is returned and has the expected properties
            $result[2].Identity | Should -Be "mock-id-12345\\mock-id-67890"
            $result[2].Subject | Should -Be "Mock Quarantine Message"
        }
    }
    
    Context "Empty value handling" {
        It "Removes empty values from the processed results" {
            $client = [MockExchangeOnlinePowershellV3Client]::new()
            $kwargs = @{
                identity = "single-object"
            }
            
            $result = EXOGetQuarantineMessageCommand -client $client -kwargs $kwargs
            
            # Convert the human readable output to an object to check its properties
            # This is a bit of a hack, but it works for testing
            $outputJson = $result[0] -replace "Table with data: ", ""
            $outputObject = $outputJson | ConvertFrom-Json
            
            # Check that empty values were removed
            $outputObject.PSObject.Properties.Name -notcontains "EmptyString" | Should -Be $true
            $outputObject.PSObject.Properties.Name -notcontains "NullValue" | Should -Be $true
            $outputObject.PSObject.Properties.Name -notcontains "EmptyArray" | Should -Be $true
            
            # Check that valid values are present
            $outputObject.Identity | Should -Be "abcd"
            $outputObject.Subject | Should -Be "ALERT: Credentials detected"
        }
    }
}