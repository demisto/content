BeforeAll {
	. $PSScriptRoot\MicrosoftECM.ps1
}


Describe 'ParseDateTimeObjectToIso' {
	It 'Check date is parsed to ISO format correctly' {
		ParseDateTimeObjectToIso (Get-Date -year 2020 -month 12 -day 12 -hour 15 -minute 00 -second 00) | Should -Be "2020-12-12T15:00:00Z"
	}
}

Describe 'AssertNoMoreThenExpectedParametersGiven' {
	It "Assert no error is raised on valid output"{
		AssertNoMoreThenExpectedParametersGiven "error message" 1 "First"
	}
	It "Assert exception is raised with non valid output" {
		{ AssertNoMoreThenExpectedParametersGiven "error message" 1 "First" "Second" } | Should -Throw
	}
}

Describe "ValidateGetCollectionListParams" {
	It "Validating with both collectionId and collectionName throws an exception" {
		{ ValidateGetCollectionListParams "collection_id" "collection_name" } | Should -Throw "*Please select only one of: collection_id, collection_name."
	}
	It "Validating with collectionId only" {
		ValidateGetCollectionListParams "collection_id" $null | Should -Be "collection_id"
	}
	It "Validating with collectionName only" {
		ValidateGetCollectionListParams $null "collection_name" | Should -Be "collection_name"
	}
	It "Validating with no parameters" {
		ValidateGetCollectionListParams $null $null | Should -Be ""
	}
}

Describe "ValidateCreateScriptParams" {
	It "Validate with both script_file_entry_id and script_text throws exception" {
		{ValidateCreateScriptParams "script_file_entry_id" "script_text"} | Should -Throw "*script_file_entry_id cannot be resolved with script_text"
	}
	It "Validate with script_file_entry_id only" {
		ValidateCreateScriptParams "script_file_entry_id" $null | Should -Be "script_path"
	}
	It "Validate with script_text only" {
		ValidateCreateScriptParams $null "script_text" | Should -Be "script_text"
	}
	It "Validate no parameters throws exception" {
		{ValidateCreateScriptParams $null $null} | Should -Throw "Please supply either script_file_entry_id or script_text"
	}
}

Describe "ValidateIncludeOrExcludeDeviceCollectionParameters"{
	It "collection name and include collection name" {
		ValidateIncludeOrExcludeDeviceCollectionParameters $null "collection name" $null "include collection name" | Should -Be "name&name"
	}
	It "collection ID and include collection ID" {
		ValidateIncludeOrExcludeDeviceCollectionParameters "collection id" $null "include collection id" $null | Should -Be "id&id"
	}
	It "Validate collection name and collection ID thorws exception" {
		{ ValidateIncludeOrExcludeDeviceCollectionParameters "collection id" "collection name" "include collection id" $null } | Should -Throw "*Can only use one of the following parameters: collection_name, collection_id"
	}
	It "Validate no collection name and no collection ID thorws exception" {
		{ ValidateIncludeOrExcludeDeviceCollectionParameters $null $null "include collection id" $null } | Should -Throw "*Must use one of the following parameters: collection_id, collection_name"
	}
	It "Validate include collection name and include collection ID thorws exception" {
		{ ValidateIncludeOrExcludeDeviceCollectionParameters $null "collection name" "include collection id" "include collection name" } | Should -Throw "*Can only use one of the following parameters: include\exclude_collection_name, include\exclude_collection_id"
	}
	It "Validate no include collection name and no include collection ID thorws exception" {
		{ ValidateIncludeOrExcludeDeviceCollectionParameters $null "collection name" $null $null } | Should -Throw "*Must use one of the following parameters: include\exclude_collection_id, include\exclude_collection_name"
	}
}

Describe "Validating ArgToBool" {
	It "Validating with null value"{
		ArgToBool $null | Should -Be $false
	}
	It "Validating with empty string" {
		ArgToBool "" | Should -Be $false
	}
	It "Validating with 'false' string"{
		ArgToBool "False" | Should -Be $false
	}
	It "Validating with UpperCase 'true' string"{
		ArgToBool "TRUE" | Should -Be $true
	}
	It "Validating with lowercase 'true' string"{
		ArgToBool "true" | Should -Be $true
	}
	It "Validating with CamelCase 'true' string"{
		ArgToBool "True" | Should -Be $true
	}
}

Describe "Validating ArgToInteger" {
	It "Validating with null value"{
		ArgToInteger $null 5 | Should -Be 5
	}
	It "Validating with '0' " {
		ArgToInteger "0" | Should -Be 0
	}
	It "Validating with '5'"{
		ArgToInteger "5" | Should -Be 5
	}
}
