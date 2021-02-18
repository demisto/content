. $PSScriptRoot\CommonServerPowerShell.ps1


$COLLECTION_TYPE_MAPPING = @{
	"0" = "Root"
	"1" = "User"
	"2" = "Device"
	"3" = "Unknown"
}
$COLLECTION_CURRENT_STATUS_MAPPING = @{
	"0" = "NONE"
	"1" = "READY"
	"2" = "REFRESHING"
	"3" = "SAVING"
	"4" = "EVALUATING"
	"5" = "AWAITING_REFRESH"
	"6" = "DELETING"
	"7" = "APPENDING_MEMBER"
	"8" = "QUERYING"
}
$SCRIPT_APPROVAL_STATE = @{
	"0" = "Waiting for approval"
	"1" = "Declined"
	"3" = "Approved"
}

$SCRIPT_EXECUTION_STATUS = @{
	"1" = "Succeeded"
	"2" = "Failed"
}

$IPV4_REGEX = "^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"

<#
.DESCRIPTION
This function converts a null or string variable to boolean

.PARAMETER arg
The argument that should be converted

.OUTPUTS
Return the boolean representation of the argument
#>
Function ArgToBool()
{
	param(
		[Parameter()]
		[AllowEmptyString()]
		[string]$arg
	)
	if (!$arg)
	{
		return $false
	}
	else
	{
		return $arg.ToLower() -eq "true"
	}
}

<#
.DESCRIPTION
This function converts a null or string variable to integer

.PARAMETER arg
The argument that should be converted

.OUTPUTS
Return the number representation of the argument
#>
Function ArgToInteger()
{
	param(
		[Parameter()]
		[AllowEmptyString()] [string]$arg,
		[Parameter()] [Int32]$defaultValue
	)
	if ($null -eq $arg -Or "" -eq $arg)
	{
		return $defaultValue
	}
	else
	{
		return $arg -as [int]
	}
}

<#
.DESCRIPTION
This function converts a datetime object onto ISO format string

.PARAMETER date
The date that should be parsed

.OUTPUTS
Return The String representation of the datetime object normalized to UTC if or $null if $date is $null
#>
Function ParseDateTimeObjectToIso($date)
{
	if ($date)
	{
		return $date.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
	}
	return $null
}
<#
.DESCRIPTION
This function Verifies only one of the following arguments was actually given and throws an exception if not.

.PARAMETER $errorMessage
The error message with which the error should be raised

.PARAMETER $parameters
The parameters list from which only non-null parameter should be given
#>
Function AssertNoMoreThenExpectedParametersGiven($errorMessage, $expectedParameters)
{
	if (([array]($args| where-Object { !!$_ })).Length -gt $expectedParameters)
	{
		throw "Parameter set cannot be resolved using the specified named parameters. $errorMessage"
	}
}

<#
.DESCRIPTION
This function Verifies only one of the following arguments was actually given and throws an exception if not.
For more info see https://docs.microsoft.com/en-us/powershell/module/configurationmanager/get-cmcollection?view=sccm-ps

.PARAMETER collection_id
Specifies a collection ID

.PARAMETER collection_name
Specifies a collection name

.OUTPUTS
Return the used parameter or throws an exception if more then one is used
#>
Function ValidateGetCollectionListParams()
{
	[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidUsingPositionalParameters", "")]
	param(
		[Parameter()] [string]$collection_id,
		[Parameter()] [string]$collection_name
	)
	AssertNoMoreThenExpectedParametersGiven "Please select only one of: collection_id, collection_name." 1 $collection_id $collection_name
	$result = ""
	if ($collection_id)
	{
		$result = "collection_id"
	}
	elseif ($collection_name)
	{
		$result = "collection_name"
	}
	Return $result
}
<#
.DESCRIPTION
This function Verifies only one of the following arguments was actually given and throws an exception if not.
For more info see https://docs.microsoft.com/en-us/powershell/module/configurationmanager/new-cmscript?view=sccm-ps

.PARAMETER script_file_entry_id
Specifies the script file entry id ID

.PARAMETER script_text
Specifies the script code string content

.OUTPUTS
Return the used parameters or throws an exception if parameter set cannot be resolved
#>
Function ValidateCreateScriptParams()
{
	[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidUsingPositionalParameters", "")]
	param(
		[Parameter()] [string]$script_file_entry_id,
		[Parameter()] [string]$script_text
	)
	AssertNoMoreThenExpectedParametersGiven "script_file_entry_id cannot be resolved with script_text" 1 $script_file_entry_id $script_text
	if (!$script_file_entry_id -And !$script_text)
	{
		throw "Please supply either script_file_entry_id or script_text"
	}
	if ($script_file_entry_id)
	{
		return "script_path"
	}
	return "script_text"
}
<#
.DESCRIPTION
This function Verifies a valid parameter set is used with excactly one of $collection_id $collection_name and one of $include_collection_id $include_collection_name
For more info see https://docs.microsoft.com/en-us/powershell/module/configurationmanager/add-cmdevicecollectionincludemembershiprule?view=sccm-ps

.PARAMETER collection_id
Specifies the collection ID

.PARAMETER collection_name
Specifies the collection name

.PARAMETER collection_id
Specifies the collection ID to include\exclude in the membership rule

.PARAMETER collection_name
Specifies the collection name to include\exclude in the membership rule

.OUTPUTS
Return the used parameters or throws an exception if parameter set cannot be resolved
#>
Function ValidateIncludeOrExcludeDeviceCollectionParameters()
{
	[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidUsingPositionalParameters", "")]
	param(
		[Parameter()] [string]$CollectionID,
		[Parameter()] [string]$CollectionName,
		[Parameter()] [string]$include_collection_id,
		[Parameter()] [string]$include_collection_name
	)
	AssertNoMoreThenExpectedParametersGiven "Can only use one of the following parameters: collection_name, collection_id" 1 $CollectionName $CollectionID
	if (!$CollectionID -And !$CollectionName)
	{
		throw "Must use one of the following parameters: collection_id, collection_name"
	}
	AssertNoMoreThenExpectedParametersGiven "Can only use one of the following parameters: include\exclude_collection_name, include\exclude_collection_id" 1 $include_collection_name $include_collection_id
	if (!$include_collection_id -And !$include_collection_name)
	{
		throw "Must use one of the following parameters: include\exclude_collection_id, include\exclude_collection_name"
	}
	if ($CollectionID -And $include_collection_id)
	{
		return "id&id"
	}
	if ($CollectionID -And $include_collection_name)
	{
		return "id&name"
	}
	if ($CollectionName -And $include_collection_id)
	{
		return "name&id"
	}
	if ($CollectionName -And $include_collection_name)
	{
		return "name&name"
	}
}
<#
.DESCRIPTION
This function Parses A configuration manager collections objects into PSCustomObject with selected keys.

.PARAMETER collections
Specifies collections to parse

.OUTPUTS
Return the PSCustomObject with the selected collection keys
#>
Function ParseCollectionObject($Collections)
{
	if ($Collections)
	{
		$output = [PSCustomObject]@{
			"MicrosoftECM.Collections(val.ID && val.ID === obj.ID)" = $Collections | ForEach-Object {
				[PSCustomObject]@{
					Name = $_.Name
					ID = $_.CollectionID
					Type = $COLLECTION_TYPE_MAPPING.Get_Item("$( $_.CollectionType )")
					Comment = $_.Comment
					CurrentStatus = $COLLECTION_CURRENT_STATUS_MAPPING.Get_Item("$( $_.CurrentStatus )")
					CollectionRules = ($_.CollectionRules -Join ",")
					HasProvisionedMember = "$( $_.HasProvisionedMember )"
					IncludeExcludeCollectionsCount = "$( $_.IncludeExcludeCollectionsCount )"
					IsBuiltIn = "$( $_.IsBuiltIn )"
					IsReferenceCollection = "$( $_.IsReferenceCollection )"
					LastChangeTime = ParseDateTimeObjectToIso $_.LastChangeTime
					LastMemberChangeTime = ParseDateTimeObjectToIso $_.LastMemberChangeTime
					LastRefreshTime = ParseDateTimeObjectToIso $_.LastRefreshTime
					LimitToCollectionID = $_.LimitToCollectionID
					LimitToCollectionName = $_.LimitToCollectionName
					LocalMemberCount = "$( $_.LocalMemberCount )"
					MemberClassName = "$( $_.MemberClassName )"
					MemberCount = "$( $_.MemberCount )"
					UseCluster = "$( $_.UseCluster )"
				}
			}
		}
		$MDOutput = $output."MicrosoftECM.Collections(val.ID && val.ID === obj.ID)" | TableToMarkdown -Name "Collection List"
		$output."MicrosoftECM.Collections(val.ID && val.ID === obj.ID)" | ForEach-Object { $_.CollectionRules = $_.CollectionRules.Split("`n,") }
		ReturnOutputs -ReadableOutput $MDOutput -Outputs $output -RawResponse $_ | Out-Null
	}
	else
	{
		$MDOutput = "### Collection List`nNo results found."
		ReturnOutputs $MDOutput | Out-Null
	}
}
<#
.DESCRIPTION
This function Parses A configuration manager script invocation object into PSCustomObject with selected keys and return the outputs to the context.

.PARAMETER collection
Specifies collection to parse

.OUTPUTS
Return the PSCustomObject with the selected collection keys
#>
Function ParseScriptInvocationResults()
{
	[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidUsingPositionalParameters", "")]
	param(
		[Parameter()] [PSCustomObject]$result,
		[Parameter()] [string]$HumanReadableTitle,
		[Parameter()] [bool]$ShouldPollResults,
		[Parameter()] [Int32]$timeoutSeconds
	)
	if ($result)
	{
		if ($ShouldPollResults)
		{
			$operationID = $result.OperationID
			InvocationResults $operationID $timeoutSeconds
		}
		else
		{
			$output = [PSCustomObject]@{
				"MicrosoftECM.ScriptsInvocation(val.OperationID && val.OperationID === obj.OperationID)" = [PSCustomObject]@{
					OperationID = $result.OperationID
				}
			}
			$MDOutput = $output."MicrosoftECM.ScriptsInvocation(val.OperationID && val.OperationID === obj.OperationID)" | TableToMarkdown -Name $HumanReadableTitle
			ReturnOutputs -ReadableOutput $MDOutput -Outputs $output -RawResponse $result | Out-Null
		}
	}
	else
	{
		$MDOutput = "### $HumanReadableTitle `nNo results found"
		ReturnOutputs $MDOutput | Out-Null
	}
}

<#
.DESCRIPTION
This function Parses A configuration manager script object into PSCustomObject with selected keys and return it's outputs.

.PARAMETER script
Specifies script to parse

.OUTPUTS
Return the PSCustomObject with the selected script keys
#>
Function ParseScriptObject($script)
{
	if ($script)
	{
		$output = [PSCustomObject]@{
			"MicrosoftECM.Scripts(val.ScriptGuid && val.ScriptGuid === obj.ScriptGuid)" = $script | ForEach-Object {
				[PSCustomObject]@{
					ApprovalState = $SCRIPT_APPROVAL_STATE.Get_Item("$( $_.ApprovalState )")
					Approver = $_.Approver
					Author = $_.Author
					Comment = $_.Comment
					LastUpdateTime = ParseDateTimeObjectToIso $_.LastUpdateTime
					Parameterlist = $_.Parameterlist
					Script = [System.Text.Encoding]::UTF8.GetString(([System.Convert]::FromBase64String("$( $_.Script )") | Where-Object{ $_ }))
					ScriptGuid = $_.ScriptGuid
					ScriptHash = $_.ScriptHash
					ScriptHashAlgorithm = $_.ScriptHashAlgorithm
					ScriptName = $_.ScriptName
					ScriptType = $_.ScriptType
					ScriptVersion = $_.ScriptVersion
				}
			}
		}
		$MDOutput = $output."MicrosoftECM.Scripts(val.ScriptGuid && val.ScriptGuid === obj.ScriptGuid)" | TableToMarkdown -Name "Scripts List"
		ReturnOutputs -ReadableOutput $MDOutput -Outputs $output -RawResponse $script | Out-Null
	}
	else
	{
		$MDOutput = "### Scripts List`nNo results found."
		ReturnOutputs $MDOutput | Out-Null
	}
}
<#
.DESCRIPTION
This function Executes a script, approves it and runs it on the configuration manager.
If a script with that name already exists - this script will be used and new script will not be created.

.PARAMETER device_name
Specifies device name to run this script in

.PARAMETER collection_id
Specifies collection to run this script in

.PARAMETER collection_name
Specifies collection to run this script in

.PARAMETER script_text
Specifies the script text that should be run.

.PARAMETER script_name
Specifies the name of the script

.OUTPUTS
Return the A script invocation object with the invocation results
#>
Function ExecuteServiceScript()
{
	[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidUsingPositionalParameters", "")]
	[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidGlobalVars", "")]
	[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseDeclaredVarsMoreThanAssignments", "")]
	param(
		[Parameter()] [string]$DeviceName,
		[Parameter()] [string]$CollectionID,
		[Parameter()] [string]$CollectionName,
		[Parameter()] [string]$ScriptText,
		[Parameter()] [string]$ScriptName
	)
	AssertNoMoreThenExpectedParametersGiven "Can only use one of the following parameters: device_name, collection_id, collection_name" 1 $DeviceName $CollectionID $CollectionName
	if (!$DeviceName -And !$CollectionID -And !$CollectionName)
	{
		throw "Must use one of the following parameters: device_name, collection_id, collection_name"
	}
	$result = Invoke-Command $global:Session -ArgumentList $global:SiteCode, $CollectionID, $CollectionName, $DeviceName, $ScriptText, $ScriptName -ErrorAction Stop -ScriptBlock {
		param($SiteCode, $CollectionID, $CollectionName, $DeviceName, $ScriptText, $ScriptName)
		Set-Location $env:SMS_ADMIN_UI_PATH\..\
		Import-Module .\ConfigurationManager.psd1
		Set-Location "$( $SiteCode ):"
		# Checking if script exists in the configuration ConfigurationManager
		$CMPSSuppressFastNotUsedCheck = $true
		$Script = Get-CMScript -ScriptName $ScriptName
		if ($script)
		{
			try
			{
				Remove-CMScript -InputObject $script -Force
			}
			catch
			{
				throw "Failed to Remove old script $ScriptName. Error: [$( $_.Exception.Message )]"
			}
		}
		Try
		{
			$script = New-CMScript -ScriptText $ScriptText -ScriptName $ScriptName
		}
		catch
		{
			throw "Failed to create script $ScriptName. Error: [$( $_.Exception.Message )]"
		}
		try
		{
			Approve-CMScript -ScriptGuid $script.ScriptGuid -Comment "$ScriptName script"
		}
		catch
		{
			throw "Failed to approve script $ScriptName. Error: [$( $_.Exception.Message )]"
		}
		try
		{
			if ($DeviceName)
			{
				$Device = Get-CMDevice -Name $DeviceName
				Invoke-CMScript -ScriptGuid $script.ScriptGuid -Device $Device -PassThru
			}
			elseif ($CollectionID)
			{
				Invoke-CMScript -ScriptGuid $script.ScriptGuid -CollectionId $CollectionID -PassThru
			}
			elseif ($CollectionName)
			{
				Invoke-CMScript -ScriptGuid $script.ScriptGuid -CollectionName $CollectionName -PassThru
			}
		}
		catch
		{
			throw "Failed to invoke script $ScriptName. Error: [$( $_.Exception.Message )]"
		}
	}
	$result
}

Function GetLastLogOnUser()
{
	[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidUsingPositionalParameters", "")]
	[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidGlobalVars", "")]
	[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSReviewUnusedParameter", "")]
	param(
		[Parameter()] [string]$DeviceName
	)
	$device = Invoke-Command $global:Session -ArgumentList $DeviceName, $global:siteCode -ErrorAction Stop -ScriptBlock {
		param($deviceName, $siteCode)
		Set-Location $env:SMS_ADMIN_UI_PATH\..\
		Import-Module .\ConfigurationManager.psd1
		Set-Location "$( $SiteCode ):"
		Get-CMDevice -Name $deviceName -Resource |Select-Object IPAddresses, Name, LastLogonTimestamp, LastLogonUserName
	}
	if ($device)
	{
		$output = [PSCustomObject]@{
			"MicrosoftECM.LastLogOnUser" = [PSCustomObject]@{
				IPAddresses = $device.IPAddresses
				DeviceName = $device.Name
				LastLogonTimestamp = ParseDateTimeObjectToIso $device.LastLogonTimestamp
				LastLogonUserName = $device.LastLogonUserName
			}
		}
		$MDOutput = $output."MicrosoftECM.LastLogOnUser" | TableToMarkdown -Name "Last log on user on $deviceName"
		ReturnOutputs -ReadableOutput $MDOutput -Outputs $Output -RawResponse $device | Out-Null
	}
	else
	{
		throw "Could not find a computer with the name $deviceName"
	}
}

Function GetCollectionList()
{
	[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidUsingPositionalParameters", "")]
	[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidGlobalVars", "")]
	param(
		[Parameter()] [string]$collectionType,
		[Parameter()] [string]$CollectionID,
		[Parameter()] [string]$CollectionName
	)
	$usedParameterName = ValidateGetCollectionListParams $CollectionID $CollectionName
	$parameters = @{
		usedParameterName = $usedParameterName
		collection_type = $collectionType
		collection_id = $CollectionID
		collection_name = $CollectionName
	}
	$Collections = Invoke-Command $global:Session -ArgumentList $parameters, $global:siteCode -ErrorAction Stop -ScriptBlock {
		param($parameters, $siteCode)
		Set-Location $env:SMS_ADMIN_UI_PATH\..\
		Import-Module .\ConfigurationManager.psd1
		Set-Location "$( $SiteCode ):"
		switch ($parameters.usedParameterName)
		{
			"collection_id" {
				Get-CMCollection -CollectionType $parameters.collection_type -Id $parameters.collection_id
			}
			"collection_name" {
				Get-CMCollection -CollectionType $parameters.collection_type -Name $parameters.collection_name
			}
			default {
				Get-CMCollection -CollectionType $parameters.collection_type
			}
		}
	}
	ParseCollectionObject $Collections
}
Function GetDeviceList()
{
	[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidUsingPositionalParameters", "")]
	[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidGlobalVars", "")]
	[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseDeclaredVarsMoreThanAssignments", "")]
	param(
		[Parameter()] [string]$CollectionID,
		[Parameter()] [string]$CollectionName,
		[Parameter()] [Int32]$limit
	)
	AssertNoMoreThenExpectedParametersGiven "Can only use one of the following parameters: collection_id, collection_name" 1 $CollectionID $CollectionName
	$parameters = @{
		collection_id = $CollectionID
		collection_name = $CollectionName
		limit = $limit
	}
	$Devices = Invoke-Command $global:Session -ArgumentList $parameters, $global:siteCode -ErrorAction Stop -ScriptBlock {
		param($parameters, $siteCode)
		Set-Location $env:SMS_ADMIN_UI_PATH\..\
		Import-Module .\ConfigurationManager.psd1
		Set-Location "$( $SiteCode ):"
		$CMPSSuppressFastNotUsedCheck = $true
		if ($parameters.CollectionID)
		{
			(Get-CMDevice -CollectionId $parameters.collection_id)[0..$parameters.limit] | Select-Object Name, ResourceID
		}
		elseif ($parameters.CollectionName)
		{
			(Get-CMDevice -CollectionName $parameters.collection_name)[0..$parameters.limit] | Select-Object Name, ResourceID
		}
		else
		{
			(Get-CMDevice)[0..$parameters.limit] | Select-Object Name, ResourceID
		}
	}
	if ($Devices)
	{
		$output = [PSCustomObject]@{
			"MicrosoftECM.Devices(val.ResourceID && val.ResourceID === obj.ResourceID)" = $Devices | ForEach-Object {
				[PSCustomObject]@{
					DeviceName = $_.Name
					ResourceID = $_.ResourceID
				}
			}
		}
		$MDOutput = $output."MicrosoftECM.Devices(val.ResourceID && val.ResourceID === obj.ResourceID)" | TableToMarkdown -Name "Devices List"
		ReturnOutputs -ReadableOutput $MDOutput -Outputs $output -RawResponse $Devices | Out-Null
	}
	else
	{
		$MDOutput = "### Devices List`nNo results found."
		ReturnOutputs $MDOutput | Out-Null
	}
}

Function GetScriptList()
{
	[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidUsingPositionalParameters", "")]
	[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidGlobalVars", "")]
	[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseDeclaredVarsMoreThanAssignments", "")]
	param(
		[Parameter()] [string]$author,
		[Parameter()] [string]$scriptName
	)
	$scripts = Invoke-Command $global:Session -ArgumentList $author, $scriptName, $global:SiteCode -ErrorAction Stop -ScriptBlock {
		param($author, $scriptName, $SiteCode)
		Set-Location $env:SMS_ADMIN_UI_PATH\..\
		Import-Module .\ConfigurationManager.psd1
		Set-Location "$( $SiteCode ):"
		$CMPSSuppressFastNotUsedCheck = $true
		if ($author -And $scriptName)
		{
			Get-CMScript -Author $author -ScriptName $scriptName
		}
		elseif ($author)
		{
			Get-CMScript -Author $author
		}
		elseif ($scriptName)
		{
			Get-CMScript -ScriptName $scriptName
		}
		else
		{
			Get-CMScript
		}
	}
	ParseScriptObject $scripts
}

Function CreateScript()
{
	[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidUsingPositionalParameters", "")]
	[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidGlobalVars", "")]
	[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseBOMForUnicodeEncodedFile", "")]
	[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseDeclaredVarsMoreThanAssignments", "")]
	param(
		[Parameter()] [string]$scriptFileEntryID,
		[Parameter()] [string]$scriptText,
		[Parameter()] [string]$scriptName
	)
	$usedParameterName = ValidateCreateScriptParams $scriptFileEntryID $scriptText
	$scriptPath = ""
	if ($scriptFileEntryID)
	{
		$scriptPath = $demisto.GetFilePath($scriptFileEntryID).path
		Copy-Item –Path $scriptPath –Destination "C:\$( $scriptPath ).ps1" –ToSession $session
	}
	$script = Invoke-Command $global:Session -ArgumentList $global:SiteCode, $usedParameterName, $scriptPath, $scriptText, $scriptName -ErrorAction Stop -ScriptBlock {
		param($SiteCode, $usedParameterName, $scriptPath, $scriptText, $scriptName)
		Set-Location $env:SMS_ADMIN_UI_PATH\..\
		Import-Module .\ConfigurationManager.psd1
		Set-Location "$( $SiteCode ):"
		$CMPSSuppressFastNotUsedCheck = $true
		switch ("$usedParameterName")
		{
			"script_path" {
				New-CMScript -ScriptFile "C:\$( $scriptPath ).ps1" -ScriptName $scriptName
			}
			"script_text" {
				New-CMScript -ScriptText $scriptText -ScriptName $scriptName
			}
		}
	}
	ParseScriptObject $script
}

Function InvokeScript()
{
	[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidUsingPositionalParameters", "")]
	[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidGlobalVars", "")]
	[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseDeclaredVarsMoreThanAssignments", "")]
	param(
		[Parameter()] [string]$scriptGuid,
		[Parameter()] [string]$CollectionID,
		[Parameter()] [string]$CollectionName,
		[Parameter()] [string]$DeviceName,
		[Parameter()] [bool]$ShouldPollResults,
		[Parameter()] [Int32]$timeoutSeconds
	)
	AssertNoMoreThenExpectedParametersGiven "Can only use one of the following parameters: collection_id, collection_name, device_name" 1 $CollectionID $CollectionName $DeviceName
	If (!($CollectionID -Or $CollectionName -Or $DeviceName))
	{
		throw "Must use one of the following parameters: collection_id, collection_name, device_name"
	}
	$InvokedScript = Invoke-Command $global:Session -ArgumentList $global:SiteCode, $scriptGuid, $CollectionID, $CollectionName, $DeviceName -ErrorAction Stop -ScriptBlock {
		param($SiteCode, $scriptGuid, $CollectionID, $CollectionName, $DeviceName)
		Set-Location $env:SMS_ADMIN_UI_PATH\..\
		Import-Module .\ConfigurationManager.psd1
		Set-Location "$( $SiteCode ):"
		$CMPSSuppressFastNotUsedCheck = $true
		if ($CollectionID)
		{
			$scriptInvocation = Invoke-CMScript -ScriptGuid $scriptGuid -CollectionId $CollectionID -PassThru
		}
		elseif ($CollectionName)
		{
			$scriptInvocation = Invoke-CMScript -ScriptGuid $scriptGuid -CollectionName $CollectionName -PassThru
		}
		elseif ($DeviceName)
		{
			$Device = Get-CMDevice -Name $DeviceName
			$scriptInvocation = Invoke-CMScript -ScriptGuid $scriptGuid -Device $Device -PassThru
		}
		$scriptInvocation
	}
	ParseScriptInvocationResults $InvokedScript "Script Invocation Result" $ShouldPollResults $timeoutSeconds
}

Function ApproveScript()
{
	[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidUsingPositionalParameters", "")]
	[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidGlobalVars", "")]
	[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseDeclaredVarsMoreThanAssignments", "")]
	param(
		[Parameter()] [string]$scriptGuid,
		[Parameter()] [string]$comment
	)
	Invoke-Command $global:Session -ArgumentList $global:SiteCode, $scriptGuid, $comment -ErrorAction Stop -ScriptBlock {
		param($SiteCode, $scriptGuid, $comment)
		Set-Location $env:SMS_ADMIN_UI_PATH\..\
		Import-Module .\ConfigurationManager.psd1
		Set-Location "$( $SiteCode ):"
		$CMPSSuppressFastNotUsedCheck = $true
		Approve-CMScript -ScriptGuid $scriptGuid -Comment $comment
	}
	$MDOutput = "### Script was approved successfully"
	ReturnOutputs $MDOutput | Out-Null
}
Function InvocationResults()
{
	[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidGlobalVars", "")]
	[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSReviewUnusedParameter", "")]
	param(
		[Parameter()] [string]$operationID,
		[Parameter()] [Int32]$timeoutSeconds
	)
	$InvocationResults = Invoke-Command $global:Session -ArgumentList $global:SiteCode, $operationID, $timeoutSeconds -ErrorAction Stop -ScriptBlock {
		param($SiteCode, $operationID, $timeoutSeconds)
		if ($timeoutSeconds)
		{
			$job = start-job -scriptblock {
				Do
				{
					$result = Get-CimInstance -Namespace "root\SMS\site_$SiteCode" -ClassName SMS_ScriptsExecutionStatus  | Where-Object { $_.ClientOperationId -eq $operationID }
				} until ($null -ne $result)
			}
			wait-job $job -timeout $timeoutSeconds
			remove-job -force $job
		}
		Get-CimInstance -Namespace "root\SMS\site_$SiteCode" -ClassName SMS_ScriptsExecutionStatus  | Where-Object { $_.ClientOperationId -eq $operationID }
	}
	if ($InvocationResults)
	{
		$output = [PSCustomObject]@{
			"MicrosoftECM.ScriptsInvocationResults(val.OperationId === obj.OperationId && val.ResourceId === obj.ResourceId)" = $InvocationResults | ForEach-Object {
				[PSCustomObject]@{
					OperationId = $_.ClientOperationId
					CollectionId = $_.CollectionId
					CollectionName = $_.CollectionName
					DeviceName = $_.DeviceName
					ResourceId = $_.ResourceId
					LastUpdateTime = ParseDateTimeObjectToIso $_.LastUpdateTime
					ScriptExecutionState = $SCRIPT_EXECUTION_STATUS.Get_Item("$( $_.ScriptExecutionState )")
					ScriptExitCode = "$( $_.ScriptExitCode )"
					ScriptGuid = $_.ScriptGuid
					ScriptLastModifiedDate = ParseDateTimeObjectToIso $_.ScriptLastModifiedDate
					ScriptName = $_.ScriptName
					ScriptOutput = $_.ScriptOutput
					ScriptOutputHash = $_.ScriptOutputHash
					ScriptVersion = $_.ScriptVersion
					TaskID = $_.TaskID
				}
			}
		}
	}
	else
	{
		$output = [PSCustomObject]@{
			"MicrosoftECM.ScriptsInvocationResults(val.OperationId === obj.OperationId && val.ResourceId === obj.ResourceId)" = [PSCustomObject]@{
				OperationId = $operationID
				ScriptExecutionState = 'Pending'
			}
		}
	}
	$MDOutput = $output."MicrosoftECM.ScriptsInvocationResults(val.OperationId === obj.OperationId && val.ResourceId === obj.ResourceId)" | TableToMarkdown -Name "Script Invocation Results"
	ReturnOutputs -ReadableOutput $MDOutput -Outputs $output -RawResponse $Devices | Out-Null
}
Function CreateDeviceCollection()
{
	[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidUsingPositionalParameters", "")]
	[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidGlobalVars", "")]
	[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseDeclaredVarsMoreThanAssignments", "")]
	param(
		[Parameter()] [string]$comment,
		[Parameter()] [string]$CollectionName,
		[Parameter()] [string]$limitingCollectionName
	)
	$collection = Invoke-Command $global:Session -ArgumentList $global:SiteCode, $comment, $CollectionName, $limitingCollectionName -ErrorAction Stop -ScriptBlock {
		param($SiteCode, $comment, $CollectionName, $limitingCollectionName)
		Set-Location $env:SMS_ADMIN_UI_PATH\..\
		Import-Module .\ConfigurationManager.psd1
		Set-Location "$( $SiteCode ):"
		$CMPSSuppressFastNotUsedCheck = $true
		New-CMCollection -Name $CollectionName -CollectionType "Device" -Comment $comment -LimitingCollectionName $limitingCollectionName
	}
	ParseCollectionObject $collection
}


Function AddMembersToDeviceCollection()
{
	[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidUsingPositionalParameters", "")]
	[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidGlobalVars", "")]
	[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseDeclaredVarsMoreThanAssignments", "")]
	param(
		[Parameter()] [string]$CollectionID,
		[Parameter()] [string]$CollectionName,
		[Parameter()] [string]$deviceResourceIDs
	)
	AssertNoMoreThenExpectedParametersGiven "Can only use one of the following parameters: collection_name, collection_id" 1 $CollectionName $CollectionID
	if (!$CollectionName -And !$deviceResourceIDs)
	{
		throw "Must use one of the following parameters: collection_id, collection_name"
	}
	$resourceIDs = ArgToList $deviceResourceIDs
	$result = Invoke-Command $global:Session -ArgumentList $global:SiteCode, $CollectionID, $CollectionName, $resourceIDs -ErrorAction Stop -ScriptBlock {
		param($SiteCode, $CollectionID, $CollectionName, $resourceIDs)
		Set-Location $env:SMS_ADMIN_UI_PATH\..\
		Import-Module .\ConfigurationManager.psd1
		Set-Location "$( $SiteCode ):"
		$CMPSSuppressFastNotUsedCheck = $true
		if ($CollectionID)
		{
			Add-CMDeviceCollectionDirectMembershipRule -ResourceId $resourceIDs -CollectionId $CollectionID -PassThru
		}
		else
		{
			Add-CMDeviceCollectionDirectMembershipRule -ResourceId $resourceIDs -CollectionName $CollectionName -PassThru
		}
	}
	ParseCollectionObject $result
}

Function IncludeDeviceCollection()
{
	[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidUsingPositionalParameters", "")]
	[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidGlobalVars", "")]
	param(
		[Parameter()] [string]$CollectionID,
		[Parameter()] [string]$CollectionName,
		[Parameter()] [string]$includeCollectionID,
		[Parameter()] [string]$includeCollectionName
	)
	$usedParameterName = ValidateIncludeOrExcludeDeviceCollectionParameters $CollectionID $CollectionName $includeCollectionID $includeCollectionName
	$parameters = @{
		usedParameterName = $usedParameterName
		collection_id = $CollectionID
		collection_name = $CollectionName
		include_collection_id = $includeCollectionID
		include_collection_name = $includeCollectionName
	}
	$result = Invoke-Command $global:Session -ArgumentList $parameters, $global:siteCode -ErrorAction Stop -ScriptBlock {
		param($parameters, $siteCode)
		Set-Location $env:SMS_ADMIN_UI_PATH\..\
		Import-Module .\ConfigurationManager.psd1
		Set-Location "$( $SiteCode ):"
		switch ($parameters.usedParameterName)
		{
			"id&id" {
				Add-CMDeviceCollectionIncludeMembershipRule -CollectionId $parameters.collection_id -IncludeCollectionId $parameters.include_collection_id -PassThru
			}
			"id&name" {
				Add-CMDeviceCollectionIncludeMembershipRule -CollectionId $parameters.collection_id -IncludeCollectionName $parameters.include_collection_name -PassThru
			}
			"name&id" {
				Add-CMDeviceCollectionIncludeMembershipRule -CollectionName $parameters.collection_name -IncludeCollectionId $parameters.include_collection_id -PassThru
			}
			"name&name" {
				Add-CMDeviceCollectionIncludeMembershipRule -CollectionName $parameters.collection_name -IncludeCollectionName $parameters.include_collection_name -PassThru
			}
		}
	}
	ParseCollectionObject $result
}

Function ExcludeDeviceCollection()
{
	[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidUsingPositionalParameters", "")]
	[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidGlobalVars", "")]
	param(
		[Parameter()] [string]$CollectionID,
		[Parameter()] [string]$CollectionName,
		[Parameter()] [string]$excludeCollectionID,
		[Parameter()] [string]$excludeCollectionName
	)
	$usedParameterName = ValidateIncludeOrExcludeDeviceCollectionParameters $CollectionID $CollectionName $excludeCollectionID $excludeCollectionName
	$parameters = @{
		usedParameterName = $usedParameterName
		collection_id = $CollectionID
		collection_name = $CollectionName
		exclude_collection_id = $excludeCollectionID
		exclude_collection_name = $excludeCollectionName
	}
	$result = Invoke-Command $global:Session -ArgumentList $parameters, $global:siteCode -ErrorAction Stop -ScriptBlock {
		param($parameters, $siteCode)
		Set-Location $env:SMS_ADMIN_UI_PATH\..\
		Import-Module .\ConfigurationManager.psd1
		Set-Location "$( $SiteCode ):"
		switch ($parameters.usedParameterName)
		{
			"id&id" {
				Add-CMDeviceCollectionExcludeMembershipRule -CollectionId $parameters.collection_id -ExcludeCollectionId $parameters.exclude_collection_id -PassThru
			}
			"id&name" {
				Add-CMDeviceCollectionExcludeMembershipRule -CollectionId $parameters.collection_id -ExcludeCollectionName $parameters.exclude_collection_name -PassThru
			}
			"name&id" {
				Add-CMDeviceCollectionExcludeMembershipRule -CollectionName $parameters.collection_name -ExcludeCollectionId $parameters.exclude_collection_id -PassThru
			}
			"name&name" {
				Add-CMDeviceCollectionExcludeMembershipRule -CollectionName $parameters.collection_name -ExcludeCollectionName $parameters.exclude_collection_name -PassThru
			}
		}
	}
	ParseCollectionObject $result
}

Function AddMembersToCollectionByQuery()
{
	[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidUsingPositionalParameters", "")]
	[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidGlobalVars", "")]
	param(
		[Parameter()] [string]$CollectionID,
		[Parameter()] [string]$CollectionName,
		[Parameter()] [string]$queryExpression,
		[Parameter()] [string]$ruleName
	)
	if (!$CollectionID -And !$CollectionName)
	{
		throw "Must use one of the following parameters: collection_id, collection_name"
	}
	$result = Invoke-Command $global:Session -ArgumentList $global:siteCode, $CollectionID, $CollectionName, $queryExpression, $ruleName -ErrorAction Stop -ScriptBlock {
		param($siteCode, $CollectionID, $CollectionName, $queryExpression, $ruleName)
		Set-Location $env:SMS_ADMIN_UI_PATH\..\
		Import-Module .\ConfigurationManager.psd1
		Set-Location "$( $SiteCode ):"
		if ($CollectionID)
		{
			Add-CMDeviceCollectionQueryMembershipRule -CollectionId $CollectionID -RuleName $ruleName -QueryExpression $queryExpression -PassThru
		}
		else
		{
			Add-CMDeviceCollectionQueryMembershipRule -CollectionName $CollectionName -RuleName $ruleName -QueryExpression $queryExpression -PassThru
		}
	}
	ParseCollectionObject $result
}

Function StartService()
{
	[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidUsingPositionalParameters", "")]
	param(
		[Parameter()] [string]$serviceName,
		[Parameter()] [string]$CollectionID,
		[Parameter()] [string]$CollectionName,
		[Parameter()] [string]$DeviceName,
		[Parameter()] [bool]$ShouldPollResults,
		[Parameter()] [Int32]$timeoutSeconds
	)
	$escapedServiceName = $serviceName.Replace("'", "''")
	$scriptText = "Get-Service '$escapedServiceName' -ErrorAction Stop | Start-Service -PassThru -ErrorAction Stop"
	$scriptName = "XSOAR StartService"
	$result = ExecuteServiceScript $DeviceName $CollectionID $CollectionName $scriptText $scriptName
	ParseScriptInvocationResults $result "StartService script Invocation Result" $ShouldPollResults $timeoutSeconds
}

Function RestartService()
{
	[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidUsingPositionalParameters", "")]
	param(
		[Parameter()] [string]$serviceName,
		[Parameter()] [string]$CollectionID,
		[Parameter()] [string]$CollectionName,
		[Parameter()] [string]$DeviceName,
		[Parameter()] [bool]$ShouldPollResults,
		[Parameter()] [Int32]$timeoutSeconds
	)
	$escapedServiceName = $serviceName.Replace("'", "''")
	$scriptText = "Get-Service '$escapedServiceName' -ErrorAction Stop | Restart-Service -PassThru -ErrorAction Stop"
	$scriptName = "XSOAR RestartService"
	$result = ExecuteServiceScript $DeviceName $CollectionID $CollectionName $scriptText $scriptName
	ParseScriptInvocationResults $result "RestartService script Invocation Result" $ShouldPollResults $timeoutSeconds
}

Function StopService()
{
	[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidUsingPositionalParameters", "")]
	param(
		[Parameter()] [string]$serviceName,
		[Parameter()] [string]$CollectionID,
		[Parameter()] [string]$CollectionName,
		[Parameter()] [string]$DeviceName,
		[Parameter()] [bool]$ShouldPollResults,
		[Parameter()] [Int32]$timeoutSeconds
	)
	$escapedServiceName = $serviceName.Replace("'", "''")
	$scriptText = "Get-Service '$escapedServiceName' -ErrorAction Stop | Stop-Service -PassThru -ErrorAction Stop"
	$scriptName = "XSOAR StopService"
	$result = ExecuteServiceScript $DeviceName $CollectionID $CollectionName $scriptText $scriptName
	ParseScriptInvocationResults $result "StopService script Invocation Result" $ShouldPollResults $timeoutSeconds
}


Function GetDeviceAsCollectionMember()
{
	[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidUsingPositionalParameters", "")]
	[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidGlobalVars", "")]
	[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseUsingScopeModifierInNewRunspaces", "")]
	param(
		[Parameter()] [string]$deviceNames,
		[Parameter()] [string]$resourceIDs
	)
	AssertNoMoreThenExpectedParametersGiven "Can only use one of the following parameters: device_names, resource_ids" 1 $deviceNames $resourceIDs
	if (!$deviceNames -And !$resourceIDs)
	{
		throw "Please use one of the following parameters: device_names, resource_ids"
	}
	$deviceNamesList = ArgToList $deviceNames
	$resourceIDsList = ArgToList $resourceIDs
	$devices = Invoke-Command $global:Session -ArgumentList $global:siteCode, $deviceNamesList, $resourceIDsList -ErrorAction Stop -ScriptBlock {
		param($siteCode, $deviceNamesList, $resourceIDsList)
		$jobs = @()
		if ($deviceNamesList)
		{
			ForEach ($deviceName in $deviceNamesList)
			{
				$jobs += start-job -ArgumentList $deviceName, $SiteCode -scriptblock {
					Set-Location $env:SMS_ADMIN_UI_PATH\..\
					Import-Module .\ConfigurationManager.psd1
					Set-Location "$( $args[1] ):"
					Get-CMDevice -Name $args[0] -CollectionMember | Select-Object Name, ClientVersion, DeviceOS, ResourceID, IsActive, LastActiveTime, LastClientCheckTime, LastDDR, LastHardwareScan, LastPolicyRequest, Domain, PrimaryUser, Status, MACAddress, IsVirtualMachine, IsDecommissioned, IsClient, IsBlocked, ExchangeServer, DeviceThreatLevel, CurrentLogonUser, LastLogonUser, DeviceOSBuild, ADLastLogonTime, SiteCode
				}
			}
		}
		if ($resourceIDsList)
		{
			ForEach ($resourceID in $resourceIDsList)
			{
				$jobs += start-job -ArgumentList $resourceID, $SiteCode -scriptblock {
					Set-Location $env:SMS_ADMIN_UI_PATH\..\
					Import-Module .\ConfigurationManager.psd1
					Set-Location "$( $args[1] ):"
					Get-CMDevice -ResourceId $args[0] -CollectionMember | Select-Object Name, ClientVersion, DeviceOS, ResourceID, IsActive, LastActiveTime, LastClientCheckTime, LastDDR, LastHardwareScan, LastPolicyRequest, Domain, PrimaryUser, Status, MACAddress, IsVirtualMachine, IsDecommissioned, IsClient, IsBlocked, ExchangeServer, DeviceThreatLevel, CurrentLogonUser, LastLogonUser, DeviceOSBuild, ADLastLogonTime, SiteCode
				}
			}
		}
		$devices = Receive-Job -Job $jobs -Wait -AutoRemoveJob
		$devices
	}
	if ($devices)
	{
		$outputToContext = $devices | ForEach-Object {
			[PSCustomObject]@{
				DeviceName = $_.Name
				ResourceID = $_.ResourceID
				CollectionMemberDetails = [PSCustomObject]@{
					ClientVersion = $_.ClientVersion
					DeviceOS = $_.DeviceOS
					IsActive = $_.IsActive
					LastActiveTime = ParseDateTimeObjectToIso $_.LastActiveTime
					LastClientCheckTime = ParseDateTimeObjectToIso $_.LastClientCheckTime
					LastDDR = ParseDateTimeObjectToIso $_.LastDDR
					LastHardwareScan = ParseDateTimeObjectToIso $_.LastHardwareScan
					LastPolicyRequest = ParseDateTimeObjectToIso $_.LastPolicyRequest
					Domain = $_.Domain
					PrimaryUser = $_.PrimaryUser
					Status = $_.Status
					IsVirtualMachine = $_.IsVirtualMachine
					IsDecommissioned = $_.IsDecommissioned
					IsClient = $_.IsClient
					IsBlocked = $_.IsBlocked
					ExchangeServer = $_.ExchangeServer
					DeviceThreatLevel = $_.DeviceThreatLevel
					CurrentLogonUser = $_.CurrentLogonUser
					LastLogonUser = $_.LastLogonUser
					DeviceOSBuild = $_.DeviceOSBuild
					ADLastLogonTime = $_.ADLastLogonTime
					SiteCode = $_.SiteCode
				}
			}
		}
		$outputToHumanReadable = $devices | ForEach-Object {
			[PSCustomObject]@{
				DeviceName = $_.Name
				ResourceID = $_.ResourceID
				ClientVersion = $_.ClientVersion
				DeviceOS = $_.DeviceOS
				IsActive = $_.IsActive
				LastActiveTime = ParseDateTimeObjectToIso $_.LastActiveTime
				LastClientCheckTime = ParseDateTimeObjectToIso $_.LastClientCheckTime
				LastDDR = ParseDateTimeObjectToIso $_.LastDDR
				LastHardwareScan = ParseDateTimeObjectToIso $_.LastHardwareScan
				LastPolicyRequest = ParseDateTimeObjectToIso $_.LastPolicyRequest
				Domain = $_.Domain
				PrimaryUser = $_.PrimaryUser
				Status = $_.Status
				IsVirtualMachine = $_.IsVirtualMachine
				IsDecommissioned = $_.IsDecommissioned
				IsClient = $_.IsClient
				IsBlocked = $_.IsBlocked
				ExchangeServer = $_.ExchangeServer
				DeviceThreatLevel = $_.DeviceThreatLevel
				CurrentLogonUser = $_.CurrentLogonUser
				LastLogonUser = $_.LastLogonUser
				DeviceOSBuild = $_.DeviceOSBuild
				ADLastLogonTime = $_.ADLastLogonTime
				SiteCode = $_.SiteCode
			}
		}
		$MDOutput = $outputToHumanReadable | TableToMarkdown -Name "Device As Collection Member"
		$output = [PSCustomObject]@{ "MicrosoftECM.Devices(val.DeviceName && val.DeviceName === obj.DeviceName)" = $outputToContext }
		ReturnOutputs -ReadableOutput $MDOutput -Outputs $output -RawResponse $devices | Out-Null
	}
	else
	{
		$MDOutput = "### Devices As Collection Member`nNo results found."
		ReturnOutputs $MDOutput | Out-Null
	}
}

Function GetDeviceAsResource()
{
	[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidUsingPositionalParameters", "")]
	[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidGlobalVars", "")]
	[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseDeclaredVarsMoreThanAssignments", "")]
	[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseUsingScopeModifierInNewRunspaces", "")]
	param(
		[Parameter()] [string]$deviceNames,
		[Parameter()] [string]$resourceIDs
	)
	AssertNoMoreThenExpectedParametersGiven "Can only use one of the following parameters: device_names, resource_ids" 1 $deviceNames $resourceIDs
	if (!$deviceNames -And !$resourceIDs)
	{
		throw "Please use one of the following parameters: device_names, resource_ids"
	}
	$deviceNamesList = ArgToList $deviceNames
	$resourceIDsList = ArgToList $resourceIDs
	$devices = Invoke-Command $global:Session -ArgumentList $global:siteCode, $deviceNamesList, $resourceIDsList -ErrorAction Stop -ScriptBlock {
		param($siteCode, $deviceNamesList, $resourceIDsList)
		$jobs = @()
		if ($deviceNamesList)
		{
			ForEach ($deviceName in $deviceNamesList)
			{
				$jobs += start-job -ArgumentList $deviceName, $SiteCode -scriptblock {
					Set-Location $env:SMS_ADMIN_UI_PATH\..\
					Import-Module .\ConfigurationManager.psd1
					Set-Location "$( $args[1] ):"
					$CMPSSuppressFastNotUsedCheck = $true
					Get-CMDevice -Name $args[0] -Resource | Select-Object Name, AgentName, ResourceId, ADSiteName, AgentSite, AgentTime, CPUType, DistinguishedName, FullDomainName, IPAddresses, NetbiosName, UserAccountControl, LastLogonUserName, LastLogonUserDomain, LastLogonTimestamp, OperatingSystemNameandVersion, VirtualMachineHostName, VirtualMachineType, DNSForestGuid, HardwareID
				}
			}
		}
		if ($resourceIDsList)
		{
			ForEach ($resourceID in $resourceIDsList)
			{
				$jobs += start-job -ArgumentList $resourceID, $SiteCode -scriptblock {
					Set-Location $env:SMS_ADMIN_UI_PATH\..\
					Import-Module .\ConfigurationManager.psd1
					Set-Location "$( $args[1] ):"
					$CMPSSuppressFastNotUsedCheck = $true
					Get-CMDevice -ResourceId $args[0] -Resource | Select-Object Name, AgentName, ResourceId, ADSiteName, AgentSite, AgentTime, CPUType, DistinguishedName, FullDomainName, IPAddresses, NetbiosName, UserAccountControl, LastLogonUserName, LastLogonUserDomain, LastLogonTimestamp, OperatingSystemNameandVersion, VirtualMachineHostName, VirtualMachineType, DNSForestGuid, HardwareID
				}
			}
		}
		$devices = Receive-Job -Job $jobs -Wait -AutoRemoveJob
		$devices
	}
	if ($devices)
	{
		$outputToContext = $devices | ForEach-Object {
			[PSCustomObject]@{
				DeviceName = $_.Name
				ResourceID = $_.ResourceId
				ResourceDetails = [PSCustomObject]@{
					AgentName = $_.AgentName
					ADSiteName = $_.ADSiteName
					AgentSite = $_.AgentSite
					AgentTime = $_.AgentTime | Foreach-Object { ParseDateTimeObjectToIso $_ }
					CPUType = $_.CPUType
					DistinguishedName = $_.DistinguishedName
					FullDomainName = $_.FullDomainName
					IPv4Addresses = $_.IPAddresses | Where-Object {$_ -match $IPV4_REGEX}
					IPv6Addresses = $_.IPAddresses | Where-Object {$_ -notmatch $IPV4_REGEX}
					NetbiosName = $_.NetbiosName
					UserAccountControl = $_.UserAccountControl
					LastLogonUserName = $_.LastLogonUserName
					LastLogonUserDomain = $_.LastLogonUserDomain
					LastLogonTimestamp = ParseDateTimeObjectToIso $_.LastLogonTimestamp
					OperatingSystemNameandVersion = $_.OperatingSystemNameandVersion
					VirtualMachineHostName = $_.VirtualMachineHostName
					VirtualMachineType = $_.VirtualMachineType
					DNSForestGuid = $_.DNSForestGuid
					HardwareID = $_.HardwareID
				}
			}
		}
		$outputToHumanReadable = $devices | ForEach-Object {
			[PSCustomObject]@{
				DeviceName = $_.Name
				ResourceID = $_.ResourceId
				AgentName = $_.AgentName
				ADSiteName = $_.ADSiteName
				AgentSite = $_.AgentSite
				AgentTime = $_.AgentTime | Foreach-Object { ParseDateTimeObjectToIso $_ }
				CPUType = $_.CPUType
				DistinguishedName = $_.DistinguishedName
				FullDomainName = $_.FullDomainName
				IPv4Addresses = $_.IPAddresses | Where-Object {$_ -match $IPV4_REGEX}
				IPv6Addresses = $_.IPAddresses | Where-Object {$_ -notmatch $IPV4_REGEX}
				NetbiosName = $_.NetbiosName
				UserAccountControl = $_.UserAccountControl
				LastLogonUserName = $_.LastLogonUserName
				LastLogonUserDomain = $_.LastLogonUserDomain
				LastLogonTimestamp = ParseDateTimeObjectToIso $_.LastLogonTimestamp
				OperatingSystemNameandVersion = $_.OperatingSystemNameandVersion
				VirtualMachineHostName = $_.VirtualMachineHostName
				VirtualMachineType = $_.VirtualMachineType
				DNSForestGuid = $_.DNSForestGuid
				HardwareID = $_.HardwareID
			}
		}
		$MDOutput = $outputToHumanReadable | TableToMarkdown -Name "Device As Resource"
		$output = [PSCustomObject]@{ "MicrosoftECM.Devices(val.ResourceID && val.ResourceID === obj.ResourceID)" = $outputToContext }
		ReturnOutputs -ReadableOutput $MDOutput -Outputs $output -RawResponse $devices | Out-Null
	}
	else
	{
		$MDOutput = "### Devices As Resource`nNo results found."
		ReturnOutputs $MDOutput | Out-Null
	}
}

Function GetUserDeviceAffinity()
{
	[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidGlobalVars", "")]
	[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidUsingPositionalParameters", "")]
	[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseUsingScopeModifierInNewRunspaces", "")]
	param(
		[Parameter()] [string]$deviceNames,
		[Parameter()] [string]$resourceIDs,
		[Parameter()] [string]$userNames
	)
	AssertNoMoreThenExpectedParametersGiven "Can only use one of the following parameters: device_names, resource_ids, user_names" 1 $deviceNames $resourceIDs $userNames
	if (!$deviceNames -And !$resourceIDs -And !$userNames)
	{
		throw "Please use one of the following parameters: device_names, resource_ids, user_names"
	}
	$deviceNamesList = ArgToList $deviceNames
	$resourceIDsList = ArgToList $resourceIDs
	$userNamesList = ArgToList $userNames
	$result = Invoke-Command $global:Session -ArgumentList $deviceNamesList, $resourceIDsList, $userNamesList, $global:siteCode -ErrorAction Stop -ScriptBlock {
		param($deviceNamesList, $resourceIDsList, $userNamesList, $siteCode)
		$jobs = @()
		if ($deviceNamesList)
		{
			ForEach ($deviceName in $deviceNamesList)
			{
				$jobs += start-job -ArgumentList $deviceName, $SiteCode -scriptblock {
					Set-Location $env:SMS_ADMIN_UI_PATH\..\
					Import-Module .\ConfigurationManager.psd1
					Set-Location "$( $args[1] ):"
					Get-CMUserDeviceAffinity -DeviceName $args[0] | Select-Object ResourceName, UniqueUserName, ResourceID, IsActive, CreationTime, RelationshipResourceID
				}
			}
		}
		if ($resourceIDsList)
		{
			ForEach ($resourceID in $resourceIDsList)
			{
				$jobs += start-job -ArgumentList $resourceID, $SiteCode -scriptblock {
					Set-Location $env:SMS_ADMIN_UI_PATH\..\
					Import-Module .\ConfigurationManager.psd1
					Set-Location "$( $args[1] ):"
					Get-CMUserDeviceAffinity -DeviceId $args[0] | Select-Object ResourceName, UniqueUserName, ResourceID, IsActive, CreationTime, RelationshipResourceID
				}
			}
		}
		if ($userNamesList)
		{
			ForEach ($userName in $userNamesList)
			{
				$jobs += start-job -ArgumentList $userName, $SiteCode -scriptblock {
					Set-Location $env:SMS_ADMIN_UI_PATH\..\
					Import-Module .\ConfigurationManager.psd1
					Set-Location "$( $args[1] ):"
					Get-CMUserDeviceAffinity -UserName $args[0] | Select-Object ResourceName, UniqueUserName, ResourceID, IsActive, CreationTime, RelationshipResourceID
				}
			}
		}
		$results = Receive-Job -Job $jobs -Wait -AutoRemoveJob
		$results
	}
	if ($result)
	{
		$output = $result | ForEach-Object {
			[PSCustomObject]@{
				DeviceName = $_.ResourceName
				UserName = $_.UniqueUserName
				ResourceID = $_.ResourceID
				IsActive = $_.IsActive
				RelationshipResourceID = $_.RelationshipResourceID
				CreationTime = ParseDateTimeObjectToIso $_.CreationTime
			}
		}
		$MDOutput = $output | TableToMarkdown -Name "User Device Affinity"
		$output = [PSCustomObject]@{ "MicrosoftECM.UserDeviceAffinity(val.RelationshipResourceID && val.RelationshipResourceID === obj.RelationshipResourceID)" = $output }
		ReturnOutputs -ReadableOutput $MDOutput -Outputs $output -RawResponse $result | Out-Null
	}
	else
	{
		$MDOutput = "### Devices As Resource`nNo results found."
		ReturnOutputs $MDOutput | Out-Null
	}
}

Function TestModule()
{
	[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidGlobalVars", "")]
	[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseDeclaredVarsMoreThanAssignments", "")]
	param()
	Invoke-Command $global:Session -ArgumentList $global:SiteCode -ErrorAction Stop -ScriptBlock {
		param($SiteCode)
		Set-Location $env:SMS_ADMIN_UI_PATH\..\
		Import-Module .\ConfigurationManager.psd1
		Set-Location "$( $SiteCode ):"
		if ($null -eq (Get-Module -Name ConfigurationManager).Version)
		{
			throw "Could not find SCCM modules in the SCCM machine"
		}
		$Devices = Get-CMResource -ResourceType System -Fast|Where-Object { $_.Name -ne $env:computername } | ForEach-Object { $_.Name }
	}
}

function Main
{
	[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidUsingPositionalParameters", "")]
	[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidGlobalVars", "")]
	[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidUsingConvertToSecureStringWithPlainText", "")]
	[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseDeclaredVarsMoreThanAssignments", "")]
	param()
	# Parse Params
	$computerName = $demisto.Params()['ComputerName']
	$userName = $demisto.Params()['credentials']['identifier']
	$password = $demisto.Params()['credentials']['password']
	$global:SiteCode = $demisto.Params()['SiteCode']
	$securePassword = ConvertTo-SecureString $password -AsPlainText -Force
	$Creds = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $username, $securePassword
	$Command = $Demisto.GetCommand()
	$Demisto.Debug("Command being called is $Command")
	try
	{
		$global:Session = New-PSSession -ComputerName $computerName -Authentication Negotiate -Credential $Creds -ErrorAction Stop
		Switch ($Command)
		{
			"test-module" {
				TestModule | Out-Null
				ReturnOutputs "ok" | Out-Null
			}
			"ms-ecm-user-last-log-on" {
				$deviceName = $demisto.Args()['device_name']
				GetLastLogOnUser $deviceName | Out-Null
			}
			"ms-ecm-get-installed-softwares" {
				$deviceName = $demisto.Args()['device_name']
				ListInstalledSoftwares $deviceName | Out-Null
			}
			"ms-ecm-collection-list" {
				$collectionType = $demisto.Args()['collection_type']
				$CollectionID = $demisto.Args()['collection_id']
				$CollectionName = $demisto.Args()['collection_name']
				GetCollectionList $collectionType $CollectionID $CollectionName
			}
			"ms-ecm-device-list" {
				$CollectionID = $demisto.Args()['collection_id']
				$CollectionName = $demisto.Args()['collection_name']
				$limit = (ArgToInteger $demisto.Args()['limit'] 100) - 1
				GetDeviceList $CollectionID $CollectionName $limit
			}
			"ms-ecm-script-list" {
				$author = $demisto.Args()['author']
				$scriptName = $demisto.Args()['script_name']
				GetScriptList $author $scriptName
			}
			"ms-ecm-script-create" {
				$scriptFileEntryID = $demisto.Args()['script_file_entry_id']
				$scriptText = $demisto.Args()['script_text']
				$scriptName = $demisto.Args()['script_name']
				CreateScript $scriptFileEntryID $scriptText $scriptName
			}
			"ms-ecm-script-invoke" {
				$scriptGuid = $demisto.Args()['script_guid']
				$CollectionID = $demisto.Args()['collection_id']
				$CollectionName = $demisto.Args()['collection_name']
				$DeviceName = $demisto.Args()['device_name']
				$ShouldPollResults = ArgToBool $demisto.Args()['poll_results']
				$timeoutSeconds = ArgToInteger $demisto.Args()['timeout'] 30
				InvokeScript $scriptGuid $CollectionID $CollectionName $DeviceName $ShouldPollResults $timeoutSeconds
			}
			"ms-ecm-script-invocation-results" {
				$operationID = $demisto.Args()['operation_id']
				InvocationResults $operationID
			}
			"ms-ecm-script-approve" {
				$scriptGuid = $demisto.Args()['script_guid']
				$comment = $demisto.Args()['comment']
				ApproveScript $scriptGuid $comment
			}
			"ms-ecm-device-collection-create" {
				$comment = $demisto.Args()['comment']
				$CollectionName = $demisto.Args()['collection_name']
				$limitingCollectionName = $demisto.Args()['limiting_collection_name']
				CreateDeviceCollection $comment $CollectionName $limitingCollectionName
			}
			"ms-ecm-device-collection-members-add" {
				$CollectionID = $demisto.Args()['collection_id']
				$CollectionName = $demisto.Args()['collection_name']
				$deviceResourceIDs = $demisto.Args()['device_resource_ids']
				AddMembersToDeviceCollection $CollectionID $CollectionName $deviceResourceIDs
			}
			"ms-ecm-device-collection-include" {
				$CollectionID = $demisto.Args()['collection_id']
				$CollectionName = $demisto.Args()['collection_name']
				$includeCollectionID = $demisto.Args()['include_collection_id']
				$includeCollectionName = $demisto.Args()['include_collection_name']
				IncludeDeviceCollection $CollectionID $CollectionName $includeCollectionID $includeCollectionName
			}
			"ms-ecm-device-collection-exclude" {
				$CollectionID = $demisto.Args()['collection_id']
				$CollectionName = $demisto.Args()['collection_name']
				$excludeCollectionID = $demisto.Args()['exclude_collection_id']
				$excludeCollectionName = $demisto.Args()['exclude_collection_name']
				ExcludeDeviceCollection $CollectionID $CollectionName $excludeCollectionID $excludeCollectionName
			}
			"ms-ecm-device-collection-members-by-query-add" {
				$CollectionID = $demisto.Args()['collection_id']
				$CollectionName = $demisto.Args()['collection_name']
				$queryExpression = $demisto.Args()['query_expression']
				$ruleName = $demisto.Args()['rule_name']
				AddMembersToCollectionByQuery $CollectionID $CollectionName $queryExpression $ruleName
			}
			"ms-ecm-service-start" {
				$serviceName = $demisto.Args()['service_name']
				$CollectionID = $demisto.Args()['collection_id']
				$CollectionName = $demisto.Args()['collection_name']
				$DeviceName = $demisto.Args()['device_name']
				$ShouldPollResults = ArgToBool $demisto.Args()['poll_results']
				$timeoutSeconds = ArgToInteger $demisto.Args()['timeout'] 30
				StartService $serviceName $CollectionID $CollectionName $DeviceName $ShouldPollResults $timeoutSeconds
			}
			"ms-ecm-service-restart" {
				$serviceName = $demisto.Args()['service_name']
				$CollectionID = $demisto.Args()['collection_id']
				$CollectionName = $demisto.Args()['collection_name']
				$DeviceName = $demisto.Args()['device_name']
				$ShouldPollResults = ArgToBool $demisto.Args()['poll_results']
				$timeoutSeconds = ArgToInteger $demisto.Args()['timeout'] 30
				RestartService $serviceName $CollectionID $CollectionName $DeviceName $ShouldPollResults $timeoutSeconds
			}
			"ms-ecm-service-stop" {
				$serviceName = $demisto.Args()['service_name']
				$CollectionID = $demisto.Args()['collection_id']
				$CollectionName = $demisto.Args()['collection_name']
				$DeviceName = $demisto.Args()['device_name']
				$ShouldPollResults = ArgToBool $demisto.Args()['poll_results']
				$timeoutSeconds = ArgToInteger $demisto.Args()['timeout'] 30
				StopService $serviceName $CollectionID $CollectionName $DeviceName $ShouldPollResults $timeoutSeconds
			}
			"ms-ecm-device-get-collection-member" {
				$deviceNames = $demisto.Args()['device_names']
				$resourceIDs = $demisto.Args()['resource_ids']
				GetDeviceAsCollectionMember $deviceNames $resourceIDs
			}
			"ms-ecm-device-get-resource" {
				$deviceNames = $demisto.Args()['device_names']
				$resourceIDs = $demisto.Args()['resource_ids']
				GetDeviceAsResource $deviceNames $resourceIDs
			}
			"ms-ecm-get-user-device-affinity" {
				$deviceNames = $demisto.Args()['device_names']
				$resourceIDs = $demisto.Args()['resource_ids']
				$userNames = $demisto.Args()['user_names']
				GetUserDeviceAffinity $deviceNames $resourceIDs $userNames
			}
		}
	}
	catch
	{
		ReturnError -Message "Error in Microsoft ECM Integration: $( $_.Exception.Message )" -Err $_ | Out-Null
		return
	}
}

# Execute Main when not in Tests
if ($MyInvocation.ScriptName -notlike "*.tests.ps1" -AND -NOT$Test)
{
	Main
}
