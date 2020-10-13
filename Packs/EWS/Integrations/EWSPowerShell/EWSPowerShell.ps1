
. $PSScriptRoot\CommonServerPowerShell.ps1

# HELPER FUNCTIONS
function BuildServerFQDN([string]$uri) {
	if (![uri]$uri.scheme) {
		$uri = "https://" + $uri + "/powershell-liveid/"
	}

	return $uri
}

function CreateNewSession ([string]$o365Server, [string]$userName, [string]$password) {
	$securePassword = ConvertTo-SecureString $password -AsPlainText -Force
	$credentials = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $username, $securePassword
	$serverFqdn = BuildServerFQDN $o365Server
	$session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri $serverFqdn -Credential $credentials -Authentication Basic -AllowRedirection -WarningAction SilentlyContinue
	if (!$session) {
		throw "Fail - establishing session to {0}" -f $o365Server 
	}

	return $session
}


function CloseSession([System.Management.Automation.Runspaces.PSSession]$session) {
	Remove-PSSession $session
}


# Client object


class Client {
	[ValidateNotNullOrEmpty()][string]$o365Server
	[ValidateNotNullOrEmpty()][string]$userName
	[ValidateNotNullOrEmpty()][string]$password

	TestConnection() {
		# Establish session to remote
		$session = CreateNewSession $this.o365Server $this.userName $this.password
		# Execute simple compliance summary query
		if (! (Invoke-Command -Session $session -ScriptBlock { Get-ComplianceSearch })) {
			throw "Fail - Unable to query compliance using pwsh command 'Get-ComplianceSearch'"
		}
		# Close session to remote
		CloseSession $session
	}

	[hashtable]EwsComplianceNewSearch([string]$search_name, [string]$content_match_query, [string]$description, [array]$exchange_location) {
		# Establish session to remote
		$session = CreateNewSession $this.o365Server $this.userName $this.password
		# Execute command
		$response = Invoke-Command -Session $session -ScriptBlock { New-ComplianceSearch -Name $search_name  -ContentMatchQuery $content_match_query -Description $description -ExchangeLocation $exchange_location}
		# Close session to remote
		CloseSession $session

		return $response
	}
	
	
	[hashtable]EwsComplianceRemoveSearch([string]$search_name) {
		# Establish session to remote
		$session = CreateNewSession $this.o365Server $this.userName $this.password
		# Execute command
		$response = Invoke-Command -Session $session -ScriptBlock { Remove-ComplianceSearch -Identity $search_name }
		# Close session to remote
		CloseSession $session

		return $response
	}
	
	
	[hashtable]EwsComplianceStartSearch([string]$search_name) {
		# Establish session to remote
		$session = CreateNewSession $this.o365Server $this.userName $this.password
		# Execute command
		$response = Invoke-Command -Session $session -ScriptBlock { Start-ComplianceSearch -Identity $search_name }
		# Close session to remote
		CloseSession $session

		return $response
	}
	
	
	[hashtable]EwsComplianceStopSearch([string]$search_name) {
		# Establish session to remote
		$session = CreateNewSession $this.o365Server $this.userName $this.password
		# Execute command
		$response = Invoke-Command -Session $session -ScriptBlock { Stop-ComplianceSearch -Identity $search_name }
		# Close session to remote
		CloseSession $session

		return $response
	}
	
	
	[hashtable]EwsComplianceGetSearch([string]$search_name) {
		# Establish session to remote
		$session = CreateNewSession $this.o365Server $this.userName $this.password
		# Execute command
		$response = Invoke-Command -Session $session -ScriptBlock { Get-ComplianceSearch -Identity $search_name }
		# Close session to remote
		CloseSession $session

		return $response
	}
	
	
	[hashtable]EwsCompliancePurge([string]$search_name, [string]$purge_type) {
		# Establish session to remote
		$session = CreateNewSession $this.o365Server $this.userName $this.password
		# Execute command
		$response = Invoke-Command -Session $session -ScriptBlock { New-ComplianceSearchAction -SearchName $searchName -Purge -PurgeType $purge_type -Confirm:$false }
		# Close session to remote
		CloseSession $session

		return $response
	}
	
	
	[hashtable]EwsGlobalSenderBlacklist() {
		
	}
	
	
	[hashtable]EwsJunkRulesGet() {
		
	}
	
	
	[hashtable]EwsJunkRulesSet() {
		
	}
	
	
	[hashtable]EwsMessageTrace() {
		
	}
}


# Command functions 


function TestModule([Client]$client) {
	$client.TestConnection()
	
	return 'ok', {}, {} 
}


function EwsComplianceNewSearchCommand([Client]$client, [hashtable]$kwargs) {
	$raw_response = $client.EwsComplianceNewSearch($kwargs['search_name'], $kwargs['content_match_query'], $kwargs['description'], $kwargs['exchange_location'])
	$human_readable = ""
	$entry_context = {}

	return $human_readable, $entry_context, $raw_response
}


function EwsComplianceRemoveSearchCommand([Client]$client, [hashtable]$kwargs) {
	$raw_response = $client.EwsComplianceRemoveSearch($kwargs['search_name'])
	$human_readable = ""
	$entry_context = {}

	return $human_readable, $entry_context, $raw_response
}


function EwsComplianceStartSearchCommand([Client]$client, [hashtable]$kwargs) {
	$raw_response = $client.EwsComplianceStartSearch($kwargs['search_name'])
	$human_readable = ""
	$entry_context = {}

	return $human_readable, $entry_context, $raw_response
}


function EwsComplianceStopSearchCommand([Client]$client, [hashtable]$kwargs) {
	$raw_response = $client.EwsComplianceStopSearch($kwargs['search_name'])
	$human_readable = ""
	$entry_context = {}

	return $human_readable, $entry_context, $raw_response
}


function EwsComplianceGetSearchCommand([Client]$client, [hashtable]$kwargs) {
	$raw_response = $client.EwsComplianceGetSearch($kwargs['search_name'])
	$human_readable = ""
	$entry_context = {}

	return $human_readable, $entry_context, $raw_response
}


function EwsCompliancePurgeCommand([Client]$client, [hashtable]$kwargs) {
	$raw_response = $client.EwsCompliancePurge($kwargs['search_name'], $kwargs['purge_type'])
	$human_readable = ""
	$entry_context = {}

	return $human_readable, $entry_context, $raw_response
}


function EwsGlobalSenderBlacklistCommand([Client]$client, [hashtable]$kwargs) {
	
}


function EwsJunkRulesGetCommand([Client]$client, [hashtable]$kwargs) {
	
}


function EwsJunkRulesSetCommand([Client]$client, [hashtable]$kwargs) {
	
}


function EwsMessageTraceCommand([Client]$client, [hashtable]$kwargs) {
	
}



function Main {
	[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidUsingPositionalParameters", "")]
	[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidGlobalVars", "")]
	[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidUsingConvertToSecureStringWithPlainText", "")]
	[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseDeclaredVarsMoreThanAssignments", "")]
	
	$Command = $Demisto.GetCommand()
	$Demisto.Debug("Command being called is $Command")
	$Client = [Client]@{
		o365Server = $demisto.Params()['ExchangeServer']
		userName   = $demisto.Params()['credentials']['identifier']
		password   = $demisto.Params()['credentials']['password']
	}

	try {
		Switch ($Command) {
			"test-module" {
				($human_readable, $entry_context, $raw_response) = TestModule $client
			}
			"ews-compliance-new-search" {
				($human_readable, $entry_context, $raw_response) = EwsComplianceNewSearchCommand $client $Demisto.Args()
			}
			"ews-compliance-remove-search" {
				($human_readable, $entry_context, $raw_response) = EwsComplianceRemoveSearchCommand $client $Demisto.Args()
			}
			"ews-compliance-start-search" {
				($human_readable, $entry_context, $raw_response) = EwsComplianceStartSearchCommand $client, $Demisto.Args()
			}
			"ews-compliance-stop-search" {
				($human_readable, $entry_context, $raw_response) = EwsComplianceStopSearchCommand $client, $Demisto.Args()
			}
			"ews-compliance-get-search" {
				($human_readable, $entry_context, $raw_response) = EwsComplianceGetSearchCommand $client, $Demisto.Args()
			}
			"ews-compliance-purge" {
				($human_readable, $entry_context, $raw_response) = EwsCompliancePurgeCommand $client, $Demisto.Args()
			}
			"ews-global-sender-blacklist" {
				($human_readable, $entry_context, $raw_response) = EwsCompliancePurgeCommand $client, $Demisto.Args()
			}
			"ews-junk-rules-get" {
				($human_readable, $entry_context, $raw_response) = EwsCompliancePurgeCommand $client, $Demisto.Args()
			}
			"ews-junk-rules-set" {
				($human_readable, $entry_context, $raw_response) = EwsCompliancePurgeCommand $client, $Demisto.Args()
			}
			"ews-message-trace" {
				($human_readable, $entry_context, $raw_response) = EwsCompliancePurgeCommand $client, $Demisto.Args()
			}
		}

		ReturnOutputs $human_readable $entry_context $raw_response
	}
	catch {
		Write-Output $_.Exception.Message
		ReturnError -Message "Error in Microsoft ECM Integration: $( $_.Exception.Message )" -Err $_ | Out-Null
		return
	}
}

# Execute Main when not in Tests
if ($MyInvocation.ScriptName -notlike "*.tests.ps1" -AND -NOT$Test) {
	Main
}
