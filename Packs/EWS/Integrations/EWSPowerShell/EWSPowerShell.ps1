
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


function ConvertPSObjectToHashtable
{
    param (
        [Parameter(ValueFromPipeline)]
        $InputObject
    )

    process
    {
        if ($null -eq $InputObject) { return $null }

        if ($InputObject -is [System.Collections.IEnumerable] -and $InputObject -isnot [string])
        {
            $collection = @(
                foreach ($object in $InputObject) { ConvertPSObjectToHashtable $object }
            )

            Write-Output -NoEnumerate $collection
        }
        elseif ($InputObject -is [psobject])
        {
            $hash = @{}

            foreach ($property in $InputObject.PSObject.Properties)
            {
                $hash[$property.Name] = ConvertPSObjectToHashtable $property.Value
            }

            $hash
        }
        else
        {
            $InputObject
        }
    }
}


# Client object


class Client {
	[ValidateNotNullOrEmpty()][string]$o365Server
	[ValidateNotNullOrEmpty()][string]$userName
	[ValidateNotNullOrEmpty()][string]$password

	[psobject]ComplianceNewSearch([string]$search_id, [string]$content_match_query, [string]$description, [string]$exchange_location) {
		# Establish session to remote
		$session = CreateNewSession $this.o365Server $this.userName $this.password
		# Import and Execute command
		Import-PSSession -Session $session -CommandName New-ComplianceSearch
		$response = New-ComplianceSearch -Name $search_id -ExchangeLocation $exchange_location
		# Close session to remote
		CloseSession $session

		return $response
	}
	
	ComplianceRemoveSearch([string]$search_id) {
		# Establish session to remote
		$session = CreateNewSession $this.o365Server $this.userName $this.password
		# Import and Execute command
		Import-PSSession -Session $session -CommandName Remove-ComplianceSearch
		Remove-ComplianceSearch -Identity $search_id -Confirm:$false
		# Close session to remote
		CloseSession $session
	}

	[array]ComplianceListSearch() {
		# Establish session to remote
		$session = CreateNewSession $this.o365Server $this.userName $this.password
		# Import and Execute command
		Import-PSSession -Session $session -CommandName Get-ComplianceSearch
		$response = Get-ComplianceSearch
		# Close session to remote
		CloseSession $session

		return $response
	}

	[psobject]ComplianceGetSearch([string]$search_id) {
		# Establish session to remote
		$session = CreateNewSession $this.o365Server $this.userName $this.password
		# Import and Execute command
		Import-PSSession -Session $session -CommandName Get-ComplianceSearch
		$response = Get-ComplianceSearch -Identity $search_id | Select-Object -Property *
		# Close session to remote
		CloseSession $session

		return $response
	}
	
	ComplianceStartSearchAction([string]$search_id) {
		# Establish session to remote
		$session = CreateNewSession $this.o365Server $this.userName $this.password
		# Import and Execute command
		Import-PSSession -Session $session -CommandName Start-ComplianceSearch
		Start-ComplianceSearch -Identity $search_id
		# Close session to remote
		CloseSession $session
	}
	
	ComplianceStopSearchAction([string]$search_id) {
		# Establish session to remote
		$session = CreateNewSession $this.o365Server $this.userName $this.password
		# Import and Execute command
		Import-PSSession -Session $session -CommandName Stop-ComplianceSearch
		Stop-ComplianceSearch -Identity $search_id -Confirm:$false
		# Close session to remote
		CloseSession $session
	}
	
	[array]ComplianceGetSearchAction([string]$search_id) {
		# Establish session to remote
		$session = CreateNewSession $this.o365Server $this.userName $this.password
		# Import and Execute command
		Import-PSSession -Session $session -CommandName Get-ComplianceSearchAction
		$response = Get-ComplianceSearchAction -Identity $search_id
		# Close session to remote
		CloseSession $session

		return $response
	}
	
	[hashtable]EwsCompliancePurge([string]$search_id, [string]$purge_type) {
		# Establish session to remote
		$session = CreateNewSession $this.o365Server $this.userName $this.password
		# Execute command
		$response = Invoke-Command -Session $session -ScriptBlock { New-ComplianceSearchAction -SearchName $searchName -Purge -PurgeType $purge_type -Confirm:$false }
		# Close session to remote
		CloseSession $session

		return $response
	}
	
	[hashtable]EwsGlobalSenderBlacklist() {
		$response = {}

		return $response
	}
	
	[hashtable]EwsJunkRulesGet() {
		$response = {}
		
		return $response
	}
	
	[hashtable]EwsJunkRulesSet() {
		$response = {}
		
		return $response
	}
	
	[hashtable]EwsMessageTrace() {
		$response = {}
		
		return $response
	}
}


# Command functions 


function TestModule([Client]$client) {
	$client.ComplianceListSearch()
	
	return 'ok', {}, {} 
}


function ComplianceNewSearchCommand([Client]$client, [hashtable]$kwargs) {
	$raw_response = $client.ComplianceNewSearch($kwargs['search_id'], $kwargs['content_match_query'], $kwargs['description'], $kwargs['exchange_location'])
	$human_readable = 
	$entry_context = {}

	return $human_readable, $entry_context, $raw_response
}


function ComplianceRemoveSearchCommand([Client]$client, [hashtable]$kwargs) {
	# Remove operation doesn't return output
	$client.ComplianceRemoveSearch($kwargs['search_id'])
	$human_readable = ""
	$entry_context = {}

	return $human_readable, $entry_context, {}
}


function ComplianceListSearchCommand([Client]$client, [hashtable]$kwargs) {
	$raw_response = $client.ComplianceListSearch()
	$human_readable = ""
	$entry_context = {}

	return $human_readable, $entry_context, $raw_response
}


function ComplianceGetSearchCommand([Client]$client, [hashtable]$kwargs) {
	$raw_response = $client.ComplianceGetSearch($kwargs['search_id'])
	$human_readable = ""
	$entry_context = {}

	return $human_readable, $entry_context, $raw_response
}


function ComplianceStartSearchActionCommand([Client]$client, [hashtable]$kwargs) {
	# Start operation doesn't return output
	$client.ComplianceStartSearchAction($kwargs['search_id'])
	$human_readable = ""
	$entry_context = {}

	return $human_readable, $entry_context, {}
}


function ComplianceStopSearchActionCommand([Client]$client, [hashtable]$kwargs) {
	# Stop operation doesn't return output
	$client.ComplianceStopSearchAction($kwargs['search_id'])
	$human_readable = ""
	$entry_context = {}

	return $human_readable, $entry_context, {}
}


function ComplianceGetSearchActionCommand([Client]$client, [hashtable]$kwargs) {
	$raw_response = $client.ComplianceGetSearchAction($kwargs['search_id']) | Select-Object *
	$human_readable = ""
	$entry_context = {}

	return $human_readable, $entry_context, $raw_response
}


function CompliancePurgeCommand([Client]$client, [hashtable]$kwargs) {
	$raw_response = $client.EwsCompliancePurge($kwargs['search_id'], $kwargs['purge_type'])
	$human_readable = ""
	$entry_context = {}

	return $human_readable, $entry_context, $raw_response
}


function EwsGlobalSenderBlacklistCommand([Client]$client, [hashtable]$kwargs) {
	$raw_response = $client.EwsCompliancePurge($kwargs['search_id'], $kwargs['purge_type'])
	$human_readable = ""
	$entry_context = {}

	return $human_readable, $entry_context, $raw_response
}


function EwsJunkRulesGetCommand([Client]$client, [hashtable]$kwargs) {
	$raw_response = $client.EwsCompliancePurge($kwargs['search_id'], $kwargs['purge_type'])
	$human_readable = ""
	$entry_context = {}

	return $human_readable, $entry_context, $raw_response
}


function EwsJunkRulesSetCommand([Client]$client, [hashtable]$kwargs) {
	$raw_response = $client.EwsCompliancePurge($kwargs['search_id'], $kwargs['purge_type'])
	$human_readable = ""
	$entry_context = {}

	return $human_readable, $entry_context, $raw_response
}


function EwsMessageTraceCommand([Client]$client, [hashtable]$kwargs) {
	$raw_response = $client.EwsCompliancePurge($kwargs['search_id'], $kwargs['purge_type'])
	$human_readable = ""
	$entry_context = {}

	return $human_readable, $entry_context, $raw_response
}



function Main {
	[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidUsingPositionalParameters", "")]
	[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidGlobalVars", "")]
	[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidUsingConvertToSecureStringWithPlainText", "")]
	[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseDeclaredVarsMoreThanAssignments", "")]
	
	$Command = $Demisto.GetCommand()
	$Demisto.Debug("Command being called is $Command")
	$client = [Client]@{
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
				($human_readable, $entry_context, $raw_response) = ComplianceNewSearchCommand $client $Demisto.Args() 
			}
			"ews-compliance-remove-search" {
				($human_readable, $entry_context, $raw_response) = ComplianceRemoveSearchCommand $client $Demisto.Args() 
			}
			"ews-compliance-list-search" {
				($human_readable, $entry_context, $raw_response) = ComplianceListSearchCommand $client $Demisto.Args() 
			}
			"ews-compliance-get-search" {
				($human_readable, $entry_context, $raw_response) = ComplianceGetSearchCommand $client $Demisto.Args() 
			}
			"ews-compliance-start-search-action" {
				($human_readable, $entry_context, $raw_response) = ComplianceStartSearchActionCommand $client $Demisto.Args() 
			}
			"ews-compliance-stop-search-action" {
				($human_readable, $entry_context, $raw_response) = ComplianceStopSearchActionCommand $client $Demisto.Args() 
			}
			"ews-compliance-get-search-action" {
				($human_readable, $entry_context, $raw_response) = ComplianceGetSearchActionCommand $client $Demisto.Args()
			}
			"ews-compliance-purge" {
				($human_readable, $entry_context, $raw_response) = EwsCompliancePurgeCommand $client $Demisto.Args()
			}
			"ews-global-sender-blacklist" {
				($human_readable, $entry_context, $raw_response) = EwsCompliancePurgeCommand $client $Demisto.Args()
			}
			"ews-junk-rules-get" {
				($human_readable, $entry_context, $raw_response) = EwsCompliancePurgeCommand $client $Demisto.Args()
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
