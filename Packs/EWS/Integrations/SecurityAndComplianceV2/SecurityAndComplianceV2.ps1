. $PSScriptRoot\CommonServerPowerShell.ps1

$script:INTEGRATION_NAME = "Security And Compliance"
$script:COMMAND_PREFIX = "o365-sc"
$script:INTEGRATION_ENTRY_CONTEX = "O365.SecurityAndCompliance.ContentSearch"
$script:SEARCH_ENTRY_CONTEXT = "$script:INTEGRATION_ENTRY_CONTEX.Search(val.Name && val.Name == obj.Name)"
$script:SEARCH_ACTION_ENTRY_CONTEXT = "$script:INTEGRATION_ENTRY_CONTEX.SearchAction(val.Name && val.Name == obj.Name)"

<# IMPORTANT NOTICE
# When conencting to ExchangeOnline - only needed command between CreateSession
# and DisconnectSession and let also the `finally` term to disconnect (it will do nothing if everything is fine).
# This will reduce the time sessions are opened between Exchange and the server and will create
# less problems.
# DO NOT USE ONE FINALLY STATEMENT: we don't know if and when it'll be executed and anyway it the DisconnectSession
# should be called before returning results to the server.
#>
Import-Module ExchangeOnlineManagement

#### HELPER FUNCTIONS ####

function ParseSuccessResults([string]$success_results, [int]$limit, [bool]$all_results) {
    $parsed_success_results = New-Object System.Collections.Generic.List[System.Object]
    if ($success_results) {
        $lines = $success_results.Split([Environment]::NewLine)

        if ($limit -ne -1) {
            $limit = ($limit, $lines.Count | Measure-Object -Minimum).Minimum
        } else {
            $limit = $lines.Count
        }

        # Results limit
        $results_count = 0
        # Lines iterator
        $lines_scanned = 0
        while ($results_count -lt $limit -and $lines_scanned -lt $lines.Count) {
            if ($lines[$lines_scanned] -match 'Location: (\S+), Item count: (\d+), Total size: (\d+)')
            {
                if ($matches[2] -ne 0 -or $all_results){
                    $parsed_success_results.Add(@{
                        "Location" = $matches[1]
                        "ItemsCount" = $matches[2]
                        "Size" = $matches[3]
                    })
                    $results_count += 1
                }
            }
            $lines_scanned += 1
        }
    }

    return $parsed_success_results
    <#
        .DESCRIPTION
        Parse string return in Search PSObject property "SuccessResults"

        .PARAMETER success_results
        SuccessResults raw string.

        .EXAMPLE
        ParseSuccessResults 'Location: Private mail box, Item count: 8, Total size: 63'

        .OUTPUTS
        List of psobject SuccessResults object.
    #>
}



function ParseResults([string]$results, [int]$limit = -1, [string]$type = "Preview") {
   if ($type -eq "Preview"){
        $results_matches_preview = (Select-String -AllMatches "\{?Location: (.*); Sender: (.*); Subject: (.*); Type: (.*); Size: (.*); Received Time: (.*); Data Link: (.*)[},]"  -InputObject $results).Matches
        $parsed_results = New-Object System.Collections.Generic.List[System.Object]
        foreach ($match in $results_matches_preview)
        {
            if ($parsed_results.Count -ge $limit -and $limit -ne -1){
                break
            }

            $parsed_results.Add(@{
                "Location" = $match.Groups[1].Value
                "Sender" = $match.Groups[2].Value
                "Subject" = $match.Groups[3].Value
                "Type" = $match.Groups[4].Value
                "Size" = $match.Groups[5].Value
                "ReceivedTime" = $match.Groups[6].Value
                "DataLink" = $match.Groups[7].Value
            })
        }
   }
    if ($type -eq "Purge"){
        $results_matches_purge = (Select-String -AllMatches "\{?Location: (.*); Item count: (.*); Total size: (.*); Failed count: (.*); [},]"  -InputObject $results).Matches
        $parsed_results = New-Object System.Collections.Generic.List[System.Object]
        foreach ($match in $results_matches_purge)
        {
            if ($parsed_results.Count -ge $limit -and $limit -ne -1){
                break
            }
            $parsed_results.Add(@{
                "Location" = $match.Groups[1].Value
                "ItemCount" = $match.Groups[2].Value
                "TotalSize" = $match.Groups[3].Value
                "FailedCount" = $match.Groups[4].Value
            })
        }
    }


    return $parsed_results
    <#
        .DESCRIPTION
        Parse string return in SearchAction PSObject property "Results"

        .PARAMETER success_results
        SuccessResults raw string.

        .EXAMPLE
        ParseResults 'Location: Private mail box; Sender: user@microsoft.com; Type: mail; Size: 100; Received Time: 16 August 2010; Data Link: xxxxx,'

        .OUTPUTS
        List of psobject Results object.
    #>
}

function ParseSearchToEntryContext([psobject]$search, [int]$limit = -1, [bool]$all_results = $false) {
    return @{
        "AllowNotFoundExchangeLocationsEnabled" = $search.AllowNotFoundExchangeLocationsEnabled
        "AzureBatchFrameworkEnabled" = $search.AzureBatchFrameworkEnabled
        "CaseId" = $search.CaseId
        "CaseName" = $search.CaseName
        "ContentMatchQuery" = $search.ContentMatchQuery
        "CreatedBy" = $search.CreatedBy
        "CreatedTime" = $search.CreatedTime
        "Description" = $search.Description
        "Errors" = $search.Errors
        "ExchangeLocation" = $search.ExchangeLocation
        "ExchangeLocationExclusion" = $search.ExchangeLocationExclusion
        "Identity" = $search.Identity
        "IsValid" = $search.IsValid
        "Items" = $search.Items
        "JobEndTime" = $search.JobEndTime
        "JobId" = $search.JobId
        "JobRunId" = $searchJobRunId
        "JobStartTime" = $search.JobStartTime
        "LastModifiedTime" = $search.LastModifiedTime
        "LogLevel" = $search.LogLevel
        "Name" = $search.Name
        "OneDriveLocation" = $search.OneDriveLocation
        "OneDriveLocationExclusion" = $search.OneDriveLocationExclusion
        "PublicFolderLocation" = $search.PublicFolderLocation
        "PublicFolderLocationExclusion" = $search.PublicFolderLocationExclusion
        "RunBy" = $search.RunBy
        "RunspaceId" = $search_action.RunspaceId
        "SharePointLocation" = $search.SharePointLocation
        "SharePointLocationExclusion" = $search.SharePointLocationExclusion
        "Size" = $search.Size
        "Status" = $search.Status
        "SuccessResults" = ParseSuccessResults -success_results $search.SuccessResults -limit $limit -all_results $all_results
        "TenantId" = $search.TenantId
    }
    <#
        .DESCRIPTION
        Parse Search raw response PSObject to Entry Context.

        .PARAMETER search
        search raw psobject.

        .PARAMETER all_results
        Whether to include also not found locations.

        .PARAMETER limit
        Limit found items.

        .EXAMPLE
        ParseSearchToEntryContext $search

        .OUTPUTS
        Search entry context.

        .Notes
        1. Microsoft internal properties: OneDriveLocationExclusion, OneDriveLocation.
        2. SuccessResults property return as string which should be parsed.
    #>
}

function ParseSearchActionToEntryContext([psobject]$search_action, [int]$limit = -1) {
    return @{
        "Action" = $search_action.Action
        "AllowNotFoundExchangeLocationsEnabled" = $search_action.AllowNotFoundExchangeLocationsEnabled
        "AzureBatchFrameworkEnabled" = $search_action.AzureBatchFrameworkEnabled
        "CaseId" = $search_action.CaseId
        "CaseName" = $search_action.CaseName
        "CreatedBy" = $search_action.CreatedBy
        "CreatedTime" = $search_action.CreatedTime
        "Description" = $search_action.Description
        "Errors" = $search_action.Errors
        "EstimateSearchJobId"  = $search_action.EstimateSearchJobId
        "EstimateSearchRunId" = $search_action.EstimateSearchRunId
        "ExchangeLocation" = $search_action.ExchangeLocation
        "ExchangeLocationExclusion" = $search_action.ExchangeLocationExclusion
        "Identity" = $search_action.Identity
        "IsValid" = $search_action.IsValid
        "JobEndTime" = $search_action.JobEndTime
        "JobId" = $search_action.JobId
        "JobRunId" = $search_action.JobRunId
        "JobStartTime" = $search_action.JobStartTime
        "LastModifiedTime" = $search_action.LastModifiedTime
        "PublicFolderLocation" = $search_action.PublicFolderLocation
        "PublicFolderLocationExclusion" = $search_action.PublicFolderLocationExclusion
        "Retry" = $search_action.Retry
        "RunspaceId" = $search_action.RunspaceId
        "SharePointLocation" = $search_action.SharePointLocation
        "SharePointLocationExclusion" = $search_action.SharePointLocationExclusion
        "Name" = $search_action.Name
        "RunBy" = $search_action.RunBy
        "SearchName" = $search_action.SearchName
        "Status" = $search_action.Status
        "TenantId" = $search_action.TenantId
        "Results" = ParseResults -results $search_action.Results -limit $limit -type $search_action.Action
    }
    <#
        .DESCRIPTION
        Parse SearchAction raw response PSObject to Entry Context.

        .PARAMETER search
        SearchAction raw response.

        .EXAMPLE
        ParseSearchActionToEntryContext $search_action

        .OUTPUTS
        SearchAction entry context.

        .Notes
        1. Microsoft internal properties: OneDriveLocationExclusion, OneDriveLocation.
        2. Results property return as string which should be parsed.
    #>
}

#### Security And Compliance client - OAUTH2.0 ####
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingConvertToSecureStringWithPlainText', '', Scope='Class')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', '', Scope='Class')]
class SecurityAndComplianceClient {
    [string]$app_id
    [string]$organization
    [SecureString]$certificate_password
    [SecureString]$delegated_password
    [System.Security.Cryptography.X509Certificates.X509Certificate2]$certificate
    [string]$upn

    SecurityAndComplianceClient([string]$app_id, [string]$organization, [string]$certificate_password,
                                [string]$delegated_password, [string]$certificate,  [string]$upn) {
        if ($certificate_password) {
            $this.certificate_password = ConvertTo-SecureString $certificate_password -AsPlainText -Force
        } else {
            $this.certificate_password = $null
        }

        if ($delegated_password) {
            $this.delegated_password = ConvertTo-SecureString $delegated_password -AsPlainText -Force
        } else {
            $this.delegated_password = $null
        }

        if ($null -ne $certificate) {
            try {
                $ByteArray = [System.Convert]::FromBase64String($certificate)
                $this.certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($ByteArray, $certificate_password)
            } catch {
            throw "Could not decode the certificate. Try to re-enter it"
            }
        }

        $this.app_id = $app_id
        $this.organization = $organization
        $this.upn = $upn
    }

    CreateSession([string]$CommandName){
        if ($null -eq $this.certificate) {
            ReturnError "Error: For this command, a Certificate is required." | Out-Null
        }
        $cmd_params = @{
            "AppID" = $this.app_id
            "Organization" = $this.organization
            "Certificate" = $this.certificate
            "CommandName" = $CommandName
        }
        Connect-IPPSSession @cmd_params -WarningAction:SilentlyContinue | Out-Null
    }

    CreateDelegatedSession(){
        if ($null -eq $this.delegated_password) {
            ReturnError "Error: For this command, delegated access is required." | Out-Null
        }
        $delegated_cred = New-Object System.Management.Automation.PSCredential ($this.upn, $this.delegated_password)
        Connect-IPPSSession -Credential $delegated_cred -CommandName New-ComplianceSearchAction,Start-ComplianceSearch,Get-ComplianceSearchAction -WarningAction:SilentlyContinue | Out-Null
    }

    DisconnectSession(){
        Disconnect-ExchangeOnline -Confirm:$false -WarningAction:SilentlyContinue 6>$null | Out-Null
    }

    [psobject]NewSearch([string]$search_name,  [string]$case, [string]$kql, [string]$description, [bool]$allow_not_found_exchange_locations, [string[]]$exchange_location,
                        [string[]]$exchange_location_exclusion, [string[]]$public_folder_location, [string[]]$share_point_location, [string[]]$share_point_location_exclusion) {

        # Establish session to remote
        $this.CreateSession("New-ComplianceSearch")
        # Import and Execute command
        $cmd_params = @{
            "Name" = $search_name
            "Case" = $case
            "ContentMatchQuery" = $kql
            "Description" = $description
            "AllowNotFoundExchangeLocationsEnabled" = $allow_not_found_exchange_locations
            "ExchangeLocation" = $exchange_location
            "ExchangeLocationExclusion" = $exchange_location_exclusion
            "PublicFolderLocation" = $public_folder_location
            "SharePointLocation" = $share_point_location
            "SharePointLocationExclusion" = $share_point_location_exclusion
        }
        $response = New-ComplianceSearch @cmd_params
        # Close session to remote
        $this.DisconnectSession()

        return $response
        <#
            .DESCRIPTION
            Create compliance search in the Security & Compliance Center.

            .PARAMETER search_name
            The name of the compliance search.

            .PARAMETER case
            Name of a Core eDiscovery case to associate the new compliance search with.

            .PARAMETER kql
            Text search string or a query that's formatted by using the Keyword Query Language (KQL).

            .PARAMETER description
            Optional description for the compliance search.

            .PARAMETER allow_not_found_exchange_locations
            Whether to include mailboxes other than regular user mailboxes in the compliance search.

            .PARAMETER exchange_location
            Mailboxes to include.

            .PARAMETER exchange_location_exclusion
            Mailboxes to exclude when you use the value "All" for the exchange_location parameter.

            .PARAMETER public_folder_location
            Whether to include all public folders in the search.

            .PARAMETER share_point_location
            SharePoint Online sites to include. You identify the site by its URL value, or you can use the value All to include all sites.

            .PARAMETER share_point_location_exclusion
            SharePoint Online sites to exclude when you use the value All for the SharePointLocation parameter. You identify the site by its URL value.

            .EXAMPLE
            $client.NewSearch("new-search")
            $client.NewSearch("new-search", "new-search-description")

            .OUTPUTS
            psobject - Raw response.

            .LINK
            https://docs.microsoft.com/en-us/powershell/module/exchange/new-compliancesearch?view=exchange-ps
        #>
    }

    SetSearch([string]$search_name, [string]$kql, [string]$description, [bool]$allow_not_found_exchange_locations, [string[]]$add_exchange_location,
              [string[]]$add_exchange_location_exclusion, [string[]]$add_public_folder_location, [string[]]$add_share_point_location, [string[]]$add_share_point_location_exclusion,
              [string[]]$remove_exchange_location, [string[]]$remove_exchange_location_exclusion, [string[]]$remove_public_folder_location, [string[]]$remove_share_point_location,
              [string[]]$remove_share_point_location_exclusion) {

        # Establish session to remote
        $this.CreateSession("Set-ComplianceSearch")
        # Execute command
        $cmd_params = @{
            "Identity" = $search_name
            "ContentMatchQuery" = $kql
            "Description" = $description
            "AllowNotFoundExchangeLocationsEnabled" = $allow_not_found_exchange_locations
            "AddExchangeLocation" = $add_exchange_location
            "AddExchangeLocationExclusion" = $add_exchange_location_exclusion
            "PublicFolderLocation" = $add_public_folder_location
            "AddSharePointLocation" = $add_share_point_location
            "AddSharePointLocationExclusion" = $add_share_point_location_exclusion
            "RemoveExchangeLocation" = $remove_exchange_location
            "RemoveExchangeLocationExclusion" = $remove_exchange_location_exclusion
            "RemovePublicFolderLocation" = $remove_public_folder_location
            "RemoveSharePointLocation" = $remove_share_point_location
            "RemoveSharePointLocationExclusion" = $remove_share_point_location_exclusion
        }
        Set-ComplianceSearch @cmd_params
        # Close session to remote
        $this.DisconnectSession()
        <#
            .DESCRIPTION
            Set compliance search in the Security & Compliance Center.

            .PARAMETER search_name
            The name of the compliance search.

            .PARAMETER kql
            Text search string or a query that's formatted by using the Keyword Query Language (KQL).

            .PARAMETER description
            Optional description for the compliance search.

            .PARAMETER allow_not_found_exchange_locations
            Whether to include mailboxes other than regular user mailboxes in the compliance search.

            .PARAMETER add_exchange_location
            Add mailboxes to include.

            .PARAMETER add_exchange_location_exclusion
            Add mailboxes to exclude when you use the value "All" for the exchange_location parameter.

            .PARAMETER add_public_folder_location
            Add public folders to include.

            .PARAMETER add_share_point_location
            Add sharePoint online sites to include. You identify the site by its URL value.

            .PARAMETER add_share_point_location_exclusion
            Add sharePoint online sites to exclude when you use the value "All" for the SharePointLocation parameter. You identify the site by its URL value.

            .PARAMETER remove_exchange_location
            Remove mailboxes to include.

            .PARAMETER remove_exchange_location_exclusion
            Remove mailboxes to exclude when you use the value "All" for the exchange_location parameter.

            .PARAMETER remove_public_folder_location
            Remove public folders to include.

            .PARAMETER remove_share_point_location
            Remove sharePoint online sites to include. You identify the site by its URL value.

            .PARAMETER remove_share_point_location_exclusion
            Remove sharePoint online sites to exclude when you use the value "All" for the exchange_location (Used in create new compliance search) argument or share_point_location argument. You identify the site by its URL value.

            .EXAMPLE
            $client.SetSearch("new-search", "new-search-description")

            .LINK
            https://docs.microsoft.com/en-us/powershell/module/exchange/set-compliancesearch?view=exchange-ps
        #>
    }

    RemoveSearch([string]$search_name) {
        # Establish session to remote
        $this.CreateSession("Remove-ComplianceSearch")
        # Import and Execute command
        Remove-ComplianceSearch -Identity $search_name -Confirm:$false

        # Close session to remote
        $this.DisconnectSession()

       <#
            .DESCRIPTION
            Remove compliance search by name from the Security & Compliance Center.

            .PARAMETER search_name
            The name of the compliance search.

            .EXAMPLE
            $client.RemoveSearch("new-search")

            .LINK
            https://docs.microsoft.com/en-us/powershell/module/exchange/remove-compliancesearch?view=exchange-ps
        #>
    }

    [array]ListSearch() {
        # Establish session to remote
        $this.CreateSession("Get-ComplianceSearch")
        # Execute command
        $response = Get-ComplianceSearch

        # Close session to remote
        $this.DisconnectSession()

        return $response

       <#
            .DESCRIPTION
            List compliance searches in the Security & Compliance Center.

            .EXAMPLE
            $client.ListSearch()

            .OUTPUTS
            array - Raw response.

            .LINK
            https://docs.microsoft.com/en-us/powershell/module/exchange/get-compliancesearch?view=exchange-ps
        #>
    }

    [psobject]GetSearch([string]$search_name) {
        # Establish session to remote
        $this.CreateSession("Get-ComplianceSearch")
        # Import and Execute command
        $response = Get-ComplianceSearch -Identity $search_name

        # Close session to remote
        $this.DisconnectSession()

        return $response
        <#
            .DESCRIPTION
            Get compliance search by name from the Security & Compliance Center.

            .PARAMETER search_name
            The name of the compliance search.

            .EXAMPLE
            $client.GetSearch("new-search")

            .OUTPUTS
            psobject - Raw response.

            .LINK
            https://docs.microsoft.com/en-us/powershell/module/exchange/get-compliancesearch?view=exchange-ps
        #>
    }

    StartSearch([string]$search_name) {
        # Establish session to remote
        $this.CreateDelegatedSession()
        # Execute command
        Start-ComplianceSearch -Identity $search_name -Confirm:$false -Force:$true

        # Close session to remote
        $this.DisconnectSession()
        <#
            .DESCRIPTION
            Start stopped, completed or not started compliance search in the Security & Compliance Center.

            .PARAMETER search_name
            The name of the compliance search.

            .EXAMPLE
            $client.StartSearch("new-search")

            .LINK
            https://docs.microsoft.com/en-us/powershell/module/exchange/start-compliancesearch?view=exchange-ps
        #>
    }

    StopSearch([string]$search_name) {

        # Establish session to remote
        $this.CreateSession("Stop-ComplianceSearch")
        # Execute command
        Stop-ComplianceSearch -Identity $search_name -Confirm:$false

        # Close session to remote
        $this.DisconnectSession()

        <#
            .DESCRIPTION
            Stop compliance search by name in the Security & Compliance Center.

            .PARAMETER search_name
            The name of the compliance search.

            .EXAMPLE
            $client.StopSearch("new-search")

            .LINK
            https://docs.microsoft.com/en-us/powershell/module/exchange/stop-compliancesearch?view=exchange-ps
        #>
    }

    [psobject]NewSearchAction([string]$search_name, [string]$action, [string]$purge_type) {
        # Establish session to remote
        $this.CreateDelegatedSession()
        # Execute command
        $cmd_params = @{
            "SearchName" = $search_name
        }
        if ($action -eq "Preview") {
            $cmd_params.Preview = $true
        } elseif ($action -eq "Purge") {
            $cmd_params.Purge = $true
            $cmd_params.PurgeType = $purge_type
            $cmd_params.Confirm = $false
            $cmd_params.Force = $true
        } else {
            throw "New action must include valid action - Preview/Purge"
        }
        $response = New-ComplianceSearchAction @cmd_params
        if (-not $response){
            # Close session to remote
            $this.DisconnectSession()

            throw "The search action didn't return any results. Please check the search_name and consider running the o365-sc-start-search command before."
        }

        # Close session to remote
        $this.DisconnectSession()

        return $response
        <#
            .DESCRIPTION
            Create compliance search action in the Security & Compliance Center.

            .PARAMETER search_name
            The name of the compliance search.

            .PARAMETER action
            Search action type - Preview (Showing results) / Purge (Delete found emails)

            .PARAMETER purge_type
            Used if action type is purge, Search action purge type - SoftDelete (allow recover) / HardDelete (not recoverable).

            .EXAMPLE
            $client.NewSearchAction("search-name", "Preview")
            $client.NewSearchAction("search-name", "Purge", "HardDelete")

            .OUTPUTS
            psobject - Raw response.

            .LINK
            https://docs.microsoft.com/en-us/powershell/module/exchange/new-compliancesearchaction?view=exchange-ps
        #>
    }

    RemoveSearchAction([string]$search_action_name) {
        # Establish session to remote
        $this.CreateSession("Remove-ComplianceSearchAction")
        # Execute command
        Remove-ComplianceSearchAction -Identity $search_action_name -Confirm:$false
        # Close session to remote
        $this.DisconnectSession()

        <#
            .DESCRIPTION
            Remove compliance search action from the Security & Compliance Center.

            .PARAMETER search_action_name
            The name of the compliance search action.

            .EXAMPLE
            $client.RemoveSearchAction("search-name")

            .LINK
            https://docs.microsoft.com/en-us/powershell/module/exchange/remove-compliancesearchaction?view=exchange-ps
        #>
    }

    [array]ListSearchActions() {
        # Establish session to remote
        $this.CreateSession("Get-ComplianceSearchAction")
        # Execute command
        $response = Get-ComplianceSearchAction

        # Close session to remote
        $this.DisconnectSession()

        return $response
        <#
            .DESCRIPTION
            List all compliance search action in the Security & Compliance Center.

            .EXAMPLE
            $client.ListearchAction()

            .OUTPUTS
            array - Raw response.

            .LINK
            https://docs.microsoft.com/en-us/powershell/module/exchange/get-compliancesearchaction?view=exchange-ps
        #>
    }

    [psobject]GetSearchAction([string]$search_action_name) {
        # Establish session to remote
        $this.CreateDelegatedSession()

        # Execute command
        $response = Get-ComplianceSearchAction -Identity $search_action_name

        # Close session to remote
        $this.DisconnectSession()
        return $response
        <#
            .DESCRIPTION
            Get compliance search action in the Security & Compliance Center.

            .PARAMETER search_action_name
            The name of the compliance search action.

            .EXAMPLE
            $client.GetSearchAction("search-name")

            .OUTPUTS
            psobject - Raw response.

            .LINK
            https://docs.microsoft.com/en-us/powershell/module/exchange/get-compliancesearchaction?view=exchange-ps
        #>
    }
}

#### COMMAND FUNCTIONS ####

function TestModuleCommand ([SecurityAndComplianceClient]$cs_client) {
    $cs_client.ListSearchActions() | Out-Null

    $raw_response = $null
    $human_readable = "ok"
    $entry_context = $null

    return $human_readable, $entry_context, $raw_response
}

function NewSearchCommand([SecurityAndComplianceClient]$client, [hashtable]$kwargs) {
    # Command arguemnts parsing
    $allow_not_found_exchange_locations = ConvertTo-Boolean $kwargs.allow_not_found_exchange_locations
    $exchange_location = ArgToList $kwargs.exchange_location
    $exchange_location_exclusion = ArgToList $kwargs.exchange_location_exclusion
    $public_folder_location = ArgToList $kwargs.public_folder_location
    $share_point_location = ArgToList $kwargs.share_point_location
    $share_point_location_exclusion = ArgToList $kwargs.share_point_location_exclusion
    if (!$kwargs.search_name -or $kwargs.search_name -eq "") {
        $kwargs.search_name = "XSOAR-$(New-Guid)"
    }
    # Raw response
    $raw_response = $client.NewSearch($kwargs.search_name, $kwargs.case, $kwargs.kql, $kwargs.description, $allow_not_found_exchange_locations,
                                      $exchange_location, $exchange_location_exclusion, $public_folder_location, $share_point_location, $share_point_location_exclusion)
    # Human readable
    $md_columns = $raw_response | Select-Object -Property Name, Description, CreatedBy, LastModifiedTime, ContentMatchQuery
    $human_readable = TableToMarkdown $md_columns  "$script:INTEGRATION_NAME - New search '$($kwargs.search_name)' created"
    # Entry context
    $entry_context = @{
        $script:SEARCH_ENTRY_CONTEXT = ParseSearchToEntryContext $raw_response
    }

    return $human_readable, $entry_context, $raw_response
}

function SetSearchCommand([SecurityAndComplianceClient]$client, [hashtable]$kwargs) {
    # Command arguemnts parsing
    if ($kwargs.allow_not_found_exchange_locations) {
        $allow_not_found_exchange_locations = ConvertTo-Boolean $kwargs.allow_not_found_exchange_locations
    }
    $add_exchange_location = ArgToList $kwargs.add_exchange_location
    $add_exchange_location_exclusion = ArgToList $kwargs.add_exchange_location_exclusion
    $add_public_folder_location = ArgToList $kwargs.add_public_folder_location
    $add_share_point_location = ArgToList $kwargs.add_share_point_location
    $add_share_point_location_exclusion = ArgToList $kwargs.add_share_point_location_exclusion
    $remove_exchange_location = ArgToList $kwargs.remove_exchange_location
    $remove_exchange_location_exclusion = ArgToList $kwargs.remove_exchange_location_exclusion
    $remove_public_folder_location = ArgToList $kwargs.remove_public_folder_location
    $remove_share_point_location = ArgToList $kwargs.remove_share_point_location
    $remove_share_point_location_exclusion = ArgToList $kwargs.remove_share_point_location_exclusion
    # Set operation doesn't return any output
    $client.SetSearch($kwargs.search_name, $kwargs.kql, $kwargs.description, $allow_not_found_exchange_locations,
                      $add_exchange_location, $add_exchange_location_exclusion, $add_public_folder_location, $add_share_point_location, $add_share_point_location_exclusion,
                      $remove_exchange_location, $remove_exchange_location_exclusion, $remove_public_folder_location, $remove_share_point_location, $remove_share_point_location_exclusion)
    # Raw response
    $raw_response = @{}
    # Human readable
    $human_readable = "$script:INTEGRATION_NAME - Search **$($kwargs.search_name)** modified!"
    # Entry context
    $entry_context = @{}

    return $human_readable, $entry_context, $raw_response
}

function RemoveSearchCommand([SecurityAndComplianceClient]$client, [hashtable]$kwargs) {
    # Remove operation doesn't return any output
    $client.RemoveSearch($kwargs.search_name)
    # Raw response
    $raw_response = @{}
    # Human readable
    $human_readable = "$script:INTEGRATION_NAME - Search **$($kwargs.search_name)** removed!"
    # Entry context
    $entry_context = @{}

    return $human_readable, $entry_context, $raw_response
}

function ListSearchCommand([SecurityAndComplianceClient]$client, [hashtable]$kwargs) {
    # Raw response
    $raw_response = $client.ListSearch()

    if ($raw_response.count -eq 0){
        return "#### No compliance searches were retrieved from the Compliance Center.", @{}, $raw_response
    }

    # Human readable
    $md_columns = $raw_response | Select-Object -Property Name, Description, CreatedBy, LastModifiedTime, RunBy
    $human_readable = TableToMarkdown $md_columns "$script:INTEGRATION_NAME - Search configurations"
    # Entry context
    $entry_context = @{
        $script:SEARCH_ENTRY_CONTEXT =  $raw_response | ForEach-Object {
            ParseSearchToEntryContext $_
        }
    }

    return $human_readable, $entry_context, $raw_response
}

function GetSearchCommand([SecurityAndComplianceClient]$client, [hashtable]$kwargs) {
    # Command arguemnts parsing
    $statistics = ConvertTo-Boolean $kwargs.statistics
    $all_results = ConvertTo-Boolean $kwargs.all_results
    $export = ConvertTo-Boolean $kwargs.export
    # Raw response
    $raw_response = $client.GetSearch($kwargs.search_name)
    # Entry context
    $entry_context = @{
        $script:SEARCH_ENTRY_CONTEXT = ParseSearchToEntryContext -search $raw_response -limit $kwargs.limit -all_results $all_results
    }
    # Human readable - Basic info
    $md_columns = $raw_response | Select-Object -Property Name, Description, CreatedBy, LastModifiedTime, RunBy, Status
    $human_readable = TableToMarkdown $md_columns  "$script:INTEGRATION_NAME - '$($kwargs.search_name)' search"
    # Human readable - Statistics
    $parsed_results = $entry_context[$script:SEARCH_ENTRY_CONTEXT].SuccessResults
    if ($parsed_results -and $statistics) {
        $human_readable += TableToMarkdown $parsed_results "Search statistics"
    }
    # Results file export
    if ($export) {
        $parsed_results_all = ParseSuccessResults -success_results $raw_response.SuccessResults -limit $kwargs.limit -all_results $all_results
        if ($parsed_results_all.Count -ne 0){
            $file_entry = FileResult "$($kwargs.search_name)_search.json" $($parsed_results_all | ConvertTo-Json) $true
        }
    }

    return $human_readable, $entry_context, $raw_response, $file_entry
}

function StartSearchCommand([SecurityAndComplianceClient]$client, [hashtable]$kwargs) {
    # Start operation doesn't return any output
    $client.StartSearch($kwargs.search_name)
    # Raw response
    $raw_response = @{}
    # Human readable
    $human_readable = "$script:INTEGRATION_NAME - search **$($kwargs.search_name)** started !"
    # Entry context
    $entry_context = @{}

    return $human_readable, $entry_context, $raw_response
}

function StopSearchCommand([SecurityAndComplianceClient]$client, [hashtable]$kwargs) {
    # Stop operation doesn't return any output
    $client.StopSearch($kwargs.search_name)
    # Raw response
    $raw_response = @{}
    # Human readable
    $human_readable = "$script:INTEGRATION_NAME - search **$($kwargs.search_name)** stopped !"
    # Entry context
    $entry_context = @{}

    return $human_readable, $entry_context, $raw_response
}

function NewSearchActionCommand([SecurityAndComplianceClient]$client, [hashtable]$kwargs) {
    # Raw response
    $raw_response = $client.NewSearchAction($kwargs.search_name, $kwargs.action, $kwargs.purge_type)
    # Human readable
    $md_columns = $raw_response | Select-Object -Property Name, SearchName, Action, LastModifiedTime, RunBy, Status
    $human_readable = TableToMarkdown $md_columns "$script:INTEGRATION_NAME - search action '$($raw_response.Name)' created"
    # Entry context
    $entry_context = @{
        $script:SEARCH_ACTION_ENTRY_CONTEXT = ParseSearchActionToEntryContext $raw_response
    }

    return $human_readable, $entry_context, $raw_response
}

function RemoveSearchActionCommand([SecurityAndComplianceClient]$client, [hashtable]$kwargs) {
    # Remove operation doesn't return any output
    $client.RemoveSearchAction($kwargs.search_action_name)
    # Raw response
    $raw_response = @{}
    # Human readable
    $human_readable = "$script:INTEGRATION_NAME - search action **$($kwargs.search_action_name)** removed!"
    # Entry context
    $entry_context = @{}

    return $human_readable, $entry_context, $raw_response
}

function GetSearchActionCommand([SecurityAndComplianceClient]$client, [hashtable]$kwargs) {
    # Command arguemnts parsing
    $results = ConvertTo-Boolean $kwargs.results
    $export = ConvertTo-Boolean $kwargs.export
    # Raw response
    $raw_response = $client.GetSearchAction($kwargs.search_action_name)
    # Entry context
    $entry_context = @{
        $script:SEARCH_ACTION_ENTRY_CONTEXT = ParseSearchActionToEntryContext $raw_response $kwargs.limit
    }
    # Human readable
    $md_columns = $raw_response | Select-Object -Property Name, SearchName, Action, LastModifiedTime, RunBy, JobEndTime, Status
    $human_readable = TableToMarkdown $md_columns "$script:INTEGRATION_NAME - search action '$($kwargs.search_action_name)'"
    # Human readable - Mail results
    $parsed_results = $entry_context[$script:SEARCH_ACTION_ENTRY_CONTEXT].Results
    if ($parsed_results -and $results) {
        $human_readable += TableToMarkdown $parsed_results "Search action results"
    }
    # Results file export
    if ($export) {
        $parsed_results_all = ParseResults -results $raw_response.Results -limit $kwargs.limit
        if ($parsed_results_all.Count -ne 0){
            $file_entry = FileResult "$($kwargs.search_action_name)_search_action.json" $($parsed_results_all | ConvertTo-Json) $true
        }
    }
    return $human_readable, $entry_context, $raw_response, $file_entry
}

function ListSearchActionsCommand([SecurityAndComplianceClient]$client, [hashtable]$kwargs) {
    # Raw response
    $raw_response = $client.ListSearchActions()

    # Human readable
    $md_columns = $raw_response | Select-Object -Property Name, SearchName, Action, LastModifiedTime, RunBy, JobEndTime, Status
    $human_readable = TableToMarkdown $md_columns "$script:INTEGRATION_NAME - search actions"
    # Entry context
    $entry_context = @{
        $script:SEARCH_ACTION_ENTRY_CONTEXT = $raw_response | ForEach-Object {
            ParseSearchActionToEntryContext $_
        }
    }

    return $human_readable, $entry_context, $raw_response
}

#### INTEGRATION COMMANDS MANAGER ####

function Main {
    $command = $Demisto.GetCommand()
    $command_arguments = $Demisto.Args()
    $integration_params = $Demisto.Params()

    try {
        $Demisto.Debug("Command being called is $Command")

        $cs_client = [SecurityAndComplianceClient]::new(
            $integration_params.app_id,
            $integration_params.organization,
            $integration_params.certificate_password,
            $integration_params.delegated_auth.password,
            $integration_params.certificate,
            $integration_params.delegated_auth.identifier
        )

        # Executing command
        switch ($command) {
            "test-module" {
                ($human_readable, $entry_context, $raw_response) = TestModuleCommand $cs_client
            }
            "$script:COMMAND_PREFIX-new-search" {
                ($human_readable, $entry_context, $raw_response) = NewSearchCommand $cs_client $command_arguments
            }
            "$script:COMMAND_PREFIX-set-search" {
                ($human_readable, $entry_context, $raw_response) = SetSearchCommand $cs_client $command_arguments
            }
            "$script:COMMAND_PREFIX-remove-search" {
                ($human_readable, $entry_context, $raw_response) = RemoveSearchCommand $cs_client $command_arguments
            }
            "$script:COMMAND_PREFIX-list-search" {
                ($human_readable, $entry_context, $raw_response) = ListSearchCommand $cs_client $command_arguments
            }
            "$script:COMMAND_PREFIX-get-search" {
                ($human_readable, $entry_context, $raw_response, $file_entry) = GetSearchCommand $cs_client $command_arguments
            }
            "$script:COMMAND_PREFIX-start-search" {
                ($human_readable, $entry_context, $raw_response) = StartSearchCommand $cs_client $command_arguments
            }
            "$script:COMMAND_PREFIX-stop-search" {
                ($human_readable, $entry_context, $raw_response) = StopSearchCommand $cs_client $command_arguments
            }
            "$script:COMMAND_PREFIX-new-search-action" {
                ($human_readable, $entry_context, $raw_response) = NewSearchActionCommand $cs_client $command_arguments
            }
            "$script:COMMAND_PREFIX-remove-search-action" {
                ($human_readable, $entry_context, $raw_response) = RemoveSearchActionCommand $cs_client $command_arguments
            }
            "$script:COMMAND_PREFIX-list-search-action" {
                ($human_readable, $entry_context, $raw_response) = ListSearchActionsCommand $cs_client $command_arguments
            }
            "$script:COMMAND_PREFIX-get-search-action" {
                ($human_readable, $entry_context, $raw_response, $file_entry) = GetSearchActionCommand $cs_client $command_arguments
            }
        }
        # Return results to Demisto Server
        ReturnOutputs $human_readable $entry_context $raw_response | Out-Null
        if ($file_entry) {
            $Demisto.results($file_entry)
        }
    } catch {
        Disconnect-ExchangeOnline -Confirm:$false -WarningAction:SilentlyContinue 6>$null | Out-Null
        $Demisto.debug("Integration: $script:INTEGRATION_NAME
Command: $command
Arguments: $($command_arguments | ConvertTo-Json)
Error: $($_.Exception.Message)")
        if ($command -ne "test-module") {
            ReturnError "Error:
            Integration: $script:INTEGRATION_NAME
            Command: $command
            Arguments: $($command_arguments | ConvertTo-Json)
            Error: $($_.Exception)" | Out-Null
        } else {
            ReturnError $_.Exception.Message
        }
    }
}

# Execute Main when not in Tests
if ($MyInvocation.ScriptName -notlike "*.tests.ps1" -AND -NOT $Test) {
    Main
}