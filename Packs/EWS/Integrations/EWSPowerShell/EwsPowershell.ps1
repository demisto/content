. $PSScriptRoot\CommonServerPowerShell.ps1

$global:INTEGRATION_NAME = "SecurityAndCompliance"
$global:COMMAND_PREFIX = "o365-sc"
$global:INTEGRATION_CONTEXT = $Demisto.getIntegrationContext()
$global:INTEGRATION_ENTRY_CONTEX = "O365.SecurityAndCompliance"
$global:COMPLAIANCE_SEARCH_ENTRY_CONTEXT = "$global:INTEGRATION_ENTRY_CONTEX.Search(val.Name && val.Name == obj.Name)"
$global:COMPLAIANCE_SEARCH_ACTIONS_ENTRY_CONTEXT = "$global:INTEGRATION_ENTRY_CONTEX.SearchActions(val.Name && val.Name == obj.Name)"


#### HELPER FUNCTIONS ####

function UpdateIntegrationContext([OAuth2DeviceCodeClient]$client){
    $integration_context = @{
        "DeviceCode" = $client.device_code
        "DeviceCodeExpiresIn" = $client.device_code_expires_in
        "DeviceCodeCreationTime" = $client.device_code_creation_time
        "AccessToken" = $client.access_token
        "RefreshToken" = $client.refresh_token
        "AccessTokenExpiresIn" = $client.access_token_expires_in
        "AccessTokenCreationTime" = $client.access_token_creation_time
    }

    $Demisto.setIntegrationContext($integration_context)
    <#
        .DESCRIPTION
        Update integration context from OAuth2DeviceCodeClient client

        .EXAMPLE
        UpdateIntegrationContext $client

        .PARAMETER search_name
        OAuth2DeviceCodeClient client.
    #>
}

function CreateNewSession([string]$uri, [string]$upn, [string]$bearer_token) {
    $tokenValue = ConvertTo-SecureString "Bearer $bearer_token" -AsPlainText -Force
    $credential = New-Object System.Management.Automation.PSCredential($upn, $tokenValue) 
    $uri = "https://eur01b.ps.compliance.protection.outlook.com/powershell-liveid?BasicAuthToOAuthConversion=true;PSVersion=7.0.3"
    $session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri $uri -Credential $credential -Authentication Basic -AllowRedirection

	if (!$session) {
		throw "Fail - establishing session to $uri"
	}

	return $session
    <#
        .DESCRIPTION
        Creates new pssession using Oauth2.0 method.
        
        .PARAMETER uri
        Security & Compliance Center uri.
        
        .PARAMETER upn
        User Principal Name (UPN) is the name of a system user in an email address format..
        
        .PARAMETER bearer_token
        Valid bearer token value.

        .EXAMPLE
        CreateNewSession("outlook.com", "user@microsoft.com", "dfhsdkjhkjhvkdvbihsgiu")

        .OUTPUTS
        PSSession - PSSession object.
        
        .LINK
        https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/new-pssession?view=powershell-7
    #>
}

function ParseSuccessResults([string]$success_results) {
    $parsed_success_results = New-Object System.Collections.Generic.List[System.Object]
    if ($success_results) {
        $lines = $success_results.Split([Environment]::NewLine)
        foreach ($line in $lines)
        {
            if ($line -match 'Location: (\S+), Item count: (\d+), Total size: (\d+)')
            {
                $parsed_success_results.Add(@{
                    "Location" = $matches[1]
                    "Items count" = $matches[2]
                    "Size" = $matches[3]
                })
            }
        }
    }

    return $parsed_success_results
    <#
        .DESCRIPTION
        Parse string return in Search PSObject property "SuccessResults" 
        
        .PARAMETER success_results
        SuccessResults raw string.

        .EXAMPLE
        ParseSuccessResults $success_results

        .OUTPUTS
        List of psobject SuccessResults object.
    #>
}

function ParseResults([string]$results) {
    $parsed_results = New-Object System.Collections.Generic.List[System.Object]
    if ($results) {
        $lines = $results.Split("Location")
        foreach ($line in $lines)
        {
            if ($line -match ': (\S+); Sender: ([\S ]+); Type: (\S+); Size: (\d+); Received Time: ([\S\d ]+);')
            {
                $parsed_results.Add(@{
                    "Location" = $matches[1]
                    "Subject" = $matches[2]
                    "Type" = $matches[3]
                    "Size" = $matches[4]
                    "Received Time" = $matches[5]
                })
            }
        }
    }

    return $parsed_results
    <#
        .DESCRIPTION
        Parse string return in SearchAction PSObject property "Results" 
        
        .PARAMETER success_results
        SuccessResults raw string.

        .EXAMPLE
        ParseSuccessResults $results

        .OUTPUTS
        List of psobject Results object.
    #>
}

function ParseSearchToEntryContext([psobject]$search) {
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
        "SuccessResults" = ParseSuccessResults $search.SuccessResults
        "TenantId" = $search.TenantId
    }
    <#
        .DESCRIPTION
        Parse Search raw response PSObject to Entry Context.
        
        .PARAMETER search
        search raw psobject.

        .EXAMPLE
        ParseSearchToEntryContext $search

        .OUTPUTS
        Search entry context.

        .Notes
        1. Microsoft internal properties: OneDriveLocationExclusion, OneDriveLocation.
        2. SuccessResults property return as string which should be parsed.
    #>
}

function ParseSearchActionsToEntryContext([psobject]$search_action) {
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
        "Results" = ParseResults $search_action.Results
    }
    <#
        .DESCRIPTION
        Parse SearchAction raw response PSObject to Entry Context.
        
        .PARAMETER search
        SearchAction raw psobject.

        .EXAMPLE
        ParseSearchActionsToEntryContext $search_action

        .OUTPUTS
        SearchAction entry context.

        .Notes
        1. Microsoft internal properties: OneDriveLocationExclusion, OneDriveLocation.
        2. Results property return as string which should be parsed.
    #>
}

#### OAUTH2.0 CLIENT - DEVICE CODE FLOW #####

class OAuth2DeviceCodeClient {
    [string]$application_id = "a0c73c16-a7e3-4564-9a95-2bdf47383716"
    [string]$application_scope = "offline_access%20https%3A//outlook.office365.com/.default"
    [string]$device_code
    [int]$device_code_expires_in
    [int]$device_code_creation_time
    [string]$access_token
    [string]$refresh_token
    [int]$access_token_expires_in
    [int]$access_token_creation_time
    [bool]$insecure
    [bool]$proxy

    OAuth2DeviceCodeClient([string]$device_code, [string]$device_code_expires_in, [string]$device_code_creation_time, [string]$access_token,
                            [string]$refresh_token,[string]$access_token_expires_in, [string]$access_token_creation_time, [bool]$insecure, [bool]$proxy) {
        $this.device_code = $device_code
        $this.device_code_expires_in = $device_code_expires_in
        $this.device_code_creation_time = $device_code_creation_time
        $this.access_token = $access_token
        $this.refresh_token = $refresh_token
        $this.access_token_expires_in = $access_token_expires_in
        $this.access_token_creation_time = $access_token_creation_time
        $this.insecure = $insecure
        $this.proxy = $proxy
        <#
            .DESCRIPTION
            OAuth2DeviceCodeClient manage state of OAuth2.0 device-code flow described in https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-device-code.

            .DESCRIPTION
            Its not recomende to create an object using the constructor, Use static method CreateClientFromIntegrationContext() instead.
            OAuth2DeviceCodeClient states are:
                1. Getting device-code (Will be used in stage 2) and user-code (Will be used by the user to authorize permissions) from Microsoft application.
                2. Getting access-token and refresh-token - after use authorize (Using stage 1 - device code)
                3. Refresh access-token if access-token is expired.
            
            .PARAMETER device_code
            A long string used to verify the session between the client and the authorization server.
            The client uses this parameter to request the access token from the authorization server.

            .PARAMETER device_code_expires_in
            The number of seconds before the device_code and user_code expire. (15 minutes)

            .PARAMETER access_token
            Opaque string, Issued for the scopes that were requested.

            .PARAMETER refresh_token
            Opaque string, Issued if the original scope parameter included offline_access. (Valid for 90 days)
            
            .PARAMETER access_token_expires_in
            Number of seconds before the included access token is valid for. (Usally - 60 minutes)

            .PARAMETER access_token_creation_time
            Unix time of access token creation (Used for knowing when to refresh the token).

            .PARAMETER access_token_expires_in
            Number of seconds before the included access token is valid for. (Usally - 60 minutes)

            .PARAMETER insecure 
            Wheter to trust any TLS/SSL Certificate) or not.
            
            .PARAMETER proxy 
            Wheter to user system proxy configuration or not.

            .NOTES
            1. Application id - a0c73c16-a7e3-4564-9a95-2bdf47383716 , This is well-known application publicly managed by Microsoft and will not work in on-premise enviorment.

            .LINK
            https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-device-code
        #>
    }

    static [OAuth2DeviceCodeClient]CreateClientFromIntegrationContext([bool]$insecure, [bool]$proxy){
        $ic = $global:INTEGRATION_CONTEXT
        $client = [OAuth2DeviceCodeClient]::new($ic.DeviceCode, $ic.DeviceCodeExpiresIn, $ic.DeviceCodeCreationTime, $ic.AccessToken, $ic.RefreshToken,
                                                $ic.AccessTokenExpiresIn, $ic.AccessTokenCreationTime, $insecure, $proxy)
        
        return $client
        <#
            .DESCRIPTION
            Static method which create object (factory method) from populated values in integration context.

            .EXAMPLE
            [OAuth2DeviceCodeClient]::CreateClientFromIntegrationContext()
            
            .OUTPUTS
            OAuth2DeviceCodeClient initialized object.
        #>
    }

    [PSObject]AuthorizationRequest() {
        # Reset object-properties
        $this.device_code = $null
        $this.device_code_expires_in = $null
        $this.device_code_creation_time = $null
        $this.access_token = $null
        $this.refresh_token = $null
        $this.access_token_expires_in = $null
        $this.access_token_creation_time = $null
        # Get device-code and user-code
        $params = @{
            "URI" = "https://login.microsoftonline.com/organizations/oauth2/v2.0/devicecode"
            "Method" = "Post"
            "Headers" = (New-Object "System.Collections.Generic.Dictionary[[String],[String]]").Add("Content-Type", "application/x-www-form-urlencoded")
            "Body" = "client_id=$($this.application_id)&scope=$($this.application_scope)"
            "NoProxy" = !$this.proxy
            "SkipCertificateCheck" = !$this.insecure
        }
        $response = Invoke-WebRequest @params
        $response_body = ConvertFrom-Json $response.Content
        # Update object properties
        $this.device_code = $response_body.device_code
        $this.device_code_creation_time = [int][double]::Parse((Get-Date -UFormat %s))
        $this.device_code_expires_in = [int]::Parse($response_body.expires_in)

        return $response_body

        <#
            .DESCRIPTION
            Reset values populated in instance context and getting new device-code and user-code.

            .EXAMPLE
            $client.AuthorizationRequest()
            
            .OUTPUTS
            psobject - Raw body response.
            
            .LINK
            https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-device-code#device-authorization-request
        #>
    }

    [psobject]AccessTokenRequest() {
        # Get new token using device-code
        try {
            $params = @{
                "URI" = "https://login.microsoftonline.com/organizations/oauth2/v2.0/token"
                "Method" = "Post"
                "Headers" = (New-Object "System.Collections.Generic.Dictionary[[String],[String]]").Add("Content-Type", "application/x-www-form-urlencoded")
                "Body" = "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code&code=$($this.device_code)&client_id=$($this.application_id)"
                "NoProxy" = !$this.proxy
                "SkipCertificateCheck" = !$this.insecure
            }
            $response = Invoke-WebRequest @params
            $response_body = ConvertFrom-Json $response.Content
        } 
        catch { 
            $response_body = ConvertFrom-Json $_.ErrorDetails.Message
            if ($response_body.error -eq "authorization_pending" -or $response_body.error -eq "invalid_grant") {
                $error_details = "Please run command !ews-start-auth , before running this command."
            }
            elseif ($response_body.error -eq "expired_token") {
                $error_details = "At least $($this.access_token_expires_in) seconds have passed from executing !ews-start-auth, Please run command !ews-start-auth again."
            } else {
                $error_details = $response_body
            }

            throw "Unable to get access token for your account, $error_details"
        }
        # Update object properties
        $this.access_token = $response_body.access_token
        $this.refresh_token = $response_body.refresh_token
        $this.access_token_expires_in = [int]::Parse($response_body.expires_in)
        $this.access_token_creation_time = [int][double]::Parse((Get-Date -UFormat %s))

        return $response_body

        <#
            .DESCRIPTION
            Getting access-token and refresh-token from Microsoft application based on the device-code we go from AuthorizationRequest() method.

            .EXAMPLE
            $client.AccessTokenRequest()
            
            .OUTPUTS
            psobject - Raw body response.

            .LINK 
            https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-device-code#authenticating-the-user
        #>
    }

    [psobject]RefreshTokenRequest() {
        # Get new token using refresh token
        try {
            $params = @{
                "URI" = "https://login.microsoftonline.com/organizations/oauth2/v2.0/token"
                "Method" = "Post"
                "Headers" = (New-Object "System.Collections.Generic.Dictionary[[String],[String]]").Add("Content-Type", "application/x-www-form-urlencoded")
                "Body" = "grant_type=refresh_token&client_id=$($this.application_id)&refresh_token=$($this.refresh_token)&scope=$($this.application_scope)"
                "NoProxy" = !$this.proxy
                "SkipCertificateCheck" = !$this.insecure
            }
            $response = Invoke-WebRequest @params
            $response_body = ConvertFrom-Json $response.Content
        } 
        catch { 
            $response_body = ConvertFrom-Json $_.ErrorDetails.Message
            if ($response_body.error -eq "invalid_grant") {
                $error_details = "Please login to grant account permissions (After 90 days grant is expired) !ews-start-auth."
            }
            else {
                $error_details = $response_body
            }

            throw "Unable to refresh access token for your account, $error_details"
        }
        # Update object properties
        $this.access_token = $response_body.access_token
        $this.refresh_token = $response_body.refresh_token
        $this.access_token_expires_in = [int]::Parse($response_body.expires_in)
        $this.access_token_creation_time = [int][double]::Parse((Get-Date -UFormat %s))

        return $response_body

        <#
            .DESCRIPTION
            Getting new access-token and refresh-token from Microsoft application based on the refresh-token we got from AccessTokenRequest() method.

            .EXAMPLE
            $client.RefreshTokenRequest()
            
            .OUTPUTS
            PSObject - Raw body response.
            
            .LINK
            https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-implicit-grant-flow#refreshing-tokens
        #>
    }

    [bool]IsDeviceCodeExpired(){
        if (!$this.device_code){
            return $true
        }
        $current_time = [int][double]::Parse((Get-Date -UFormat %s)) - 30
        $valid_until = $this.device_code_creation_time + $this.access_token_expires_in

        return $current_time -gt $valid_until

        <#
            .DESCRIPTION
            Check if device-code expired.

            .EXAMPLE
            $client.IsDeviceCodeExpired()
            
            .OUTPUTS
            bool - True If device-code expired else False.
            
            .LINK
            https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-configurable-token-lifetimes#configurable-token-lifetime-properties-after-the-retirement
        #>
    }

    [bool]IsAccessTokenExpired(){
        if (!$this.access_token){
            return $true
        }
        $current_time = [int][double]::Parse((Get-Date -UFormat %s)) - 30
        $valid_until = $this.access_token_creation_time + $this.access_token_expires_in

        return $current_time -gt $valid_until
        <#
            .DESCRIPTION
            Check if access-token expired.

            .EXAMPLE
            $client.IsAccessTokenExpired()
            
            .OUTPUTS
            bool - True If access-token expired else False.
            
            .LINK
            https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-configurable-token-lifetimes#configurable-token-lifetime-properties-after-the-retirement
        #>
    }

    RefreshTokenIfExpired(){
        if ($this.access_token -and $this.IsAccessTokenExpired()) {
            $this.RefreshTokenRequest()
        }
        <#
            .DESCRIPTION
            Refresh access token if expired, with offset of 30 seconds.

            .EXAMPLE
            $client.RefreshTokenIfExpired()
        #>
    }
}

#### Security And Compliance client - OAUTH2 ####

class SecurityAndComplianceClient {
	[ValidateNotNullOrEmpty()][string]$uri
	[ValidateNotNullOrEmpty()][string]$upn
    [string]$bearer_token
    [psobject]$session
    [bool]$insecure
    [bool]$proxy
    
    SecurityAndComplianceClient([string]$uri, [string]$upn, [string]$bearer_token, [bool]$insecure, [bool]$proxy) {
        $this.uri = $uri
        $this.upn = $upn
        $this.bearer_token = $bearer_token
        $this.insecure = $insecure
        $this.proxy = $proxy
        <#
            .DESCRIPTION
            SecurityAndComplianceClient connect to Security & Compliance Center using powershell session (OAuth2.0) and allow interact with it.

            .PARAMETER uri
            Security & Compliance Center uri.
            
            .PARAMETER upn
            User Principal Name (UPN) is the name of a system user in an email address format..
            
            .PARAMETER bearer_token
            Valid bearer token value.

            .PARAMETER insecure 
            Wheter to trust any TLS/SSL Certificate) or not.
            
            .EXAMPLE proxy
            Wheter to user system proxy configuration or not.
            
            .EXAMPLE
            $cs_client = [SecurityAndComplianceClient]::new("outlook.com", "user@microsoft.com", "dfhsdkjhkjhvkdvbihsgiu")

            .NOTES
            1. Linux issues compatability - 
                a. Unable to redirect correctly to right uri - Therefor use https://eur01b.ps.compliance.protection.outlook.com/powershell-liveid?BasicAuthToOAuthConversion=true;PSVersion=7.0.3
                b. For windows it should be - https://ps.compliance.protection.outlook.com/powershell-liveid?BasicAuthToOAuthConversion=true;PSVersion=7.0.3

            .LINK
            https://docs.microsoft.com/en-us/powershell/module/exchange/?view=exchange-ps#policy-and-compliance-content-search
        #>
    }

    CreateSession() {
        $this.session = CreateNewSession $this.uri $this.upn $this.bearer_token
        <#
            .DESCRIPTION
            This method is for internal use. It creates session to Security & Compliance Center.

            .EXAMPLE
            $client.CreateSession()
            
            .LINK
            https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/new-pssession?view=powershell-7
            https://docs.microsoft.com/en-us/powershell/partnercenter/multi-factor-auth?view=partnercenterps-3.0#exchange-online-powershell
        #>
    }

    CloseSession() {
        if ($this.session) {
            Remove-PSSession $this.session
        }
        <#
            .DESCRIPTION
            This method is for internal use. It creates session to Security & Compliance Center.

            .EXAMPLE
            $client.CloseSession()
            
            .LINK
            https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/remove-pssession?view=powershell-7
            https://docs.microsoft.com/en-us/powershell/partnercenter/multi-factor-auth?view=partnercenterps-3.0#exchange-online-powershell
        #>
    }

    [psobject]NewSearch([string]$search_name,  [string]$case, [string]$kql, [string]$description, [bool]$allow_not_found_exchange_locations, [string[]]$exchange_location,
                        [string[]]$exchange_location_exclusion, [string[]]$public_folder_location, [string[]]$share_point_location, [string[]]$share_point_location_exclusion) {
		try{
            # Establish session to remote
            $this.CreateSession()
            # Import and Execute command
            Import-PSSession -Session $this.session -CommandName New-ComplianceSearch
            $parameters = @{
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
            $response = New-ComplianceSearch -Name $search_name @parameters
            
            return $response
        }
        finally {
            # Close session to remote
            $this.CloseSession()
        }
        <#
            .DESCRIPTION
            Create compliance searches in the Security & Compliance Center.

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

    [psobject]SetSearch([string]$search_name,  [string]$case, [string]$kql, [string]$description, [bool]$allow_not_found_exchange_locations, [string[]]$exchange_location,
                        [string[]]$exchange_location_exclusion, [string[]]$public_folder_location, [string[]]$share_point_location, [string[]]$share_point_location_exclusion) {
		try{
            # Establish session to remote
            $this.CreateSession()
            # Import and Execute command
            Import-PSSession -Session $this.session -CommandName New-ComplianceSearch
            $parameters = @{
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
            $response = New-ComplianceSearch -Name $search_name @parameters
            
            return $response
        }
        finally {
            # Close session to remote
            $this.CloseSession()
        }
        <#
            .DESCRIPTION
            Create compliance searches in the Security & Compliance Center.

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
	
	RemoveSearch([string]$search_name) {
        try{
            # Establish session to remote
            $this.CreateSession()
            # Import and Execute command
            Import-PSSession -Session $this.session -CommandName Remove-ComplianceSearch
            Remove-ComplianceSearch -Identity $search_name -Confirm:$false
        }
        finally {
            # Close session to remote
            $this.CloseSession()
        }
	}

	[array]ListSearch() {
        try {
            # Establish session to remote
            $this.CreateSession()
            # Import and Execute command
            Import-PSSession -Session $this.session -CommandName Get-ComplianceSearch
            $response = Get-ComplianceSearch 
            
            return $response
        }
        finally {
            # Close session to remote
            $this.CloseSession()
        }
	}

	[psobject]GetSearch([string]$search_name) {
        try{
            # Establish session to remote
            $this.CreateSession()
            # Import and Execute command
            Import-PSSession -Session $this.session -CommandName Get-ComplianceSearch
            $response = Get-ComplianceSearch -Identity $search_name
            return $response
        }
        finally {
            # Close session to remote
            $this.CloseSession()
        }
	}

    StartSearch([string]$search_name) {
        try{
            # Establish session to remote
            $this.CreateSession()
            # Import and Execute command
            Import-PSSession -Session $this.session -CommandName Start-ComplianceSearch
            Start-ComplianceSearch -Identity $search_name -Confirm:$false -Force:$true
        }
        finally {
            # Close session to remote
            $this.CloseSession()
        }
	}

    StopSearch([string]$search_name) {
        try{
            # Establish session to remote
            $this.CreateSession()
            # Import and Execute command
            Import-PSSession -Session $this.session -CommandName Stop-ComplianceSearch 
            Stop-ComplianceSearch -Identity $search_name -Confirm:$false
        }
        finally {
            # Close session to remote
            $this.CloseSession()
        }
	}

    [array]NewSearchAction([string]$search_name, [string]$action, [string]$purge_type) {
        try{
            # Establish session to remote
            $this.CreateSession()
            # Import and Execute command
            Import-PSSession -Session $this.session -CommandName New-ComplianceSearchAction
            $parameters = @{
                "SearchName" = $search_name
            }
            if ($action -eq "Preview") {
                $parameters.Preview = $true
            } elseif ($action -eq "Purge") {
                $parameters.Purge = $true
                $parameters.PurgeType = $purge_type
            } else {
                throw "New action must include valid action - Preview/Purge"
            }
            $response = New-ComplianceSearchAction @parameters
            
            return $response
        }
        finally {
            # Close session to remote
            $this.CloseSession()
        }
	}

    RemoveSearchAction([string]$search_action_id) {
        try{
            # Establish session to remote
            $this.CreateSession()
            # Import and Execute command
            Import-PSSession -Session $this.session -CommandName Remove-ComplianceSearchAction
            Remove-ComplianceSearchAction -Identity $search_action_id -Confirm:$false
        }
        finally {
            # Close session to remote
            $this.CloseSession()
        }
	}

    [array]ListSearchActions() {
        try{
            # Establish session to remote
            $this.CreateSession()
            # Import and Execute command
            Import-PSSession -Session $this.session -CommandName Get-ComplianceSearchAction
            $response = Get-ComplianceSearchAction
            
            return $response
        }
        finally {
            # Close session to remote
            $this.CloseSession()
        }
	}

    [array]GetSearchAction([string]$search_action_id) {
        try{
            # Establish session to remote
            $this.CreateSession()
            # Import and Execute command
            Import-PSSession -Session $this.session -CommandName Get-ComplianceSearchAction
            $response = Get-ComplianceSearchAction -Identity $search_action_id
            
            return $response
        }
        finally {
            # Close session to remote
            $this.CloseSession()
        }
	}
}


#### COMMAND FUNCTIONS ####

function StartAuthCommand ([OAuth2DeviceCodeClient]$client) {
    $raw_response = $client.AuthorizationRequest()
	$human_readable = "## Security And Compliance - Authorize instructions
1. To sign in, use a web browser to open the page [https://microsoft.com/devicelogin](https://microsoft.com/devicelogin) and enter the code **$($raw_response.user_code)** to authenticate.
2. Run the following command **!$global:COMMAND_PREFIX-complete-auth** in the War Room."
    $entry_context = @{}
    
    return $human_readable, $entry_context, $raw_response
}

function CompleteAuthCommand ([OAuth2DeviceCodeClient]$client) {
    $raw_response = $client.AccessTokenRequest()
    $human_readable = "Your account **successfully** authorized!"
    $entry_context = @{}
    
    return $human_readable, $entry_context, $raw_response
}

function TestAuthCommand ([OAuth2DeviceCodeClient]$oclient, [SecurityAndComplianceClient]$cs_client) {
    $raw_response = $oclient.RefreshTokenRequest()
    $human_readable = "**Test ok!**"
    $entry_context = @{}
    try {
        $cs_client.CreateSession()
    }
    finally {
        $cs_client.CloseSession()
    }
    
    return $human_readable, $entry_context, $raw_response
}

function IntegrationContextCommand () {
    $raw_response = @{}
    $human_readable = TableToMarkdown $Demisto.getIntegrationContext()
    $entry_context = @{}
    
    return $human_readable, $entry_context, $raw_response
}

function NewSearchCommand([SecurityAndComplianceClient]$client, [hashtable]$kwargs) {
    # Command arguemnts parsing
    $allow_not_found_exchange_locations = ConvertTo-Boolean $kwargs.allow_not_found_exchange_locations
    $exchange_location = ArgToList $kwargs.exchange_location
    $exchange_location_exclusion = ArgToList $kwargs.exchange_location_exclusion
    $public_folder_location = ArgToList $kwargs.public_folder_location
    $share_point_location = ArgToList $kwargs.exchange_location
    $share_point_location_exclusion = ArgToList $kwargs.exchange_location_exclusion
    # Raw response
    $raw_response = $client.NewSearch($kwargs.search_name, $kwargs.case, $kwargs.kql, $kwargs.description, $allow_not_found_exchange_locations,
                                      $exchange_location, $exchange_location_exclusion, $public_folder_location, $share_point_location, $share_point_location_exclusion)
    # Human readable
    $md_columns = $raw_response | Select-Object -Property Name, Description, CreatedBy, LastModifiedTime, ContentMatchQuery
	$human_readable = TableToMarkdown $md_columns  "Security And Compliance - New search '$($kwargs.search_name)' created"
    # Entry context
    $entry_context = @{
        $global:COMPLAIANCE_SEARCH_ENTRY_CONTEXT = ParseSearchToEntryContext $raw_response
    }

	return $human_readable, $entry_context, $raw_response
}

function SetSearchCommand([SecurityAndComplianceClient]$client, [hashtable]$kwargs) {
    # Command arguemnts parsing
    $allow_not_found_exchange_locations = ConvertTo-Boolean $kwargs.allow_not_found_exchange_locations
    $exchange_location = ArgToList $kwargs.exchange_location
    $exchange_location_exclusion = ArgToList $kwargs.exchange_location_exclusion
    $public_folder_location = ArgToList $kwargs.public_folder_location
    $share_point_location = ArgToList $kwargs.exchange_location
    $share_point_location_exclusion = ArgToList $kwargs.exchange_location_exclusion
    # Raw response
    $raw_response = $client.NewSearch($kwargs.search_name, $kwargs.case, $kwargs.kql, $kwargs.description, $allow_not_found_exchange_locations,
                                      $exchange_location, $exchange_location_exclusion, $public_folder_location, $share_point_location, $share_point_location_exclusion)
    # Human readable
    $md_columns = $raw_response | Select-Object -Property Name, Description, CreatedBy, LastModifiedTime, ContentMatchQuery
	$human_readable = TableToMarkdown $md_columns  "Security And Compliance - New search '$($kwargs.search_name)' created"
    # Entry context
    $entry_context = @{
        $global:COMPLAIANCE_SEARCH_ENTRY_CONTEXT = ParseSearchToEntryContext $raw_response
    }

	return $human_readable, $entry_context, $raw_response
}

function RemoveSearchCommand([SecurityAndComplianceClient]$client, [hashtable]$kwargs) {
	# Remove operation doesn't return any output
	$client.RemoveSearch($kwargs.search_name)
    # Raw response
    $raw_response = @{}
    # Human readable
    $human_readable = "Security And Compliance - Search **$($kwargs.search_name)** removed!"
    # Entry context
    $entry_context = @{}

	return $human_readable, $entry_context, $raw_response
}

function ListSearchCommand([SecurityAndComplianceClient]$client, [hashtable]$kwargs) {
    # Raw response
    $raw_response = $client.ListSearch()
    # Human readable
    $md_columns = $raw_response | Select-Object -Property Name, Description, CreatedBy, LastModifiedTime, RunBy
    $human_readable = TableToMarkdown $md_columns "Security And Compliance - Search configurations"
    # Entry context
    $search_entry_context = New-Object System.Collections.Generic.List[System.Object]
    foreach ($search in $raw_response) { 
        $ec = ParseSearchToEntryContext $search
        $search_entry_context.Add($ec)
    }
	$entry_context = @{
        $global:COMPLAIANCE_SEARCH_ENTRY_CONTEXT = $search_entry_context 
    }

	return $human_readable, $entry_context, $raw_response
}

function GetSearchCommand([SecurityAndComplianceClient]$client, [hashtable]$kwargs) {
    # Command arguemnts parsing
    $statistics = ConvertTo-Boolean $kwargs.statistics
    # Raw response
    $raw_response = $client.GetSearch($kwargs.search_name)
    # Human readable - Basic info
    $md_columns = $raw_response | Select-Object -Property Name, Description, CreatedBy, LastModifiedTime, RunBy
	$human_readable = TableToMarkdown $md_columns  "Security And Compliance - '$($kwargs.search_name)' search"
    # Human readable - Statistics
    if ($raw_response.SuccessResults -and $statistics) {
        $human_readable += TableToMarkdown $(ParseSuccessResults $raw_response.SuccessResults) "Search statistics"
    }
    # Entry context
    $entry_context = @{
        $global:COMPLAIANCE_SEARCH_ENTRY_CONTEXT = ParseSearchToEntryContext $raw_response
    }

	return $human_readable, $entry_context, $raw_response
}

function StartSearchCommand([SecurityAndComplianceClient]$client, [hashtable]$kwargs) {
    # Start operation doesn't return any output
    $client.StartSearch($kwargs.search_name)
    # Raw response
    $raw_response = @{}
    # Human readable
    $human_readable = "Security And Compliance - search **$($kwargs.search_name)** started !"
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
    $human_readable = "Security And Compliance - search **$($kwargs.search_name)** stopped !"
    # Entry context
    $entry_context = @{}

	return $human_readable, $entry_context, $raw_response
}


function NewSearchActionCommand([SecurityAndComplianceClient]$client, [hashtable]$kwargs) {
    # Raw response
    $raw_response = $client.NewSearchAction($kwargs.search_name, $kwargs.action, $kwargs.purge_type)
    # Human readable
    $md_columns = $raw_response | Select-Object -Property Name, SearchName, Action, LastModifiedTime, RunBy, Status
    $human_readable = TableToMarkdown $md_columns "Security And Compliance - search action '$($raw_response.Name)' created"
    # Entry context
    $entry_context = @{ 
        $global:COMPLAIANCE_SEARCH_ACTIONS_ENTRY_CONTEXT = ParseSearchActionsToEntryContext $raw_response
    }

	return $human_readable, $entry_context, $raw_response
}



function RemoveSearchActionCommand([SecurityAndComplianceClient]$client, [hashtable]$kwargs) {
    # Remove operation doesn't return any output
    $client.RemoveSearchAction($kwargs.search_action_id)
    # Raw response
    $raw_response = @{}
    # Human readable
    $human_readable = "Security And Compliance - search action **$($kwargs.search_action_id)** removed!"
    # Entry context
    $entry_context = @{}

	return $human_readable, $entry_context, $raw_response
}

function GetSearchActionCommand([SecurityAndComplianceClient]$client, [hashtable]$kwargs) {
    # Raw response
    $raw_response = $client.GetSearchAction($kwargs.search_action_id)
    # Human readable
    $md_columns = $raw_response | Select-Object -Property Name, SearchName, Action, LastModifiedTime, RunBy, JobEndTime, Status
	$human_readable = TableToMarkdown $md_columns "Security And Compliance - search action '$($kwargs.search_action_id)'"
    # Entry context
    $entry_context = @{ 
        $global:COMPLAIANCE_SEARCH_ACTIONS_ENTRY_CONTEXT = ParseSearchActionsToEntryContext $raw_response
    }

	return $human_readable, $entry_context, $raw_response
}
function ListSearchActionsCommand([SecurityAndComplianceClient]$client, [hashtable]$kwargs) {
    # Raw response
    $raw_response = $client.ListSearchActions()
    # Human readable
    $md_columns = $raw_response | Select-Object -Property Name, SearchName, Action, LastModifiedTime, RunBy, JobEndTime, Status
    $human_readable = TableToMarkdown $md_columns "Security And Compliance - search actions"
    # Entry context
    $search_actions_ec = New-Object System.Collections.Generic.List[System.Object]
    foreach ($search in $raw_response) { 
        $ec = ParseSearchActionsToEntryContext $search
        $search_actions_ec.Add($ec)
    }
	$entry_context = @{ 
        $global:COMPLAIANCE_SEARCH_ACTIONS_ENTRY_CONTEXT = $search_actions_ec
    }

	return $human_readable, $entry_context, $raw_response
}


#### INTEGRATION COMMANDS MANAGER ####

function Main {
	[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidUsingPositionalParameters", "")]
	[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidGlobalVars", "")]
	[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidUsingConvertToSecureStringWithPlainText", "")]
	[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseDeclaredVarsMoreThanAssignments", "")]
	$command = $Demisto.GetCommand()
    $command_arguments = $Demisto.Args()
    $integration_params = $Demisto.Params()
    $proxy = ConvertTo-Boolean $integration_params.proxy
    $insecure = ConvertTo-Boolean $integration_params.insecure
	
    $Demisto.Debug("Command being called is $Command")

	try {
        # Creating Compliance and search client
        $oauth2_client = [OAuth2DeviceCodeClient]::CreateClientFromIntegrationContext($insecure, $proxy) 
        # Refreshing tokens if expired
        $oauth2_client.RefreshTokenIfExpired()
        # Creating Compliance and search client
        $cs_client = [SecurityAndComplianceClient]::new($integration_params.compliance_and_search_uri, $integration_params.upn, $oauth2_client.access_token, $insecure, $proxy)
        switch ($command) {
            "test-module" {
				throw "This button isn't functional - Please test integration using !ews-test-auth command"
			}
            "$global:COMMAND_PREFIX-start-auth" {
                ($human_readable, $entry_context, $raw_response) = StartAuthCommand $oauth2_client
            }
            "$global:COMMAND_PREFIX-complete-auth" {
                ($human_readable, $entry_context, $raw_response) = CompleteAuthCommand $oauth2_client
            }
            "$global:COMMAND_PREFIX-test" {
                ($human_readable, $entry_context, $raw_response) = TestAuthCommand $oauth2_client $cs_client
            }
            "$global:COMMAND_PREFIX-integration-context" {
                ($human_readable, $entry_context, $raw_response) = IntegrationContextCommand 
            }
			"$global:COMMAND_PREFIX-new-search" {
				($human_readable, $entry_context, $raw_response) = NewSearchCommand $cs_client $command_arguments   
			}
			"$global:COMMAND_PREFIX-remove-search" {
				($human_readable, $entry_context, $raw_response) = RemoveSearchCommand $cs_client $command_arguments
			}
			"$global:COMMAND_PREFIX-list-search" {
				($human_readable, $entry_context, $raw_response) = ListSearchCommand $cs_client $command_arguments 
			}
			"$global:COMMAND_PREFIX-get-search" {
				($human_readable, $entry_context, $raw_response) = GetSearchCommand $cs_client $command_arguments
			}
            "$global:COMMAND_PREFIX-start-search" {
				($human_readable, $entry_context, $raw_response) = StartSearchCommand $cs_client $command_arguments
			}
            "$global:COMMAND_PREFIX-stop-search" {
				($human_readable, $entry_context, $raw_response) = StopSearchCommand $cs_client $command_arguments
			}
			"$global:COMMAND_PREFIX-new-search-action" {
				($human_readable, $entry_context, $raw_response) = NewSearchActionCommand $cs_client $command_arguments
			}
            "$global:COMMAND_PREFIX-remove-search-action" {
				($human_readable, $entry_context, $raw_response) = RemoveSearchActionCommand $cs_client $command_arguments
			}
            "$global:COMMAND_PREFIX-list-search-actions" {
				($human_readable, $entry_context, $raw_response) = ListSearchActionsCommand $cs_client $command_arguments
			}
            "$global:COMMAND_PREFIX-get-search-action" {
				($human_readable, $entry_context, $raw_response) = GetSearchActionCommand $cs_client $command_arguments
			}
        }

        UpdateIntegrationContext $oauth2_client

        ReturnOutputs $human_readable $entry_context $raw_response | Out-Null
    }
    catch {
        $Demisto.debug("Integration: $global:INTEGRATION_NAME
Command: $command
Arguments: $($command_arguments | ConvertTo-Json)
Error: $($_.Exception.Message)")
        ReturnError "Error:
Integration: $global:INTEGRATION_NAME
Command: $command
Arguments: $($command_arguments | ConvertTo-Json)
Error: $($_.Exception)" | Out-Null
    }
}

# Execute Main when not in Tests
if ($MyInvocation.ScriptName -notlike "*.tests.ps1" -AND -NOT$Test) {
	Main
}