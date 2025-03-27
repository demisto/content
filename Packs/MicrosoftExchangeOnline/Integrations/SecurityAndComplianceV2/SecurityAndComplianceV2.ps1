. $PSScriptRoot\CommonServerPowerShell.ps1


$script:INTEGRATION_NAME = "Security And Compliance"
$script:COMMAND_PREFIX = "o365-sc"
$script:INTEGRATION_ENTRY_CONTEX = "O365.SecurityAndCompliance.ContentSearch"
$script:INTEGRATION_ENTRY_COMPLIANCE_CASE = "O365.SecurityAndCompliance.ComplianceCase"
$script:INTEGRATION_ENTRY_CASE_HOLD_POLICY = "O365.SecurityAndCompliance.CaseHoldPolicy"
$script:INTEGRATION_ENTRY_CASE_HOLD_RULE = "O365.SecurityAndCompliance.CaseHoldRule"
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

    SetIntegrationContext $integration_context
    <#
        .DESCRIPTION
        Update integration context from OAuth2DeviceCodeClient client

        .EXAMPLE
        UpdateIntegrationContext $client

        .PARAMETER search_name
        OAuth2DeviceCodeClient client.
    #>
}

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
        "SearchStatus" = "Success"
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
        "SearchStatus" = "Success"
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

#### OAuth Client - Access Token Management ####
class OAuth2DeviceCodeClient {
    [string]$application_id
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
    [string]$app_secret
    [string]$tenant_id

    OAuth2DeviceCodeClient([string]$device_code, [string]$device_code_expires_in, [string]$device_code_creation_time, [string]$access_token,
                            [string]$refresh_token,[string]$access_token_expires_in, [string]$access_token_creation_time,
                           [bool]$insecure, [bool]$proxy, [string]$application_id, [string]$app_secret, [string]$tenant_id) {
        $this.device_code = $device_code
        $this.device_code_expires_in = $device_code_expires_in
        $this.device_code_creation_time = $device_code_creation_time
        $this.access_token = $access_token
        $this.refresh_token = $refresh_token
        $this.access_token_expires_in = $access_token_expires_in
        $this.access_token_creation_time = $access_token_creation_time
        $this.insecure = $insecure
        $this.proxy = $proxy
        $this.application_id = $application_id
        $this.app_secret = $app_secret
        $this.tenant_id = $tenant_id
        <#
            .DESCRIPTION
            OAuth2DeviceCodeClient manage state of OAuth2.0 device-code flow described in https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-device-code.

            .DESCRIPTION
            Its not recomended to create an object using the constructor, Use static method CreateClientFromIntegrationContext() instead.

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

    static [OAuth2DeviceCodeClient]CreateClientFromIntegrationContext([bool]$insecure, [bool]$proxy, [string]$application_id, [string]$app_secret, [string]$tenant_id) {
        $ic = GetIntegrationContext
        $client = [OAuth2DeviceCodeClient]::new($ic.DeviceCode, $ic.DeviceCodeExpiresIn, $ic.DeviceCodeCreationTime, $ic.AccessToken, $ic.RefreshToken,
                                                $ic.AccessTokenExpiresIn, $ic.AccessTokenCreationTime, $insecure, $proxy, $application_id, $app_secret, $tenant_id)

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
        # Get device-code and user-code
        $params = @{
            "URI" = "https://login.microsoftonline.com/$($this.tenant_id)/oauth2/v2.0/devicecode"
            "Method" = "Post"
            "Headers" = @{
                "Content-Type" = "application/x-www-form-urlencoded"
            }
            "Body" = "client_id=$($this.application_id)&scope=$($this.application_scope)"
            "NoProxy" = !$this.proxy
            "SkipCertificateCheck" = $this.insecure
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
                "URI" = "https://login.microsoftonline.com/$($this.tenant_id)/oauth2/v2.0/token"
                "Method" = "Post"
                "Headers" = (New-Object "System.Collections.Generic.Dictionary[[String],[String]]").Add("Content-Type", "application/x-www-form-urlencoded")
                "Body" = "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code&code=$($this.device_code)&client_id=$($this.application_id)"
                "NoProxy" = !$this.proxy
                "SkipCertificateCheck" = $this.insecure
            }
            $response = Invoke-WebRequest @params
            $response_body = ConvertFrom-Json $response.Content
        }
        catch {
            $response_body = ConvertFrom-Json $_.ErrorDetails.Message
            if ($response_body.error -eq "authorization_pending" -or $response_body.error -eq "invalid_grant") {
                $error_details = "Please run command !$script:COMMAND_PREFIX-auth-start , before running this command."
            }
            elseif ($response_body.error -eq "expired_token") {
                $error_details = "At least $($this.access_token_expires_in) seconds have passed from executing !$script:COMMAND_PREFIX-auth-start, Please run the ***$script:COMMAND_PREFIX-auth-start*** command again."
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
                "URI" = "https://login.microsoftonline.com/$($this.tenant_id)/oauth2/v2.0/token"
                "Method" = "Post"
                "Headers" = (New-Object "System.Collections.Generic.Dictionary[[String],[String]]").Add("Content-Type", "application/x-www-form-urlencoded")
                "Body" = "grant_type=refresh_token&client_id=$($this.application_id)&refresh_token=$($this.refresh_token)&scope=$($this.application_scope)"
                "NoProxy" = !$this.proxy
                "SkipCertificateCheck" = $this.insecure
            }
            $response = Invoke-WebRequest @params
            $response_body = ConvertFrom-Json $response.Content
        }
        catch {
            $response_body = ConvertFrom-Json $_.ErrorDetails.Message
            $error_details = "Unable to refresh access token for your account"

            # AADSTS50173 points to password change https://login.microsoftonline.com/error?code=50173.
            # In that case, the integration context should be overwritten and the user should execute the auth process from the begining.
            if ($response_body.error_description -like "*AADSTS50173*") {
                $this.ClearContext()
                $error_details = "The account password has been changed or reset. Please run !$script:COMMAND_PREFIX-auth-start to re-authenticate"
            }
            elseif ($response_body.error -eq "invalid_grant") {
                $error_details = "Please login to grant account permissions (After 90 days grant is expired) !$script:COMMAND_PREFIX-auth-start"
            }
            throw "$error_details. Full error message: $response_body"
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

    ClearContext(){
        $this.access_token = $null
        $this.refresh_token = $null
        $this.access_token_expires_in = $null
        $this.access_token_creation_time = $null
        UpdateIntegrationContext $this
        <#
            .DESCRIPTION
            Clear the token fields from the integration context on password change case.

            .EXAMPLE
            $client.ClearContext()
        #>

    }
}

#### Security And Compliance client ####
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingConvertToSecureStringWithPlainText', '', Scope='Class')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', '', Scope='Class')]
class SecurityAndComplianceClient {
    [string]$access_token
    [string]$upn
    [string]$tenant_id
    [string]$connection_uri
    [string]$azure_ad_authorization_endpoint_uri_base
    [string]$azure_ad_authorization_endpoint_uri

    SecurityAndComplianceClient([string]$access_token, [string]$upn, [string]$tenant_id, [string]$connection_uri, [string]$azure_ad_authorization_endpoint_uri_base) {

        $this.access_token = $access_token

        $this.upn = $upn

        if ($tenant_id) {
            $this.tenant_id = $tenant_id
        } else {
            $this.tenant_id = $null
        }

        if ($connection_uri) {
            $this.connection_uri = $connection_uri
        } else {
            $this.connection_uri = $null
        }

        if ($azure_ad_authorization_endpoint_uri_base) {
            if ($tenant_id){
                $this.azure_ad_authorization_endpoint_uri = "$azure_ad_authorization_endpoint_uri_base/$tenant_id"
            } else {
                $this.azure_ad_authorization_endpoint_uri = "$azure_ad_authorization_endpoint_uri_base/common"
            }
        } else {
            $this.azure_ad_authorization_endpoint_uri = $null
        }
    }

    CreateDelegatedSession([string]$CommandName){
        $cmd_params = @{
            "UserPrincipalName" = $this.upn
            "Organization" = $this.organization
            "AccessToken" = $this.access_token
            "ConnectionUri" = $this.connection_uri
            "AzureADAuthorizationEndpointUri" = $this.azure_ad_authorization_endpoint_uri
        }
        Connect-ExchangeOnline @cmd_params -CommandName $CommandName -WarningAction:SilentlyContinue -ShowBanner:$false | Out-Null
    }

    DisconnectSession(){
        Disconnect-ExchangeOnline -Confirm:$false -WarningAction:SilentlyContinue 6>$null | Out-Null
    }

    [psobject]NewSearch([string]$search_name,  [string]$case, [string]$kql, [string]$description, [bool]$allow_not_found_exchange_locations, [string[]]$exchange_location,
                        [string[]]$public_folder_location, [string[]]$share_point_location, [string[]]$share_point_location_exclusion) {

        # Establish session to remote
        $this.CreateDelegatedSession("New-ComplianceSearch")
        # Import and Execute command
        $cmd_params = @{
            "Name" = $search_name
            "Case" = $case
            "ContentMatchQuery" = $kql
            "Description" = $description
            "AllowNotFoundExchangeLocationsEnabled" = $allow_not_found_exchange_locations
            "ExchangeLocation" = $exchange_location
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
        $this.CreateDelegatedSession("Set-ComplianceSearch")
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
        $this.CreateDelegatedSession("Remove-ComplianceSearch")
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
        $this.CreateDelegatedSession("Get-ComplianceSearch")
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
        $this.CreateDelegatedSession("Get-ComplianceSearch")
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
        $this.CreateDelegatedSession("Start-ComplianceSearch")
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
        $this.CreateDelegatedSession("Stop-ComplianceSearch")
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

    [psobject]NewSearchAction([string]$search_name, [string]$action, [string]$purge_type,
                              [string]$share_point_archive_format, [string]$format,
                              [bool]$include_sharepoint_document_versions, [string]$notify_email,
                              [string]$notify_email_cc, [string]$scenario, [string]$scope) {
        # Establish session to remote
        $this.CreateDelegatedSession("New-ComplianceSearchAction")
        # Execute command
        $cmd_params = @{
            "SearchName" = $search_name
        }
        if ($action -eq "Preview") {
            $cmd_params.Preview = $true
            $cmd_params.Confirm = $false
        } elseif ($action -eq "Purge") {
            $cmd_params.Purge = $true
            $cmd_params.PurgeType = $purge_type
            $cmd_params.Confirm = $false
            $cmd_params.Force = $true
        } elseif ($action -eq "Export") {
            $cmd_params.Export = $true
            $cmd_params.Confirm = $false
            if ($share_point_archive_format) {
                $cmd_params.SharePointArchiveFormat = $share_point_archive_format
            }
            if ($format) {
                $cmd_params.Format = $format
            }
            if ($include_sharepoint_document_versions -eq "true") {
                $cmd_params.IncludeSharePointDocumentVersions = $true
            }
            if ($notify_email) {
                $cmd_params.NotifyEmail = $notify_email
            }
            if ($notify_email_cc) {
                $cmd_params.NotifyEmailCC = $notify_email_cc
            }
            if ($scenario) {
                $cmd_params.Scenario = $scenario
            }
            if ($scope) {
                $cmd_params.Scope = $scope
            }
        } else {
            throw "New action must include valid action - Preview/Purge/Export"
        }
        $response = New-ComplianceSearchAction @cmd_params

        # Close session to remote
        $this.DisconnectSession()

        return $response
        <#
            .DESCRIPTION
            Create compliance search action in the Security & Compliance Center.

            .PARAMETER search_name
            The name of the compliance search.

            .PARAMETER action
            Search action type - Preview (Showing results) / Purge (Delete found emails) / Export (Create Export file in UI)

            .PARAMETER purge_type
            Used if action type is purge, Search action purge type - SoftDelete (allow recover) / HardDelete (not recoverable).

            .EXAMPLE
            $client.NewSearchAction("search-name", "Preview")
            $client.NewSearchAction("search-name", "Purge", "HardDelete")
            $client.NewSearchAction("search-name", "Export")
         #>

            .OUTPUTS
            psobject - Raw response.

            .LINK
            https://docs.microsoft.com/en-us/powershell/module/exchange/new-compliancesearchaction?view=exchange-ps
        #>
    }

    RemoveSearchAction([string]$search_action_name) {
        # Establish session to remote
        $this.CreateDelegatedSession("Remove-ComplianceSearchAction")
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
        $this.CreateDelegatedSession("Get-ComplianceSearchAction")
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
        $this.CreateDelegatedSession("Get-ComplianceSearchAction")

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

    [psobject]ComplianceCaseCreate([string]$case_name, [string]$case_type, [string]$description, [string]$external_id) {
        # Establish session to remote
        $this.CreateDelegatedSession("New-ComplianceCase")

        $cmd_params = @{
            "Name" = $case_name
            "CaseType" = $case_type
        }
        if ($description) {
            $cmd_params.Description = $description
        }
        if ($external_id) {
            $cmd_params.ExternalId = $external_id
        }

        # Execute command
        $response = New-ComplianceCase @cmd_params
        # Close session to remote
        $this.DisconnectSession()
        return $response
           <#
            .DESCRIPTION
            Create eDiscovery cases in the Microsoft Purview compliance portal.

            .PARAMETER case_name
            The name of the case to create.
            .PARAMETER case_type
            Type of case from a closed list.
            .PARAMETER description
            Attach a description to case.
            .PARAMETER external_id
            Optional ID or external case number that you can associate with the new compliance case.

            .EXAMPLE
            $client.ComplianceCaseCreate("case_name", "case_type", "description", "external_id")

            .OUTPUTS
            psobject - Raw response.

            .LINK
            https://learn.microsoft.com/en-us/powershell/module/exchange/new-compliancecase?view=exchange-ps
        #>
    }

    [psobject]ComplianceCaseList([string]$identity, [string]$case_type, [int]$limit) {
        # Establish session to remote
        $this.CreateDelegatedSession("Get-ComplianceCase")

        $cmd_params = @{}
        if ($identity) {
            $cmd_params.Identity = $identity
        }
        if ($case_type) {
            $case_type_list = ArgToList($case_type)
            $response = @()
            $case_type_list | ForEach-Object{
                $cmd_params.CaseType = $_
                $response += Get-ComplianceCase @cmd_params
            }
        } else {
            $response = Get-ComplianceCase @cmd_params
        }
        $response = $response | Select-Object -First $limit
        if (-not $response){
            # Close session to remote
            $this.DisconnectSession()
            throw "The list action didn't return any results. The Compliance cases do not exist or have been deleted."
        }
        # Close session to remote
        $this.DisconnectSession()
        return $response
           <#
            .DESCRIPTION
            List different types of compliance cases in the Microsoft Purview compliance portal

            .PARAMETER identity
            List case with the identity.
            .PARAMETER case_type
            List cases of the sepecified case_type.
            .PARAMETER limit
            Limit the amount of results default is 50.

            .EXAMPLE
            $client.ComplianceCaseList()

            .OUTPUTS
            psobject - Raw response.

            .LINK
            https://learn.microsoft.com/en-us/powershell/module/exchange/get-compliancecase?view=exchange-ps
        #>
    }

    [psobject]ComplianceCaseDelete([string]$identity) {
        # Establish session to remote
        $this.CreateDelegatedSession("Remove-ComplianceCase")

        # Execute command
        $response = Remove-ComplianceCase -Identity $identity -Confirm:$false
        # Close session to remote
        $this.DisconnectSession()
        return $response
           <#
            .DESCRIPTION
            Removes compliance cases from the Microsoft Purview compliance portal or the Microsoft Purview compliance portal.

            .PARAMETER identity
            Identity of the case to remove.

            .EXAMPLE
            $client.ComplianceCaseDelete("case_identity")

            .OUTPUTS
            psobject - Raw response.

            .LINK
            https://learn.microsoft.com/en-us/powershell/module/exchange/remove-compliancecase?view=exchange-ps
        #>
    }

    [psobject]CaseHoldPolicyCreate([string]$policy_name, [string]$case, [string]$comment, [string]$exchange_location,
                                   [string]$public_folder_location, [string]$share_point_location, [bool]$enabled) {
        # Establish session to remote
        $this.CreateDelegatedSession("New-CaseHoldPolicy")
        $cmd_params = @{
            "Name" = $policy_name
            "Case" = $case
            "Enabled" = $enabled
        }
        if ($comment) {
            $cmd_params.Comment = $comment
        }
        if ($exchange_location) {
            $cmd_params.ExchangeLocation = $exchange_location
        }
        if ($public_folder_location) {
            $cmd_params.PublicFolderLocation = $public_folder_location
        }
        if ($share_point_location) {
            $cmd_params.SharePointLocation = $share_point_location
        }
        # Execute command
        $response = New-CaseHoldPolicy @cmd_params
        # Close session to remote
        $this.DisconnectSession()
        return $response
           <#
            .DESCRIPTION
            Creates new case hold policies in the Microsoft Purview compliance portal

            .PARAMETER policy_name
             Name of a new policy name to create.

            .PARAMETER case
            Case to connect the policy to.

            .PARAMETER comment
            Attach a comment to the policy.

            .PARAMETER exchange_location
            The ExchangeLocation parameter specifies the mailboxes to include in the policy.

            .PARAMETER public_folder_location
            Specifies that you want to include all public folders in the case hold policy.

            .PARAMETER share_point_location
            Specifies the SharePoint Online and OneDrive for Business sites to include.

            .PARAMETER enabled
            Whether the policy is enabled or disabled.

            .EXAMPLE
            New-CaseHoldPolicy -Name "Regulation 123 Compliance" -Case "123 Compliance Case" -ExchangeLocation "Kitty Petersen", "Scott Nakamura" -SharePointLocation "https://contoso.sharepoint.com/sites/teams/finance"

            .OUTPUTS
            psobject - Raw response.

            .LINK
            https://learn.microsoft.com/en-us/powershell/module/exchange/new-caseholdpolicy?view=exchange-ps
        #>
    }

    [psobject]CaseHoldPolicyGet([string]$identity, [string]$case, [bool]$distribution_detail, [bool]$include_bindings){
        # Establish session to remote
        $this.CreateDelegatedSession("Get-CaseHoldPolicy")
        $cmd_params = @{
            "DistributionDetail" = $distribution_detail
            "IncludeBindings" = $include_bindings
        }
        if ($identity) {
            $cmd_params.Identity = $identity
        }
        if ($case) {
            $cmd_params.Case = $case
        }
        # Execute command
        $response = Get-CaseHoldPolicy @cmd_params
        if (-not $response) {
            # Close session to remote
            $this.DisconnectSession()
            throw "The Get action didn't return any results. The Policy does not exist or has been deleted."
        }
        # Close session to remote
        $this.DisconnectSession()
        return $response
        <#
        .DESCRIPTION
        View existing case hold policies in the Microsoft Purview compliance portal

        .PARAMETER identity
        Specifies the case hold policy that you want to view.

        .PARAMETER case
        The Case parameter specifies the case hold policy that you want to view by using the eDiscovery case that's associated with the policy.

        .PARAMETER distribution_detail
        Returns detailed policy distribution information on the case hold policy.

        .PARAMETER include_bindindgs
        The ExchangeLocation parameter specifies the mailboxes to include in the policy.

        .EXAMPLE
        Get-CaseHoldPolicy -Case "Contoso Legal"
        Get-CaseHoldPolicy -Identity "Regulation 123 Compliance"

        .OUTPUTS
        psobject - Raw response.

        .LINK
        https://learn.microsoft.com/en-us/powershell/module/exchange/get-caseholdpolicy?view=exchange-ps
        #>
    }

    [psobject]CaseHoldPolicyDelete([string]$identity, [bool]$force_delete){
        # Establish session to remote
        $this.CreateDelegatedSession("Remove-CaseHoldPolicy")
        # Execute command
        if($force_delete) {
            $response = Remove-CaseHoldPolicy -Identity $identity -ForceDeletion -Confirm:$false
        } else {
            $response = Remove-CaseHoldPolicy -Identity $identity -Confirm:$false
        }
        # Close session to remote
        $this.DisconnectSession()
        return $response
        <#
        .DESCRIPTION
        Remove case hold policies from the Microsoft Purview compliance portal.

        .PARAMETER identity
        Specify the case hold policy to remove.

        .PARAMETER distribution_detail
        Returns detailed policy distribution information on the case hold policy.

        .EXAMPLE
        Remove-CaseHoldPolicy -Identity "Regulation 123 Compliance"

        .OUTPUTS
        psobject - Raw response.

        .LINK
        https://learn.microsoft.com/en-us/powershell/module/exchange/remove-caseholdpolicy?view=exchange-ps
        #>
    }


    CaseHoldPolicySet([string]$identity, [bool]$enabled, [string[]]$add_exchange_locations, [string[]] $add_sharepoint_locations, [string[]]$add_public_locations,
        [string[]]$remove_exchange_locations, [string[]]$remove_sharepoint_locations, [string[]]$remove_public_locations, [string]$comment){
        $this.CreateDelegatedSession("Set-CaseHoldPolicy")
      $cmd_params = @{}
  
      if ($identity) { $cmd_params.Identity = $identity }
      if ($enabled) { $cmd_params.Enabled = $enabled }
      if ($add_exchange_locations) { $cmd_params.AddExchangeLocation = $add_exchange_locations }
      if ($add_sharepoint_locations) { $cmd_params.AddSharePointLocation = $add_sharepoint_locations }
      if ($add_public_locations) { $cmd_params.AddPublicFolderLocation = $add_public_locations }
      if ($remove_exchange_locations) { $cmd_params.RemoveExchangeLocation = $remove_exchange_locations }
      if ($remove_sharepoint_locations) { $cmd_params.RemoveSharePointLocation = $remove_sharepoint_locations }
      if ($remove_public_locations) { $cmd_params.RemovePublicFolderLocation = $remove_public_locations }
      if ($comment) { $cmd_params.Comment = $comment }

        Set-CaseHoldPolicy @cmd_params
        $this.DisconnectSession()
    }


    [psobject]CaseHoldRuleCreate([string]$rule_name, [string]$policy_name, [string]$query, [string]$comment, [bool]$is_disabled){
        # Establish session to remote
        $this.CreateDelegatedSession("New-CaseHoldRule")
        $cmd_params = @{
            "Name" = $rule_name
            "Policy" = $policy_name
            "Disabled" = $is_disabled
        }
        if ($comment) {
            $cmd_params.Comment = $comment
        }
        if ($query) {
            $cmd_params.ContentMatchQuery = $query
        }
        # Execute command
        $response = New-CaseHoldRule @cmd_params
        # Close session to remote
        $this.DisconnectSession()
        return $response
        <#
        .DESCRIPTION
        Creates new case hold rules in the Microsoft Purview compliance portal.

        .PARAMETER rule_name
        The rule name to create.
        .PARAMETER policy_name
        Policy to attach the newly created rule to.
        .PARAMETER query
        Query using Keyword Query Language (KQL).
        .PARAMETER comment
        Attach a comment to the rule.
        .PARAMETER is_disabled
        Whether the rule is disabled or not. Default is false.
        .EXAMPLE
        New-CaseHoldRule -Name "2016 Budget Spreadsheets" -Policy "CaseHoldPolicy 16" -ContentMatchQuery "filename:2016 budget filetype:xlsx"

        .OUTPUTS
        psobject - Raw response.

        .LINK
        https://learn.microsoft.com/en-us/powershell/module/exchange/new-caseholdrule
        #>
    }

    [psobject]CaseHoldRuleList([string]$identity, [string]$policy, [int]$limit){
        # Establish session to remote
        $this.CreateDelegatedSession("Get-CaseHoldRule")
        if ($identity) {
            $response = Get-CaseHoldRule -Identity $identity
        } elseif ($policy){
            $response = Get-CaseHoldRule -Policy $policy
        } else {
            $response = Get-CaseHoldRule
        }
        if (-not $response){
            # Close session to remote
            $this.DisconnectSession()
            throw "The list action didn't return any results. The rules do not exist or have been deleted."
        }
        $response = $response | Select-Object -First $limit
        # Close session to remote
        $this.DisconnectSession()
        return $response
        <#
        .DESCRIPTION
        View case hold rules in the Microsoft Purview compliance portal.

        .PARAMETER identity
        List rules by policy identity.
        .PARAMETER policy
        List rules by policy.
        .PARAMETER limit
        Limit number of rules returned. Default is 50.

        .EXAMPLE
        Get-CaseHoldRule  -Identity "Test Rule 66"

        .OUTPUTS
        psobject - Raw response.

        .LINK
        https://learn.microsoft.com/en-us/powershell/module/exchange/get-caseholdrule
        #>
    }

    [psobject]CaseHoldRuleDelete([string]$identity, [bool]$force_delete){
        # Establish session to remote
        $this.CreateDelegatedSession("Remove-CaseHoldRule")
        # Execute command
        if ($force_delete) {
            $response = Remove-CaseHoldRule -Identity $identity -ForceDeletion -Confirm:$false
        } else {
            $response = Remove-CaseHoldRule -Identity $identity -Confirm:$false
        }
        # Close session to remote
        $this.DisconnectSession()
        return $response
        <#
        .DESCRIPTION
        Removes case hold rules from the Microsoft Purview compliance portal.

        .PARAMETER identity
        Identity of rule to delete.
        .PARAMETER force_delete
        Wethere to use force_delete or not.

        .EXAMPLE
        Remove-CaseHoldRule -Identity "Test Rule 3" -Confirm:$false

        .OUTPUTS
        psobject - Raw response.

        .LINK
        https://learn.microsoft.com/en-us/powershell/module/exchange/remove-caseholdrule
        #>
    }
}


#### COMMAND FUNCTIONS ####

function TestModuleCommand () {
    $raw_response = $null
    $human_readable = "The test module does not work for MFA auth. Use the command !$script:COMMAND_PREFIX-auth-start for Oauth2.0 authorization and !$script:COMMAND_PREFIX-auth-test to instead."
    $entry_context = $null

    return $human_readable, $entry_context, $raw_response
}

function StartAuthCommand ([OAuth2DeviceCodeClient]$client) {
    $raw_response = $client.AuthorizationRequest()
    $human_readable = "## $script:INTEGRATION_NAME - Authorize instructions
1. To sign in, use a web browser to open the page [https://microsoft.com/devicelogin](https://microsoft.com/devicelogin) and enter the code **$($raw_response.user_code)** to authenticate.
2. Run the **!$script:COMMAND_PREFIX-auth-complete** command in the War Room.
3. Run the **!$script:COMMAND_PREFIX-auth-test** command in the War Room to test the completion of the authorization process and the configured parameters."
    $entry_context = @{}

    return $human_readable, $entry_context, $raw_response
}

function CompleteAuthCommand ([OAuth2DeviceCodeClient]$client) {
    # Verify that user run start before complete
    if (!$client.device_code) {
        throw "Please run !o365-sc-auth-start and follow the command instructions"
    }
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
        $cs_client.CreateDelegatedSession("Start-ComplianceSearch")
    }
    finally {
        $cs_client.DisconnectSession()
    }

    return $human_readable, $entry_context, $raw_response
}

function NewSearchCommand([SecurityAndComplianceClient]$client, [hashtable]$kwargs) {
    # Command arguemnts parsing
    $allow_not_found_exchange_locations = ConvertTo-Boolean $kwargs.allow_not_found_exchange_locations
    $exchange_location = ArgToList $kwargs.exchange_location
    $public_folder_location = ArgToList $kwargs.public_folder_location
    $share_point_location = ArgToList $kwargs.share_point_location
    $share_point_location_exclusion = ArgToList $kwargs.share_point_location_exclusion
    if (!$kwargs.search_name -or $kwargs.search_name -eq "") {
        $kwargs.search_name = "XSOAR-$(New-Guid)"
    }
    # Raw response
    $raw_response = $client.NewSearch($kwargs.search_name, $kwargs.case, $kwargs.kql, $kwargs.description, $allow_not_found_exchange_locations,
                                      $exchange_location, $public_folder_location, $share_point_location, $share_point_location_exclusion)
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
    # Check if raw_response is null
    if ($null -eq $raw_response) {
        # Handle the scenerio if a search is not found:
        $human_readable = "Failed to retrieve search for the name: $($kwargs.search_name)"
        $entry_context = @{
            $script:SEARCH_ENTRY_CONTEXT = @{
                "SearchStatus" = "NotFound"
                "Name" = $kwargs.search_name
            }
        }
        $raw_response = "Failed to retrieve search for the name: $($kwargs.search_name)"
        return $human_readable, $entry_context, $raw_response
    }
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
    $raw_response = $client.NewSearchAction($kwargs.search_name, $kwargs.action, $kwargs.purge_type,
                                            $kwargs.share_point_archive_format, $kwargs.format,
                                            $kwargs.include_sharepoint_document_versions, $kwargs.notify_email,
                                            $kwargs.notify_email_cc, $kwargs.scenario, $kwargs.scope)

    if ($null -eq $raw_response) {
        # Handle the scenario if a search is not found:
        $human_readable = "Failed to retrieve search for the name: $($kwargs.search_name)"
        $entry_context = @{
            $script:SEARCH_ACTION_ENTRY_CONTEXT = @{
                "SearchStatus" = "NotFound"
                "Name" = $kwargs.search_name
            }
        }
        $raw_response = "Failed to retrieve search for the name: $($kwargs.search_name)"
        return $human_readable, $entry_context, $raw_response
    }

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

function ComplianceCaseCreateCommand([SecurityAndComplianceClient]$client, [hashtable]$kwargs) {
    # Raw response
    $raw_response = $client.ComplianceCaseCreate($kwargs.case_name, $kwargs.case_type, $kwargs.description, $kwargs.external_id)
    $md_columns = $raw_response | Select-Object -Property Identity, Name, Status, CreatedDateTime, CaseType
    $human_readable = TableToMarkdown $md_columns "Results of $command"
    $entry_context = @{"$script:INTEGRATION_ENTRY_COMPLIANCE_CASE" = $raw_response }
    return $human_readable, $entry_context, $raw_response
}

function ComplianceCaseListCommand([SecurityAndComplianceClient]$client, [hashtable]$kwargs) {
    # Raw response
    $raw_response = $client.ComplianceCaseList($kwargs.identity, $kwargs.case_type, $kwargs.limit)
    $md_columns = $raw_response | Select-Object -Property Identity, Name, Status, CreatedDateTime, CaseType
    $human_readable = TableToMarkdown $md_columns "Results of $command"
    $entry_context = @{"$script:INTEGRATION_ENTRY_COMPLIANCE_CASE(obj.Identity === val.Identity)" = $raw_response}
    return $human_readable, $entry_context, $raw_response
}

function ComplianceCaseDeleteCommand([SecurityAndComplianceClient]$client, [hashtable]$kwargs) {
    # Raw response
    $raw_response = $client.ComplianceCaseDelete($kwargs.identity)
    # Human readable
    $human_readable = "$script:INTEGRATION_ENTRY_COMPLIANCE_CASE - Case **$($kwargs.identity)** removed!"
    # Entry context
    $entry_context = @{}
    return $human_readable, $entry_context, $raw_response
}

function CaseHoldPolicyCreateCommand([SecurityAndComplianceClient]$client, [hashtable]$kwargs) {
    $enabled = ConvertTo-Boolean $kwargs.enabled
    $exchange_location = @()
    if ($kwargs.exchange_location) {
        $exchange_location = ArgToList($kwargs.exchange_location)
    }
    $public_folder_location = @()
    if ($kwargs.public_folder_location) {
        $public_folder_location = ArgToList($kwargs.public_folder_location)
    }
    $share_point_location = @()
    if ($kwargs.share_point_location) {
        $share_point_location = ArgToList($kwargs.share_point_location)
    }
    # Raw response
    $raw_response = $client.CaseHoldPolicyCreate($kwargs.policy_name, $kwargs.case, $kwargs.comment, $exchange_location,
    $public_folder_location, $share_point_location, $enabled)
    $entry_context = @{"$script:INTEGRATION_ENTRY_CASE_HOLD_POLICY(obj.Guid === val.Guid)" = $raw_response}
    $md_columns = $raw_response | Select-Object -Property Name, Workload, Enabled, Mode, @{Name = "Guid";Expression = {$_.Guid.ToString()}}
    $human_readable = TableToMarkdown $md_columns "Results of $command"
    return $human_readable, $entry_context, $raw_response
}

function CaseHoldPolicyGetCommand([SecurityAndComplianceClient]$client, [hashtable]$kwargs) {
    if ($kwargs.Identity -And $kwargs.case) {
        return "Invlid. Include Indentity or Case. Not both."
    }
    $distribution_detail = ConvertTo-Boolean $kwargs.distribution_detail
    $include_bindings = ConvertTo-Boolean $kwargs.include_bindings
    $raw_response = $client.CaseHoldPolicyGet($kwargs.identity, $kwargs.case, $distribution_detail, $include_bindings)
    $entry_context = @{"$script:INTEGRATION_ENTRY_CASE_HOLD_POLICY(obj.Guid === val.Guid)" = $raw_response}
    $md_columns = $raw_response | Select-Object -Property Name, Workload, Status, Mode, @{Name = "Guid";Expression = {$_.Guid.ToString()}}
    $human_readable = TableToMarkdown $md_columns "Results of $command"
    return $human_readable, $entry_context, $raw_response
}

function CaseHoldPolicyDeleteCommand([SecurityAndComplianceClient]$client, [hashtable]$kwargs) {
    $force_delete = ConvertTo-Boolean $kwargs.force_delete
    $raw_response = $client.CaseHoldPolicyDelete($kwargs.identity, $force_delete)
    $human_readable = "$script:INTEGRATION_ENTRY_COMPLIANCE_CASE - Case Hold policy **$($kwargs.identity)** was removed successfully"
    $entry_context = @{}
    return $human_readable, $entry_context, $raw_response
}

function CaseHoldRuleCreateCommand([SecurityAndComplianceClient]$client, [hashtable]$kwargs) {
    $rule_name = $kwargs.rule_name
    $policy_name = $kwargs.policy_name
    $query = $kwargs.query
    $comment = $kwargs.comment
    $is_disabled = ConvertTo-Boolean $kwargs.is_disabled
    $raw_response = $client.CaseHoldRuleCreate($rule_name, $policy_name, $query, $comment, $is_disabled)
    $md_columns = $raw_response | Select-Object -Property Name, Status, Mode, @{Name = "Guid";Expression = {$_.Guid.ToString()}}
    $human_readable = TableToMarkdown $md_columns "Results of $command"
    $entry_context = @{"$script:INTEGRATION_ENTRY_CASE_HOLD_RULE(obj.Guid === val.Guid)" = $raw_response}
    return $human_readable, $entry_context, $raw_response
}
function CaseHoldRuleListCommand([SecurityAndComplianceClient]$client, [hashtable]$kwargs) {
    $identity = $kwargs.identity
    $policy = $kwargs.policy
    $limit = $kwargs.limit
    $raw_response = $client.CaseHoldRuleList($identity, $policy, $limit)
    $md_columns = $raw_response | Select-Object -Property Name, Status, Mode, @{Name = "Guid";Expression = {$_.Guid.ToString()}}
    $human_readable = TableToMarkdown $md_columns "Results of $command"
    $entry_context = @{"$script:INTEGRATION_ENTRY_CASE_HOLD_RULE(obj.Guid === val.Guid)" = $raw_response}
    return $human_readable, $entry_context, $raw_response
}

function CaseHoldRuleDeleteCommand([SecurityAndComplianceClient]$client, [hashtable]$kwargs) {
    $identity = $kwargs.identity
    $force_delete = ConvertTo-Boolean $kwargs.force_delete
    $raw_response = $client.CaseHoldRuleDelete($identity, $force_delete)
    $human_readable = "$script:INTEGRATION_ENTRY_COMPLIANCE_CASE - Case Hold rule **$($kwargs.identity)** was removed successfully"
    $entry_context = @{}
    return $human_readable, $entry_context, $raw_response
}

function CaseHoldPolicySetCommand([SecurityAndComplianceClient]$client, [hashtable]$kwargs){
    $enabled = ConvertTo-Boolean $kwargs.enabled
    $add_exchange_locations = ArgToList $kwargs.add_exchange_locations
    $add_sharepoint_locations = ArgToList $kwargs.add_sharepoint_locations
    $add_public_locations = ArgToList $kwargs.add_public_locations
    $remove_exchange_locations = ArgToList $kwargs.remove_exchange_locations
    $remove_sharepoint_locations = ArgToList $kwargs.remove_sharepoint_locations
    $remove_public_locations = ArgToList $kwargs.remove_public_locations

    $client.CaseHoldPolicySet($kwargs.identity, $enabled, $add_exchange_locations,
                                $add_sharepoint_locations, $add_public_locations, $remove_exchange_locations,
                                $remove_sharepoint_locations, $remove_public_locations, $kwargs.comment)

    $raw_response = @{}
    # Human readable
    $human_readable = "$script:INTEGRATION_NAME - case hold policy **$($kwargs.identity)** modified!"
    # Entry context
    $entry_context = @{}

    return $human_readable, $entry_context, $raw_response
}

#### INTEGRATION COMMANDS MANAGER ####

function Main {
    $command = $Demisto.GetCommand()
    $command_arguments = $Demisto.Args()
    $integration_params = $Demisto.Params()
    $app_secret = if ($integration_params.credentials_app_secret.password) {$integration_params.credentials_app_secret.password} else {$integration_params.app_secret}
    $tenant_id = if ($integration_params.credentials_tenant_id.identifier) {$integration_params.credentials_tenant_id.identifier} else {$integration_params.tenant_id}
    $app_id = if ($integration_params.credentials_app_id.identifier) {$integration_params.credentials_app_id.identifier} else {$integration_params.app_id}
    if ($integration_params.insecure -eq $true) {
        # Bypass SSL verification if insecure is true
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
    }

    try {
        $Demisto.Debug("Command being called is $Command")

        # Creating Compliance and search client
        $oauth2_client = [OAuth2DeviceCodeClient]::CreateClientFromIntegrationContext($insecure, $false,
            $app_id, $app_secret, $tenant_id)

        # Executing oauth2 commands
        switch ($command) {
            "$script:COMMAND_PREFIX-auth-start" {
                ($human_readable, $entry_context, $raw_response) = StartAuthCommand $oauth2_client
            }
            "$script:COMMAND_PREFIX-auth-complete" {
                ($human_readable, $entry_context, $raw_response) = CompleteAuthCommand $oauth2_client
            }
        }

        # Refreshing tokens if expired
        if ($command -ne "$script:COMMAND_PREFIX-auth-start")
        {
            $oauth2_client.RefreshTokenIfExpired()
        }

        $cs_client = [SecurityAndComplianceClient]::new(
            $oauth2_client.access_token,
            $integration_params.delegated_auth.identifier,
            $tenant_id,
            $integration_params.connection_uri,
            $integration_params.azure_ad_authorized_endpoint_uri_base
        )

        # Executing command
        switch ($command) {
            "test-module" {
                ($human_readable, $entry_context, $raw_response) = TestModuleCommand
            }
            "$script:COMMAND_PREFIX-auth-test" {
                ($human_readable, $entry_context, $raw_response) = TestAuthCommand $oauth2_client $cs_client
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
            "$script:COMMAND_PREFIX-compliance-case-create" {
                ($human_readable, $entry_context, $raw_response, $file_entry) = ComplianceCaseCreateCommand $cs_client $command_arguments
            }
            "$script:COMMAND_PREFIX-compliance-case-list" {
                ($human_readable, $entry_context, $raw_response, $file_entry) = ComplianceCaseListCommand $cs_client $command_arguments
            }
            "$script:COMMAND_PREFIX-compliance-case-delete" {
                ($human_readable, $entry_context, $raw_response, $file_entry) = ComplianceCaseDeleteCommand $cs_client $command_arguments
            }
            "$script:COMMAND_PREFIX-case-hold-policy-create" {
                ($human_readable, $entry_context, $raw_response, $file_entry) = CaseHoldPolicyCreateCommand $cs_client $command_arguments
            }
            "$script:COMMAND_PREFIX-case-hold-policy-get" {
                ($human_readable, $entry_context, $raw_response, $file_entry) = CaseHoldPolicyGetCommand $cs_client $command_arguments
            }
            "$script:COMMAND_PREFIX-case-hold-policy-delete" {
                ($human_readable, $entry_context, $raw_response, $file_entry) = CaseHoldPolicyDeleteCommand $cs_client $command_arguments
            }
            "$script:COMMAND_PREFIX-case-hold-rule-create" {
                ($human_readable, $entry_context, $raw_response, $file_entry) = CaseHoldRuleCreateCommand $cs_client $command_arguments
            }
            "$script:COMMAND_PREFIX-case-hold-rule-list" {
                ($human_readable, $entry_context, $raw_response, $file_entry) = CaseHoldRuleListCommand $cs_client $command_arguments
            }
            "$script:COMMAND_PREFIX-case-hold-rule-delete" {
                ($human_readable, $entry_context, $raw_response, $file_entry) = CaseHoldRuleDeleteCommand $cs_client $command_arguments
            }
            "$script:COMMAND_PREFIX-case-hold-policy-set" {
                ($human_readable, $entry_context, $raw_response) = CaseHoldPolicySetCommand $cs_client $command_arguments
            }
        }

        # Updating integration context if access token changed
        UpdateIntegrationContext $oauth2_client

        # Return results to Demisto Server
        ReturnOutputs $human_readable $entry_context $raw_response | Out-Null
        if ($file_entry) {
            $Demisto.results($file_entry)
        }
    } catch {
        $Demisto.debug("Integration: $script:INTEGRATION_NAME
Command: $command
Arguments: $($command_arguments | ConvertTo-Json)
Error: $($_.Exception.Message)")
        if ($_.Exception.Message -like "*Unable to open a web page using xdg-open*" ) {
           Write-Host "It looks like the access token has expired. Please run the command !$script:COMMAND_PREFIX-auth-start, before running this command."
        } elseif ($command -ne "test-module") {
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
