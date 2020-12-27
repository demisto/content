. $PSScriptRoot\CommonServerPowerShell.ps1

$script:INTEGRATION_NAME = "Security And Compliance"
$script:COMMAND_PREFIX = "o365-sc"
$script:INTEGRATION_ENTRY_CONTEX = "O365.SecurityAndCompliance.ContentSearch"
$script:SEARCH_ENTRY_CONTEXT = "$script:INTEGRATION_ENTRY_CONTEX.Search(val.Name && val.Name == obj.Name)"
$script:SEARCH_ACTION_ENTRY_CONTEXT = "$script:INTEGRATION_ENTRY_CONTEX.SearchAction(val.Name && val.Name == obj.Name)"

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

function GetRedirectUri {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingConvertToSecureStringWithPlainText', '', Scope='Function')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', '', Scope='Function')]
    param([string]$url, [string]$upn, [string]$password, [string]$bearer_token, [bool]$insecure, [bool]$proxy)
    $end_uri = $url
    if ($password){
        $end_uri = "$url/powershell-liveid/"
    }
    elseif ($bearer_token) {
        $token_value = ConvertTo-SecureString "Bearer $bearer_token" -AsPlainText -Force
        $credential = New-Object System.Management.Automation.PSCredential($upn, $token_value)
        $params = @{
            "URI" = "$url/powershell-liveid?BasicAuthToOAuthConversion=true;PSVersion=7.0.3"
            "Method" = "Post"
            "Credential" = $credential
            "NoProxy" = !$proxy
            "SkipCertificateCheck" = $insecure
            "MaximumRedirection" = 0
        }
        try {
            Invoke-WebRequest @params
        }
        catch {
            if ($_.Exception.Response.StatusCode -eq "Redirect") {
                $end_uri = $_.Exception.Response.Headers.Location.AbsoluteUri
            } else {
                throw $_.Exception
            }
        }
    }

    return $end_uri
    <#
        .DESCRIPTION
        Solve Bug - When using bearer token the new-pssession unable to get redirect url for establishing pssession.
        This function get redirect URI by interacting with WSMAN directly via Rest-API.


        .PARAMETER uri
        Security & Compliance Center uri.

        .PARAMETER upn
        User Principal Name (UPN) is the name of a system user in an email address format.

        .PARAMETER password
        Password is filled only if authentication method is basic auth.

        .PARAMETER bearer_token
        Valid bearer token value.

        .EXAMPLE proxy
        Wheter to user system proxy configuration or not.

        .PARAMETER insecure
        Wheter to trust any TLS/SSL Certificate) or not.

        .OUTPUTS
        [string] Redirect uri if redirected.

        .LINK
        https://github.com/PowerShell/PowerShell/issues/12563
    #>
}

function CreateNewSession {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingConvertToSecureStringWithPlainText', '', Scope='Function')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', '', Scope='Function')]
    param([string]$url, [string]$upn, [string]$password, [string]$bearer_token, [bool]$insecure, [bool]$proxy)

    $url = GetRedirectUri -url $url -upn $upn -password $password -bearer_token $bearer_token -insecure $insecure -proxy $proxy

    if ($password){
        $credential = ConvertTo-SecureString "$password" -AsPlainText -Force
    } else {
        $credential = ConvertTo-SecureString "Bearer $bearer_token" -AsPlainText -Force
    }
    $credential = New-Object System.Management.Automation.PSCredential($upn, $credential)
    $session_option_params = @{
        "SkipCACheck" = $insecure
        "SkipCNCheck" = $insecure
    }
    $session_options =  New-PSSessionOption @session_option_params
    $sessions_params = @{
        "ConfigurationName" = "Microsoft.Exchange"
        "ConnectionUri" = $url
        "Credential" = $credential
        "Authentication" = "Basic"
        "AllowRedirection" = $true
        "SessionOption" = $session_options
    }
    $session = New-PSSession @sessions_params -WarningAction:SilentlyContinue

    if (!$session) {
        throw "Fail - establishing session to $url"
    }

    return $session
    <#
        .DESCRIPTION
        Creates new pssession using Oauth2.0 method.

        .PARAMETER uri
        Security & Compliance Center uri.

        .PARAMETER upn
        User Principal Name (UPN) is the name of a system user in an email address format.

        .PARAMETER password
        Password is filled only if authentication method is basic auth.

        .PARAMETER bearer_token
        Valid bearer token value.

        .EXAMPLE proxy
        Wheter to user system proxy configuration or not.

        .PARAMETER insecure
        Wheter to trust any TLS/SSL Certificate) or not.


        .EXAMPLE
        CreateNewSession("outlook.com", "user@microsoft.com", "dfhsdkjhkjhvkdvbihsgiu")

        .OUTPUTS
        PSSession - PSSession object.

        .LINK
        https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/new-pssession?view=powershell-7
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

function ParseResults([string]$results, [int]$limit = -1) {
    $parsed_results = New-Object System.Collections.Generic.List[System.Object]
    $lines = $results.Split(",")
    # Results limit
    foreach ($line in $lines)
    {
        if ($limit -ne -1 -and $parsed_results.Count -ge $limit){
            break
        }
        if ($line -match "Location: (\S+); Sender: ([\S ]+); Subject: ([\S ]+); Type: (\S+); Size: (\d+); Received Time: ([\S\d ]+); Data Link: ([^\}]+)")
        {
            $parsed_results.Add(@{
                "Location" = $matches[1]
                "Sender" = $matches[2]
                "Subject" = $matches[3]
                "Type" = $matches[4]
                "Size" = $matches[5]
                "ReceivedTime" = $matches[6]
                "DataLink" = $matches[7]
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
        "Results" = ParseResults -results $search_action.Results -limit $limit
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

    static [OAuth2DeviceCodeClient]CreateClientFromIntegrationContext([bool]$insecure, [bool]$proxy){
        $ic = $script:Demisto.getIntegrationContext()
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
        # Get device-code and user-code
        $params = @{
            "URI" = "https://login.microsoftonline.com/organizations/oauth2/v2.0/devicecode"
            "Method" = "Post"
            "Headers" = (New-Object "System.Collections.Generic.Dictionary[[String],[String]]").Add("Content-Type", "application/x-www-form-urlencoded")
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
                "URI" = "https://login.microsoftonline.com/organizations/oauth2/v2.0/token"
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
                "URI" = "https://login.microsoftonline.com/organizations/oauth2/v2.0/token"
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
            if ($response_body.error -eq "invalid_grant") {
                $error_details = "Please login to grant account permissions (After 90 days grant is expired) !$script:COMMAND_PREFIX-auth-start."
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

#### Security And Compliance client - OAUTH2.0 ####

class SecurityAndComplianceClient {
    [string]$url
    [string]$upn
    [string]$password
    [string]$bearer_token
    [psobject]$session
    [bool]$insecure
    [bool]$proxy

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', '', Scope='Function')]
    SecurityAndComplianceClient([string]$url, [string]$upn, [string]$password, [string]$bearer_token, [bool]$insecure, [bool]$proxy) {
        $this.upn = $upn
        $this.password = $password
        $this.bearer_token = $bearer_token
        $this.insecure = $insecure
        $this.proxy = $proxy
        $this.url = $url
        <#
            .DESCRIPTION
            SecurityAndComplianceClient connect to Security & Compliance Center using powershell session (OAuth2.0) and allow interact with it.

            .PARAMETER uri
            Security & Compliance Center uri.

            .PARAMETER upn
            User Principal Name (UPN) is the name of a system user in an email address format.

            .PARAMETER password
            Password is filled only if authentication method is basic auth.

            .PARAMETER bearer_token
            Valid bearer token value.

            .PARAMETER insecure
            Wheter to trust any TLS/SSL Certificate) or not.

            .EXAMPLE proxy
            Wheter to user system proxy configuration or not.

            .EXAMPLE
            $cs_client = [SecurityAndComplianceClient]::new("outlook.com", "user@microsoft.com", "dfhsdkjhkjhvkdvbihsgiu")

            .LINK
            https://docs.microsoft.com/en-us/powershell/module/exchange/?view=exchange-ps#policy-and-compliance-content-search
        #>
    }

    CreateSession() {
        $this.session = CreateNewSession -url $this.url -upn $this.upn -password $this.password -bearer_token $this.bearer_token -insecure $this.insecure -proxy $this.proxy
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
            Import-PSSession -Session $this.session -CommandName New-ComplianceSearch -AllowClobber
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

            return $response
        }
        finally {
            # Close session to remote
            $this.CloseSession()
        }
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
        try{
            # Establish session to remote
            $this.CreateSession()
            # Import and Execute command
            Import-PSSession -Session $this.session -CommandName Set-ComplianceSearch -AllowClobber
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
        }
        finally {
            # Close session to remote
            $this.CloseSession()
        }
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
        try{
            # Establish session to remote
            $this.CreateSession()
            # Import and Execute command
            Import-PSSession -Session $this.session -CommandName Remove-ComplianceSearch -AllowClobber
            Remove-ComplianceSearch -Identity $search_name -Confirm:$false
        }
        finally {
            # Close session to remote
            $this.CloseSession()
        }
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
        try {
            # Establish session to remote
            $this.CreateSession()
            # Import and Execute command
            Import-PSSession -Session $this.session -CommandName Get-ComplianceSearch -AllowClobber
            $response = Get-ComplianceSearch

            return $response
        }
        finally {
            # Close session to remote
            $this.CloseSession()
        }
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

    [psobject]GetSearch([string]$search_name, [int]$limit) {
        try{
            # Establish session to remote
            $this.CreateSession()
            # Import and Execute command
            Import-PSSession -Session $this.session -CommandName Get-ComplianceSearch -AllowClobber
            $response = Get-ComplianceSearch -Identity $search_name

            return $response
        }
        finally {
            # Close session to remote
            $this.CloseSession()
        }
        <#
            .DESCRIPTION
            Get compliance search by name from the Security & Compliance Center.

            .PARAMETER search_name
            The name of the compliance search.

            .PARAMETER limit
            Results limit (-1 is unlimited).

            .EXAMPLE
            $client.GetSearch("new-search")

            .OUTPUTS
            psobject - Raw response.

            .LINK
            https://docs.microsoft.com/en-us/powershell/module/exchange/get-compliancesearch?view=exchange-ps
        #>
    }

    StartSearch([string]$search_name) {
        try{
            # Establish session to remote
            $this.CreateSession()
            # Import and Execute command
            Import-PSSession -Session $this.session -CommandName Start-ComplianceSearch -AllowClobber
            Start-ComplianceSearch -Identity $search_name -Confirm:$false -Force:$true
        }
        finally {
            # Close session to remote
            $this.CloseSession()
        }
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
        try{
            # Establish session to remote
            $this.CreateSession()
            # Import and Execute command
            Import-PSSession -Session $this.session -CommandName Stop-ComplianceSearch  -AllowClobber
            Stop-ComplianceSearch -Identity $search_name -Confirm:$false
        }
        finally {
            # Close session to remote
            $this.CloseSession()
        }
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
        try{
            # Establish session to remote
            $this.CreateSession()
            # Import and Execute command
            Import-PSSession -Session $this.session -CommandName New-ComplianceSearchAction -AllowClobber
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

            return $response
        }
        finally {
            # Close session to remote
            $this.CloseSession()
        }
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
        try{
            # Establish session to remote
            $this.CreateSession()
            # Import and Execute command
            Import-PSSession -Session $this.session -CommandName Remove-ComplianceSearchAction -AllowClobber
            Remove-ComplianceSearchAction -Identity $search_action_name -Confirm:$false
        }
        finally {
            # Close session to remote
            $this.CloseSession()
        }
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
        try{
            # Establish session to remote
            $this.CreateSession()
            # Import and Execute command
            Import-PSSession -Session $this.session -CommandName Get-ComplianceSearchAction -AllowClobber
            $response = Get-ComplianceSearchAction

            return $response
        }
        finally {
            # Close session to remote
            $this.CloseSession()
        }
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

    [psobject]GetSearchAction([string]$search_action_name, [int]$limit) {
        try{
            # Establish session to remote
            $this.CreateSession()
            # Import and Execute command
            Import-PSSession -Session $this.session -CommandName Get-ComplianceSearchAction -AllowClobber
            if ($limit -eq -1) {
                $limit = "unlimited"
            }
            $response = Get-ComplianceSearchAction -Identity $search_action_name

            return $response
        }
        finally {
            # Close session to remote
            $this.CloseSession()
        }
        <#
            .DESCRIPTION
            Get compliance search action in the Security & Compliance Center.

            .PARAMETER search_action_name
            The name of the compliance search action.

            .PARAMETER limit
            Results limit (-1 is unlimited).

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

function TestModuleCommand ([OAuth2DeviceCodeClient]$oclient, [SecurityAndComplianceClient]$cs_client) {
    if ($cs_client.password) {
        $cs_client.ListSearchActions() | Out-Null
    }
    else {
        throw "Fill password for basic auth or use command !$script:COMMAND_PREFIX-auth-start for Oauth2.0 authorization (MFA enabled accounts)."
    }
    $raw_response = $null
    $human_readable = "ok"
    $entry_context = $null

    return $human_readable, $entry_context, $raw_response
}

function StartAuthCommand ([OAuth2DeviceCodeClient]$client) {
    $raw_response = $client.AuthorizationRequest()
    $human_readable = "## $script:INTEGRATION_NAME - Authorize instructions
1. To sign in, use a web browser to open the page [https://microsoft.com/devicelogin](https://microsoft.com/devicelogin) and enter the code **$($raw_response.user_code)** to authenticate.
2. Run the following command **!$script:COMMAND_PREFIX-auth-complete** in the War Room."
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
    $raw_response = $client.GetSearch($kwargs.search_name, $kwargs.limit)
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
        $parsed_results_all = ParseSuccessResults -success_results $raw_response.SuccessResults -limit -1 -all_results $true
        if ($parsed_results_all.Count -ne 0){
            $file_entry = FileResult "$($kwargs.search_name)_search.json" $($parsed_results_all | ConvertTo-Json)
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
    $raw_response = $client.GetSearchAction($kwargs.search_action_name, $kwargs.limit)
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
        $parsed_results_all = ParseResults -results $raw_response.Results -limit -1
        if ($parsed_results_all.Count -ne 0){
            $file_entry = FileResult "$($kwargs.search_action_name)_search_action.json" $($parsed_results_all | ConvertTo-Json)
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
    <#
        Proxy currently isn't supported by PWSH New-Pssession, However partly implmentation of proxy feature still function (OAuth2.0 and redirect),
        leaving this parameter for feature development if required.
    #>
    $no_proxy = $false
    $insecure = (ConvertTo-Boolean $integration_params.insecure)

    try {
        # Creating Compliance and search client
        $oauth2_client = [OAuth2DeviceCodeClient]::CreateClientFromIntegrationContext($insecure, $no_proxy)
        # Refreshing tokens if expired
        $oauth2_client.RefreshTokenIfExpired()
        # Creating Compliance and search client
        $cs_client = [SecurityAndComplianceClient]::new($integration_params.url, $integration_params.credentials.identifier,
                                                        $integration_params.credentials.password, $oauth2_client.access_token, $insecure, $no_proxy)
        # Executing command
        $Demisto.Debug("Command being called is $Command")
        switch ($command) {
            "test-module" {
                ($human_readable, $entry_context, $raw_response) = TestModuleCommand $oauth2_client $cs_client
            }
            "$script:COMMAND_PREFIX-auth-start" {
                ($human_readable, $entry_context, $raw_response) = StartAuthCommand $oauth2_client
            }
            "$script:COMMAND_PREFIX-auth-complete" {
                ($human_readable, $entry_context, $raw_response) = CompleteAuthCommand $oauth2_client
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
        }
        # Updating integration context if access token changed
        UpdateIntegrationContext $oauth2_client
        # Return results to Demisto Server
        ReturnOutputs $human_readable $entry_context $raw_response | Out-Null
        if ($file_entry) {
            $Demisto.results($file_entry)
        }
    }
    catch {
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
        }
        else {
            ReturnError $_.Exception.Message
        }
    }
}

# Execute Main when not in Tests
if ($MyInvocation.ScriptName -notlike "*.tests.ps1" -AND -NOT $Test) {
    Main
}