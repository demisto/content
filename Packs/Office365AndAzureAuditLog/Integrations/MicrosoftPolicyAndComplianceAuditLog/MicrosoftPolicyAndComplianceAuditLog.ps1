$script:COMMAND_PREFIX = "o365-auditlog"
$script:INTEGRATION_ENTRY_CONTEXT = "O365AuditLog"

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

function CreateNewSession {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingConvertToSecureStringWithPlainText', '', Scope='Function')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', '', Scope='Function')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Scope='Function')]
    param([string]$url, [string]$upn, [string]$password, [string]$bearer_token, [bool]$insecure, [bool]$proxy)
    if ($password){
        $url = "$url/powershell-liveid"
    }
    else
    {
        $url = "$url/powershell-liveid?BasicAuthToOAuthConversion=true"
    }

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
        Creates new PSSession using Oauth2.0 method.

        .PARAMETER url
        Exchange Online url.

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
        https://docs.microsoft.com/en-us/powershell/partnercenter/multi-factor-auth?view=partnercenterps-3.0#exchange-online-powershell
    #>
}

class OAuth2DeviceCodeClient
{
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

    OAuth2DeviceCodeClient(
            [string]$device_code, [string]$device_code_expires_in, [string]$device_code_creation_time, [string]$access_token,
            [string]$refresh_token,[string]$access_token_expires_in, [string]$access_token_creation_time, [bool]$insecure, [bool]$proxy
    ) {
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
            Its not recommended to create an object using the constructor, Use static method CreateClientFromIntegrationContext() instead.

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
            Number of seconds before the included access token is valid for. (Usually - 60 minutes)

            .PARAMETER access_token_creation_time
            Unix time of access token creation (Used for knowing when to refresh the token).

            .PARAMETER access_token_expires_in
            Number of seconds before the included access token is valid for. (Usually - 60 minutes)

            .PARAMETER insecure
            Whether to trust any TLS/SSL Certificate) or not.

            .PARAMETER proxy
            Whether to user system proxy configuration or not.

            .NOTES
            1. Application id - a0c73c16-a7e3-4564-9a95-2bdf47383716 , This is well-known application publicly managed by Microsoft and will not work in on-premise environment.

            .LINK
            https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-device-code
        #>
    }

    static [OAuth2DeviceCodeClient]CreateClientFromIntegrationContext([bool]$insecure, [bool]$proxy){
        $ic = $script:Demisto.getIntegrationContext()
        $client = [OAuth2DeviceCodeClient]::new(
                $ic.DeviceCode, $ic.DeviceCodeExpiresIn, $ic.DeviceCodeCreationTime, $ic.AccessToken, $ic.RefreshToken,
                $ic.AccessTokenExpiresIn, $ic.AccessTokenCreationTime, $insecure, $proxy
        )

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

class ExchangeOnlineClient {
    [string]$url
    [string]$upn
    [string]$password
    [string]$bearer_token
    [psobject]$session
    [bool]$insecure
    [bool]$proxy

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', '', Scope='Function')]
    ExchangeOnlineClient([string]$url, [string]$upn, [string]$password, [string]$bearer_token, [bool]$insecure, [bool]$proxy) {
        $this.upn = $upn
        $this.password = $password
        $this.bearer_token = $bearer_token
        $this.insecure = $insecure
        $this.proxy = $proxy
        $this.url = $url
        <#
            .DESCRIPTION
            ExchangeOnlineClient connect to Exchange Online using power-shell session (OAuth2.0) and allow interact with it.

            .PARAMETER url
            Exchange online url.

            .PARAMETER upn
            User Principal Name (UPN) is the name of a system user in an email address format.

            .PARAMETER password
            Password is filled only if authentication method is basic auth.

            .PARAMETER bearer_token
            Valid bearer token value.

            .PARAMETER insecure
            Whether to trust any TLS/SSL Certificate) or not.

            .EXAMPLE proxy
            Whether to user system proxy configuration or not.

            .EXAMPLE
            $exo_client = [ExchangeOnlineClient]::new("outlook.com", "user@microsoft.com", "dfhsdkjhkjhvkdvbihsgiu")
        #>
    }

    CreateSession() {
        $this.session = CreateNewSession -url $this.url -upn $this.upn -password $this.password -bearer_token $this.bearer_token -insecure $this.insecure -proxy $this.proxy
        <#
            .DESCRIPTION
            This method is for internal use. It creates session to Exchange Online.

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
            This method is for internal use. It creates session to Exchange Online.

            .EXAMPLE
            $client.CloseSession()

            .LINK
            https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/remove-pssession?view=powershell-7
            https://docs.microsoft.com/en-us/powershell/partnercenter/multi-factor-auth?view=partnercenterps-3.0#exchange-online-powershell
        #>
    }
    [Array]SearchUnifiedAuditLog(
        [string]$start_date,
        [string]$end_date,
        [string]$free_text,
        [string]$record_type,
        [String[]]$ip_addresses,
        [String[]]$operations,
        [String[]]$user_ids,
        [int]$result_size
    ){
        Import-PSSession -Session $this.session -CommandName Search-UnifiedAuditLog -AllowClobber
        $cmd_args = @{
            "StartDate" = $start_date
            "EndDate" = $end_date
        }
        if ($record_type){
            $cmd_args.RecordType = $record_type
        }
        if ($free_text){
            $cmd_args.FreeText = $free_text
        }
        if ($operations.Length -gt 0){
            $cmd_args.Operations = $operations
        }
        if ($ip_addresses.Length -gt 0)
        {
            $cmd_args.IPAddresses = $ip_addresses
        }
        if ($user_ids.Length -gt 0)
        {
            $cmd_args.UserIds = $user_ids
        }
        if ($result_size -gt 0){
            $cmd_args.ResultSize = $result_size
        } else {
            $cmd_args.ResultSize = 5000
        }
        return Search-UnifiedAuditLog @cmd_args -ErrorAction Stop
    }
}

#### COMMAND FUNCTIONS ####

function TestModuleCommand {
    [CmdletBinding()]
    Param(
        [ExchangeOnlineClient]$exo_client
    )
    try {
        $exo_client.CreateSession()
    }
    finally {
        $exo_client.CloseSession()
    }
    $raw_response = $null
    $human_readable = "ok"
    $entry_context = $null

    Write-Output $human_readable, $entry_context, $raw_response
}

function StartAuthCommand {
    [CmdletBinding()]
    Param(
        [OAuth2DeviceCodeClient]$client
    )
    $raw_response = $client.AuthorizationRequest()
    $human_readable = "## $script:INTEGRATION_NAME - Authorize instructions
1. To sign in, use a web browser to open the page [https://microsoft.com/devicelogin](https://microsoft.com/devicelogin) and enter the code **$($raw_response.user_code)** to authenticate.
2. Run the following command **!$script:COMMAND_PREFIX-auth-complete** in the War Room."
    $entry_context = @{}

    Write-Output $human_readable, $entry_context, $raw_response
}

function CompleteAuthCommand {
    [OutputType([PSObject])]
    [CmdletBinding()]
    Param(
        [OAuth2DeviceCodeClient]$client
    )
    # Verify that user run start before complete
    if (!$client.device_code) {
        throw "Please run !ews-auditlog-auth-start and follow the command instructions"
    }
    $raw_response = $client.AccessTokenRequest()
    $human_readable = "Your account **successfully** authorized!"
    $entry_context = @{}

    Write-Output $human_readable, $entry_context, $raw_response
}

function TestAuthCommand ([OAuth2DeviceCodeClient]$oclient, [ExchangeOnlineClient]$exo_client) {
    [CmdletBinding()]
    $raw_response = $oclient.RefreshTokenRequest()
    $human_readable = "**Test ok!**"
    $entry_context = @{}
    try {
        $exo_client.CreateSession()
    }
    finally {
        $exo_client.CloseSession()
    }

    Write-Output $human_readable, $entry_context, $raw_response
}

function SearchAuditLogCommand{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)][ExchangeOnlineClient]$client,
        [hashtable]$kwargs
    )
    try
    {
        $client.CreateSession()
        if ($kwargs.end_date){
            $end_date = Get-Date $kwargs.end_date
        } else {
            $end_date = Get-Date
        }
        try {
            # If parse date range works, it is fine. The end date will be automatically now.
            $start_date, $end_date = ParseDateRange $kwargs.start_date
        } catch {
            try
            {
                # If it didn't work, it should be a date.
                $start_date = Get-Date $kwargs.start_date
            } catch {
                # If it's not a date and not a date range - throw.
                $start_date = $kwargs.start_date
                throw "start_date ('$start_date') is not a date range or a valid date "
            }
        }

        $raw_response = $client.SearchUnifiedAuditLog(
                $start_date,
                $end_date,
                $kwargs.free_text,
                $kwargs.record_type,
                (ArgToList $kwargs.ip_addresses),
                (ArgToList $kwargs.operations),
                (ArgToList $kwargs.user_ids),
                ($kwargs.result_size -as [int])
        )
        if ($raw_response){
            $list = New-Object Collections.Generic.List[PSObject]
            foreach ($item in $raw_response)
            {
                $list.add((ConvertFrom-Json $item.AuditData))
            }
            $context = @{
                "$script:INTEGRATION_ENTRY_CONTEXT(val.Id === obj.Id)" = $list
            }
            $human_readable = TableToMarkdown $list.ToArray() "Audit log from $start_date to $end_date"
            Write-Output $human_readable, $context, $list
        } else {
            $human_readable = "Audit log from $start_date to $end_date is empty"
            Write-Output $human_readable, $null, $null
        }

    } finally {
        $client.CloseSession()
    }
}

function Main {
    $command = $demisto.GetCommand()
    $command_arguments = $demisto.Args()
    $integration_params = $demisto.Params()
    <#
        Proxy currently isn't supported by PWSH New-Pssession, However partly implmentation of proxy feature still function (OAuth2.0 and redirect),
        leaving this parameter for feature development if required.
    #>
    $no_proxy = $false
    $insecure = (ConvertTo-Boolean $integration_params.insecure)

    try
    {
        # Creating Compliance and search client
        $oauth2_client = [OAuth2DeviceCodeClient]::CreateClientFromIntegrationContext($insecure, $no_proxy)
        # Refreshing tokens if expired
        $oauth2_client.RefreshTokenIfExpired()
        # Creating ExchangeOnline client
        $exo_client = [ExchangeOnlineClient]::new(
                $integration_params.url, $integration_params.credentials.identifier,
                $integration_params.credentials.password, $oauth2_client.access_token, $insecure, $no_proxy)
        # Executing command
        $demisto.Debug("Command being called is $command")
        switch ($command)
        {
            "test-module" {
                ($human_readable, $entry_context, $raw_response) = TestModuleCommand $exo_client
            }
            "$script:COMMAND_PREFIX-search" {
                ($human_readable, $entry_context, $raw_response) = SearchAuditLogCommand $exo_client $command_arguments
            }
                "$script:COMMAND_PREFIX-auth-start" {
                ($human_readable, $entry_context, $raw_response) = StartAuthCommand $oauth2_client
            }
            "$script:COMMAND_PREFIX-auth-complete" {
                ($human_readable, $entry_context, $raw_response) = CompleteAuthCommand $oauth2_client
            }
            "$script:COMMAND_PREFIX-auth-test" {
                ($human_readable, $entry_context, $raw_response) = TestAuthCommand $oauth2_client $exo_client
            }
            default{
                throw "Command $command no implemented"
            }
        }
        # Updating integration context if access token changed
        UpdateIntegrationContext $oauth2_client
        # Return results to Demisto Server
        ReturnOutputs $human_readable $entry_context $raw_response | Out-Null
    } catch {
                $demisto.debug("Integration: $script:INTEGRATION_NAME
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
