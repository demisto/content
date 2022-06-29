$COMMAND_PREFIX = "o365-defender-safelinks"
$INTEGRATION_ENTRY_CONTEXT = "O365Defender.SafeLinks"


function EncloseArgWithQuotes {
    Param (
        [string]$arg_value
    )
    if (!($arg_value)) {
        return ""
    }

    $arrayed_value = $arg_value -split ","
    if ($arrayed_value.Length -eq 1) {
        return $arrayed_value
    }
    for ($i = 0; $i -lt $arrayed_value.Count; $i++) {
        $temp_val = $arrayed_value[$i]
        if ($temp_val[0] -ne '"') {
            $arrayed_value[$i] = '"' + $arrayed_value[$i].Trim() + '"'
        }
    }

    $return_value = $arrayed_value -join ","

    return $return_value

    <#
    .DESCRIPTION
    Encloses the value of an argument with double quotes and trim it. In the case it's a CSV value
    it will do that for every value in the list.

    .PARAMETER arg_value
    The raw value of the argument.

    .EXAMPLE
    EncloseArgWithQuotes("a,b,c") -> "a","b","c"
    EncloseArgWithQuotes("a, b,c ") -> "a","b","c"
    EncloseArgWithQuotes("\"a\",b,c") -> "a","b","c"
    EncloseArgWithQuotes("") -> ""
    EncloseArgWithQuotes -> ""
    #>
}

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
        $ic = GetIntegrationContext
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
            Check if device-code expired with offset of 30 seconds.

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
            Check if access-token expired with offset of 30 seconds.

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

    [PSObject]
    GetPolicyList([string]$identity) {
        try
        {
            $cmd_params = @{ }
            if ($identity)
            {
                $cmd_params.Identity = $identity
            }
            $this.CreateSession()
            Import-PSSession -Session $this.session -CommandName Get-SafeLinksPolicy -AllowClobber

            $results = Get-SafeLinksPolicy @cmd_params
            return $results
        }
        finally {
        # Close session to remote
        $this.CloseSession()
        }

        <#
        .DESCRIPTION
        Use this cmdlet to view Safe Links policies in your cloud-based organization.
        This cmdlet is available only in the cloud-based service.

        .PARAMETER identity
        The Identity parameter specifies the Safe Links policy that you want to view.

        You can use any value that uniquely identifies the policy. For example:
        * Name
        * Distinguished name (DN)
        * GUID

        .EXAMPLE
        GetPolicyList("1254y894-feae-9yn7-a3e1-f2483a154tft")

        .OUTPUTS
        PSObject - Raw response

        .LINK
        https://docs.microsoft.com/en-us/powershell/module/exchange/get-safelinkspolicy?view=exchange-ps
        #>
    }

    [PSObject]
    CreateUpdatePolicy([string]$command_type, [hashtable]$kwargs)
    {
        try
        {
            $cmd_params = @{
                Name = $kwargs.name
            }
            if ($kwargs.admin_display_name) {
                $cmd_params.AdminDisplayName = $kwargs.admin_display_name
            }
            if ($kwargs.custom_notification_text) {
                $cmd_params.CustomNotificationText = $kwargs.custom_notification_text
            }
            if ($kwargs.deliver_message_after_scan) {
                $cmd_params.DeliverMessageAfterScan = ConvertTo-Boolean $kwargs.deliver_message_after_scan
            }
            if ($kwargs.do_not_allow_click_through) {
                $cmd_params.DoNotAllowClickThrough = ConvertTo-Boolean $kwargs.do_not_allow_click_through
            }
            if ($kwargs.do_not_rewrite_urls) {
                $cmd_params.DoNotRewriteUrls = EncloseArgWithQuotes($kwargs.do_not_rewrite_urls)
            }
            if ($kwargs.do_not_track_user_clicks) {
                $cmd_params.DoNotTrackUserClicks = ConvertTo-Boolean $kwargs.do_not_track_user_clicks
            }
            if ($kwargs.enable_for_internal_senders) {
                $cmd_params.EnableForInternalSenders = ConvertTo-Boolean $kwargs.enable_for_internal_senders
            }
            if ($kwargs.enable_organization_branding) {
                $cmd_params.EnableOrganizationBranding = ConvertTo-Boolean $kwargs.enable_organization_branding
            }
            if ($kwargs.enable_safe_links_for_teams) {
                $cmd_params.EnableSafeLinksForTeams = ConvertTo-Boolean $kwargs.enable_safe_links_for_teams
            }
            if ($kwargs.is_enabled) {
                $cmd_params.IsEnabled = ConvertTo-Boolean $kwargs.is_enabled
            }
            if ($kwargs.scan_urls) {
                $cmd_params.ScanUrls = ConvertTo-Boolean $kwargs.scan_urls
            }
            if ($kwargs.use_translated_notification_text) {
                $cmd_params.UseTranslatedNotificationText = ConvertTo-Boolean $kwargs.use_translated_notification_text
            }

            $this.CreateSession()
            Import-PSSession -Session $this.session -CommandName New-SafeLinksPolicy -AllowClobber

            if ($command_type -eq "create") {
                $results = New-SafeLinksPolicy @cmd_params
            }
            else {
                $results = Set-SafeLinksPolicy @cmd_params
            }
            return $results
        }
        finally
        {
            $this.CloseSession()
        }

        <#
        .DESCRIPTION
        Use this cmdlet to create or update Safe Links policies in your cloud-based organization.
        This cmdlet is available only in the cloud-based service.

        .EXAMPLE
        CreateUpdatePolicy("1254y894-feae-9yn7-a3e1-f2483a154tft")

        .OUTPUTS
        PSObject - Raw response

        .LINK
        https://docs.microsoft.com/en-us/powershell/module/exchange/new-safelinkspolicy?view=exchange-ps
        https://docs.microsoft.com/en-us/powershell/module/exchange/set-safelinkspolicy?view=exchange-ps
        #>
    }

    RemovePolicy([string]$identity) {
        try
        {
            $this.CreateSession()
            Import-PSSession -Session $this.session -CommandName Remove-SafeLinksPolicy -AllowClobber

            Remove-SafeLinksPolicy -Identity $identity -Confirm:$false -WarningAction:SilentlyContinue > $null
        }
        finally
        {
            $this.CloseSession()
        }


        <#
        .DESCRIPTION
        Use this cmdlet to remove Safe Links policies from your cloud-based organization.
        This cmdlet is available only in the cloud-based service.

        .PARAMETER identity
        The Identity parameter specifies the Safe Links policy that you want to remove.

        You can use any value that uniquely identifies the policy. For example:
        * Name
        * Distinguished name (DN)
        * GUID

        .EXAMPLE
        RemovePolicy("1254y894-feae-9yn7-a3e1-f2483a154tft")

        .OUTPUTS
        PSObject - Raw response

        .LINK
        https://docs.microsoft.com/en-us/powershell/module/exchange/remove-safelinkspolicy?view=exchange-ps
        #>
    }

    [PSObject]
    GetRules([string]$identity, [string]$state)
    {
        try
        {
            $cmd_params = @{ }
            if ($identity) {
                $cmd_params.Identity = $identity
            }
            if ($state) {
                $cmd_params.State = $state
            }
            $this.CreateSession()
            Import-PSSession -Session $this.session -CommandName Get-SafeLinksRule -AllowClobber

            $results = Get-SafeLinksRule @cmd_params
            return $results

        }
        finally
        {
            $this.CloseSession()
        }

        <#
        .DESCRIPTION
        Use this cmdlet to view Safe Links rules in your cloud-based organization.
        This cmdlet is available only in the cloud-based service.

        .PARAMETER identity
        The Identity parameter specifies the Safe Links rule that you want to view.

        You can use any value that uniquely identifies the policy. For example:
        * Name
        * Distinguished name (DN)
        * GUID

        .EXAMPLE
        GetRules("1254y894-feae-9yn7-a3e1-f2483a154tft")

        .OUTPUTS
         PSObject- Raw response

        .LINK
        https://docs.microsoft.com/en-us/powershell/module/exchange/get-safelinksrule?view=exchange-ps
        #>
    }

    [PSObject]
    CreateUpdateRule([string]$command_type, [hashtable]$kwargs)
    {
        try {
            $cmd_params = @{
                Name = $kwargs.name
            }

            if ($kwargs.safe_links_policy) {
                $cmd_params.SafeLinksPolicy = $kwargs.safe_links_policy
            }
            if ($kwargs.comments) {
                $cmd_params.Comments = $kwargs.comments
            }
            if ($kwargs.enabled) {
                $cmd_params.Enabled = ConvertTo-Boolean $kwargs.enabled
            }
            if ($kwargs.except_if_recipient_domain_is) {
                $cmd_params.ExceptIfRecipientDomainIs = $kwargs.except_if_recipient_domain_is
            }
            if ($kwargs.except_if_sent_to) {
                $cmd_params.ExceptIfSentTo = EncloseArgWithQuotes($kwargs.except_if_sent_to)
            }
            if ($kwargs.except_if_sent_to_member_of) {
                $cmd_params.ExceptIfSentToMemberOf = $kwargs.except_if_sent_to_member_of
            }
            if ($kwargs.priority) {
                $cmd_params.Priority = $kwargs.priority -as [Int32]
            }
            if ($kwargs.recipient_domain_is) {
                $cmd_params.RecipientDomainIs = EncloseArgWithQuotes($kwargs.recipient_domain_is)
            }
            if ($kwargs.sent_to) {
                $cmd_params.SentTo =  EncloseArgWithQuotes($kwargs.sent_to)
            }
            if ($kwargs.sent_to_member_of) {
                $cmd_params.SentToMemberOf = EncloseArgWithQuotes($kwargs.sent_to_member_of)
            }

            $this.CreateSession()

            if ($command_type -eq "create") {
                Import-PSSession -Session $this.session -CommandName New-SafeLinksRule -AllowClobber
                $results = New-SafeLinksRule @cmd_params
            }
            else {
                Import-PSSession -Session $this.session -CommandName Set-SafeLinksRule -AllowClobber
                $results = Set-SafeLinksRule @cmd_params
            }
            return $results
        }
        finally {
            $this.CloseSession()
        }

        <#
        .DESCRIPTION
        Use this cmdlet to create or update Safe Links rules in your cloud-based organization.
        This cmdlet is available only in the cloud-based service.

        .EXAMPLE
        CreateUpdatePolicy("1254y894-feae-9yn7-a3e1-f2483a154tft")

        .OUTPUTS
        PSObject - Raw response

        .LINK
        https://docs.microsoft.com/en-us/powershell/module/exchange/new-safelinksrule?view=exchange-ps
        https://docs.microsoft.com/en-us/powershell/module/exchange/set-safelinksrule?view=exchange-ps
        #>
    }

    [PSObject]
    GetDetailReport([hashtable]$kwargs)
    {
        try
        {
            $cmd_args = @{
                "StartDate" = $kwargs.start_date
                "EndDate" = $kwargs.end_date
                }
            if ($kwargs.click_id)
            {
                $cmd_args.ClickId = $kwargs.click_id
            }
            if ($kwargs.recipient_address)
            {
                $cmd_args.RecipientAddress = EncloseArgWithQuotes($kwargs.recipient_address)
            }
            if ($kwargs.domain)
            {
                $cmd_args.Domain = $kwargs.domain
            }
            if ($kwargs.app_names)
            {
                $cmd_args.AppNameList = EncloseArgWithQuotes($kwargs.app_names)
            }
            if ($kwargs.page)
            {
                $cmd_args.Page = [int]$kwargs.page
            }
            $this.CreateSession()
            Import-PSSession -Session $this.session -CommandName Get-SafeLinksDetailReport -AllowClobber

            $results = Get-SafeLinksDetailReport @cmd_args

            return $results
        }
        finally
        {
            $this.CloseSession()
        }

    }

}

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
    [OutputType([System.Object[]])]
    [CmdletBinding()]
    Param(
        [OAuth2DeviceCodeClient]$client
    )
    $raw_response = $client.AuthorizationRequest()
    $human_readable = "## $script:INTEGRATION_NAME - Authorize instructions
1. To sign in, use a web browser to open the page [https://microsoft.com/devicelogin](https://microsoft.com/devicelogin) and enter the code **$($raw_response.user_code)** to authenticate.
2. Run the **!$script:COMMAND_PREFIX-auth-complete** command in the War Room.
3. Run the **!$script:COMMAND_PREFIX-auth-test** command in the War Room to test the completion of the authorization process and the configured parameters."
    $entry_context = @{}

    return $human_readable, $entry_context, $raw_response
}

function CompleteAuthCommand {
    [OutputType([System.Object[]])]
    [CmdletBinding()]
    Param(
        [OAuth2DeviceCodeClient]$client
    )
    # Verify that user run start before complete
    if (!$client.device_code) {
        throw "Please run **!$script:COMMAND_PREFIX-auth-start** and follow the command instructions"
    }
    $raw_response = $client.AccessTokenRequest()
    $human_readable = "Your account **successfully** authorized!"
    $entry_context = @{}

    return $human_readable, $entry_context, $raw_response
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

    return $human_readable, $entry_context, $raw_response
}

function GetPolicyListCommand {
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    Param (
        [Parameter(Mandatory)][ExchangeOnlineClient]$client,
        [hashtable]$kwargs
    )

    $raw_response = $client.GetPolicyList($kwargs.identity)
    if (!$raw_response){
        return "#### No policies were found.", @{}, @{}
    }

    $human_readable = TableToMarkdown $raw_response "Results of $command"
    $entry_context = @{ "$script:INTEGRATION_ENTRY_CONTEXT.Policy(obj.Guid === val.Guid)" = $raw_response }
    return $human_readable, $entry_context, $raw_response
}

function CreateUpdatePolicyCommand {
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    Param (
        [Parameter(Mandatory)][ExchangeOnlineClient]$client,
        [Parameter(Mandatory)][string]$command_type,
        [hashtable]$kwargs
    )
    $raw_response = $client.CreateUpdatePolicy(
        $command_type,
        $kwargs
    )
    if (!$raw_response){
        return "#### The policy was not ${command_type}d successfully.", @{}, @{}
    }

    $human_readable = TableToMarkdown $raw_response "Results of $command"
    $entry_context = @{ "$script:INTEGRATION_ENTRY_CONTEXT.Policy(obj.Guid === val.Guid)" = $raw_response }
    return $human_readable, $entry_context, $raw_response
}

function RemovePolicyCommand {
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    Param (
        [Parameter(Mandatory)][ExchangeOnlineClient]$client,
        [hashtable]$kwargs
    )
    $identity = $kwargs.identity
    $client.RemovePolicy($identity)
    $human_readable = "#### Policy with Identity: ${identity} was removed successfully."
    return $human_readable, $null, $null
}

function GetRulesCommand {
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    Param (
        [Parameter(Mandatory)][ExchangeOnlineClient]$client,
        [hashtable]$kwargs
    )
    $identity = $kwargs.identity
    $raw_response = $client.GetRules($identity, $kwargs.state)

    if (!$raw_response){
        return "#### No rules were found.", @{}, @{}
    }

    $human_readable = TableToMarkdown $raw_response "Results of $command"
    $entry_context = @{ "$script:INTEGRATION_ENTRY_CONTEXT.Rule(obj.Guid === val.Guid)" = $raw_response }
    return $human_readable, $entry_context, $raw_response
}

function CreateUpdateRuleCommand {
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    Param (
        [Parameter(Mandatory)][ExchangeOnlineClient]$client,
        [Parameter(Mandatory)][string]$command_type,
        [hashtable]$kwargs
    )

    $raw_response = $client.CreateUpdateRule(
        $command_type,
        $kwargs
    )
    if (!$raw_response){
        return "#### The rule was not ${command_type}d successfully.", @{}, @{}
    }

    $human_readable = TableToMarkdown $raw_response "Results of $command"
    $entry_context = @{ "$script:INTEGRATION_ENTRY_CONTEXT.Policy(obj.Guid === val.Guid)" = $raw_response }
    return $human_readable, $entry_context, $raw_response
}

function GetDetailReportCommand {
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    Param (
        [Parameter(Mandatory)][ExchangeOnlineClient]$client,
        [hashtable]$kwargs
    )
    $raw_response = $client.GetDetailReport($kwargs)
    if (!$raw_response){
        return "#### No detailed information about Safe Links results found for the given criteria.", @{}, @{}
    }

    $human_readable = TableToMarkdown $raw_response "Results of $command"
    $entry_context = @{ "$script:INTEGRATION_ENTRY_CONTEXT.DetailReport(obj.Url === val.Url)" = $raw_response }
    return $human_readable, $entry_context, $raw_response
}

function TestModuleCommand($client) {
    try {
        $client.CreateSession()
        $demisto.results("ok")
    }
    finally {
        $client.CloseSession()
    }

}

function Main {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingConvertToSecureStringWithPlainText', '')]
    param()

    $command = $demisto.GetCommand()
    $command_arguments = $demisto.Args()
    $integration_params = [Hashtable] $demisto.Params()
    $insecure = (ConvertTo-Boolean $integration_params.insecure)

    <#
        Proxy currently isn't supported by PWSH New-Pssession, However partly implmentation of proxy feature still function (OAuth2.0 and redirect),
        leaving this parameter for feature development if required.
    #>
    $no_proxy = $false

    $oauth2_client = [OAuth2DeviceCodeClient]::CreateClientFromIntegrationContext($insecure, $no_proxy)
    $oauth2_client.RefreshTokenIfExpired()

    $exo_client = [ExchangeOnlineClient]::new(
        $integration_params.url,
        $integration_params.credentials.identifier,
        $integration_params.credentials.password,
        $oauth2_client.access_token,
        $insecure,
        $no_proxy
        )

    try {
        # Executing command
        $Demisto.Debug("Command being called is $command")
        switch ($command) {
            "test-module" {
                ($human_readable, $entry_context, $raw_response) = TestModuleCommand $exo_client
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
            "$script:COMMAND_PREFIX-policy-list" {
                ($human_readable, $entry_context, $raw_response) = GetPolicyListCommand -client $exo_client -kwargs $command_arguments
            }
            "$script:COMMAND_PREFIX-policy-create" {
                ($human_readable, $entry_context, $raw_response) = CreateUpdatePolicyCommand -client $exo_client "create" -kwargs $command_arguments
            }
            "$script:COMMAND_PREFIX-policy-update" {
                ($human_readable, $entry_context, $raw_response) = CreateUpdatePolicyCommand -client $exo_client "update" -kwargs $command_arguments
            }
            "$script:COMMAND_PREFIX-policy-remove" {
                ($human_readable, $entry_context, $raw_response) = RemovePolicyCommand -client $exo_client -kwargs $command_arguments
            }
            "$script:COMMAND_PREFIX-rule-list" {
                ($human_readable, $entry_context, $raw_response) = GetRulesCommand -client $exo_client -kwargs $command_arguments
            }
            "$script:COMMAND_PREFIX-rule-create" {
                ($human_readable, $entry_context, $raw_response) = CreateUpdateRuleCommand -client $exo_client -command_type "create" -kwargs $command_arguments
            }
            "$script:COMMAND_PREFIX-rule-update" {
                ($human_readable, $entry_context, $raw_response) = CreateUpdateRuleCommand -client $exo_client -command_type "update" -kwargs $command_arguments
            }
            "$script:COMMAND_PREFIX-detail-report-get" {
                ($human_readable, $entry_context, $raw_response) = GetDetailReportCommand -client $exo_client -kwargs $command_arguments
            }

            default {
                ReturnError "Could not recognize $command"
            }
        }
        # Updating integration context if access token changed
        UpdateIntegrationContext $oauth2_client

        # Return results to Demisto Server
        ReturnOutputs $human_readable $entry_context $raw_response | Out-Null
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