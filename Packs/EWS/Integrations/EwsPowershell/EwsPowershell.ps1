. $PSScriptRoot\CommonServerPowerShell.ps1

$global:INTEGRATION_NAME = "EwsPowershell"
$global:COMMAND_PREFIX = "ews"
$global:INTEGRATION_CONTEXT = $Demisto.getIntegrationContext()

#### HELPER FUNCTIONS ####

<#
.DESCRIPTION
    Update integration context from OAuth2Client client
.EXAMPLE
    UpdateIntegrationContext $client
.INPUTS
    $client OAuth2Client client
#>
function UpdateIntegrationContext([OAuth2Client]$client){
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
}

#### OAUTH2.0 CLIENT - DEVICE FLOW FUNCTIONS #####

<#
.SYNOPSIS
    OAuth2Client manage state of OAuth2.0 device-code flow described in https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-device-code.

.DESCRIPTION 
    OAuth2Client states are:
        1. Getting device-code (Will be used in stage 2) and user-code (Will be used by the user to authorize permissions) from Microsoft application.
        2. Getting access-token and refresh-token - after use authorize (Using stage 1 - device code)
        3. Refresh access-token if access-token is expired.
 
.EXAMPLE
    [OAuth2Client]::CreateClientFromIntegrationContext()

.NOTES
    1. Expiration time:
        - device-code - 15 minutes.
        - access-token - If not changed by the user will be 60 minutes.
        - refresh-token - 90 days.
    2. Application id - a0c73c16-a7e3-4564-9a95-2bdf47383716 , This well-known application publicly managed by Microsoft and will not work in on-premise enviorment.

.LINK
    https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-device-code
#>
class OAuth2Client {
    [string]$application_id = "a0c73c16-a7e3-4564-9a95-2bdf47383716"
    [string]$application_scope = "offline_access%20https%3A//outlook.office365.com/.default"
    [string]$device_code
    [string]$device_code_expires_in
    [string]$device_code_creation_time
    [string]$access_token
    [string]$refresh_token
    [string]$access_token_expires_in
    [string]$access_token_creation_time
    [bool]$verify_certificate = $true
    [bool]$use_system_proxy = $false

    OAuth2Client([string]$device_code, [string]$device_code_expires_in, [string]$device_code_creation_time, [string]$access_token, [string]$refresh_token,[string]$access_token_expires_in, [string]$access_token_creation_time) {
        $this.device_code = $device_code
        $this.device_code_expires_in = $device_code_expires_in
        $this.device_code_creation_time = $device_code_creation_time
        $this.access_token = $access_token
        $this.refresh_token = $refresh_token
        $this.access_token_expires_in = $access_token_expires_in
        $this.access_token_creation_time = $access_token_creation_time
    }

    <#
    .DESCRIPTION
        Static method which create object (factory method) from populated values in integration context.

    .EXAMPLE
        [OAuth2Client]::CreateClientFromIntegrationContext()
    
    .OUTPUTS
        OAuth2Client initialized object.
    #>
    static [OAuth2Client]CreateClientFromIntegrationContext(){
        $ic = $global:INTEGRATION_CONTEXT
        $client = [OAuth2Client]::new($ic.DeviceCode, $ic.DeviceCodeExpiresIn, $ic.DeviceCodeCreationTime, $ic.AccessToken, $ic.RefreshToken, $ic.AccessTokenExpiresIn, $ic.AccessTokenCreationTime)
        
        return $client
    }

    <#
    .SYNOPSIS
       Reset values populated in instance context and getting new device-code and user-code.

    .EXAMPLE
        $client.AuthorizationRequest()
    
    .OUTPUTS
        PSObject - Raw body response.
    
    .LINK
        https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-device-code#device-authorization-request
    #>
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
            "NoProxy" = !$this.use_system_proxy
            "SkipCertificateCheck" = !$this.verify_certificate
        }
        $response = Invoke-WebRequest @params
        $response_body = ConvertFrom-Json $response.Content
        # Update object properties
        $this.device_code = $response_body.device_code
        $this.device_code_creation_time = [int][double]::Parse((Get-Date -UFormat %s))
        $this.device_code_expires_in = $response_body.expires_in

        return $response_body
    }

    <#
    .SYNOPSIS
       Getting access-token and refresh-token from Microsoft application based on the device-code we go from AuthorizationRequest() method.

    .EXAMPLE
        $client.AccessTokenRequest()
    
    .OUTPUTS
        PSObject - Raw body response.

    .LINK 
        https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-device-code#authenticating-the-user
    #>
    [PSObject]AccessTokenRequest() {
        # Get new token using device-code
        try {
            $params = @{
                "URI" = "https://login.microsoftonline.com/organizations/oauth2/v2.0/token"
                "Method" = "Post"
                "Headers" = (New-Object "System.Collections.Generic.Dictionary[[String],[String]]").Add("Content-Type", "application/x-www-form-urlencoded")
                "Body" = "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code&code=$($this.device_code)&client_id=$($this.application_id)"
                "NoProxy" = !$this.use_system_proxy
                "SkipCertificateCheck" = !$this.verify_certificate
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
        $this.access_token_expires_in = $response_body.expires_in
        $this.access_token_creation_time = [int][double]::Parse((Get-Date -UFormat %s))

        return $response_body
    }

    <#
    .SYNOPSIS
       Getting new access-token and refresh-token from Microsoft application based on the refresh-token we got from AccessTokenRequest() method.

    .EXAMPLE
        $client.RefreshTokenRequest()
    
    .OUTPUTS
        PSObject - Raw body response.
    
    .LINK
        https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-implicit-grant-flow#refreshing-tokens
    #>
    [PSObject]RefreshTokenRequest() {
        # Get new token using refresh token
        try {
            $params = @{
                "URI" = "https://login.microsoftonline.com/organizations/oauth2/v2.0/token"
                "Method" = "Post"
                "Headers" = (New-Object "System.Collections.Generic.Dictionary[[String],[String]]").Add("Content-Type", "application/x-www-form-urlencoded")
                "Body" = "grant_type=refresh_token&client_id=$($this.application_id)&refresh_token=$($this.refresh_token)&scope=$($this.application_scope)"
                "NoProxy" = !$this.use_system_proxy
                "SkipCertificateCheck" = !$this.verify_certificate
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
        $this.access_token_expires_in = $response_body.expires_in
        $this.access_token_creation_time = [int][double]::Parse((Get-Date -UFormat %s))

        return $response_body
    }

    <#
    .SYNOPSIS
       Check if device-code expired.

    .EXAMPLE
        $client.IsDeviceCodeExpired()
    
    .OUTPUTS
        bool - True If device-code expired else False.
    
    .LINK
        https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-configurable-token-lifetimes#configurable-token-lifetime-properties-after-the-retirement
    #>
    [bool]IsDeviceCodeExpired(){
        if (!$this.device_code){
            return $true
        }
        $current_time = [int][double]::Parse((Get-Date -UFormat %s))
        $valid_until = $this.device_code_creation_time + $this.access_token_expires_in

        return $valid_until -gt $current_time
    }

    <#
    .SYNOPSIS
       Check if access-token expired.

    .EXAMPLE
        $client.IsAccessTokenExpired()
    
    .OUTPUTS
        bool - True If access-token expired else False.
    
    .LINK
        https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-configurable-token-lifetimes#configurable-token-lifetime-properties-after-the-retirement
    #>
    [bool]IsAccessTokenExpired(){
        if (!$this.access_token){
            return $true
        }
        $current_time = [int][double]::Parse((Get-Date -UFormat %s))
        $valid_until = $this.access_token_creation_time + $this.access_token_expires_in

        return $valid_until -gt $current_time
    }

    RefreshTokenIfExpired(){
        if ($this.access_token -and $this.IsAccessTokenExpired()) {
            $this.RefreshTokenRequest()
        }
    }
}



#### COMMAND FUNCTIONS ####


function StartAuthCommand ([Oauth2Client]$client) {
    $raw_response = $client.AuthorizationRequest()
	$human_readable = "## Authorize instructions
1. To sign in, use a web browser to open the page [https://microsoft.com/devicelogin](https://microsoft.com/devicelogin) and enter the code **$($raw_response.user_code)** to authenticate.
2. Run the following command **!ews-complete-auth** in the War Room."
    $entry_context = @{}
    
    return $human_readable, $entry_context, $raw_response
}

function CompleteAuthCommand ([Oauth2Client]$client) {
    $raw_response = $client.AccessTokenRequest()
    $human_readable = "Your account **successfully** authorized!"
    $entry_context = @{}
    
    return $human_readable, $entry_context, $raw_response
}

function RefreshAuthCommand ([Oauth2Client]$client) {
    $raw_response = $client.RefreshTokenRequest()
    $human_readable = "**Test ok!**"
    $entry_context = @{}
    
    return $human_readable, $entry_context, $raw_response
}

function IntegrationContextCommand () {
    $raw_response = @{}
    $human_readable = $Demisto.getIntegrationContext() | ConvertTo-Json
    $entry_context = @{}
    
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
	$Demisto.Debug("Command being called is $Command")
    # Creating OAuth2Client client
    $oauth2_client = [OAuth2Client]::CreateClientFromIntegrationContext()
    $oauth2_client.use_system_proxy = $integration_params.proxy
    $oauth2_client.verify_certificate = $integration_params.insecure
	try {
        # Refreshing tokens if expired
        $oauth2_client.RefreshTokenIfExpired()
        switch ($command) {
            "$global:COMMAND_PREFIX-start-auth" {
                ($human_readable, $entry_context, $raw_response) = StartAuthCommand $oauth2_client
            }
            "$global:COMMAND_PREFIX-complete-auth" {
                ($human_readable, $entry_context, $raw_response) = CompleteAuthCommand $oauth2_client
            }
            "$global:COMMAND_PREFIX-test-auth" {
                ($human_readable, $entry_context, $raw_response) = RefreshAuthCommand $oauth2_client
            }
            "$global:COMMAND_PREFIX-integration-context" {
                ($human_readable, $entry_context, $raw_response) = IntegrationContextCommand 
            }
        }

        UpdateIntegrationContext $oauth2_client

        $raw_response = $raw_response | ConvertTo-Json

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
Error: $($_.Exception.Message)" | Out-Null
    }
}

# Execute Main when not in Tests
if ($MyInvocation.ScriptName -notlike "*.tests.ps1" -AND -NOT$Test) {
	Main
}