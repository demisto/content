Import-Module ExchangeOnlineManagement


$COMMAND_PREFIX = "o365-atp-safe-links"
$INTEGRATION_ENTRY_CONTEXT = "O365ATP.SafeLinks"


class ExchangeOnlinePowershellV2Client {
    [string]$url
    [System.Security.Cryptography.X509Certificates.X509Certificate2]$certificate
    [string]$organization
    [string]$app_id
    [SecureString]$password
    ExchangeOnlinePowershellV2Client(
        [string]$url,
        [string]$app_id,
        [string]$organization,
        [string]$certificate,
        [SecureString]$password
    ) {
        $this.url = $url
        try {
            $ByteArray = [System.Convert]::FromBase64String($certificate)
        }
        catch {
            throw "Could not decode the certificate. Try to re-enter it"
        }
        $this.certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($ByteArray, $password)

        $this.organization = $organization
        $this.app_id = $app_id
    }
    CreateSession() {
        $cmd_params = @{
            "AppID"        = $this.app_id
            "Organization" = $this.organization
            "Certificate"  = $this.certificate
        }
        Connect-ExchangeOnline @cmd_params -ShowBanner:$false -SkipImportSession -WarningAction:SilentlyContinue | Out-Null
    }
    DisconnectSession() {
        Disconnect-ExchangeOnline -Confirm:$false -WarningAction:SilentlyContinue | Out-Null
    }

    [PSObject]
    GetPolicyList(
            [string]$identity
    )
    {
        $cmd_params = @{ }
        if ($identity)
        {
            $cmd_params.Identity = $identity
        }
        $this.CreateSession()
        $results = Get-SafeLinksPolicy @cmd_params
        $this.DisconnectSession()
        return $results

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
    CreatePolicy(
        [string]$name,
        [string]$admin_display_name,
        [string]$custom_notification_text,
        [bool]$deliver_message_after_scan,
        [bool]$do_not_allow_click_through,
        [string]$do_not_rewrite_urls,
        [bool]$do_not_track_user_clicks,
        [bool]$enable_for_internal_senders,
        [bool]$enable_organization_branding,
        [bool]$enable_safe_links_for_teams,
        [bool]$is_enabled,
        [bool]$scan_urls,
        [bool]$use_translated_notification_text
    ) {
        $cmd_params = @{ 
            Name = $name
        }
        if ($admin_display_name) {
            $cmd_params.AdminDisplayName = $admin_display_name
        }
        if ($custom_notification_text) {
            $cmd_params.CustomNotificationText = $custom_notification_text
        }
        if ($deliver_message_after_scan) {
            $cmd_params.DeliverMessageAfterScan = $deliver_message_after_scan
        }
        if ($do_not_allow_click_through) {
            $cmd_params.DoNotAllowClickThrough = $do_not_allow_click_through
        }
        if ($do_not_rewrite_urls) {
            $cmd_params.DoNotRewriteUrls = $do_not_rewrite_urls
        }
        if ($do_not_track_user_clicks) {
            $cmd_params.DoNotTrackUserClicks = $do_not_track_user_clicks
        }
        if ($enable_for_internal_senders) {
            $cmd_params.EnableForInternalSenders = $enable_for_internal_senders
        }
        if ($enable_organization_branding) {
            $cmd_params.EnableOrganizationBranding = $enable_organization_branding
        }
        if ($enable_safe_links_for_teams) {
            $cmd_params.EnableSafeLinksForTeams = $enable_safe_links_for_teams
        }
        if ($is_enabled) {
            $cmd_params.IsEnabled = $is_enabled
        }
        if ($scan_urls) {
            $cmd_params.ScanUrls = $scan_urls
        }
        if ($use_translated_notification_text) {
            $cmd_params.UseTranslatedNotificationText = $use_translated_notification_text
        }

        
        $this.CreateSession()
        $results = New-SafeLinksPolicy @cmd_params
        $this.DisconnectSession()
        return $results

        <#
        .DESCRIPTION
        Use this cmdlet to create Safe Links policies in your cloud-based organization.
        This cmdlet is available only in the cloud-based service.

        .EXAMPLE
        GetPolicyList("1254y894-feae-9yn7-a3e1-f2483a154tft")

        .OUTPUTS
        PSObject - Raw response

        .LINK
        https://docs.microsoft.com/en-us/powershell/module/exchange/new-safelinkspolicy?view=exchange-ps
        #>
    }
}


function GetPolicyListCommand
{
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory)][ExchangeOnlinePowershellV2Client]$client,
        [hashtable]$kwargs
    )
    $identity = $kwargs.identity
    $raw_response = $client.GetPolicyList(
            $identity
    )
    $human_readable = TableToMarkdown $raw_response "Results of $command"
    $entry_context = @{ "$script:INTEGRATION_ENTRY_CONTEXT.PolicyList(obj.Guid === val.Guid)" = $raw_response }
    Write-Output $human_readable, $entry_context, $raw_response
}

function CreatePolicyCommand
{
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory)][ExchangeOnlinePowershellV2Client]$client,
        [hashtable]$kwargs
    )
    $name = $kwargs.name
    $admin_display_name = $kwargs.admin_display_name
    $custom_notification_text = $kwargs.custom_notification_text,
    $deliver_message_after_scan = $kwargs.deliver_message_after_scan -as [bool]
    $do_not_allow_click_through = $kwargs.do_not_allow_click_through -as [bool]
    $do_not_rewrite_urls = $kwargs.do_not_rewrite_urls
    $do_not_track_user_clicks = $kwargs.do_not_track_user_clicks -as [bool]
    $enable_for_internal_senders = $kwargs.enable_for_internal_senders -as [bool]
    $enable_organization_branding = $kwargs.enable_organization_branding -as [bool]
    $enable_safe_links_for_teams = $kwargs.enable_safe_links_for_teams -as [bool]
    $is_enabled = $kwargs.is_enabled -as [bool]
    $scan_urls = $kwargs.scan_urls -as [bool]
    $use_translated_notification_text = $kwargs.use_translated_notification_text -as [bool]

    $raw_response = $client.GetPolicyList(
            $identity
    )
    $human_readable = TableToMarkdown $raw_response "Results of $command"
    $entry_context = @{ "$script:INTEGRATION_ENTRY_CONTEXT.PolicyList(obj.Guid === val.Guid)" = $raw_response }
    Write-Output $human_readable, $entry_context, $raw_response
}


function TestModuleCommand($client)
{
    try
    {
        $client.CreateSession()
        $demisto.results("ok")
    }
    finally
    {
        $client.DisconnectSession()
    }

}

function Main {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidUsingConvertToSecureStringWithPlainText", "")]
    param()
    $command = $demisto.GetCommand()
    $command_arguments = $demisto.Args()
    $integration_params = [Hashtable] $demisto.Params()

    if ($integration_params.certificate.password) {
        $password = ConvertTo-SecureString $integration_params.certificate.password -AsPlainText -Force
    }
    else {
        $password = $null
    }

    $exo_client = [ExchangeOnlinePowershellV2Client]::new(
        $integration_params.url,
        $integration_params.app_id,
        $integration_params.organization,
        $integration_params.certificate.identifier,
        $password
    )
    try {
        # Executing command
        $Demisto.Debug("Command being called is $Command")
        switch ($command) {
            "test-module" {
                ($human_readable, $entry_context, $raw_response) = TestModuleCommand $exo_client
            }
            "$script:COMMAND_PREFIX-policy-list" {
                ($human_readable, $entry_context, $raw_response) = GetPolicyListCommand $exo_client $command_arguments
            }
            "$script:COMMAND_PREFIX-policy-create" {
                ($human_readable, $entry_context, $raw_response) = GetEXOMailBoxCommand $exo_client $command_arguments
            }
            "$script:COMMAND_PREFIX-mailbox-permission-list" {
                ($human_readable, $entry_context, $raw_response) = GetEXOMailBoxPermissionCommand $exo_client $command_arguments
            }
            "$script:COMMAND_PREFIX-recipient-permission-list" {
                ($human_readable, $entry_context, $raw_response) = GetEXORecipientPermissionCommand $exo_client $command_arguments
            }
            "$script:COMMAND_PREFIX-recipient-list" {
                ($human_readable, $entry_context, $raw_response) = GetEXORecipientCommand $exo_client $command_arguments
            }
            default {
                ReturnError "Could not recognize $command"
            }
        }
        # Return results to Demisto Server
        ReturnOutputs $human_readable $entry_context $raw_response | Out-Null
    }
    catch {
        $Demisto.debug(
            "Integration: $script:INTEGRATION_NAME
        Command: $command
        Arguments: $( $command_arguments | ConvertTo-Json )
        Error: $( $_.Exception.Message )"
        )
        if ($command -ne "test-module") {
            ReturnError "Error:
            Integration: $script:INTEGRATION_NAME
            Command: $command
            Arguments: $( $command_arguments | ConvertTo-Json )
            Error: $( $_.Exception )"
        }
        else {
            ReturnError $_.Exception.Message
        }
    }
    finally {
        # Always disconnect the session, even if no sessions available.
        $exo_client.DisconnectSession()
    }
}

# Execute Main when not in Tests
if ($MyInvocation.ScriptName -notlike "*.tests.ps1" -AND -NOT$Test) {
    Main
}