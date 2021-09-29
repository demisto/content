Import-Module ExchangeOnlineManagement


$COMMAND_PREFIX = "o365-atp-safe-links"
$INTEGRATION_ENTRY_CONTEXT = "O365ATP.SafeLinks"


function EncloseArgWithQuotes {
    Param (
        [string]$arg_value
    )
    if (!($arg_value)) {
        return ""
    }

    $arrayed_value = $arg_value -split ","

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
        Connect-ExchangeOnline @cmd_params -ShowBanner:$false -WarningAction:SilentlyContinue | Out-Null
    }
    DisconnectSession() {
        Disconnect-ExchangeOnline -Confirm:$false -WarningAction:SilentlyContinue | Out-Null
    }

    [PSObject]
    GetPolicyList(
        [string]$identity
    ) {
        $cmd_params = @{ }
        if ($identity) {
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
    CreateUpdatePolicy(
        [string]$command_type,
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
        
        if (command_type -e "create") {
            $results = New-SafeLinksPolicy @cmd_params
        }
        else {
            $results = Set-SafeLinksPolicy @cmd_params
        }
        
        $this.DisconnectSession()
        return $results

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

    [PSObject]
    RemovePolicy(
        [string]$identity
    ) {
        $cmd_params = @{ }
        if ($identity) {
            $cmd_params.Identity = $identity
        }
        $this.CreateSession()
        $results = Remove-SafeLinksPolicy @cmd_params
        $this.DisconnectSession()
        return $results

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
    GetRules(
        [string]$identity
    ) {
        $cmd_params = @{ }
        if ($identity) {
            $cmd_params.Identity = $identity
        }
        $this.CreateSession()
        $results = Get-SafeLinksRule @cmd_params
        $this.DisconnectSession()
        return $results

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
        PSObject - Raw response

        .LINK
        https://docs.microsoft.com/en-us/powershell/module/exchange/get-safelinksrule?view=exchange-ps
        #>
    }

    [PSObject]
    CreateUpdateRule(
        [string]$command_type,
        [string]$name,
        [string]$safe_links_policy,
        [string]$comments,
        [bool]$enabled,
        [string]$except_if_recipient_domain_is,
        [string]$except_if_sent_to,
        [string]$except_if_sent_to_member_of,
        [Int32]$priority,
        [string]$recipient_domain_is,
        [string]$sent_to,
        [string]$sent_to_member_of

    ) {
        $cmd_params = @{ 
            Name = $name
        }
        if ($safe_links_policy) {
            $cmd_params.SafeLinksPolicy = $safe_links_policy
        }
        if ($comments) {
            $cmd_params.Comments = $comments
        }
        if ($enabled) {
            $cmd_params.Enabled = $enabled
        }
        if ($except_if_recipient_domain_is) {
            $cmd_params.ExceptIfRecipientDomainIs = $except_if_recipient_domain_is
        }
        if ($except_if_sent_to) {
            $cmd_params.ExceptIfSentTo = $except_if_sent_to
        }
        if ($except_if_sent_to_member_of) {
            $cmd_params.ExceptIfSentToMemberOf = $except_if_sent_to_member_of
        }
        if ($priority) {
            $cmd_params.Priority = $priority
        }
        if ($recipient_domain_is) {
            $cmd_params.RecipientDomainIs = $recipient_domain_is
        }
        if ($sent_to) {
            $cmd_params.EnableForInternalSenders = $sent_to
        }
        if ($sent_to_member_of) {
            $cmd_params.SentToMemberOf = $sent_to_member_of
        }
        
        $this.CreateSession()
        
        if (command_type -e "create") {
            $results = New-SafeLinksRule @cmd_params
        }
        else {
            $results = Set-SafeLinksRule @cmd_params
        }
        
        $this.DisconnectSession()
        return $results

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
}


function GetPolicyListCommand {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory)][ExchangeOnlinePowershellV2Client]$client,
        [hashtable]$kwargs
    )
    $identity = EncloseArgWithQuotes($kwargs.identity)
    $raw_response = $client.GetPolicyList(
        $identity
    )
    $human_readable = TableToMarkdown $raw_response "Results of $command"
    $entry_context = @{ "$script:INTEGRATION_ENTRY_CONTEXT.PolicyList(obj.Guid === val.Guid)" = $raw_response }
    Write-Output $human_readable, $entry_context, $raw_response
}

function CreateUpdatePolicyCommand {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory)][ExchangeOnlinePowershellV2Client]$client,
        [Parameter(Mandatory)][string]$command_type,
        [hashtable]$kwargs
    )
    $name = EncloseArgWithQuotes($kwargs.name)
    $admin_display_name = EncloseArgWithQuotes($kwargs.admin_display_name)
    $custom_notification_text = EncloseArgWithQuotes($kwargs.custom_notification_text)
    $deliver_message_after_scan = $kwargs.deliver_message_after_scan -eq "true"
    $do_not_allow_click_through = $kwargs.do_not_allow_click_through -eq "true"
    $do_not_rewrite_urls = EncloseArgWithQuotes($kwargs.do_not_rewrite_urls)
    $do_not_track_user_clicks = $kwargs.do_not_track_user_clicks -eq "true"
    $enable_for_internal_senders = $kwargs.enable_for_internal_senders -eq "true"
    $enable_organization_branding = $kwargs.enable_organization_branding -eq "true"
    $enable_safe_links_for_teams = $kwargs.enable_safe_links_for_teams -eq "true"
    $is_enabled = $kwargs.is_enabled -eq "true"
    $scan_urls = $kwargs.scan_urls -eq "true"
    $use_translated_notification_text = $kwargs.use_translated_notification_text -eq "true"

    $raw_response = $client.CreateUpdatePolicy(
        $command_type,
        $name,
        $admin_display_name,
        $custom_notification_text,
        $deliver_message_after_scan,
        $do_not_allow_click_through,
        $do_not_rewrite_urls,
        $do_not_track_user_clicks,
        $enable_for_internal_senders,
        $enable_organization_branding,
        $enable_safe_links_for_teams,
        $is_enabled,
        $scan_urls,
        $use_translated_notification_text
    )
    $human_readable = TableToMarkdown $raw_response "Results of $command"
    $entry_context = @{ "$script:INTEGRATION_ENTRY_CONTEXT.Policy(obj.Guid === val.Guid)" = $raw_response }
    Write-Output $human_readable, $entry_context, $raw_response
}

function RemovePolicyCommand {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory)][ExchangeOnlinePowershellV2Client]$client,
        [hashtable]$kwargs
    )
    $identity = EncloseArgWithQuotes($kwargs.identity)
    $raw_response = $client.RemovePolicy(
        $identity
    )
    $human_readable = TableToMarkdown $raw_response "Results of $command"
    $entry_context = @{ "$script:INTEGRATION_ENTRY_CONTEXT.Policy(obj.Guid === val.Guid)" = $raw_response }
    Write-Output $human_readable, $entry_context, $raw_response
}

function GetRulesCommand {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory)][ExchangeOnlinePowershellV2Client]$client,
        [hashtable]$kwargs
    )
    $identity = EncloseArgWithQuotes($kwargs.identity)
    $raw_response = $client.GetRules(
        $identity
    )
    $human_readable = TableToMarkdown $raw_response "Results of $command"
    $entry_context = @{ "$script:INTEGRATION_ENTRY_CONTEXT.Policy(obj.Guid === val.Guid)" = $raw_response }
    Write-Output $human_readable, $entry_context, $raw_response
}

function CreateUpdateRuleCommand {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory)][ExchangeOnlinePowershellV2Client]$client,
        [Parameter(Mandatory)][string]$command_type,
        [hashtable]$kwargs
    )
    $name = EncloseArgWithQuotes($kwargs.name)
    $safe_links_policy = EncloseArgWithQuotes($kwargs.safe_links_policy)
    $comments = EncloseArgWithQuotes($kwargs.comments)
    $enabled = $kwargs.enabled -eq "true"
    $except_if_recipient_domain_is = EncloseArgWithQuotes($kwargs.except_if_recipient_domain_is)
    $except_if_sent_to = EncloseArgWithQuotes($kwargs.except_if_sent_to)
    $except_if_sent_to_member_of = EncloseArgWithQuotes($kwargs.except_if_sent_to_member_of)
    $priority = $kwargs.enable_for_internal_senders -as [Int32]
    $recipient_domain_is = EncloseArgWithQuotes($kwargs.recipient_domain_is)
    $sent_to = EncloseArgWithQuotes($kwargs.sent_to)
    $sent_to_member_of = EncloseArgWithQuotes($kwargs.sent_to_member_of)

    $raw_response = $client.CreateUpdateRule(
        $command_type,
        $name,
        $safe_links_policy,
        $comments,
        $enabled,
        $except_if_recipient_domain_is,
        $except_if_sent_to,
        $except_if_sent_to_member_of,
        $priority,
        $recipient_domain_is,
        $sent_to,
        $sent_to_member_of
    )
    $human_readable = TableToMarkdown $raw_response "Results of $command"
    $entry_context = @{ "$script:INTEGRATION_ENTRY_CONTEXT.Policy(obj.Guid === val.Guid)" = $raw_response }
    Write-Output $human_readable, $entry_context, $raw_response
}
function TestModuleCommand($client) {
    try {
        $client.CreateSession()
        $demisto.results("ok")
    }
    finally {
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
                ($human_readable, $entry_context, $raw_response) = CreateUpdatePolicyCommand $exo_client "create" $command_arguments
            }
            "$script:COMMAND_PREFIX-policy-update" {
                ($human_readable, $entry_context, $raw_response) = CreateUpdatePolicyCommand $exo_client "update" $command_arguments
            }
            "$script:COMMAND_PREFIX-policy-remove" {
                ($human_readable, $entry_context, $raw_response) = RemovePolicyCommand $exo_client $command_arguments
            }
            "$script:COMMAND_PREFIX-rule-list" {
                ($human_readable, $entry_context, $raw_response) = GetRulesCommand $exo_client $command_arguments
            }
            "$script:COMMAND_PREFIX-rule-create" {
                ($human_readable, $entry_context, $raw_response) = CreateUpdateRuleCommand $exo_client "create" $command_arguments
            }
            "$script:COMMAND_PREFIX-rule-update" {
                ($human_readable, $entry_context, $raw_response) = CreateUpdateRuleCommand $exo_client "update" $command_arguments
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