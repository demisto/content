Import-Module ExchangeOnlineManagement
. $PSScriptRoot\CommonServerPowerShell.ps1

$COMMAND_PREFIX = "o365-defender-safelinks"
$INTEGRATION_ENTRY_CONTEXT = "O365Defender.SafeLinks"

function CreateContextForReport{
    Param(
        $raw_response
    )
    $context_data = @{"Data"=$raw_response}
    if ($raw_response -is [array]) {
        # RunSapceId is the same for all items in data.
        $context_data.ReportId=$raw_response[0].RunspaceId
    }

    else {
        $context_data.ReportId=$raw_response.RunspaceId
    }

    return $context_data
}
    <#
    .DESCRIPTION
    Create context data for report commands. Where the context is divided to "Data" and "ReportId"

    .PARAMETER arg_value
    The raw value of the response.

    .EXAMPLE
    CreateContextForReport {field="data_1";RunspaceId="1"} -> {"Data"={field="data_1";RunspaceId="1"};
                                                               "ReportId" = "1"}
    #>

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
        Connect-ExchangeOnline @cmd_params -CommandName Get-SafeLinksPolicy,New-SafeLinksPolicy,Set-SafeLinksPolicy,Remove-SafeLinksPolicy,Get-SafeLinksRule,New-SafeLinksRule,Set-SafeLinksRule,Get-SafeLinksDetailReport,Get-SafeLinksAggregateReport,Get-AtpPolicyForO365,Set-AtpPolicyForO365 -ShowBanner:$false -WarningAction:SilentlyContinue | Out-Null
    }
    DisconnectSession() {
        Disconnect-ExchangeOnline -Confirm:$false -WarningAction:SilentlyContinue -InformationAction:Ignore | Out-Null
    }

    [PSObject]
    GetPolicyList(
        [string]$identity
    ) {
        try
        {
            $cmd_params = @{ }
            if ($identity)
            {
                $cmd_params.Identity = $identity
            }
            $this.CreateSession()
            $results = Get-SafeLinksPolicy @cmd_params
            return $results
        }
        finally {
            $this.DisconnectSession()
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
    CreateUpdatePolicy(
        [string]$command_type,
        [hashtable]$kwargs
    ) {
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
            $this.DisconnectSession()
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
            Remove-SafeLinksPolicy -Identity $identity -Confirm:$false -WarningAction:SilentlyContinue > $null
        }

        finally
        {
            $this.DisconnectSession()
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
    GetRules(
        [string]$identity,
        [string]$state
    ) {
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
            $results = Get-SafeLinksRule @cmd_params

            return $results

        }
        finally
        {
            $this.DisconnectSession()
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
    CreateUpdateRule(
        [string]$command_type,
        [hashtable]$kwargs
    ) {
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
                $results = New-SafeLinksRule @cmd_params
            }
            else {
                $results = Set-SafeLinksRule @cmd_params
            }
            return $results
        }
        finally {
            $this.DisconnectSession()
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
    GetSafeLinksDetailReport(
        [hashtable]$kwargs
    ) {
        try
        {
            $cmd_params = @{
                "StartDate" = $kwargs.start_date
                "EndDate" = $kwargs.end_date
            }
            if ($kwargs.domain) {
                $cmd_params.Domain = $kwargs.domain
            }
            if ($kwargs.app_names) {
                $cmd_params.AppNameList = ArgToList($kwargs.app_names)
            }
            if ($kwargs.action) {
                $cmd_params.Action = $kwargs.action
            }
            if ($kwargs.recipient_address) {
                $cmd_params.RecipientAddress = ArgToList($kwargs.recipient_address)
            }
            if ($kwargs.page) {
                $cmd_params.Page = [int]$kwargs.page
            }
            if ($kwargs.page_size) {
                $cmd_params.PageSize = [int]$kwargs.page_size
            }

            $this.CreateSession()
            $results = Get-SafeLinksDetailReport @cmd_params

            return $results

        }
        finally
        {
            $this.DisconnectSession()
        }

        <#
        .DESCRIPTION
        Use this cmdlet to view Safe Links report in your cloud-based organization.
        This cmdlet is available only in the cloud-based service.

        .OUTPUTS
        PSObject- Raw response

        .LINK
        https://docs.microsoft.com/en-us/powershell/module/exchange/get-safelinksdetailreport?view=exchange-ps
        #>
    }
    [PSObject]
    GetSafeLinksAggregateReport(
        [hashtable]$kwargs
    ) {
        try
        {
            $cmd_params = @{
                "StartDate" = $kwargs.start_date
                "EndDate" = $kwargs.end_date
            }
            if ($kwargs.app_names) {
                $cmd_params.AppNameList = ArgToList($kwargs.app_names)
            }
            if ($kwargs.action) {
                $cmd_params.Action = $kwargs.action
            }
            if ($kwargs.summerize_by) {
                $cmd_params.SummarizeBy = $kwargs.summerize_by
            }

            $this.CreateSession()
            $results = Get-SafeLinksAggregateReport @cmd_params

            return $results

        }
        finally
        {
            $this.DisconnectSession()
        }

        <#
        .DESCRIPTION
        Use this cmdlet to view Safe Links report in your cloud-based organization.
        This cmdlet is available only in the cloud-based service.

        .OUTPUTS
        PSObject- Raw response

        .LINK
        https://docs.microsoft.com/en-us/powershell/module/exchange/get-safelinksaggregatereport?view=exchange-ps
        #>
    }
    [PSObject]
    GetAtpPolicy() {
        try{
            $this.CreateSession()
            $results = Get-AtpPolicyForO365
            return $results
        }
        finally {
            $this.DisconnectSession()
        }
        <#
        .DESCRIPTION
        Use this cmdlet to get the ATP policy.

        .OUTPUTS
        PSObject- Raw response

        .LINK
        https://docs.microsoft.com/en-us/powershell/module/exchange/get-atppolicyforo365
        #>
    }
    [PSObject]
    SetAtpPolicy(
        [hashtable]$kwargs
    ) {
        try{
            $cmd_params = @{}
            if ($kwargs.allow_safe_docs_open) {
                $cmd_params.AllowSafeDocsOpen = ConvertTo-Boolean $kwargs.allow_safe_docs_open
            }
            if ($kwargs.enable_atp_spo_teams_odb) {
                $cmd_params.EnableATPForSPOTeamsODB = ConvertTo-Boolean $kwargs.enable_atp_spo_teams_odb
            }
            if ($kwargs.enable_safe_docs) {
                $cmd_params.EnableSafeDocs = ConvertTo-Boolean $kwargs.enable_safe_docs
            }
            $this.CreateSession()
            $results = Set-AtpPolicyForO365 @cmd_params
            return $results
        }
        finally {
            $this.DisconnectSession()
        }
        <#
        .DESCRIPTION
        Use this cmdlet to set the ATP policy.

        .OUTPUTS
        PSObject- Raw response

        .LINK
        https://docs.microsoft.com/en-us/powershell/module/exchange/set-atppolicyforo365
        #>
    }
}


function GetPolicyListCommand {
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    Param (
        [Parameter(Mandatory)][ExchangeOnlinePowershellV2Client]$client,
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
        [Parameter(Mandatory)][ExchangeOnlinePowershellV2Client]$client,
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
        [Parameter(Mandatory)][ExchangeOnlinePowershellV2Client]$client,
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
        [Parameter(Mandatory)][ExchangeOnlinePowershellV2Client]$client,
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
        [Parameter(Mandatory)][ExchangeOnlinePowershellV2Client]$client,
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

function GetDetailedReportCommand {
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    Param (
        [Parameter(Mandatory)][ExchangeOnlinePowershellV2Client]$client,
        [hashtable]$kwargs
    )

    $raw_response = $client.GetSafeLinksDetailReport($kwargs)
    if (!$raw_response){
        return "#### No records were found.", @{}, @{}
    }

    $human_readable = TableToMarkdown $raw_response "Results of $command"
    $entry_context = @{ "$script:INTEGRATION_ENTRY_CONTEXT.DetailedReport" = CreateContextForReport $raw_response }
    return $human_readable, $entry_context, $raw_response
}

function GetAggregateReportCommand {
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    Param (
        [Parameter(Mandatory)][ExchangeOnlinePowershellV2Client]$client,
        [hashtable]$kwargs
    )

    $raw_response = $client.GetSafeLinksAggregateReport($kwargs)
    if (!$raw_response){
        return "#### No records were found.", @{}, @{}
    }

    $human_readable = TableToMarkdown $raw_response "Results of $command"
    $entry_context = @{ "$script:INTEGRATION_ENTRY_CONTEXT.AggregateReport" = CreateContextForReport $raw_response }
    return $human_readable, $entry_context, $raw_response
}

function GetAtpPolicyCommand {
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    Param (
        [Parameter(Mandatory)][ExchangeOnlinePowershellV2Client]$client
    )

    $raw_response = $client.GetAtpPolicy()
    if (!$raw_response){
        return "#### No records were found.", @{}, @{}
    }
    $human_readable = TableToMarkdown $raw_response "Results of $command"
    $entry_context = @{ "$script:INTEGRATION_ENTRY_CONTEXT.AtpPolicy(obj.Guid === val.Guid)" = $raw_response }
    return $human_readable, $entry_context, $raw_response

}

function SetAtpPolicyCommand {
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    Param (
        [Parameter(Mandatory)][ExchangeOnlinePowershellV2Client]$client,
        [hashtable]$kwargs
    )

    $raw_response = $client.SetAtpPolicy($kwargs)
    if (!$raw_response){
        return "#### SetAtpPolicyCommand finished with no output.", @{}, @{}
    }
    $human_readable = TableToMarkdown $raw_response "Results of $command"
    $entry_context = @{ "$script:INTEGRATION_ENTRY_CONTEXT.AtpPolicy(obj.Guid === val.Guid)" = $raw_response }
    return $human_readable, $entry_context, $raw_response
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
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingConvertToSecureStringWithPlainText', '')]
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
        $Demisto.Debug("Command being called is $command")
        switch ($command) {
            "test-module" {
                ($human_readable, $entry_context, $raw_response) = TestModuleCommand $exo_client
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
            "$script:COMMAND_PREFIX-detailed-report-get" {
                ($human_readable, $entry_context, $raw_response) = GetDetailedReportCommand -client $exo_client -kwargs $command_arguments
            }
            "$script:COMMAND_PREFIX-aggregate-report-get" {
                ($human_readable, $entry_context, $raw_response) = GetAggregateReportCommand -client $exo_client -kwargs $command_arguments
            }
            "$script:COMMAND_PREFIX-atp-policy-get" {
                ($human_readable, $entry_context, $raw_response) = GetAtpPolicyCommand -client $exo_client
            }
            "$script:COMMAND_PREFIX-atp-policy-set" {
                ($human_readable, $entry_context, $raw_response) = SetAtpPolicyCommand -client $exo_client -kwargs $command_arguments
            }

            default {
                ReturnError "Could not recognize $command"
            }
        }
        # Return results to Demisto Server
        ReturnOutputs $human_readable $entry_context $raw_response
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