. $PSScriptRoot\CommonServerPowerShell.ps1
<# IMPORTANT NOTICE
# When conencting to ExchangeOnline - only needed command between CreateSession
# and DisconnectSession and let also the `finally` term to disconnect (it will do nothing if everything is fine).
# This will reduce the time sessions are opened between Exchange and the server and will create
# less problems.
# DO NOT USE ONE FINALLY STATEMENT: we don't know if and when it'll be executed and anyway it the DisconnectSession
# should be called before returning results to the server.
#>
Import-Module ExchangeOnlineManagement

# Disable PowerShell progress bars, as they aren't helpful in a non-interactive script
$Global:ProgressPreference = 'SilentlyContinue'

$script:INTEGRATION_NAME = "EWS extension"
$script:COMMAND_PREFIX = "ews"
$script:INTEGRATION_ENTRY_CONTEXT = "EWS"
$script:JUNK_RULE_ENTRY_CONTEXT = "$script:INTEGRATION_ENTRY_CONTEXT.Rule.Junk(val.Email && val.Email == obj.Email)"
$script:MESSAGE_TRACE_ENTRY_CONTEXT = "$script:INTEGRATION_ENTRY_CONTEXT.MessageTrace(val.MessageId && val.MessageId == obj.MessageId)"


function ParseJunkRulesToEntryContext([PSObject]$raw_response) {
    return @{
        $script:JUNK_RULE_ENTRY_CONTEXT = @{
            "MailboxOwnerId"              = $raw_response.MailboxOwnerId
            "Identity"                    = $raw_response.Identity
            "BlockedSendersAndDomains"    = $raw_response.BlockedSendersAndDomains
            "TrustedRecipientsAndDomains" = $raw_response.TrustedRecipientsAndDomains
            "TrustedSendersAndDomains"    = $raw_response.TrustedSendersAndDomains
            "TrustedListsOnly"            = $raw_response.TrustedListsOnly
            "ContactsTrusted"             = $raw_response.ContactsTrusted
            "Enabled"                     = $raw_response.Enabled
        }
    }

    <#
        .DESCRIPTION
        Parse junk rules raw response.

        .PARAMETER raw_response
        Junk rules raw response.

        .EXAMPLE
        ParseJunkRulesToEntryContext $raw_response

        .OUTPUTS
        PSObject - entry context.
    #>
}


function ParseMessageTraceToEntryContext([PSObject]$raw_response) {
    $entry_context = @{}
    if ($raw_response) {
        $entry_context = @{
            $script:MESSAGE_TRACE_ENTRY_CONTEXT = $raw_response | ForEach-Object {
                @{
                    "MessageId"        = $_.MessageId
                    "MessageTraceId"   = $_.MessageTraceId
                    "Organization"     = $_.Organization
                    "Received"         = $_.Received
                    "RecipientAddress" = $_.RecipientAddress
                    "SenderAddress"    = $_.SenderAddress
                    "Size"             = $_.Size
                    "StartDate"        = $_.StartDate
                    "EndDate"          = $_.EndDate
                    "Status"           = $_.Status
                    "Subject"          = $_.Subject
                    "ToIP"             = $_.ToIP
                    "FromIP"           = $_.FromIP
                    "Index"            = $_.Index
                }
            }
        }
    }

    return $entry_context
    <#
        .DESCRIPTION
        Parse message trace raw response.

        .PARAMETER raw_response
        Message trace raw response.

        .EXAMPLE
        ParseMessageTraceToEntryContext $raw_response

        .OUTPUTS
        PSObject - entry context.
    #>
}


class ExchangeOnlinePowershellV3Client
{
    [string]$url
    [System.Security.Cryptography.X509Certificates.X509Certificate2]$certificate
    [string]$organization
    [string]$app_id
    [SecureString]$password
    ExchangeOnlinePowershellV3Client(
            [string]$url,
            [string]$app_id,
            [string]$organization,
            [string]$certificate,
            [SecureString]$password
    )
    {
        $this.url = $url
        try
        {
            $ByteArray = [System.Convert]::FromBase64String($certificate)
        }
        catch
        {
            throw "Could not decode the certificate. Try to re-enter it"
        }
        $this.certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($ByteArray, $password)

        $this.organization = $organization
        $this.app_id = $app_id
    }
    CreateSession()
    {
        $cmd_params = @{
            "AppID" = $this.app_id
            "Organization" = $this.organization
            "Certificate" = $this.certificate
        }
        Connect-ExchangeOnline @cmd_params -ShowBanner:$false -CommandName New-TenantAllowBlockListItems,Get-TenantAllowBlockListItems,Remove-TenantAllowBlockListItems,Get-RemoteDomain,Get-MailboxAuditBypassAssociation,Get-User,Get-FederatedOrganizationIdentifier,Get-FederationTrust,Get-MessageTrace,Set-MailboxJunkEmailConfiguration,Get-Mailbox,Get-MailboxJunkEmailConfiguration -WarningAction:SilentlyContinue | Out-Null
    }
    DisconnectSession()
    {
        Disconnect-ExchangeOnline -Confirm:$false -WarningAction:SilentlyContinue 6>$null | Out-Null
    }
    [PSObject]
    GetEXOCASMailbox(
            [string]$identity,
            [string]$organizational_unit,
            [string]$primary_smtp_address,
            [string]$user_principal_name,
            [int]$limit
    )
    {
        $cmd_params = @{ }
        if ($identity)
        {
            $cmd_params.Identity = $identity
        }
        if ($organizational_unit)
        {
            $cmd_params.OrganizationalUnit = $organizational_unit
        }
        if ($primary_smtp_address)
        {
            $cmd_params.PrimarySmtpAddress = $primary_smtp_address
        }
        if ($user_principal_name)
        {
            $cmd_params.UserPrincipalName = $user_principal_name
        }
        $this.CreateSession()
        if ($limit -gt 0)
        {
            $results = Get-EXOCASMailbox @cmd_params -ResultSize $limit
        }
        else
        {
            $results = Get-EXOCASMailbox @cmd_params -ResultSize Unlimited
        }
        $this.DisconnectSession()
        return $results

        <#
        .DESCRIPTION
        This cmdlet returns a variety of client access settings for one or more mailboxes.
        These settings include options for Outlook on the web, Exchange ActiveSync, POP3, and IMAP4.
        This cmdlet is available only in the Exchange Online PowerShell V2 module.

        .PARAMETER identity
        The Identity parameter specifies the mailbox you want to view.
        For the best performance, we recommend using the following values:
            * User ID or user principal name (UPN)
            * GUID

        Otherwise, you can use any value that uniquely identifies the mailbox. For example:
            * Name
            * Alias
            * Distinguished name (DN)
            * Domain\Username
            * Email address
            * LegacyExchangeDN
            * SamAccountName

        .PARAMETER organizational_unit
        The OrganizationalUnit parameter filters the results based on the object's location in Active Directory.

        .PARAMETER primary_smtp_address
        The PrimarySmtpAddress identifies the mailbox that you want to view by primary SMTP email address (for example, navin@contoso.onmicrosoft.com).
        Can't be used with user_principal_name.

        .PARAMETER user_principal_name
        The UserPrincipalName parameter identifies the mailbox that you want to view by UPN (for example, navin@contoso.onmicrosoft.com).
        Can't be used with primary_smtp_address.

        .EXAMPLE
        GetEXOCasMailbox("1254y894-feae-9yn7-a3e1-f2483a154tft")

        .OUTPUTS
        PSObject - Raw response

        .LINK
        https://docs.microsoft.com/en-us/powershell/module/exchange/get-exocasmailbox?view=exchange-ps
        #>
    }

    [PSObject]
    GetEXOMailbox(
            [string]$identity,
            [string]$property_sets,
            [int]$limit
    )
    {
        $cmd_params = @{ }
        if ($identity)
        {
            $cmd_params.Identity = $identity
        }
        if ($property_sets)
        {
            $cmd_params.PropertySets = $property_sets
        }
        $this.CreateSession()
        if ($limit -gt 0)
        {
            $results = Get-EXOMailbox @cmd_params -ResultSize $limit
        }
        else
        {
            $results = Get-EXOMailbox @cmd_params -ResultSize Unlimited
        }
        $this.DisconnectSession()
        return $results
        <#
        .DESCRIPTION
        Use the Get-EXOMailbox cmdlet to view mailbox objects and attributes,
        populate property pages, or supply mailbox information to other tasks.
        This cmdlet is available only in the Exchange Online PowerShell V2 module

        .PARAMETER identity
        The Identity parameter specifies the mailbox you want to view.
        For the best performance, we recommend using the following values:
            * User ID or user principal name (UPN)
            * GUID

        Otherwise, you can use any value that uniquely identifies the mailbox. For example:
            * Name
            * Alias
            * Distinguished name (DN)
            * Domain\Username
            * Email address
            * LegacyExchangeDN
            * SamAccountName

        .EXAMPLE
        GetEXOMailbox("1254y894-feae-9yn7-a3e1-f2483a154tft")

        .OUTPUTS
        PSObject - Raw response

        .LINK
        https://docs.microsoft.com/en-us/powershell/module/exchange/get-exomailbox?view=exchange-ps
        #>
    }

    [PSObject]
    GetEXOMailboxPermission(
            [string]$identity
    )
    {
        # Import and Execute command
        $cmd_params = @{ }
        if ($identity)
        {
            $cmd_params.Identity = $identity
        }
        $this.CreateSession()
        $results = Get-EXOMailboxPermission @cmd_params
        $this.DisconnectSession()
        return $results

        <#
        .DESCRIPTION
        View information about SendAs permissions that are configured for users.
        This command is available only in the Exchange Online PowerShell V2 module.

        .PARAMETER identity
        The Identity parameter the user that you want to view. You can use any value that uniquely identifies the user

        .EXAMPLE
        GetEXOMailboxPermission("1254y894-feae-9yn7-a3e1-f2483a154tft")

        .OUTPUTS
        PSObject - Raw response

        .LINK
        https://docs.microsoft.com/en-us/powershell/module/exchange/get-exomailboxpermission?view=exchange-ps
        #>
    }
    [PSObject]
    GetEXORecipientPermission(
            [string]$identity,
            [int]$limit
    )
    {
        $this.CreateSession()

        $cmd_params = @{ }
        if ($identity) {
            $cmd_params.Identity = $identity
        }
        if ($limit -gt 0) {
            $cmd_params.ResultSize = $limit
        } else  {
            $cmd_params.ResultSize = Unliimited
        }
        $results = Get-EXORecipientPermission @cmd_params

        $this.DisconnectSession()
        return $results
        <#
        .DESCRIPTION
        Use the Get-EXORecipientPermission cmdlet to view information about SendAs permissions that are
        configured for users in a cloud-based organization.
        This command is available only in the Exchange Online PowerShell V2 module

        .PARAMETER identity
        The Identity parameter specifies the mailbox you want to view.
        For the best performance, we recommend using the following values:
            * User ID or user principal name (UPN)
            * GUID

        Otherwise, you can use any value that uniquely identifies the mailbox. For example:
            * Name
            * Alias
            * Distinguished name (DN)
            * Domain\Username
            * Email address
            * LegacyExchangeDN
            * SamAccountName
        #>
    }
    [PSObject]
    GetEXORecipient(
            [string]$identity,
            [int]$limit
    )
    {
        $cmd_params = @{ Properties="Guid" }
        if ($identity)
        {
            $cmd_params.Identity = $identity
        }
        $this.CreateSession()
        if ($limit -gt 0)
        {
            $results = Get-EXORecipient @cmd_params -ResultSize $limit
        }
        else
        {
            $results = Get-EXORecipient @cmd_params -ResultSize Unlimited
        }
        $this.DisconnectSession()
        return $results
        <#
            .DESCRIPTION
            Use the Get-ExORecipient cmdlet to view existing recipient objects in your organization.
            This cmdlet returns all mail-enabled objects (for example,
            mailboxes, mail users, mail contacts, and distribution groups).

            #>
    }

    [PSObject]
    EXONewTenantAllowBlockList(
            [string]$entries,
            [string]$list_type,
            [string]$list_subtype,
            [string]$action,
            [string]$notes,
            [bool]$no_expiration,
            [string]$expiration_date
    )
    {
        $cmd_params = @{ }
        $entries_array = @()
        if ($entries.Contains(','))
        {
            $entries_array = $entries -split ','
        }
        if ($entries -and -not $entries_array)
        {
            $entries_array += $entries
            $cmd_params.Entries = $entries_array
        }
        else
        {
            $cmd_params.Entries = $entries_array
        }
        if ($list_type)
        {
            $cmd_params.ListType = $list_type
        }
        if ($list_subtype)
        {
            $cmd_params.ListSubType = $list_subtype
        }
        if ($notes)
        {
            $cmd_params.Notes = $notes
        }
        if ($no_expiration)
        {
            $cmd_params.NoExpiration = $null
        }
        if ($expiration_date)
        {
            $cmd_params.ExpirationDate = $expiration_date
        }
        if ($action -eq "Block")
        {
            $cmd_params.Block = $null
        }
        if ($action -eq "Allow")
        {
            $cmd_params.Allow = $null
        }
        $this.CreateSession()
        $results = New-TenantAllowBlockListItems @cmd_params
        $this.DisconnectSession()
        return $results
        <#
            .DESCRIPTION
            Use the New-TenantAllowBlockListItems cmdlet to add new entries to the Tenant Allow/Block Lists for your organization.
            This cmdlet returns all new entries created, details about them, and their status

            .LINK
            https://learn.microsoft.com/en-us/powershell/module/exchange/new-tenantallowblocklistitems?view=exchange-ps

        #>
    }

    [PSObject]
    EXORemoveTenantAllowBlockList(
            [string]$entries,
            [string]$ids,
            [string]$list_type,
            [string]$list_subtype
    )
    {
        $cmd_params = @{ }
        $entries_array = @()
        $ids_array = @()
        if ($entries.Contains(','))
        {
            $entries_array = $entries -split ','
        }
        if ($entries -and -not $entries_array)
        {
            $entries_array += $entries
            $cmd_params.Entries = $entries_array
        }
        elseif ($entries_array)
        {
            $cmd_params.Entries = $entries_array
        }
        if ($ids -and $ids.Contains(','))
        {
            $ids_array = $ids -split ','
        }
        if ($ids_array)
        {
            $cmd_params.Ids = $ids_array
        }
        if ($list_type)
        {
            $cmd_params.ListType = $list_type
        }
        if ($list_subtype)
        {
            $cmd_params.ListSubType = $list_subtype
        }
        $this.CreateSession()
        $results = Remove-TenantAllowBlockListItems @cmd_params
        $this.DisconnectSession()
        return $results
        <#
            .DESCRIPTION
            Use the New-TenantAllowBlockListItems cmdlet to add new entries to the Tenant Allow/Block Lists for your organization.
            This cmdlet returns all new entries created, details about them, and their status

            .LINK
            https://learn.microsoft.com/en-us/powershell/module/exchange/remove-tenantallowblocklistitems?view=exchange-ps

        #>
    }

    [PSObject]
    EXOGetTenantAllowBlockList(
            [string]$entry,
            [string]$list_type,
            [string]$list_subtype,
            [string]$action,
            [bool]$no_expiration,
            [string]$expiration_date
    )
    {
        $results = ""
        try {
            $cmd_params = @{ }
            if ($entry)
            {
                $cmd_params.Entry = $entry
            }
            if ($list_type)
            {
                $cmd_params.ListType = $list_type
            }
            if ($list_subtype)
            {
                $cmd_params.ListSubType = $list_subtype
            }
            if ($no_expiration)
            {
                $cmd_params.NoExpiration = $null
            }
            if ($expiration_date)
            {
                $cmd_params.ExpirationDate = $expiration_date
            }
            if ($action -eq "Block")
            {
                $cmd_params.Block = $null
            }
            if ($action -eq "Allow")
            {
                $cmd_params.Allow = $null
            }
            $this.CreateSession()
            $results = Get-TenantAllowBlockListItems @cmd_params
        }
        finally {
            $this.DisconnectSession()
        }
        return $results
        <#
            .DESCRIPTION
            Use the Get-TenantAllowBlockListItems cmdlet to retrieve current entries in the Tenant Allow/Block Lists for your organization.
            This cmdlet returns current entries and details about them.

            .LINK
            https://learn.microsoft.com/en-us/powershell/module/exchange/get-tenantallowblocklistitems?view=exchange-ps

        #>
    }
    [psobject]GetJunkRules([string]$mailbox) {
        $response = ''
        try {
            # Establish session to remote
            $this.CreateSession()
            # Import and Execute command
            $cmd_params = @{
                "Identity" = $mailbox
            }
            $response = Get-MailboxJunkEmailConfiguration @cmd_params
        }
        finally {
            # Close session to remote
            $this.DisconnectSession()
        }
        return $response
        <#
            .DESCRIPTION
            Get junk rules in mailbox.

            .PARAMETER mailbox
            Mailbox ID.

            .EXAMPLE
            $client.GetJunkRules("test@microsoft.com")

            .OUTPUTS
            psobject - Raw response.

            .LINK
            https://docs.microsoft.com/en-us/powershell/module/exchange/get-mailboxjunkemailconfiguration?view=exchange-ps
        #>
    }

    SetJunkRules([string]$mailbox, [string[]]$add_blocked_senders_and_domains, [string[]]$remove_blocked_senders_and_domains,
        [string[]]$add_trusted_senders_and_domains, [string[]]$remove_trusted_senders_and_domains,
        [bool]$trusted_lists_only, [bool]$contacts_trusted, [bool]$enabled) {
        try {
            # Establish session to remote
            $this.CreateSession()
            # Import and Execute command
            $cmd_params = @{
                "Identity"                 = $mailbox
                "BlockedSendersAndDomains" = @{Add = $add_blocked_senders_and_domains
                    Remove                         = $remove_blocked_senders_and_domains
                }
                "TrustedSendersAndDomains" = @{Add = $add_trusted_senders_and_domains
                    Remove                         = $remove_trusted_senders_and_domains
                }
                "TrustedListsOnly"         = $trusted_lists_only
                "ContactsTrusted"          = $contacts_trusted
                "Enabled"                  = $enabled
                "Confirm"                  = $false
            }
            Set-MailboxJunkEmailConfiguration @cmd_params
        }
        finally {
            # Close session to remote
            $this.DisconnectSession()
        }
        <#
            .DESCRIPTION
            Set junk rules in mailbox.

            .PARAMETER mailbox
            Mailbox ID.

            .PARAMETER add_blocked_senders_and_domains
            Blocked senders and domains (Comma separated).

            .PARAMETER remove_blocked_senders_and_domains
            Blocked senders and domains (Comma separated) to remove.

            .PARAMETER add_trusted_senders_and_domains
            Trusted senders and domains (Comma separated).

            .PARAMETER remove_trusted_senders_and_domains
            Trusted senders and domains (Comma separated) to remove.

            .PARAMETER trusted_lists_only
            Whether to trust only list of defined in trusted lists.

            .PARAMETER contacts_trusted
            Whether contacts trusted by default.

            .PARAMETER enabled
            Whether junk rule is enabled.

            .OUTPUTS
            psobject - Raw response.

            .LINK
            https://docs.microsoft.com/en-us/powershell/module/exchange/set-mailboxjunkemailconfiguration?view=exchange-ps
        #>
    }

    SetGlobalJunkRules([string]$mailbox, [string[]]$add_blocked_senders_and_domains, [string[]]$remove_blocked_senders_and_domains,
        [string[]]$add_trusted_senders_and_domains, [string[]]$remove_trusted_senders_and_domains,
        [bool]$trusted_lists_only, [bool]$contacts_trusted, [bool]$enabled) {
        try {
            # Establish session to remote
            $this.CreateSession()
            # Import and Execute command
            $cmd_params = @{
                "BlockedSendersAndDomains" = @{Add = $add_blocked_senders_and_domains
                    Remove                         = $remove_blocked_senders_and_domains
                }
                "TrustedSendersAndDomains" = @{Add = $add_trusted_senders_and_domains
                    Remove                         = $remove_trusted_senders_and_domains
                }
                "TrustedListsOnly"         = $trusted_lists_only
                "ContactsTrusted"          = $contacts_trusted
                "Enabled"                  = $enabled
                "Confirm"                  = $false
            }
            Get-Mailbox -RecipientTypeDetails UserMailbox -ResultSize Unlimited | ForEach-Object {
                Set-MailboxJunkEmailConfiguration -Identity $_.Name @cmd_params
            }
        }
        finally {
            # Close session to remote
            $this.DisconnectSession()
        }
        <#
            .DESCRIPTION
            Set junk rules in all managed accounts.

            .PARAMETER add_blocked_senders_and_domains
            Blocked senders and domains (Comma separated).

            .PARAMETER remove_blocked_senders_and_domains
            Blocked senders and domains (Comma separated) to remove.

            .PARAMETER add_trusted_senders_and_domains
            Trusted senders and domains (Comma separated).

            .PARAMETER remove_trusted_senders_and_domains
            Trusted senders and domains (Comma separated) to remove.

            .PARAMETER trusted_lists_only
            Whether to trust only list of defined in trusted lists.

            .PARAMETER contacts_trusted
            Whether contacts trusted by default.

            .PARAMETER enabled
            Whether junk rule is enabled.

            .PARAMETER mailbox
            Mailbox ID.

            .OUTPUTS
            psobject - Raw response.

            .LINK
            https://docs.microsoft.com/en-us/exchange/antispam-and-antimalware/antispam-protection/configure-antispam-settings?view=exchserver-2019
        #>
    }

    [PSObject]GetMessageTrace([string[]]$sender_address, [string[]]$recipient_address, [string[]]$from_ip, [string[]]$to_ip, [string[]]$message_id,
        [string]$message_trace_id, [int32]$page, [int32]$page_size, [String]$start_date, [String]$end_date, [string]$status) {
        $response = ""
        try {
            # Establish session to remote
            $this.CreateSession()
            # Import and Execute command
            $cmd_params = @{
                "Page"             = $page
                "PageSize"         = $page_size
            }
            if ($sender_address) {
                $cmd_params.SenderAddress = $sender_address
            }
            if ($recipient_address) {
                $cmd_params.RecipientAddress = $recipient_address
            }
            if ($status) {
                $cmd_params.Status = $status
            }
            if ($start_date) {
                $cmd_params.StartDate = $start_date
                if ($end_date) {
                    $cmd_params.EndDate = $end_date
                }
                else {
                    $cmd_params.EndDate = Get-Date -UFormat "%D %I:%M %p"
                }
            }
            if ($from_ip) {
                $cmd_params.FromIP = $from_ip
            }
            if ($to_ip) {
                $cmd_params.ToIP = $to_ip
            }
            if ($message_id) {
                $cmd_params.MessageId = $message_id
            }
            if ($message_trace_id) {
                $cmd_params.MessageTraceId = $message_trace_id
            }
            $response = Get-MessageTrace @cmd_params
        }
        finally {
            # Close session to remote
            $this.DisconnectSession()
        }
        return $response
        <#
            .DESCRIPTION
            Search message data for the last 10 days.

            .PARAMETER sender_address
            The sender_address parameter filters the results by the sender's email address.

            .PARAMETER recipient_address
            The recipient_address parameter filters the results by the recipient's email address. You can specify multiple values separated by commas.

            .PARAMETER from_ip
            The from_ip parameter filters the results by the source IP address.
            For incoming messages, the value of from_ip is the public IP address of the SMTP email server that sent the message.
            For outgoing messages from Exchange Online, the value is blank.

            .PARAMETER to_ip
            The to_ip parameter filters the results by the destination IP address.
            For outgoing messages, the value of to_ip is the public IP address in the resolved MX record for the destination domain.
            For incoming messages to Exchange Online, the value is blank.

            .PARAMETER message_id
            The message_id parameter filters the results by the Message-ID header field of the message.
            This value is also known as the Client ID. The format of the Message-ID depends on the messaging server that sent the message.
            The value should be unique for each message. However, not all messaging servers create values for the Message-ID in the same way.
            Besure to include the full Message ID string (which may include angle brackets) and enclose the value in quotation marks (for example,"d9683b4c-127b-413a-ae2e-fa7dfb32c69d@DM3NAM06BG401.Eop-nam06.prod.protection.outlook.com").

            .PARAMETER message_trace_id
            The message_trace_id parameter can be used with the recipient address to uniquely identify a message trace and obtain more details.
            A message trace ID is generated for every message that's processed by the system.

            .PARAMETER page
            The page parameter specifies the page number of the results you want to view.
            Valid input for this parameter is an integer between 1 and 1000. The default value is 1.

            .PARAMETER page_size
            The page_size parameter specifies the maximum number of entries per page.
            Valid input for this parameter is an integer between 1 and 5000. The default value is 100.

            .PARAMETER start_date
            The start_date parameter specifies the start date of the date range.
            Use the short date format that's defined in the Regional Options settings on the computer where you're running the command. For example, if the computer is configured to use the short date format mm/dd/yyyy,
            enter 09/01/2018 to specify September 1, 2018. You can enter the date only, or you can enter the date and time of day.
            If you enter the date and time of day, enclose the value in quotation marks ("), for example, "09/01/2018 5:00 PM".
            Valid input for this parameter is from 10 days - now ago. The default value is 48 hours ago.

            .PARAMETER end_date
            The end_date parameter specifies the end date of the date range.
            Use the short date format that's defined in the Regional Options settings on the computer where you're running the command.
            For example, if the computer is configured to use the short date format mm/dd/yyyy, enter 09/01/2018 to specify September 1, 2018.
            You can enter the date only, or you can enter the date and time of day.
            If you enter the date and time of day, enclose the value in quotation marks ("), for example, "09/01/2018 5:00 PM".
            Valid input for this parameter is from start_date - now. The default value is now.

            .PARAMETER status
            * GettingStatus: The message is waiting for status update.
            * Failed: Message delivery was attempted and it failed or the message was filtered as spam or malware, or by transport rules.
            * Pending: Message delivery is underway or was deferred and is being retried.
            * Delivered: The message was delivered to its destination.
            * Expanded: There was no message delivery because the message was addressed to a distribution group and the membership of the distribution was expanded.
            * Quarantined: The message was quarantined.
            * FilteredAsSpam: The message was marked as spam.

            .OUTPUTS
            psobject - Raw response.

            .LINK
            https://docs.microsoft.com/en-us/powershell/module/exchange/get-messagetrace?view=exchange-ps
        #>
    }

    [PSObject]GetFederationTrust(
            [string]$domain_controller,
            [string]$identity
    )
    {
        $response = ""
        try {
            # Establish session to remote
            $this.CreateSession()
            # Import and Execute command
            $cmd_params = @{}
            if ($identity) {
                $cmd_params.Identity = $identity
            }
            if ($domain_controller) {
                $cmd_params.DomainController = $domain_controller
            }
            $response = Get-FederationTrust @cmd_params
        }
        finally {
            $this.DisconnectSession()
        }
        return $response
        <#
        .DESCRIPTION
        Use the Get-FederationTrust cmdlet to view the federation trust configured for the Exchange organization.

        .PARAMETER domain_controller
        This parameter is available only in on-premises Exchange.
        The DomainController parameter specifies the domain controller that's used by this
        cmdlet to read data from or write data to Active Directory. You identify the domain
        controller by its fully qualified domain name (FQDN).
        For example, dc01.contoso.com.

        .PARAMETER identity
        The Identity parameter specifies a federation trust ID. If not specified, the cmdlet returns
        all federation trusts configured for the Exchange organization.

        .EXAMPLE
        GetFederationTrust("dc01.contoso.com", "1254y894-feae-9yn7-a3e1-f2483a154tft")

        .OUTPUTS
        PSObject - Raw response

        .LINK
        https://docs.microsoft.com/en-us/powershell/module/exchange/get-federationtrust?view=exchange-ps
    #>
    }


    [PSObject]GetFederationConfiguration(
        [string]$domain_controller,
        [string]$identity,
        [bool]$include_extended_domain_info
    ) {
        $response = ""
        try {
            # Establish session to remote
            $this.CreateSession()
            # Import and Execute command
            $cmd_params = @{}
            if ($identity) {
                $cmd_params.Identity = $identity
            }
            if ($domain_controller) {
                $cmd_params.DomainController = $domain_controller
            }
            if ($include_extended_domain_info) {
                $cmd_params.IncludeExtendedDomainInfo = $include_extended_domain_info
            }
            $response = Get-FederatedOrganizationIdentifier @cmd_params
        }
        finally {
            $this.DisconnectSession()
        }
        return $response
        <#
        .DESCRIPTION
        Use the Get-FederatedOrganizationIdentifier cmdlet to retrieve the Exchange organization's federated
        organization identifier and related details, such as federated domains, organization contact and status.

        .PARAMETER domain_controller
        This parameter is available only in on-premises Exchange.
        The DomainController parameter specifies the domain controller that's used by this
        cmdlet to read data from or write data to Active Directory. You identify the domain
        controller by its fully qualified domain name (FQDN).
        For example, dc01.contoso.com.

        .PARAMETER identity
        The Identity parameter specifies a federation trust ID. If not specified, the cmdlet returns
        all federation trusts configured for the Exchange organization.

        .PARAMETER include_extended_domain_info
        The IncludeExtendedDomainInfo switch specifies that the command query Microsoft Federation Gateway for the status of each
        accepted domain that's federated. The status is returned with each domain in the Domains property.

        .EXAMPLE
        GetFederationConfiguration("dc01.contoso.com", "1254y894-feae-9yn7-a3e1-f2483a154tft", $true)

        .OUTPUTS
        PSObject - Raw response

        .LINK
        https://docs.microsoft.com/en-us/powershell/module/exchange/get-federatedorganizationidentifier?view=exchange-ps
        #>
    }
    [PSObject]GetUser(
        [string]$identity,
        [string]$organizational_unit,
        [int]$limit
    ) {
        $response = ""
        try
        {
            # Establish session to remote
            $this.CreateSession()
            # Import and Execute command
            $cmd_params = @{ }
            if ($identity)
            {
                $cmd_params.Identity = $identity
            }
            if ($organizational_unit)
            {
                $cmd_params.OrganizationalUnit = $organizational_unit
            }
            if ($limit -gt 0)
            {
                $response = Get-User @cmd_params -ResultSize $limit -WarningAction:SilentlyContinue
            }
            else
            {
                $response = Get-User @cmd_params -ResultSize Unlimited
            }
        } finally {
            $this.DisconnectSession()
        }
        return $response
        <#
        .DESCRIPTION
        Use the Get-User command to view existing user objects in your organization.

        .PARAMETER identity
        The Identity parameter the user that you want to view. You can use any value that uniquely identifies the user

        .PARAMETER orgranizational_unit
        The OrganizationalUnit parameter filters the results based on the object's location in Active Directory.

        .EXAMPLE
        GetUser("user@microsoft.com")

        .OUTPUTS
        PSObject - Raw response

        .LINK
        https://docs.microsoft.com/en-us/powershell/module/exchange/get-user?view=exchange-ps        #>
    }
    [PSObject]GetMailboxAuditBypassAssociation(
        [string]$identity,
        [string]$domain_controller,
        [int]$limit
    )
    {
        $response = ""
        try {
            # Establish session to remote
            $this.CreateSession()
            # Import and Execute command
            $cmd_params = @{ }
            if ($identity) {
                $cmd_params.Identity = $identity
            }
            if ($domain_controller) {
                $cmd_params.DomainController = $domain_controller
            }
            if ($limit -gt 0){
                $cmd_params.ResultSize = $limit
            }
            $response = Get-MailboxAuditBypassAssociation @cmd_params -WarningAction:SilentlyContinue
        } finally {
            $this.DisconnectSession()
        }
        return $response
        <#
        .DESCRIPTION
        Retrieve information about the AuditBypassEnabled property value for user accounts
        (on-premises Exchange and the cloud) and computer accounts (on-premises Exchange only).

        .PARAMETER identity
        The Identity parameter the user that you want to view. You can use any value that uniquely identifies the user

        .PARAMETER domain_controller
        The DomainController parameter specifies the domain controller that's used by this cmdlet to read data from
        or write data to Active Directory. You identify the domain controller by its fully qualified domain name (FQDN).

        .EXAMPLE

        .OUTPUTS
        PSObject - Raw response

        .LINK
        https://docs.microsoft.com/en-us/powershell/module/exchange/get-mailboxauditbypassassociation?view=exchange-ps
        #>
    }

    [PSCustomObject]GetRemoteDomain(
        [string]$domain_controller,
        [string]$identity
    ) {
        $response = ""
        try {
            # Establish session to remote
            $this.CreateSession()
            # Import and Execute command
            $cmd_params = @{}
            if ($identity) {
                $cmd_params.Identity = $identity
            }
            if ($domain_controller) {
                $cmd_params.DomainController = $domain_controller
            }
            return Get-RemoteDomain @cmd_params -WarningAction:SilentlyContinue
        }
        finally {
            $this.DisconnectSession()
        }
        return $response
        <#
        .DESCRIPTION
        Use the Get-RemoteDomain cmdlet to view the configuration information for the remote domains configured in
        your organization.

        .PARAMETER domain_controller
        This parameter is available only in on-premises Exchange.
        The DomainController parameter specifies the domain controller that's used by this
        cmdlet to read data from or write data to Active Directory. You identify the domain
        controller by its fully qualified domain name (FQDN).
        For example, dc01.contoso.com.

        .PARAMETER identity
        The Identity parameter specifies a federation trust ID. If not specified, the cmdlet returns
        all federation trusts configured for the Exchange organization.

        .EXAMPLE
        GetRemoteDomain("1254y894-feae-9yn7-a3e1-f2483a154tft")

        .OUTPUTS
        PSObject - Raw response

        .LINK
        https://docs.microsoft.com/en-us/powershell/module/exchange/get-remotedomain?view=exchange-ps
        #>
    }
}

function GetEXORecipientCommand
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)][ExchangeOnlinePowershellV3Client]$client,
        [hashtable]$kwargs
    )
    $identity = $kwargs.identity
    $limit = $kwargs.limit -as [int]
    $raw_response = $client.GetEXORecipient($identity, $limit)
    $human_readable = TableToMarkdown $raw_response "Results of $command"
    $entry_context = @{ "$script:INTEGRATION_ENTRY_CONTEXT.Recipient(obj.Guid === val.Guid)" = $raw_response }
    Write-Output $human_readable, $entry_context, $raw_response
}

function GetEXORecipientPermissionCommand
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)][ExchangeOnlinePowershellV3Client]$client,
        [hashtable]$kwargs
    )
    $identity = $kwargs.identity
    $limit = $kwargs.limit -as [int]
    $raw_response = $client.GetEXORecipientPermission($identity, $limit)
    $human_readable = TableToMarkdown $raw_response "Results of $command"
    $entry_context = @{ "$script:INTEGRATION_ENTRY_CONTEXT.RecipientPermission(obj.Identity === val.Identity)" = $raw_response }
    Write-Output $human_readable, $entry_context, $raw_response
}

function GetEXOMailBoxPermissionCommand
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)][ExchangeOnlinePowershellV3Client]$client,
        [hashtable]$kwargs
    )
    $identity = $kwargs.identity
    $raw_response = $client.GetEXOMailBoxPermission($identity)
    $human_readable = TableToMarkdown $raw_response "Results of $command"
    $entry_context = @{
        "$script:INTEGRATION_ENTRY_CONTEXT.MailboxPermission(obj.Identity === val.Identity)" = @{
            "Identity" = $identity
            "Permission" = $raw_response
        }
    }
    Write-Output $human_readable, $entry_context, $raw_response
}

function GetEXOMailBoxCommand
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)][ExchangeOnlinePowershellV3Client]$client,
        [hashtable]$kwargs
    )
    $identity = $kwargs.identity
    $limit = $kwargs.limit -as [int]
    $raw_response = $client.GetEXOMailBox($identity, $kwargs.property_sets, $limit)
    $human_readable = TableToMarkdown $raw_response "Results of $command"
    $entry_context = @{
        "$script:INTEGRATION_ENTRY_CONTEXT.Mailbox(obj.Guid === val.Guid)" = $raw_response }
    Write-Output $human_readable, $entry_context, $raw_response
}

function GetEXOCASMailboxCommand
{
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory)][ExchangeOnlinePowershellV3Client]$client,
        [hashtable]$kwargs
    )
    $identity = $kwargs.identity
    $organizational_unit = $kwargs.organizational_unit
    $primary_smtp_address = $kwargs.primary_smtp_address
    $user_principal_name = $kwargs.user_principal_name
    $limit = $kwargs.limit -as [int]
    $raw_response = $client.GetEXOCASMailbox(
            $identity, $organizational_unit, $primary_smtp_address, $user_principal_name, $limit
    )
    $human_readable = TableToMarkdown $raw_response "Results of $command"
    $entry_context = @{ "$script:INTEGRATION_ENTRY_CONTEXT.CASMailbox(obj.Guid === val.Guid)" = $raw_response }
    Write-Output $human_readable, $entry_context, $raw_response
}

function EXONewTenantAllowBlockListCommand
{
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory)][ExchangeOnlinePowershellV3Client]$client,
        [hashtable]$kwargs
    )
    $entries = $kwargs.entries
    $list_type = $kwargs.list_type
    $list_subtype = $kwargs.list_subtype
    $action = $kwargs.action
    $notes = $kwargs.notes
    $no_expiration = if ($kwargs.no_expiration -eq "true") { $true } else { $false }
    $expiration_date = $kwargs.expiration_date
    $raw_response = $client.EXONewTenantAllowBlockList(
        $entries, $list_type, $list_subtype, $action, $notes, $no_expiration, $expiration_date
    )
    $human_readable = TableToMarkdown $raw_response "Results of $command"
    $entry_context = @{ "$script:INTEGRATION_ENTRY_CONTEXT.NewTenantBlocks" = $raw_response }
    Write-Output $human_readable, $entry_context, $raw_response

}

function EXOGetTenantAllowBlockListCommand
{
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory)][ExchangeOnlinePowershellV3Client]$client,
        [hashtable]$kwargs
    )
    $entry = $kwargs.entry
    $list_type = $kwargs.list_type
    $list_subtype = $kwargs.list_subtype
    $action = $kwargs.action
    $no_expiration = if ($kwargs.no_expiration -eq "true") { $true } else { $false }
    $expiration_date = $kwargs.expiration_date
    $raw_response = $client.EXOGetTenantAllowBlockList(
        $entry, $list_type, $list_subtype, $action, $no_expiration, $expiration_date
    )
    $human_readable = TableToMarkdown $raw_response "Results of $command"
    $entry_context = @{ "$script:INTEGRATION_ENTRY_CONTEXT.CurrentTenantBlocks" = $raw_response }
    Write-Output $human_readable, $entry_context, $raw_response
}

function EXOCountTenantAllowBlockListCommand
{
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory)][ExchangeOnlinePowershellV3Client]$client,
        [hashtable]$kwargs
    )
    $list_type = $kwargs.list_type
    $list_subtype = $kwargs.list_subtype
    $m = $client.EXOGetTenantAllowBlockList($null, $list_type, $list_subtype, $null, $null, $null) | Measure-Object
    $raw_response = [PSCustomObject]@{
        ListType = $list_type
        ListSubType = $list_subtype
        Count = $m.Count
    }
    $human_readable = TableToMarkdown $raw_response "Results of $command"
    $entry_context = @{ "$script:INTEGRATION_ENTRY_CONTEXT.CurrentListCount" = $raw_response }
    Write-Output $human_readable, $entry_context, $raw_response

}

function EXORemoveTenantAllowBlockListCommand
{
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory)][ExchangeOnlinePowershellV3Client]$client,
        [hashtable]$kwargs
    )
    $entries = $kwargs.entries
    $ids = $kwargs.ids
    $list_type = $kwargs.list_type
    $list_subtype = $kwargs.list_subtype
    if ($entries -and $ids)
    {
        ReturnError "Error: Please provide either entries by value OR IDs, not both."
    }
    $raw_response = $client.EXORemoveTenantAllowBlockList(
        $entries, $ids, $list_type, $list_subtype
    )
    $human_readable = TableToMarkdown $raw_response "Results of $command"
    $entry_context = @{ "$script:INTEGRATION_ENTRY_CONTEXT.RemovedTenantBlocks" = $raw_response }
    Write-Output $human_readable, $entry_context, $raw_response

}

function GetJunkRulesCommand([ExchangeOnlinePowershellV3Client]$client, [hashtable]$kwargs) {
    $raw_response = $client.GetJunkRules($kwargs.mailbox)
    $md_columns = $raw_response | Select-Object -Property BlockedSendersAndDomains, TrustedSendersAndDomains, ContactsTrusted, TrustedListsOnly, Enabled
    $human_readable = TableToMarkdown $md_columns  "$script:INTEGRATION_NAME - '$($kwargs.mailbox)' Junk rules"
    $entry_context = ParseJunkRulesToEntryContext $raw_response $kwargs.mailbox

    return $human_readable, $entry_context, $raw_response
}

function SetJunkRulesCommand([ExchangeOnlinePowershellV3Client]$client, [hashtable]$kwargs) {
    # Parse arguments
    $add_blocked_senders_and_domains = ArgToList $kwargs.add_blocked_senders_and_domains
    $remove_blocked_senders_and_domains = ArgToList $kwargs.remove_blocked_senders_and_domains
    $add_trusted_senders_and_domains = ArgToList $kwargs.add_trusted_senders_and_domains
    $remove_trusted_senders_and_domains = ArgToList $kwargs.remove_trusted_senders_and_domains
    if ($kwargs.trusted_lists_only) {
        $trusted_lists_only = ConvertTo-Boolean $kwargs.trusted_lists_only
    }
    if ($kwargs.contacts_trusted) {
        $contacts_trusted = ConvertTo-Boolean $kwargs.contacts_trusted
    }
    if ($kwargs.enabled) {
        $enabled = ConvertTo-Boolean $kwargs.enabled
    }

    # Execute commands - No output for the command
    $client.SetJunkRules($kwargs.mailbox, $add_blocked_senders_and_domains, $remove_blocked_senders_and_domains,
        $add_trusted_senders_and_domains, $remove_trusted_senders_and_domains,
        $trusted_lists_only, $contacts_trusted, $enabled)

    $raw_response = @{}
    $human_readable = "$script:INTEGRATION_NAME - '$($kwargs.mailbox)' Junk rules **modified**!"
    $entry_context = @{}

    return $human_readable, $entry_context, $raw_response
}

function SetGlobalJunkRulesCommand([ExchangeOnlinePowershellV3Client]$client, [hashtable]$kwargs) {
    # Parse arguments
    $add_blocked_senders_and_domains = ArgToList $kwargs.add_blocked_senders_and_domains
    $remove_blocked_senders_and_domains = ArgToList $kwargs.remove_blocked_senders_and_domains
    $add_trusted_senders_and_domains = ArgToList $kwargs.add_trusted_senders_and_domains
    $remove_trusted_senders_and_domains = ArgToList $kwargs.remove_trusted_senders_and_domains
    if ($kwargs.trusted_lists_only) {
        $trusted_lists_only = ConvertTo-Boolean $kwargs.trusted_lists_only
    }
    if ($kwargs.contacts_trusted) {
        $contacts_trusted = ConvertTo-Boolean $kwargs.contacts_trusted
    }
    if ($kwargs.enabled) {
        $enabled = ConvertTo-Boolean $kwargs.enabled
    }
    # Execute commands - No output for the command
    $client.SetGlobalJunkRules($kwargs.mailbox, $add_blocked_senders_and_domains, $remove_blocked_senders_and_domains,
        $add_trusted_senders_and_domains, $remove_trusted_senders_and_domains,
        $trusted_lists_only, $contacts_trusted, $enabled)

    $raw_response = @{}
    $human_readable = "$script:INTEGRATION_NAME - Junk rules globally **modified**!"
    $entry_context = @{}

    return $human_readable, $entry_context, $raw_response
}

function GetMessageTraceCommand([ExchangeOnlinePowershellV3Client]$client, [hashtable]$kwargs) {
    # Parse arguments
    $sender_address = ArgToList $kwargs.sender_address
    $recipient_address = ArgToList $kwargs.recipient_address
    $from_ip = ArgToList $kwargs.from_ip
    $to_ip = ArgToList $kwargs.to_ip

    $raw_response = $client.GetMessageTrace($sender_address, $recipient_address, $from_ip, $to_ip, $kwargs.message_id,
        $kwargs.message_trace_id, $kwargs.page, $kwargs.page_size, $kwargs.start_date,
        $kwargs.end_date, $kwargs.status)

    $entry_context = ParseMessageTraceToEntryContext $raw_response
    if ($entry_context.($script:MESSAGE_TRACE_ENTRY_CONTEXT)) {
        $human_readable = TableToMarkdown $entry_context.($script:MESSAGE_TRACE_ENTRY_CONTEXT)  "$script:INTEGRATION_NAME - Messages trace"
    }
    else {
        $human_readable = "**No messages trace found**"
    }

    return $human_readable, $entry_context, $raw_response
}

function GetFederationTrustCommand([ExchangeOnlinePowershellV3Client]$client, [hashtable]$kwargs) {
    [CmdletBinding()]
    # parse arguments
    $domain_controller = $kwargs.domain_controller
    $identity = $kwargs.identity
    $raw_response = $client.GetFederationTrust(
        $domain_controller, $identity
    )
    $human_readable = TableToMarkdown $raw_response "Results of $command"
    $entry_context = @{
        "$script:INTEGRATION_ENTRY_CONTEXT.FederationTrust(obj.ApplicationIdentifier === val.ApplicationIdentifier)" = $raw_response
    }
    Write-Output $human_readable, $entry_context, $raw_response
}
function GetFederationConfigurationCommand {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [ExchangeOnlinePowershellV3Client]$client,
        [hashtable]$kwargs
    )
    # parse arguments
    $domain_controller = $kwargs.domain_controller
    $identity = $kwargs.identity
    $include_extended_domain_info = ConvertTo-Boolean $kwargs.include_extended_domain_info
    $raw_response = $client.GetFederationConfiguration(
        $domain_controller,
        $identity,
        $include_extended_domain_info
    )
    $human_readable = TableToMarkdown $raw_response "Results of $command"
    $entry_context = @{
        "$script:INTEGRATION_ENTRY_CONTEXT.FederationConfiguration(obj.Guid === val.Guid)" = $raw_response
    }
    Write-Output $human_readable, $entry_context, $raw_response
}
function GetRemoteDomainCommand {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)][ExchangeOnlinePowershellV3Client]$client,
        [hashtable]$kwargs
    )
    $identity = $kwargs.identity
    $domain_controller = $kwargs.domain_controller
    $raw_response = $client.GetRemoteDomain($domain_controller, $identity)
    $human_readable = TableToMarkdown $raw_response "Results of $command"
    $entry_context = @{"$script:INTEGRATION_ENTRY_CONTEXT.RemoteDomain(obj.Guid === val.Guid)" = $raw_response }
    Write-Output $human_readable, $entry_context, $raw_response
}
function GetUserCommand {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)][ExchangeOnlinePowershellV3Client]$client,
        [hashtable]$kwargs
    )
    $identity = $kwargs.identity
    $organizational_unit = $kwargs.organizational_unit
    $limit = ($kwargs.limit -as [int])
    $raw_response = $client.GetUser($identity, $organizational_unit, $limit)
    $human_readable = TableToMarkdown $raw_response "Results of $command"
    $entry_context = @{"$script:INTEGRATION_ENTRY_CONTEXT.User(obj.Guid === val.Guid)" = $raw_response}
    Write-Output $human_readable, $entry_context, $raw_response
}
function GetMailboxAuditBypassAssociationCommand {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)][ExchangeOnlinePowershellV3Client]$client,
        [hashtable]$kwargs
    )
    $identity = $kwargs.identity
    $domain_controller = $kwargs.domain_controller
    $limit = ($kwargs.limit -as [int])
    $raw_response = $client.GetMailboxAuditBypassAssociation($identity, $domain_controller, $limit)
    $human_readable = TableToMarkdown $raw_response "Results of $command"
    $entry_context = @{"$script:INTEGRATION_ENTRY_CONTEXT.MailboxAuditBypassAssociation(obj.Guid === val.Guid)" = $raw_response }
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
function Main
{
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidUsingConvertToSecureStringWithPlainText", "")]
    param()
    $command = $demisto.GetCommand()
    $command_arguments = $demisto.Args()
    $integration_params = [Hashtable] $demisto.Params()

    if ($integration_params.password.password)
    {
        $password = ConvertTo-SecureString $integration_params.password.password -AsPlainText -Force
    }
    else
    {
        $password = $null
    }

    $exo_client = [ExchangeOnlinePowershellV3Client]::new(
            $integration_params.url,
            $integration_params.app_id,
            $integration_params.organization,
            $integration_params.certificate.password,
            $password
    )
    try
    {
        # Executing command
        $Demisto.Debug("Command being called is $Command")
        switch ($command)
        {
            "test-module" {
                ($human_readable, $entry_context, $raw_response) = TestModuleCommand $exo_client
            }
            "$script:COMMAND_PREFIX-cas-mailbox-list" {
                ($human_readable, $entry_context, $raw_response) = GetEXOCASMailboxCommand $exo_client $command_arguments
            }
            "$script:COMMAND_PREFIX-mailbox-list" {
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
            "$script:COMMAND_PREFIX-new-tenant-allow-block-list-items" {
                ($human_readable, $entry_context, $raw_response) = EXONewTenantAllowBlockListCommand $exo_client $command_arguments
            }
            "$script:COMMAND_PREFIX-get-tenant-allow-block-list-items" {
                ($human_readable, $entry_context, $raw_response) = EXOGetTenantAllowBlockListCommand $exo_client $command_arguments
            }
            "$script:COMMAND_PREFIX-get-tenant-allow-block-list-count" {
                ($human_readable, $entry_context, $raw_response) = EXOCountTenantAllowBlockListCommand $exo_client $command_arguments
            }
            "$script:COMMAND_PREFIX-remove-tenant-allow-block-list-items" {
                ($human_readable, $entry_context, $raw_response) = EXORemoveTenantAllowBlockListCommand $exo_client $command_arguments
            }
            "$script:COMMAND_PREFIX-junk-rules-get" {
                ($human_readable, $entry_context, $raw_response) = GetJunkRulesCommand $exo_client $command_arguments
            }
            "$script:COMMAND_PREFIX-junk-rules-set" {
                ($human_readable, $entry_context, $raw_response) = SetJunkRulesCommand $exo_client $command_arguments
            }
            "$script:COMMAND_PREFIX-global-junk-rules-set" {
                ($human_readable, $entry_context, $raw_response) = SetGlobalJunkRulesCommand $exo_client $command_arguments
            }
            "$script:COMMAND_PREFIX-message-trace-get" {
                ($human_readable, $entry_context, $raw_response) = GetMessageTraceCommand $exo_client $command_arguments
            }
            "$script:COMMAND_PREFIX-federation-trust-get" {
                ($human_readable, $entry_context, $raw_response) = GetFederationTrustCommand $exo_client $command_arguments
            }
            "$script:COMMAND_PREFIX-federation-configuration-get" {
                ($human_readable, $entry_context, $raw_response) = GetFederationConfigurationCommand $exo_client $command_arguments
            }
            "$script:COMMAND_PREFIX-remote-domain-get" {
                ($human_readable, $entry_context, $raw_response) = GetRemoteDomainCommand $exo_client $command_arguments
            }
            "$script:COMMAND_PREFIX-user-list" {
                ($human_readable, $entry_context, $raw_response) = GetUserCommand $exo_client $command_arguments
            }
            "$script:COMMAND_PREFIX-mailbox-audit-bypass-association-list" {
                ($human_readable, $entry_context, $raw_response) = GetMailboxAuditBypassAssociationCommand $exo_client $command_arguments
            }
            default {
                ReturnError "Could not recognize $command"
            }
        }
        # Return results to Demisto Server
        ReturnOutputs $human_readable $entry_context $raw_response | Out-Null
    }
    catch
    {
        $Demisto.debug(
                "Integration: $script:INTEGRATION_NAME
        Command: $command
        Arguments: $( $command_arguments | ConvertTo-Json )
        Error: $( $_.Exception.Message )"
        )
        if ($command -ne "test-module")
        {
            ReturnError "Error:
            Integration: $script:INTEGRATION_NAME
            Command: $command
            Arguments: $( $command_arguments | ConvertTo-Json )
            Error: $( $_.Exception )"
        }
        else
        {
            ReturnError $_.Exception.Message
        }
    }
    finally
    {
        # Always disconnect the session, even if no sessions available.
        $exo_client.DisconnectSession()
    }
}

# Execute Main when not in Tests
if ($MyInvocation.ScriptName -notlike "*.tests.ps1" -AND -NOT$Test)
{
    Main
}
