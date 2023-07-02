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

$COMMAND_PREFIX = "ews"
$INTEGRATION_ENTRY_CONTEXT = "EWS"

class ExchangeOnlinePowershellV2Client
{
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
        Connect-ExchangeOnline @cmd_params -ShowBanner:$false -CommandName New-TenantAllowBlockListItems,Get-TenantAllowBlockListItems,Remove-TenantAllowBlockListItems -WarningAction:SilentlyContinue | Out-Null
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
        $cmd_params = @{ }
        if ($identity)
        {
            $cmd_params.Identity = $identity
        }
        $this.CreateSession()
        if ($limit -gt 0)
        {
            if ($identity)
            {
                $results = Get-EXORecipientPermission -Identity $identity -ResultSize $limit
            }
            else
            {
                $results = Get-EXORecipientPermission -ResultSize $limit
            }
        }
        else
        {
            if ($identity)
            {
                $results = Get-EXORecipientPermission -Identity $identity -ResultSize Unlimited
            }
            else
            {
                $results = Get-EXORecipientPermission -ResultSize Unlimited
            }
        }
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
        if ($ids -and -not $ids_array)
        {
            $ids_array += $ids
            $cmd_params.Ids = $ids_array
        }
        elseif ($ids_array)
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
        $this.DisconnectSession()
        return $results
        <#
            .DESCRIPTION
            Use the Get-TenantAllowBlockListItems cmdlet to retrieve current entries in the Tenant Allow/Block Lists for your organization.
            This cmdlet returns current entries and details about them.

        #>
    }
}

function GetEXORecipientCommand
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)][ExchangeOnlinePowershellV2Client]$client,
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
        [Parameter(Mandatory)][ExchangeOnlinePowershellV2Client]$client,
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
        [Parameter(Mandatory)][ExchangeOnlinePowershellV2Client]$client,
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
        [Parameter(Mandatory)][ExchangeOnlinePowershellV2Client]$client,
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
        [Parameter(Mandatory)][ExchangeOnlinePowershellV2Client]$client,
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
        [Parameter(Mandatory)][ExchangeOnlinePowershellV2Client]$client,
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
        [Parameter(Mandatory)][ExchangeOnlinePowershellV2Client]$client,
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
        [Parameter(Mandatory)][ExchangeOnlinePowershellV2Client]$client,
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
        [Parameter(Mandatory)][ExchangeOnlinePowershellV2Client]$client,
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

    $exo_client = [ExchangeOnlinePowershellV2Client]::new(
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
