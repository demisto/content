$script:COMMAND_PREFIX = "o365-auditlog"
$script:INTEGRATION_ENTRY_CONTEXT = "O365AuditLog"

Import-Module ExchangeOnlineManagement

class ExchangeOnlinePowershellV3Client
{
    [System.Security.Cryptography.X509Certificates.X509Certificate2]$certificate
    [string]$organization
    [string]$app_id
    [SecureString]$password
    ExchangeOnlinePowershellV3Client(
            [string]$app_id,
            [string]$organization,
            [string]$certificate,
            [SecureString]$password
    )
    {
        try
        {
            $ByteArray = [System.Convert]::FromBase64String($certificate)
        }
        catch
        {
            throw "Could not decode the certificate. Try to re-enter it"
        }
        $this.certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList ($ByteArray, $password)

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
        Connect-ExchangeOnline @cmd_params -ShowBanner:$false -CommandName Search-UnifiedAuditLog -WarningAction:SilentlyContinue | Out-Null
    }
    DisconnectSession()
    {
        Disconnect-ExchangeOnline -Confirm:$false -WarningAction:SilentlyContinue 6>$null | Out-Null
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
    ) {
        $cmd_args = @{
            "StartDate" = $start_date
            "EndDate"   = $end_date
        }
        if ($record_type) {
            $cmd_args.RecordType = $record_type
        }
        if ($free_text) {
            $cmd_args.FreeText = $free_text
        }
        if ($operations.Length -gt 0) {
            $cmd_args.Operations = $operations
        }
        if ($ip_addresses.Length -gt 0) {
            $cmd_args.IPAddresses = $ip_addresses
        }
        if ($user_ids.Length -gt 0) {
            $cmd_args.UserIds = $user_ids
        }
        if ($result_size -gt 0) {
            $cmd_args.ResultSize = $result_size
        }
        else {
            $cmd_args.ResultSize = 5000
        }
        return Search-UnifiedAuditLog @cmd_args -ErrorAction Stop
    }
}

function SearchAuditLogCommand {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)][ExchangeOnlinePowershellV3Client]$client,
        [hashtable]$kwargs
    )
    try {
        $client.CreateSession()
        if ($kwargs.end_date) {
            $end_date = Get-Date $kwargs.end_date
        }
        else {
            $end_date = Get-Date
        }
        try {
            # If parse date range works, it is fine. The end date will be automatically now.
            $start_date, $end_date = ParseDateRange $kwargs.start_date
        }
        catch {
            try {
                # If it didn't work, it should be a date.
                $start_date = Get-Date $kwargs.start_date
            }
            catch {
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
        if ($raw_response) {
            $list = [System.Collections.Generic.List[object]]::new()
            foreach ($item in $raw_response) {
                $list.add((ConvertFrom-Json $item.AuditData))
            }
            # foreach ($item in ,@{AuditData = Get-Content "test_data/audit_log.json" -Raw}) {$list.add((ConvertFrom-Json $item.AuditData))}
            $context = @{
                "$script:INTEGRATION_ENTRY_CONTEXT(val.Id === obj.Id)" = $list
            }
            $human_readable = TableToMarkdown $list.ToArray() "Audit log from $start_date to $end_date"
            Write-Output $human_readable, $context, $list
        }
        else {
            $human_readable = "Audit log from $start_date to $end_date is empty"
            Write-Output $human_readable, $null, $null
        }

    }
    finally {
        $client.DisconnectSession()
    }
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
    $integration_params = $demisto.Params()

    $password = ConvertTo-SecureString $integration_params.certificate.password -AsPlainText -Force

    $audit_log_client = [ExchangeOnlinePowershellV3Client]::new(
            $integration_params.app_id,
            $integration_params.organization,
            $integration_params.certificate.identifier,
            $password
    )
    try {
        # Executing command
        $demisto.Debug("Command being called is $command")
        switch ($command) {
            "test-module" {
                $human_readable, $entry_context, $raw_response = TestModuleCommand $audit_log_client
            }
            "$script:COMMAND_PREFIX-search" {
                $human_readable, $entry_context, $raw_response = SearchAuditLogCommand $audit_log_client $command_arguments
            }
            default {
                throw "Command $command no implemented"
            }
        }
        # Return results to server
        ReturnOutputs $human_readable $entry_context $raw_response | Out-Null
    }
    catch {
        $demisto.debug("Integration: $script:INTEGRATION_NAME
            Command: $command
            Arguments: $($command_arguments | ConvertTo-Json)
            Error: $($_.Exception.Message)")
        ReturnError "Error:
            Integration: $script:INTEGRATION_NAME
            Command: $command
            Arguments: $($command_arguments | ConvertTo-Json)
            Error: $($_.Exception)" | Out-Null
    }
}

# Execute Main when not in Tests
if ($MyInvocation.ScriptName -notlike "*.tests.ps1" -AND -NOT $Test) {
    Main
}