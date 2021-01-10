. $PSScriptRoot\CommonServerPowerShell.ps1

$script:INTEGRATION_NAME = "XSOAR Server Powershell"
$script:COMMAND_PREFIX = "xsoar"
$script:INTEGRATION_ENTRY_CONTEX = "XSOAR"

#### HELPER FUNCTIONS ####

function SetIntegrationContextCommand() {
    # Raw response
    $raw_response = @{}
    # Human readable
    $human_readable = "Ok!"
    # Entry context
    $entry_context = @{}

    return $human_readable, $entry_context, $raw_response
}

function GetIntegrationContextCommand() {
    # Raw response
    $raw_response = $demisto.GetIntegrationContext()
    # Human readable
    $human_readable = "Integration context value is **$raw_response**"
    # Entry context
    $entry_context = @{}
    $entry_context = @{
        "$script:INTEGRATION_ENTRY_CONTEX.IntegrationContext.Value" = $raw_response[0]
    }

    return $human_readable, $entry_context, $raw_response
}

function SetIntegrationContextCommand([hashtable]$kwargs) {
    # Raw response
    $demisto.SetIntegrationContext($kwargs.value)
    $raw_response = @{}
    # Human readable
    $human_readable = "Integration context value set to **$($kwargs.value)** "
    # Entry context
    $entry_context = @{}

    return $human_readable, $entry_context, $raw_response
}

#### INTEGRATION COMMANDS MANAGER ####

function Main {
    $command = $Demisto.GetCommand()
    $command_arguments = $Demisto.Args()

    try {
        # Executing command
        $Demisto.Debug("Command being called is $Command")
        switch ($command) {
            "test-module" {
                ($human_readable, $entry_context, $raw_response) = TestModuleCommand
            }
            "$script:COMMAND_PREFIX-get-integration-context" {
                ($human_readable, $entry_context, $raw_response) = GetIntegrationContextCommand
            }
            "$script:COMMAND_PREFIX-set-integration-context" {
                ($human_readable, $entry_context, $raw_response) = SetIntegrationContextCommand $command_arguments
            }
        }
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