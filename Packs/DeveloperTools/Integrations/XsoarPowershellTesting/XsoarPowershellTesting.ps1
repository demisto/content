. $PSScriptRoot\CommonServerPowerShell.ps1

$script:INTEGRATION_NAME = "XSOAR Powershell Testing"
$script:COMMAND_PREFIX = "pwsh-test"
$script:INTEGRATION_ENTRY_CONTEX = "XSOAR"

#### HELPER FUNCTIONS ####

function TestModuleCommand() {
    # Raw response
    $raw_response = $null
    # Human readable
    $human_readable = "ok"
    # Entry context
    $entry_context = $null

    return $human_readable, $entry_context, $raw_response
}

function GetIntegrationContextCommand() {
    # Raw response
    $raw_response = GetIntegrationContext
    $raw_response_json = $raw_response | ConvertTo-Json
    # Human readable
    $human_readable = "Integration context value is **$raw_response_json**"
    # Entry context
    $entry_context = @{}
    $entry_context = @{
        "$script:INTEGRATION_ENTRY_CONTEX.IntegrationContext" = $raw_response
    }

    return $human_readable, $entry_context, $raw_response
}

function SetIntegrationContextCommand([hashtable]$kwargs) {
    # Raw response
    $integration_context = @{
    "Value" = $kwargs.value
    }
    SetIntegrationContext $integration_context
    $raw_response = @{}
    # Human readable
    $human_readable = "Integration context value set to **$($kwargs.value)** "
    # Entry context
    $entry_context = @{}

    return $human_readable, $entry_context, $raw_response
}

function SetVersionedIntegrationContextCommand([hashtable]$kwargs) {
    # Raw response
    $integration_context = @{
    "Value" = $kwargs.value
    }
    $version = $kwargs.version

    SetIntegrationContext -context $integration_context -version $version
    $raw_response = @{}
    # Human readable
    $human_readable = "Integration context with version **$($version)** value set to **$($kwargs.value)** "
    # Entry context
    $entry_context = @{}

    return $human_readable, $entry_context, $raw_response
}

function GetVersionedIntegrationContextCommand() {
    # Raw response
    $raw_response = GetIntegrationContext -withVersion $true
    $raw_response_json = $raw_response | ConvertTo-Json
    # Human readable
    $human_readable = "Integration context with version is **$raw_response_json**"
    # Entry context
    $entry_context = @{}

    if (DemistoVersionGreaterEqualThen -version "6.1.0") {
        $version = $raw_response.version.version
    }
    else {
         $version = $raw_response.version
    }

    $entry_context = @{
        $script:INTEGRATION_ENTRY_CONTEX = @{
            "IntegrationContext" = $raw_response.context
            "Version" = $version
        }
    }

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
            "$script:COMMAND_PREFIX-get-integration-versioned-context" {
                ($human_readable, $entry_context, $raw_response) = GetVersionedIntegrationContextCommand
            }
            "$script:COMMAND_PREFIX-set-integration-versioned-context" {
                ($human_readable, $entry_context, $raw_response) = SetVersionedIntegrationContextCommand $command_arguments
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
