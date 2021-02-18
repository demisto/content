. $PSScriptRoot\CommonServerPowerShell.ps1

function Main() {
    $json = $demisto.Args()["json"]
    $schema = $demisto.Args()["schema"]
    if ($schema) {
        $res = Test-Json -Json $json -Schema $schema -ErrorAction SilentlyContinue -ErrorVariable err
    }
    else {
        $res = Test-Json -Json $json -ErrorAction SilentlyContinue -ErrorVariable err
    }
    $outputs = @{VerifyJSON = @{Result = $res } }
    if ($res) {
        ReturnOutputs "Verify JSON completed successfully" -Outputs $outputs | Out-Null
        return
    }
    else {
        $errMsg = "$($err[0].Exception.Message)"
        if ($err[0].Exception.InnerException.Message) {
            $errMsg += " $($err[0].Exception.InnerException.Message)"
        }
        if ($err[0].ErrorDetails.Message) {
            $errMsg += " $($err[0].ErrorDetails.Message)"
        }
        ReturnError $errMsg $err $outputs | Out-Null
    }
}

# Execute Main when not in Tests
if ($MyInvocation.ScriptName -notlike "*.Tests.ps1") {
    Main
}
