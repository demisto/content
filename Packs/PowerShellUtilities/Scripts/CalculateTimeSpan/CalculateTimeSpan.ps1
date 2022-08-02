. $PSScriptRoot\CommonServerPowerShell.ps1
$startTime =  $demisto.Args()["start_time"]
$endTime = $demisto.Args()["end_time"]

if(! $startTime)
{
    $startTime = Get-Date
}

if(! $endTime)
{
    $endTime = Get-Date
}

try{
    $timeSpan = New-TimeSpan -Start $startTime -End $endTime
}
catch
{
    $errMsg = "$($err[0].Exception.Message)"
    if ($err[0].Exception.InnerException.Message) {
        $errMsg += " $($err[0].Exception.InnerException.Message)"
    }
    if ($err[0].ErrorDetails.Message) {
        $errMsg += " $($err[0].ErrorDetails.Message)"
    }
    ReturnError $errMsg $err $outputs | Out-Null
}

$outputs = @{TimeSpan = @{Result = $timeSpan } }
ReturnOutputs -ReadableOutput ($TimeSpan | ConvertTo-Markdown) -Outputs $outputs -RawResponse $timeSpan | Out-Null
