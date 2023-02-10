. $PSScriptRoot\CommonServerPowerShell.ps1
$left =  $demisto.Args()["left"]
$right = $demisto.Args()["right"]

try{
    $left = [System.Version]$left
}
catch{
    $errMsg = "Left Side [$left] invalid version number"
    ReturnError $errMsg
}

try{
    $right = [System.Version]$right
}
catch
{
    $errMsg = "Right Side [$right] invalid version number"
    ReturnError $errMsg
}

if($left -eq $right)
{
    $demisto.Results($true)
}
else
{
    $demisto.Results($false)
}
