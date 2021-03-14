Import-Module MicrosoftTeams

function Main()
{
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingConvertToSecureStringWithPlainText', '')]
    param()
    $dargs = $demisto.Args()
    $plain_username = $dargs.username
    $plain_pass = $dargs.password
    $password = (ConvertTo-SecureString -String $plain_pass -AsPlainText -Force)
    $app_id = $dargs.app_id
    $identity = $dargs.identity
    try
    {
        $credential = New-Object System.Management.Automation.PSCredential($plain_username, $password)

        $connection_info = Connect-MicrosoftTeams -Credential $credential

        New-CsApplicationAccessPolicy -Identity Test-policy -AppIds $app_id
        Grant-CsApplicationAccessPolicy -PolicyName Test-policy -Identity $identity

        ReturnOutputs "Access policy was given"
    }
    finally
    {
        Disconnect-MicrosoftTeams
    }
}

if ($MyInvocation.ScriptName -notlike "*.tests.ps1" -AND -NOT$Test)
{
    Main
}