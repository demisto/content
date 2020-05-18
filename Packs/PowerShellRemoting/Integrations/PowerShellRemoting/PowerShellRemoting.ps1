. $PSScriptRoot\CommonServerPowerShell.ps1
$global:HOSTNAME = $demisto.Params().hostname
$global:USERNAME = $demisto.Params().credentials.identifier
$global:PASSWORD = $demisto.Params().credentials.password

function CreateSession ()
{
    <#
    .Description
    Creates a session to target machine using hostname, username and password
    #>
    $SecurePassword = ConvertTo-SecureString -AsPlainText -Force -String $global:PASSWORD
    $Creds = new-object -typename System.Management.Automation.PSCredential -argumentlist $global:USERNAME,$SecurePassword
    $Session = New-PSSession -computername $global:HOSTNAME -credential $Creds
    return $Session
}

function InvokeCommand ($Command)
{
    <#
    .Description
    Runs invoke-command on existing session.
    .Example
    Get-Process powershell
    #>
    $Title = "Result for PowerShell Remote SSH Command: $Command `n"
    $Session = CreateSession
    $Result = Invoke-Command $Session -ScriptBlock { $Command }

    $EntryContext = [PSCustomObject]@{Command = $Command;Result = $Result}
    $Context = [PSCustomObject]@{
        PowerShellSSH = [PSCustomObject]@{Query=$EntryContext}
    }
    $Contents = $Title + $Result

    $DemistoResult = @{
        Type = 1;
        ContentsFormat = "json";
        Contents = $Contents;
        EntryContext = $Context;
        ReadableContentsFormat = "markdown";
        HumanReadable = $Contents
    }
    return $DemistoResult
}

$demisto.Info("Current command is: " + $demisto.GetCommand())

switch -Exact ($demisto.GetCommand())
{
    'test-module' {
        $TestConnection = InvokeCommand('$PSVersionTable')
        $demisto.Results($TestConnection); Break
    }
    'pwsh-remoting-query' {
        $Command = $demisto.Args().command
        $RunCommand = InvokeCommand($Command)
        $demisto.Results($RunCommand); Break
    }
    Default {
        $demisto.Error('Unsupported command was entered.')
    }
}
