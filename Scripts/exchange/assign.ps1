param (
    [string]$server = $null,
    [string]$username = $env:USERNAME,
    [string]$role = "Mailbox Import Export"
 )

. RemoteExchange.ps1

if (!$server){
    Connect-ExchangeServer -auto
}
else {
    Connect-ExchangeServer -ServerFqdn $server
}

if (!$username){
    $username=whoami
}

$assignment = New-ManagementRoleAssignment -Role $role -User:$username

if (!$assignment){
    $msg ="Failed to assign '$username' to role: '$role'"
    throw $msg
}

Remove-PSSession $remoteSession
