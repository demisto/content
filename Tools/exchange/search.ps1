param (
    [string]$server = $null,
    [string]$username = $env:USERNAME,
    [string]$query = $null,
    [string]$targetmbx = $null,
    [string]$targetFolder = $null,
    [switch]$delete = $false
 )

. RemoteExchange.ps1

if (!$query){
    throw "Missing parameter: -query"
}

if (!$server){
    Connect-ExchangeServer -auto
}
else {
    Connect-ExchangeServer -ServerFqdn $server
}

if ($delete){
    Get-Mailbox -ResultSize Unlimited | Search-Mailbox -SearchQuery '$query' -Force:$true -DeleteContent
}
else {
    if (!$targetmbx){
        throw "Missing parameter: -targetmbx"
    }
    if (!$targetFolder){
        throw "Missing parameter: -targetFolder"
    }
    Get-Mailbox -ResultSize Unlimited | Search-Mailbox -SearchQuery '$query' -TargetMailbox $targetmbx -TargetFolder $targetFolder
}

Remove-PSSession $remoteSession
