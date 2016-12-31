
[CmdletBinding()]
Param(
[Parameter(Mandatory=$True)]
[string]$username,

[Parameter(Mandatory=$True)]
[string]$password,

[Parameter(Mandatory=$True)]
[string]$query,

[Parameter(Mandatory=$False)]
[string]$timeout = 30
)

# Generate a unique search name
$searchName = [guid]::NewGuid().ToString() -replace '[-]'
$searchName = "DemistoSearch" + $searchName

# Create Credential object
$secpasswd = ConvertTo-SecureString $password -AsPlainText -Force
$UserCredential = New-Object System.Management.Automation.PSCredential ($username, $secpasswd)


# open remote PS session to Office 365 Security & Compliance Center
$session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri https://ps.compliance.protection.outlook.com/powershell-liveid/ -Credential $UserCredential -Authentication Basic -AllowRedirection
if (!$session)
{
    "Failed to create remote PS session"
    return
}

Import-PSSession $session -AllowClobber -DisableNameChecking

# Create a new search
New-ComplianceSearch -Name $searchName -ExchangeLocation All -ContentMatchQuery $query -Confirm:$false

# Start the search
Start-ComplianceSearch -Identity $searchName

Start-Sleep 5

$searchStatus = ""
$i = 0
while($i -lt $timeout)
{
    $searchStatus = Get-ComplianceSearch $searchName
    "Search status: " + $searchStatus.Status
    if ($searchStatus.Status -eq "Completed")
    {
        break
    }
    "Waiting for search to complete..."
    Start-Sleep 1
    $i++
}

if (($i -eq $timeout) -and ($searchStatus.Status -ne "Completed"))
{
    # Remove the search
    Remove-ComplianceSearch $searchName -Confirm:$false

    # Close the session
    Remove-PSSession $session
    "Timedout while waiting for search to complete"
    return
}

$searchStatus = Get-ComplianceSearch $searchName
"Search results: " + $searchStatus.SuccessResults

# Remove the search
Remove-ComplianceSearch $searchName -Confirm:$false

# Close the session
Remove-PSSession $session
