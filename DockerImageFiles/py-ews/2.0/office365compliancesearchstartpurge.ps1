[CmdletBinding()]
Param(
[Parameter(Mandatory=$True)]
[string]$username,

[Parameter(Mandatory=$True)]
[string]$password,

[Parameter(Mandatory=$True)]
[string]$searchName
)

$WarningPreference = "silentlyContinue"
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


Import-PSSession $session -CommandName *Compliance* -AllowClobber -DisableNameChecking -Verbose:$false | Out-Null

# Delete mails based on an existing search criteria
$newActionResult = New-ComplianceSearchAction -SearchName $searchName -Purge -PurgeType SoftDelete -Confirm:$false
if (!$newActionResult)
{
    # Happens when there are no results from the search
    "No action was created"
}

# Close the session
Remove-PSSession $session
return
