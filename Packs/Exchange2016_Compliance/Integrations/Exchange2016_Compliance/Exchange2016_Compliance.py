import demistomock as demisto
from CommonServerPython import *
import subprocess
import uuid

USERNAME = demisto.params()['credentials']['identifier'].replace("'", "''")
PASSWORD = demisto.params()['credentials']['password'].replace("'", "''")
EXCHANGE_FQDN = demisto.params()['exchangeFQDN'].replace("'", "''")
UNSECURE = demisto.params()['insecure']

STARTCS = '''
[CmdletBinding()]
Param(
[Parameter(Mandatory=$True)]
[string]$username,
[Parameter(Mandatory=$True)]
[string]$query,
[Parameter(Mandatory=$True)]
[string]$server,
[Parameter(Mandatory=$True)]
[bool]$unsecure
)
$WarningPreference = "silentlyContinue"
$password = Read-Host
$secpasswd = ConvertTo-SecureString $password -AsPlainText -Force
$UserCredential = New-Object System.Management.Automation.PSCredential ($username, $secpasswd)
$searchName = [guid]::NewGuid().ToString() -replace '[-]'
$searchName = "DemistoSearch" + $searchName
if($unsecure){
    $url = "http://" + $server + "/PowerShell"
    $session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri $url `
    -Credential $UserCredential -Authentication Kerberos
}else{
    $url = "https://" + $server + "/PowerShell"
    $session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri $url `
    -Credential $UserCredential -Authentication Basic -AllowRedirection
}
if (!$session)
{
    "Failed to create remote PS session"
    return
}
Import-PSSession $session -CommandName *Compliance* -AllowClobber -DisableNameChecking -Verbose:$false | Out-Null
$compliance = New-ComplianceSearch -Name $searchName -ExchangeLocation All -ContentMatchQuery $query -Confirm:$false
Start-ComplianceSearch -Identity $searchName
$complianceSearchName = "Action status: " + $searchName
$complianceSearchName | ConvertTo-Json
Remove-PSSession $session
'''

GETCS = '''
[CmdletBinding()]
Param(
[Parameter(Mandatory=$True)]
[string]$username,
[Parameter(Mandatory=$True)]
[string]$searchName,
[Parameter(Mandatory=$True)]
[string]$server,
[Parameter(Mandatory=$True)]
[bool]$unsecure
)
$WarningPreference = "silentlyContinue"
$password = Read-Host
$secpasswd = ConvertTo-SecureString $password -AsPlainText -Force
$UserCredential = New-Object System.Management.Automation.PSCredential ($username, $secpasswd)
if($unsecure){
    $url = "http://" + $server + "/PowerShell"
    $session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri $url `
    -Credential $UserCredential -Authentication Kerberos
}else{
    $url = "https://" + $server + "/PowerShell"
    $session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri $url `
    -Credential $UserCredential -Authentication Basic -AllowRedirection
}
if (!$session)
{
    "Failed to create remote PS session"
    return
}
Import-PSSession $session -CommandName Get-ComplianceSearch -AllowClobber `
-DisableNameChecking -Verbose:$false | Out-Null
$searchStatus = Get-ComplianceSearch $searchName
$searchStatus.Status
if ($searchStatus.Status -eq "Completed")
{
    $searchStatus.SuccessResults | ConvertTo-Json
}
Remove-PSSession $session
'''

REMOVECS = '''
[CmdletBinding()]
Param(
[Parameter(Mandatory=$True)]
[string]$username,
[Parameter(Mandatory=$True)]
[string]$searchName,
[Parameter(Mandatory=$True)]
[string]$server,
[Parameter(Mandatory=$True)]
[bool]$unsecure
)
$WarningPreference = "silentlyContinue"
$password = Read-Host
$secpasswd = ConvertTo-SecureString $password -AsPlainText -Force
$UserCredential = New-Object System.Management.Automation.PSCredential ($username, $secpasswd)
if($unsecure){
    $url = "http://" + $server + "/PowerShell"
    $session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri $url `
    -Credential $UserCredential -Authentication Kerberos
}else{
    $url = "https://" + $server + "/PowerShell"
    $session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri $url `
    -Credential $UserCredential -Authentication Basic -AllowRedirection
}
if (!$session)
{
    "Failed to create remote PS session"
    return
}
Import-PSSession $session -CommandName *Compliance* -AllowClobber -DisableNameChecking -Verbose:$false | Out-Null
Remove-ComplianceSearch $searchName -Confirm:$false
Remove-PSSession $session
'''

STARTPURGE = '''
[CmdletBinding()]
Param(
[Parameter(Mandatory=$True)]
[string]$username,
[Parameter(Mandatory=$True)]
[string]$searchName,
[Parameter(Mandatory=$True)]
[string]$server,
[Parameter(Mandatory=$True)]
[bool]$unsecure
)
$WarningPreference = "silentlyContinue"
$password = Read-Host
$secpasswd = ConvertTo-SecureString $password -AsPlainText -Force
$UserCredential = New-Object System.Management.Automation.PSCredential ($username, $secpasswd)
if($unsecure){
    $url = "http://" + $server + "/PowerShell"
    $session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri $url `
    -Credential $UserCredential -Authentication Kerberos
}else{
    $url = "https://" + $server + "/PowerShell"
    $session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri $url `
    -Credential $UserCredential -Authentication Basic -AllowRedirection
}
if (!$session)
{
    "Failed to create remote PS session"
    return
}
Import-PSSession $session -CommandName *Compliance* -AllowClobber -DisableNameChecking -Verbose:$false | Out-Null
$newActionResult = New-ComplianceSearchAction -SearchName $searchName -Purge -PurgeType SoftDelete -Confirm:$false
if (!$newActionResult)
{
    "No action was created"
}
Remove-PSSession $session
return
'''

CHECKPURGE = '''
[CmdletBinding()]
Param(
[Parameter(Mandatory=$True)]
[string]$username,
[Parameter(Mandatory=$True)]
[string]$searchName,
[Parameter(Mandatory=$True)]
[string]$server,
[Parameter(Mandatory=$True)]
[bool]$unsecure
)
$WarningPreference = "silentlyContinue"
$password = Read-Host
$secpasswd = ConvertTo-SecureString $password -AsPlainText -Force
$UserCredential = New-Object System.Management.Automation.PSCredential ($username, $secpasswd)
if($unsecure){
    $url = "http://" + $server + "/PowerShell"
    $session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri $url `
    -Credential $UserCredential -Authentication Kerberos
}else{
    $url = "https://" + $server + "/PowerShell"
    $session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri $url `
    -Credential $UserCredential -Authentication Basic -AllowRedirection
}
if (!$session)
{
    "Failed to create remote PS session"
    return
}
Import-PSSession $session -CommandName *Compliance* -AllowClobber -DisableNameChecking -Verbose:$false | Out-Null
$actionName = $searchName + "_Purge"
$actionStatus = Get-ComplianceSearchAction $actionName
""
$actionStatus.Status
Remove-PSSession $session
'''

TESTCON = '''
[CmdletBinding()]
Param(
[Parameter(Mandatory=$True)]
[string]$username,
[Parameter(Mandatory=$True)]
[string]$server,
[Parameter(Mandatory=$True)]
[bool]$unsecure
)
$errorActionPreference = 'Stop'
$WarningPreference = "silentlyContinue"
$password = Read-Host
$secpasswd = ConvertTo-SecureString $password -AsPlainText -Force
$UserCredential = New-Object System.Management.Automation.PSCredential ($username, $secpasswd)
try{
    if($unsecure){
        $url = "http://" + $server + "/PowerShell"
        $session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri $url `
        -Credential $UserCredential -Authentication Kerberos
    }else{
        $url = "https://" + $server + "/PowerShell"
        $session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri $url `
        -Credential $UserCredential -Authentication Basic -AllowRedirection
    }
    echo "successful connection"
} catch {
    $e = $_.Exception
    echo $e.Message
} finally {
    Remove-PSSession $session
}
'''


def prepare_args(d):
    return dict((k.replace("-", "_"), v) for k, v in d.items())


def str_to_unicode(obj):
    if isinstance(obj, dict):
        obj = {k: str_to_unicode(v) for k, v in obj.iteritems()}
    elif isinstance(obj, list):
        obj = map(str_to_unicode, obj)
    elif isinstance(obj, str):
        obj = unicode(obj, "utf-8")
    return obj


def encode_and_submit_results(obj):
    demisto.results(str_to_unicode(obj))


def get_cs_status(search_name, status):
    return {
        'Type': entryTypes['note'],
        'ContentsFormat': formats['text'],
        'Contents': 'Search {} status: {}'.format(search_name, status),
        'EntryContext': {
            'EWS.ComplianceSearch(val.Name === obj.Name)': {'Name': search_name, 'Status': status}
        }
    }


def create_ps_file(ps_name, ps_content):
    temp_path = os.getenv('TEMP')
    if not temp_path:
        return_error("Check that the integration is using single engine without docker."
                     " If so, add TEMP variable to the enviroment varibes.")

    ps_path = temp_path + '\\' + ps_name  # type: ignore
    with open(ps_path, 'w+') as file:
        file.write(ps_content)
    return ps_path


def delete_ps_file(ps_path):
    if os.path.exists(ps_path):
        os.remove(ps_path)


def start_compliance_search(query):
    try:
        ps_path = create_ps_file('startcs_' + str(uuid.uuid4()).replace('-', '') + '.ps1', STARTCS)
        output = subprocess.Popen(["powershell.exe", ps_path, "'" + USERNAME + "'",
                                   "'" + str(query).replace("'", "''") + "'", "'" + EXCHANGE_FQDN + "'", "$" + str(UNSECURE)],
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = output.communicate(input=PASSWORD.encode())
    finally:
        delete_ps_file(ps_path)

    if stderr:
        return_error(stderr)
    prefix = '"Action status: '
    pref_ind = stdout.find(prefix)
    sub_start = pref_ind + len(prefix)
    sub_end = sub_start + 45
    search_name = stdout[sub_start:sub_end]
    return {
        'Type': entryTypes['note'],
        'ContentsFormat': formats['text'],
        'Contents': 'Search started: {}'.format(search_name),
        'EntryContext': {
            'EWS.ComplianceSearch': {'Name': search_name, 'Status': 'Starting'}
        }
    }


def get_compliance_search(search_name):
    try:
        ps_path = create_ps_file('getcs_' + search_name + '.ps1', GETCS)
        output = subprocess.Popen(["powershell.exe", ps_path, "'" + USERNAME + "'",
                                   "'" + search_name + "'", "'" + EXCHANGE_FQDN + "'", "$" + str(UNSECURE)],
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = output.communicate(input=PASSWORD.encode())
    finally:
        delete_ps_file(ps_path)

    stdout = stdout[len(PASSWORD):]

    if stderr:
        return_error(stderr)
    stdsplit = stdout.split('\n', 1)
    status = stdsplit[0].strip()
    results = [get_cs_status(search_name, status)]

    if status == 'Completed' and len(stdsplit[1].strip()) > 4:
        res = list(r[:-1].split(', ') if r[-1] == ',' else r.split(', ') for r in stdsplit[1][2:-4].split(r'\r\n'))
        res = map(lambda x: {k: v for k, v in (s.split(': ') for s in x)}, res)
        results.append(
            {
                'Type': entryTypes['note'],
                'ContentsFormat': formats['text'],
                'Contents': stdout,
                'ReadableContentsFormat': formats['markdown'],
                'HumanReadable': tableToMarkdown('Exchange 2016 Compliance search results',
                                                 res, ['Location', 'Item count', 'Total size'])
            }
        )
    return results


def remove_compliance_search(search_name):
    try:
        ps_path = create_ps_file('removecs_' + search_name + '.ps1', REMOVECS)
        output = subprocess.Popen(["powershell.exe", ps_path, "'" + USERNAME + "'",
                                   "'" + search_name + "'", "'" + EXCHANGE_FQDN + "'", "$" + str(UNSECURE)],
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = output.communicate(input=PASSWORD.encode())
    finally:
        delete_ps_file(ps_path)

    return return_error(stderr) if stderr else get_cs_status(search_name, 'Removed')


def purge_compliance_search(search_name):
    try:
        ps_path = create_ps_file('startpurge_' + search_name + '.ps1', STARTPURGE)
        output = subprocess.Popen(["powershell.exe", ps_path, "'" + USERNAME + "'",
                                   "'" + search_name + "'", "'" + EXCHANGE_FQDN + "'", "$" + str(UNSECURE)],
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = output.communicate(input=PASSWORD.encode())
    finally:
        delete_ps_file(ps_path)
    return return_error(stderr) if stderr else get_cs_status(search_name, 'Purging')


def check_purge_compliance_search(search_name):
    try:
        ps_path = create_ps_file('checkpurge_' + search_name + '.ps1', CHECKPURGE)
        output = subprocess.Popen(["powershell.exe", ps_path, "'" + USERNAME + "'",
                                   "'" + search_name + "'", "'" + EXCHANGE_FQDN + "'", "$" + str(UNSECURE)],
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = output.communicate(input=PASSWORD.encode())
    finally:
        delete_ps_file(ps_path)

    return return_error(stderr) if stderr else get_cs_status(search_name,
                                                             'Purged' if stdout.strip() == 'Completed' else 'Purging')


def test_module():
    try:
        ps_path = create_ps_file('testcon_' + str(uuid.uuid4()).replace('-', '') + '.ps1', TESTCON)
        output = subprocess.Popen(["powershell.exe", ps_path, "'" + USERNAME + "'",
                                   "'" + EXCHANGE_FQDN + "'", "$" + str(UNSECURE)],
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout = output.communicate(input=PASSWORD.encode())[0].strip()
    finally:
        delete_ps_file(ps_path)

    stdout = stdout[len(PASSWORD):]

    if stdout == "successful connection":
        demisto.results('ok')
    else:
        return_error(stdout)


args = prepare_args(demisto.args())
try:
    if demisto.command() == 'exchange2016-start-compliance-search':
        encode_and_submit_results(start_compliance_search(**args))
    elif demisto.command() == 'exchange2016-get-compliance-search':
        encode_and_submit_results(get_compliance_search(**args))
    elif demisto.command() == 'exchange2016-remove-compliance-search':
        encode_and_submit_results(remove_compliance_search(**args))
    elif demisto.command() == 'exchange2016-purge-compliance-search-results':
        encode_and_submit_results(purge_compliance_search(**args))
    elif demisto.command() == 'exchange2016-get-compliance-search-purge-status':
        encode_and_submit_results(check_purge_compliance_search(**args))
    elif demisto.command() == 'test-module':
        test_module()
except Exception as e:
    if isinstance(e, WindowsError):  # pylint: disable=undefined-variable
        return_error("Could not open powershell on the target engine.")
    else:
        return_error(e)
