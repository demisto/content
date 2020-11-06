import pytest
from MicrosoftGraphSecurity import MsGraphClient

# msg-get-user data:
RAW_USERS_DATA = {'@odata.context': 'https://graph.microsoft.com/v1.0/$metadata#users', 'value': [
    {'businessPhones': [], 'displayName': 'Graph Test', 'givenName': None, 'jobTitle': 'Test',
     'mail': "Test@demistodev.onmicrosoft.com", 'mobilePhone': None, 'officeLocation': None, 'preferredLanguage': None,
     'surname': None, 'userPrincipalName': '0e3f5d4140cc4448a857e565a4d228e1@demistodev.onmicrosoft.com',
     'id': '5bfe522c-d817-4ea8-b52c-cc959e10e623'},
    {'businessPhones': ['0525399091'], 'displayName': 'Test Graph 2', 'givenName': 'Test',
     'jobTitle': 'Staff Software Developer', 'mail': 'test2@demistodev.onmicrosoft.com', 'mobilePhone': '0525399091',
     'officeLocation': None, 'preferredLanguage': None, 'surname': None,
     'userPrincipalName': 'test2@demistodev.onmicrosoft.com', 'id': '00df702c-cdae-460d-a442-46db6cecca29'}]}
EXPECTED_USER_CONTEXT = {'MsGraph.User(val.ID && val.ID === obj.ID)': [
    {'Name': 'Graph Test', 'Title': 'Test', 'Email': 'Test@demistodev.onmicrosoft.com',
     'ID': '5bfe522c-d817-4ea8-b52c-cc959e10e623'},
    {'Name': 'Test Graph 2', 'Title': 'Staff Software Developer', 'Email': 'test2@demistodev.onmicrosoft.com',
     'ID': '00df702c-cdae-460d-a442-46db6cecca29'}]}
EXPECTED_USER_HUMAN_READABLE = \
    '### Microsoft Graph Users\n|Name|Title|Email|ID|\n|---|---|---|---|\n' \
    '| Graph Test | Test | Test@demistodev.onmicrosoft.com | 5bfe522c-d817-4ea8-b52c-cc959e10e623 |\n' \
    '| Test Graph 2 | Staff Software Developer | test2@demistodev.onmicrosoft.com | ' \
    '00df702c-cdae-460d-a442-46db6cecca29 |\n'

# msg-search-alerts data:
ALERTS_RAW_RESPONSE = {'@odata.context': 'https://graph.microsoft.com/v1.0/$metadata#Security/alerts', 'value': [{
    'id': 'da637229984903196572_-755436942', 'azureTenantId': '<azureTenantId>',
    'azureSubscriptionId': None, 'riskScore': None, 'tags': [], 'activityGroupName': None,
    'assignedTo': None,
    'category': 'None', 'closedDateTime': None, 'comments': [], 'confidence': None,
    'createdDateTime': '2020-04-20T16:54:50.2722072Z', 'description': 'Created for test',
    'detectionIds': [],
    'eventDateTime': '2020-04-20T16:34:28.061101Z', 'feedback': None,
    'lastModifiedDateTime': '2020-04-20T16:54:51.57Z', 'recommendedActions': [],
    'severity': 'medium',
    'sourceMaterials': [
        'https://securitycenter.microsoft.com/alert/da637229984903196572_-755436942'],
    'status': 'newAlert', 'title': 'test alert',
    'vendorInformation': {'provider': 'Microsoft Defender ATP', 'providerVersion': None,
                          'subProvider': 'MicrosoftDefenderATP', 'vendor': 'Microsoft'},
    'cloudAppStates': [],
    'fileStates': [],
    'hostStates': [
        {'fqdn': 'desktop-s2455r8', 'isAzureAdJoined': True, 'isAzureAdRegistered': None,
         'isHybridAzureDomainJoined': None, 'netBiosName': None, 'os': 'Windows10',
         'privateIpAddress': '127.0.0.1', 'publicIpAddress': '127.0.0.1',
         'riskScore': 'High'}],
    'historyStates': [], 'malwareStates': [], 'networkConnections': [], 'processes': [],
    'registryKeyStates': [],
    'triggers': [], 'userStates': [], 'vulnerabilityStates': []},
    {'id': 'da637218501473413212_-1554891308', 'azureTenantId': '<azureTenantId>',
     'azureSubscriptionId': None, 'riskScore': None, 'tags': [], 'activityGroupName': None,
     'assignedTo': None,
     'category': 'None', 'closedDateTime': None, 'comments': [], 'confidence': None,
     'createdDateTime': '2020-04-07T09:55:47.3413212Z', 'description': 'Created for test',
     'detectionIds': [],
     'eventDateTime': '2020-04-07T09:37:43.0372259Z', 'feedback': None,
     'lastModifiedDateTime': '2020-04-20T13:54:13.7933333Z', 'recommendedActions': [],
     'severity': 'medium',
     'sourceMaterials': [
         'https://securitycenter.microsoft.com/alert/da637218501473413212_-1554891308'],
     'status': 'newAlert', 'title': 'test alert',
     'vendorInformation': {'provider': 'Microsoft Defender ATP', 'providerVersion': None,
                           'subProvider': 'MicrosoftDefenderATP', 'vendor': 'Microsoft'},
     'cloudAppStates': [],
     'fileStates': [],
     'hostStates': [
         {'fqdn': 'desktop-s2455r8', 'isAzureAdJoined': True, 'isAzureAdRegistered': None,
          'isHybridAzureDomainJoined': None, 'netBiosName': None, 'os': 'Windows10',
          'privateIpAddress': '127.0.0.1', 'publicIpAddress': '127.0.0.1',
          'riskScore': 'High'}], 'historyStates': [], 'malwareStates': [],
     'networkConnections': [], 'processes': [], 'registryKeyStates': [], 'triggers': [],
     'userStates': [],
     'vulnerabilityStates': []},
    {'id': 'da637226278996299656_1986871053', 'azureTenantId': '<azureTenantId>',
     'azureSubscriptionId': None, 'riskScore': None, 'tags': [], 'activityGroupName': None,
     'assignedTo': 'Automation',
     'category': 'None', 'closedDateTime': '2020-04-19T07:09:16.2118771Z',
     'comments': ['testing', 'testing'],
     'confidence': None, 'createdDateTime': '2020-04-16T09:58:19.4253561Z',
     'description': 'Created for test',
     'detectionIds': [], 'eventDateTime': '2020-04-15T15:27:53.8499648Z', 'feedback': None,
     'lastModifiedDateTime': '2020-04-20T12:34:46.29Z', 'recommendedActions': [],
     'severity': 'medium',
     'sourceMaterials': [
         'https://securitycenter.microsoft.com/alert/da637226278996299656_1986871053'],
     'status': 'resolved', 'title': 'test alert',
     'vendorInformation': {'provider': 'Microsoft Defender ATP', 'providerVersion': None,
                           'subProvider': 'MicrosoftDefenderATP', 'vendor': 'Microsoft'},
     'cloudAppStates': [],
     'fileStates': [],
     'hostStates': [
         {'fqdn': 'desktop-s2455r8', 'isAzureAdJoined': True, 'isAzureAdRegistered': None,
          'isHybridAzureDomainJoined': None, 'netBiosName': None, 'os': 'Windows10',
          'privateIpAddress': '127.0.0.1', 'publicIpAddress': '127.0.0.1',
          'riskScore': 'High'}], 'historyStates': [], 'malwareStates': [],
     'networkConnections': [], 'processes': [], 'registryKeyStates': [], 'triggers': [],
     'userStates': [],
     'vulnerabilityStates': []}]}
EXPECTED_ALERTS_OUTPUT = {'MsGraph.Alert(val.ID && val.ID === obj.ID)': [
    {'ID': 'da637229984903196572_-755436942', 'Title': 'test alert', 'Category': 'None', 'Severity': 'medium',
     'CreatedDate': '2020-04-20T16:54:50.2722072Z', 'EventDate': '2020-04-20T16:34:28.061101Z', 'Status': 'newAlert',
     'Vendor': 'Microsoft', 'Provider': 'Microsoft Defender ATP'},
    {'ID': 'da637218501473413212_-1554891308', 'Title': 'test alert', 'Category': 'None', 'Severity': 'medium',
     'CreatedDate': '2020-04-07T09:55:47.3413212Z', 'EventDate': '2020-04-07T09:37:43.0372259Z', 'Status': 'newAlert',
     'Vendor': 'Microsoft', 'Provider': 'Microsoft Defender ATP'},
    {'ID': 'da637226278996299656_1986871053', 'Title': 'test alert', 'Category': 'None', 'Severity': 'medium',
     'CreatedDate': '2020-04-16T09:58:19.4253561Z', 'EventDate': '2020-04-15T15:27:53.8499648Z', 'Status': 'resolved',
     'Vendor': 'Microsoft', 'Provider': 'Microsoft Defender ATP'}]}

# msg-get-alert-details data:
RAW_ALERT_DETAILS = {
    '@odata.context': 'https://graph.microsoft.com/v1.0/$metadata#Security/alerts/$entity',
    'id': 'da637225970530734950_-1768941086', 'azureTenantId': '<tenant id>',
    'azureSubscriptionId': None, 'riskScore': None, 'tags': [], 'activityGroupName': None,
    'assignedTo': None, 'category': 'Malware', 'closedDateTime': None, 'comments': [],
    'confidence': None, 'createdDateTime': '2020-04-16T01:24:13.0578348Z',
    'description': 'Backdoors are malicious remote access tools that allow attackers to access and control infected '
                   'machines. Backdoors can also be used to exfiltrate data.\n\nA malware is considered active if it '
                   'is found running on the machine or it already has persistence mechanisms in place. Active malware '
                   'detections are assigned higher severity ratings.\n\nBecause this malware was active, '
                   'take precautionary measures and check for residual signs of infection.',
    'detectionIds': [], 'eventDateTime': '2020-04-16T01:22:39.3222427Z', 'feedback': None,
    'lastModifiedDateTime': '2020-04-19T10:18:39.35Z', 'recommendedActions': [], 'severity': 'medium',
    'sourceMaterials': ['https://securitycenter.microsoft.com/alert/da637225970530734950_-1768941086'],
    'status': 'newAlert', 'title': "An active 'Wintapp' backdoor was detected",
    'vendorInformation': {'provider': 'Microsoft Defender ATP', 'providerVersion': None,
                          'subProvider': 'MicrosoftDefenderATP', 'vendor': 'Microsoft'},
    'cloudAppStates': [], 'fileStates': [
        {'name': '<file_name>', 'path': '<file_path>', 'riskScore': None,
         'fileHash': {'hashType': 'sha1', 'hashValue': 'f809b926576cab647125a3907ef9265bdb130a0a'}}], 'hostStates': [
        {'fqdn': 'desktop-s2455r8', 'isAzureAdJoined': True, 'isAzureAdRegistered': None,
         'isHybridAzureDomainJoined': None, 'netBiosName': None, 'os': 'Windows10', 'privateIpAddress': '127.0.0.1',
         'publicIpAddress': '127.0.0.1', 'riskScore': 'High'}], 'historyStates': [], 'malwareStates': [],
    'networkConnections': [], 'processes': [], 'registryKeyStates': [], 'triggers': [],
    'userStates': [], 'vulnerabilityStates': []}
EXPECTED_ALERT_DETAILS_CONTEXT = {
    'MsGraph.Alert(val.ID && val.ID === obj.ID)': {'ID': 'da637225970530734950_-1768941086',
                                                   'Title': "An active 'Wintapp' backdoor was detected",
                                                   'Category': 'Malware', 'Severity': 'medium',
                                                   'CreatedDate': '2020-04-16T01:24:13.0578348Z',
                                                   'EventDate': '2020-04-16T01:22:39.3222427Z',
                                                   'Status': 'newAlert', 'Vendor': 'Microsoft',
                                                   'Provider': 'Microsoft Defender ATP'}}
EXPECTED_ALERT_DETAILS_HR_ALL = \
    '## Microsoft Security Graph Alert Details - alert_id\n' \
    '### Basic Properties\n' \
    '|AzureTenantID|Category|CreatedDate|Description|EventDate|LastModifiedDate|Severity|Status' \
    '|Title|\n' \
    '|---|---|---|---|---|---|---|---|---|\n' \
    '| <tenant id> | Malware | 2020-04-16T01:24:13.0578348Z | Backdoors are malicious remote ' \
    'access tools that allow attackers to access and control infected machines. Backdoors can ' \
    'also be used to exfiltrate data.<br><br>A malware is considered active if it is found ' \
    'running on the machine or it already has persistence mechanisms in place. Active malware ' \
    'detections are assigned higher severity ratings.<br><br>Because this malware was active, ' \
    'take precautionary measures and check for residual signs of infection. | ' \
    '2020-04-16T01:22:39.3222427Z | 2020-04-16T01:22:39.3222427Z | medium | ' \
    "newAlert | An active 'Wintapp' backdoor was detected |\n" \
    "### File Security States for Alert\n" \
    "|FileHash|Name|Path|\n" \
    "|---|---|---|\n" \
    "| f809b926576cab647125a3907ef9265bdb130a0a | <file_name> | <file_path> |\n" \
    "### Host Security States for Alert\n" \
    "|Fqdn|OS|PrivateIPAddress|PublicIPAddress|RiskScore|\n" \
    "|---|---|---|---|---|\n" \
    "| desktop-s2455r8 | Windows10 | 127.0.0.1 | 127.0.0.1 | High |\n" \
    "### Vendor Information for Alert\n" \
    "|Provider|SubProvider|Vendor|\n" \
    "|---|---|---|\n" \
    "| Microsoft Defender ATP | MicrosoftDefenderATP | Microsoft |\n"
EXPECTED_ALERT_DETAILS_HR_FILE_STATE = \
    '## Microsoft Security Graph Alert Details - alert_id\n' \
    '### Basic Properties\n' \
    '|AzureTenantID|Category|CreatedDate|Description|EventDate|LastModifiedDate|Severity|Status' \
    '|Title|\n' \
    '|---|---|---|---|---|---|---|---|---|\n' \
    '| <tenant id> | Malware | 2020-04-16T01:24:13.0578348Z | Backdoors are malicious remote ' \
    'access tools that allow attackers to access and control infected machines. Backdoors can ' \
    'also be used to exfiltrate data.<br><br>A malware is considered active if it is found ' \
    'running on the machine or it already has persistence mechanisms in place. Active malware ' \
    'detections are assigned higher severity ratings.<br><br>Because this malware was active, ' \
    'take precautionary measures and check for residual signs of infection. | ' \
    '2020-04-16T01:22:39.3222427Z | 2020-04-16T01:22:39.3222427Z | medium | ' \
    "newAlert | An active 'Wintapp' backdoor was detected |\n" \
    "### File Security States for Alert\n" \
    "|FileHash|Name|Path|\n" \
    "|---|---|---|\n" \
    "| f809b926576cab647125a3907ef9265bdb130a0a | <file_name> | <file_path> |\n"

client_mocker = MsGraphClient(tenant_id="tenant_id", auth_id="auth_id", enc_key='enc_key', app_name='app_name',
                              base_url='url', verify='use_ssl', proxy='proxy', self_deployed='self_deployed')


def test_get_users_command(mocker):
    from MicrosoftGraphSecurity import get_users_command
    mocker.patch.object(client_mocker, "get_users", return_value=RAW_USERS_DATA)
    hr, ec, _ = get_users_command(client_mocker, {})
    assert hr == EXPECTED_USER_HUMAN_READABLE
    assert ec == EXPECTED_USER_CONTEXT


@pytest.mark.parametrize(
    'args,expected_hr', [
        ({"alert_id": 'alert_id', "fields_to_include": "All"}, EXPECTED_ALERT_DETAILS_HR_ALL),
        ({"alert_id": 'alert_id', "fields_to_include": "FileStates"}, EXPECTED_ALERT_DETAILS_HR_FILE_STATE)

    ])
def test_get_alert_details_command(mocker, args, expected_hr):
    from MicrosoftGraphSecurity import get_alert_details_command
    mocker.patch.object(client_mocker, 'get_alert_details', return_value=RAW_ALERT_DETAILS)
    hr, ec, _ = get_alert_details_command(client_mocker, args)
    assert hr == expected_hr
    assert ec == EXPECTED_ALERT_DETAILS_CONTEXT


def test_search_alerts_command(mocker):
    """
    Unit test
    Given
    - search-alerts command
    - command args
    - command raw response
    When
    - mock the Client's search_alerts command.
    Then
    - run the search alerts command using the Client.
    Validate the contents of the output.
    """
    from MicrosoftGraphSecurity import search_alerts_command
    mocker.patch.object(client_mocker, 'search_alerts', return_value=ALERTS_RAW_RESPONSE)
    _, ec, _ = search_alerts_command(client_mocker, {'severity': 'medium'})
    assert ec == EXPECTED_ALERTS_OUTPUT


def test_fetch_incidents_command(mocker):
    """
    Unit test
    Given
    - fetch incidents command
    - command args
    - command raw response
    When
    - mock the parse_date_range.
    - mock the Client's search_alerts command.
    Then
    - run the fetch incidents command using the Client.
    Validate the length of the results and the different fields of the fetched incidents.
    """
    from MicrosoftGraphSecurity import fetch_incidents
    mocker.patch('MicrosoftGraphSecurity.parse_date_range', return_value=("2020-04-19 08:14:21", 'never mind'))
    mocker.patch.object(client_mocker, 'search_alerts', return_value=ALERTS_RAW_RESPONSE)
    incidents = fetch_incidents(client_mocker, fetch_time='1 hour', fetch_limit=10, providers='', filter='')
    assert len(incidents) == 3
    assert incidents[0].get('severity') == 2
    assert incidents[2].get('occurred') == '2020-04-20T16:54:50.2722072Z'

    incidents = fetch_incidents(client_mocker, fetch_time='1 hour', fetch_limit=1, providers='', filter='')
    assert len(incidents) == 1
    assert incidents[0].get('name') == 'test alert - da637218501473413212_-1554891308'

    incidents = fetch_incidents(client_mocker, fetch_time='1 hour', fetch_limit=0, providers='', filter='')
    assert len(incidents) == 0
