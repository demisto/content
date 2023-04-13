import pytest
from MicrosoftGraphSecurity import MsGraphClient, create_search_alerts_filters

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
SEARCH_ALERTS_RAW_RESPONSE_V1 = {'@odata.context': 'https://graph.microsoft.com/v1.0/$metadata#Security/alerts', 'value': [{
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
EXPECTED_SEARCH_ALERTS_OUTPUT_V1 = {'MsGraph.Alert(val.ID && val.ID === obj.ID)': [
    {'ID': 'da637229984903196572_-755436942', 'Title': 'test alert', 'Category': 'None', 'Severity': 'medium',
     'CreatedDate': '2020-04-20T16:54:50.2722072Z', 'EventDate': '2020-04-20T16:34:28.061101Z', 'Status': 'newAlert',
     'Vendor': 'Microsoft', 'Provider': 'Microsoft Defender ATP'},
    {'ID': 'da637218501473413212_-1554891308', 'Title': 'test alert', 'Category': 'None', 'Severity': 'medium',
     'CreatedDate': '2020-04-07T09:55:47.3413212Z', 'EventDate': '2020-04-07T09:37:43.0372259Z', 'Status': 'newAlert',
     'Vendor': 'Microsoft', 'Provider': 'Microsoft Defender ATP'},
    {'ID': 'da637226278996299656_1986871053', 'Title': 'test alert', 'Category': 'None', 'Severity': 'medium',
     'CreatedDate': '2020-04-16T09:58:19.4253561Z', 'EventDate': '2020-04-15T15:27:53.8499648Z', 'Status': 'resolved',
     'Vendor': 'Microsoft', 'Provider': 'Microsoft Defender ATP'}]}
EXPECTED_SEARCH_ALERTS_HR_V1 = '### Microsoft Security Graph Alerts\n|ID|Vendor|Provider|Title|Category|Severity|CreatedDate|' \
                               'EventDate|Status|\n|---|---|---|---|---|---|---|---|---|\n| da637229984903196572_-755436942 |' \
                               ' Microsoft | Microsoft Defender ATP | test alert | None | medium | 2020-04-20T16:54:50.2722072Z' \
                               ' | 2020-04-20T16:34:28.061101Z | newAlert |\n| da637218501473413212_-1554891308 | Microsoft | ' \
                               'Microsoft Defender ATP | test alert | None | medium | 2020-04-07T09:55:47.3413212Z | ' \
                               '2020-04-07T09:37:43.0372259Z | newAlert |\n| da637226278996299656_1986871053 | Microsoft | ' \
                               'Microsoft Defender ATP | test alert | None | medium | 2020-04-16T09:58:19.4253561Z | ' \
                               '2020-04-15T15:27:53.8499648Z | resolved |\n'

RAW_ALERT_DETAILS_V2: dict = {"@odata.context": "https://graph.microsoft.com/v1.0/$metadata#security/alerts_v2/$entity",
                              "actorDisplayName": None,
                              "alertWebUrl": "https://security.microsoft.com/alerts/alert_id?tid=tid", "assignedTo": None,
                              "category": "SuspiciousActivity", "classification": None, "comments": [],
                              "createdDateTime": "2022-10-16T01:48:05.8655909Z",
                              "description": "Some description about the alert.", "detectionSource": "automatedInvestigation",
                              "detectorId": "aaa", "determination": None, "id": "alert_id", "incidentId": "incidentId",
                              "severity": "informational", "status": "resolved", "serviceSource": "microsoftDefenderForEndpoint",
                              "title": "Automated", "lastUpdateDateTime": "2022-10-16T02:08:57.1233333Z"
                              }
EXPECTED_ALERT_DETAILS_HR_V2 = '## Microsoft Security Graph Alert Details - alert_id\n' \
                               '|id|incidentId|status|severity|detectionSource|serviceSource|title|category|createdDateTime|' \
                               'lastUpdateDateTime|\n|---|---|---|---|---|---|---|---|---|---|\n| alert_id | incidentId |' \
                               ' resolved | informational | automatedInvestigation | microsoftDefenderForEndpoint | Automated ' \
                               '| SuspiciousActivity | 2022-10-16T01:48:05.8655909Z | 2022-10-16T02:08:57.1233333Z |\n'


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
    'test_case', [
        ("test_case_1"),
        # (EXPECTED_ALERT_DETAILS_HR_FILE_STATE, 'API V1',
        #  EXPECTED_ALERT_DETAILS_CONTEXT),
        # ({"alert_id": 'alert_id', "fields_to_include": "FileStates"}, EXPECTED_ALERT_DETAILS_HR_V2, 'API V2',
        #  RAW_ALERT_DETAILS_V2, {'MsGraph.Alert(val.id && val.id === obj.id)': RAW_ALERT_DETAILS_V2})

    ])
def test_get_alert_details_command(mocker, test_case):
    """
        Given:
        - args including alert_id and fields_to_include, response mock, expected hr and ec outputs, and api version.
        - Case 1: args with all fields to include in fields_to_include, response of a v1 alert and, api version 1 flag.
        - Case 2: args with only FileStates to include in fields_to_include, response of a v1 alert and, api version 1 flag.
        - Case 3: args with only FileStates to include in fields_to_include, response of a v1 alert and, api version 2 flag.

        When:
        - Running get_alert_details_command.

        Then:
        - Ensure that the alert was parsed correctly and right HR and EC outputs are returned.
        - Case 1: Should parse all the response information into the HR,
                  and only the relevant fields from the response into the ec.
        - Case 2: Should parse only the FileStates section from the response into the HR,
                  and only the relevant fields from the response into the ec.
        - Case 3: Should ignore the the fields_to_include argument and parse all the response information into the HR,
                  and all fields from the response into the ec.
    """
    from MicrosoftGraphSecurity import get_alert_details_command
    from test_data.test_get_alert_details_command import test_get_alert_details_command_mock_data
    test_data = test_get_alert_details_command_mock_data.get(test_case)
    mocker.patch.object(client_mocker, 'get_alert_details', return_value=test_data.get('mock_response'))
    mocker.patch('MicrosoftGraphSecurity.API_VER', test_data.get('api_version'))
    hr, ec, _ = get_alert_details_command(client_mocker, test_data.get('args'))
    assert hr == test_data.get('expected_hr')
    assert ec == test_data.get('expected_ec')


@pytest.mark.parametrize(
    'args, api_ver, mock_response, expected_ec, expected_hr', [
        ({'severity': 'medium', 'limit': '50'}, 'API V1', SEARCH_ALERTS_RAW_RESPONSE_V1, EXPECTED_SEARCH_ALERTS_OUTPUT_V1,
         EXPECTED_SEARCH_ALERTS_HR_V1),

    ])
def test_search_alerts_command(mocker, args, api_ver, mock_response, expected_ec, expected_hr):
    """
        Given:
        - args, api version, response mock, expected hr and ec outputs.
        - Case 1: args with medium severity and limit of 50 incidents, response of a v1 search_alert, and a V1 api version flag.

        When:
        - Running search_alerts_command.

        Then:
        - Ensure that the response was parsed correctly and right HR and EC outputs are returned.
        - Case 1: Should parse all the response information into the HR and only the relevant fields from the response into the ec.
    """
    from MicrosoftGraphSecurity import search_alerts_command
    mocker.patch.object(client_mocker, 'search_alerts', return_value=mock_response)
    mocker.patch('MicrosoftGraphSecurity.API_VER', api_ver)
    hr, ec, _ = search_alerts_command(client_mocker, args)
    assert ec == expected_ec
    assert hr == expected_hr


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
    mocker.patch.object(client_mocker, 'search_alerts', return_value=SEARCH_ALERTS_RAW_RESPONSE_V1)
    incidents = fetch_incidents(client_mocker, fetch_time='1 hour', fetch_limit=10, providers='', filter='', service_sources='')
    assert len(incidents) == 3
    assert incidents[0].get('severity') == 2
    assert incidents[2].get('occurred') == '2020-04-20T16:54:50.2722072Z'

    incidents = fetch_incidents(client_mocker, fetch_time='1 hour', fetch_limit=1, providers='', filter='', service_sources='')
    assert len(incidents) == 1
    assert incidents[0].get('name') == 'test alert - da637218501473413212_-1554891308'

    incidents = fetch_incidents(client_mocker, fetch_time='1 hour', fetch_limit=0, providers='', filter='', service_sources='')
    assert len(incidents) == 0


def mock_request(method, url_suffix, params):
    return params


@pytest.mark.parametrize('filter_query, expected_filter_query', [
    ("Category eq 'Malware' and Severity eq 'High'", "Category eq 'Malware' and Severity eq 'High'"),
    ("Severity eq 'High'", "Severity eq 'High'"),
    ("Category eq 'Malware'", "Category eq 'Malware'")
])
def test_filter_query(filter_query, expected_filter_query, mocker):
    from MicrosoftGraphSecurity import MicrosoftClient
    mocker.patch.object(MicrosoftClient, 'http_request', side_effect=mock_request)

    args = {'filter': filter_query}
    params = create_search_alerts_filters(args, is_fetch=True)
    response = client_mocker.search_alerts(params=params)

    assert response.get('$filter') == expected_filter_query


@pytest.mark.parametrize(argnames='client_id', argvalues=['test_client_id', None])
def test_test_module_command_with_managed_identities(mocker, requests_mock, client_id):
    """
        Given:
            - Managed Identities client id for authentication.
        When:
            - Calling test_module.
        Then:
            - Ensure the output are as expected.
    """

    from MicrosoftGraphSecurity import main, MANAGED_IDENTITIES_TOKEN_URL, Resources
    import demistomock as demisto
    import re

    mock_token = {'access_token': 'test_token', 'expires_in': '86400'}
    get_mock = requests_mock.get(MANAGED_IDENTITIES_TOKEN_URL, json=mock_token)
    requests_mock.get(re.compile(f'^{Resources.graph}.*'), json={'value': []})

    params = {
        'managed_identities_client_id': {'password': client_id},
        'use_managed_identities': 'True',
        'resource_group': 'test_resource_group',
        'host': Resources.graph
    }
    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'command', return_value='test-module')
    mocker.patch.object(demisto, 'results')
    mocker.patch('MicrosoftApiModule.get_integration_context', return_value={})

    main()

    assert 'ok' in demisto.results.call_args[0][0]['Contents']
    qs = get_mock.last_request.qs
    assert qs['resource'] == [Resources.graph]
    assert client_id and qs['client_id'] == [client_id] or 'client_id' not in qs
