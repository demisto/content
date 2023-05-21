import pytest
from freezegun import freeze_time
from pytest import raises
from CommonServerPython import *
import io
import copy


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


SINGLE_INCIDENTS_MOCK_RESPONSE = util_load_json('test_data/fetch_single_incident.json')
MULTIPLE_INCIDENTS_MOCK_RESPONSE = util_load_json('test_data/fetch_multiple_incident.json')
FIRST_STATIC_ATT_MOCK_RESPONSE = util_load_json('test_data/incident_static_attributes_first.json')
FIRST_EDITABLE_ATT_MOCK_RESPONSE = util_load_json('test_data/incident_editable_attributes_first.json')
SECOND_STATIC_ATT_MOCK_RESPONSE = util_load_json('test_data/incident_static_attributes_second.json')
SECOND_EDITABLE_ATT_MOCK_RESPONSE = util_load_json('test_data/incident_editable_attributes_second.json')

FIRST_INCIDENT_DETAILS = json.dumps({"ID": 3620, "severity": "High", "customAttributeGroup": [
    {"name": "custom_attribute_group.default",
     "customAttribute": [{"name": "Custom Attribute1", "index": 1}, {"name": "cust2", "index": 2},
                         {"name": "bla", "index": 3}]},
    {"name": "att group2", "customAttribute": [{"name": "kjv", "index": 4}]}], "policyVersion": 4, "attachmentInfo": [
    {"componentType": 3, "messageComponentName": "token", "messageComponentId": 4623, "wasCracked": False,
     "documentFormat": "unknown", "mimeType": "application/octet-stream", "originalSize": 0}],
    "messageSubject": "HTTP incident", "policyName": "Network Test policy",
    "policyGroupName": "policy_group.default.name", "policyGroupId": 1,
    "messageSource": "NETWORK", "messageId": 2104, "messageOriginatorID": 828,
    "matchCount": 3, "creationDate": "2022-03-06T15:23:53.245",
                                     "isBlockedStatusSuperseded": False,
                                     "detectionServerName": "Detection - Network monitor", "networkSenderPort": 59637,
                                     "messageType": "HTTP", "policyId": 2, "detectionDate": "2022-03-06T15:23:39.197",
                                     "messageTypeId": 3, "detectionServerId": 1,
                                     "messageDate": "2022-03-06T15:23:39.197", "senderIPAddress": "1.1.1.1",
                                     "endpointMachineIpAddress": "1.1.1.1", "recipientInfo": [
        {"recipientType": 1, "recipientPort": 80, "recipientDomain": "2.2.2.254",
         "recipientIdentifier": "http://2.2.2.254/latest/api/token", "recipientIPAddress": "2.2.2.254",
         "recipientUrl": "http://2.2.2.254/latest/api/token"}], "networkSenderIdentifier": "1.1.1.1",
    "isHidingNotAllowed": False, "incidentStatusName": "incident.status.New",
    "incidentStatusId": 1, "isHidden": False, "preventOrProtectStatusId": 0})

SECOND_INCIDENT_DETAILS = json.dumps({"ID": 3629, "severity": "High", "customAttributeGroup": [
    {"name": "custom_attribute_group.default",
     "customAttribute": [{"name": "Custom Attribute1", "index": 1}, {"name": "cust2", "index": 2},
                         {"name": "bla", "index": 3}]},
    {"name": "att group2", "customAttribute": [{"name": "kjv", "index": 4}]}], "policyVersion": 1, "attachmentInfo": [
    {"componentType": 3, "messageComponentName": "423.txt", "messageComponentId": 4638, "wasCracked": False,
     "documentFormat": "ascii", "originalSize": 3928}], "fileCreateDate": "2022-01-05T14:10:04.798",
    "discoverServer": "c:", "fileAccessDate": "2022-01-05T14:10:04.798",
    "discoverTargetName": "Discovery server - File system", "messageType": "RAW",
    "discoverRepositoryLocation": "c:/das/423.txt", "discoverScanId": 216,
    "discoverContentRootPath": "c:/das", "policyName": "Illegal Drugs",
    "policyGroupName": "Test Policy group for Endpoint Discover", "policyGroupId": 21,
    "messageSource": "DISCOVER", "messageId": 2110, "matchCount": 100,
    "creationDate": "2022-03-06T15:23:53.246",
    "discoverMillisSinceFirstSeen": 5244552861, "isBlockedStatusSuperseded": False,
    "detectionServerName": "Detection - Discovery", "messageAclEntries": [
        {"principal": "NT AUTHORITY\\SYSTEM", "aclType": "FILE", "permission": "READ", "grantDeny": "GRANT"},
        {"principal": "NT AUTHORITY\\SYSTEM", "aclType": "FILE", "permission": "WRITE", "grantDeny": "GRANT"},
        {"principal": "BUILTIN\\Administrators", "aclType": "FILE", "permission": "READ", "grantDeny": "GRANT"},
        {"principal": "BUILTIN\\Administrators", "aclType": "FILE", "permission": "WRITE", "grantDeny": "GRANT"},
        {"principal": "BUILTIN\\Users", "aclType": "FILE", "permission": "READ", "grantDeny": "GRANT"}], "policyId": 43,
    "detectionDate": "2022-03-06T15:23:39.197", "messageTypeId": 9,
    "discoverTargetId": 2, "discoverScanStartDate": "2022-03-06T07:00:00",
    "discoverName": "423.txt", "detectionServerId": 21,
    "messageDate": "2022-01-05T14:10:16.548", "fileOwner": "BUILTIN\\Administrators",
    "discoverUrl": "c:/das/423.txt", "isHidingNotAllowed": False,
    "incidentStatusName": "incident.status.New", "detectedRemediationStatus": 0,
    "incidentStatusId": 1, "isHidden": False, "preventOrProtectStatusId": 0})


def test_parse_custom_attribute():
    from SymantecDLPV2 import parse_custom_attribute
    custom_attribute_group_list = [
        {
            'customAttributes': [
                {
                    "name": "cn",
                    "index": 1,
                    "displayOrder": 1,
                    "value": None,
                    "email": False
                }
            ],
            'name': 'Default Attribute Group'
        },
        {
            'customAttributes': [
                {
                    'name': 'Resolution',
                    "index": 2,
                    "displayOrder": 2,
                    "value": None,
                    "email": False
                },
                {
                    'name': 'First Name',
                    'value': 'Admin',
                    "index": 3,
                    "displayOrder": 3,
                    "email": False
                }
            ],
            'name': 'Predefined'
        }
    ]
    args_all = {'custom_attributes': 'all'}
    custom_attribute_all_list_output = [{'customAttribute': [{'index': 1, 'name': 'cn'}],
                                         'name': 'Default Attribute Group'},
                                        {'customAttribute': [{'index': 2, 'name': 'Resolution'},
                                                             {'index': 3, 'name': 'First Name', 'value': 'Admin'}],
                                         'name': 'Predefined'}]
    assert custom_attribute_all_list_output == parse_custom_attribute(custom_attribute_group_list, args_all)
    args_none = {'custom_attributes': 'none'}
    assert [] == parse_custom_attribute(custom_attribute_group_list, args_none)
    args_custom = {'custom_attributes': 'specific attributes'}
    with raises(DemistoException, match='When choosing the custom value for custom_attributes argument -'
                                        ' the custom_data list must be filled with custom attribute names.'
                                        ' For example: custom_value=ca1,ca2,ca3'):
        parse_custom_attribute(custom_attribute_group_list, args_custom)
    args_custom['custom_data'] = 'cn, First Name, bbb'
    custom_attribute_custom_list_output = [{'customAttribute': {'index': 1, 'name': 'cn'},
                                            'name': 'Default Attribute Group'},
                                           {'customAttribute': {'index': 3, 'name': 'First Name', 'value': 'Admin'},
                                            'name': 'Predefined'}]
    assert custom_attribute_custom_list_output == parse_custom_attribute(custom_attribute_group_list, args_custom)
    args_custom['custom_data'] = 'aaa'
    assert [] == parse_custom_attribute(custom_attribute_group_list, args_custom)
    args_group = {'custom_attributes': 'custom attribute group name'}
    with raises(DemistoException, match='When choosing the group value for custom_attributes argument -'
                                        ' the custom_data list must be filled with group names.'
                                        ' For example: custom_value=g1,g2,g3'):
        parse_custom_attribute(custom_attribute_group_list, args_group)
    args_group['custom_data'] = 'Default Attribute Group, Predefined, uuu'
    custom_attribute_group_list_output = [{'customAttribute': [{'index': 1, 'name': 'cn'}],
                                           'name': 'Default Attribute Group'},
                                          {'customAttribute': [{'index': 2, 'name': 'Resolution'},
                                                               {'index': 3, 'name': 'First Name', 'value': 'Admin'}],
                                           'name': 'Predefined'}]
    assert custom_attribute_group_list_output == parse_custom_attribute(custom_attribute_group_list, args_group)


@pytest.mark.parametrize('custom_attribute,expected_result', [
    (['1:test', '2:test2'], [{"columnIndex": 1, "value": 'test'}, {"columnIndex": 2, "value": 'test2'}]),
    (['1:test'], [{"columnIndex": 1, "value": 'test'}])])
def test_build_custom_attributes_update(custom_attribute, expected_result):
    """
    Given
    - A string represting a date.
    When
    - running date_format_parsing on the date.
    Then
    - Ensure the datestring is converted to the ISO-8601 format.
    """
    from SymantecDLPV2 import build_custom_attributes_update

    assert build_custom_attributes_update(custom_attribute) == expected_result


@pytest.mark.parametrize('severity,expected_result', [
    (1, 'High'),
    (4, 'Info')])
def test_get_severity_name_by_id(severity, expected_result):
    """
    Given
    - A number represting severity.
    When
    - running get_severity_name_by_id on the severity.
    Then
    - Ensure the severity is converted to severity name.
    """
    from SymantecDLPV2 import get_severity_name_by_id

    assert get_severity_name_by_id(severity) == expected_result


@freeze_time("2022-03-04T13:34:14Z")
@pytest.mark.parametrize('creation_date,expected_result', [
    ('2 days', "2022-03-02T13:34:14Z"),
    ("2022-03-02T13:34:14Z", "2022-03-02T13:34:14Z")])
def test_parse_creation_date(creation_date, expected_result):
    """
    Given
    - A number represting severity.
    When
    - running get_severity_name_by_id on the severity.
    Then
    - Ensure the severity is converted to severity name.
    """
    from SymantecDLPV2 import parse_creation_date

    assert parse_creation_date(creation_date) == expected_result


def test_create_update_body():
    """
    Given
    - Arguments to update in the incident.
    When
    - Run create_update_body function
    Then
    - Ensure the body is created successfully
    """
    from SymantecDLPV2 import create_update_body

    update_body = create_update_body(incident_ids=[3620], data_owner_email='testing@gmail.com', note='test note',
                                     custom_attributes=['1:test'])
    assert update_body == {'incidentIds': [3620], 'dataOwnerEmail': 'testing@gmail.com',
                           'incidentNotes': [{'note': 'test note'}],
                           'incidentCustomAttributes': [{'columnIndex': 1, 'value': 'test'}]}


# COMMANDS UNITESTS


def test_get_incidents_list_command(mocker):
    """
    Given
    - Get incidents command with no arguments.
    When
    - Run get incidents list command
    Then
    - Ensure response
    """
    from SymantecDLPV2 import Client, list_incidents_command

    client = Client(base_url='https://SymantecDLPV2.com/', auth=("test", "pass"), verify=False, proxy=False,
                    headers={"Content-type": "application/json"})
    args = {}
    mock_response = util_load_json('test_data/incidents_list_response.json')

    mocker.patch.object(client, 'get_incidents_request', return_value=mock_response)

    incidents_response = list_incidents_command(client, args)
    expected_response = util_load_json('test_data/incidents_list_context.json')
    assert incidents_response.outputs == expected_response


def test_get_incidents_list_command_with_filters(mocker):
    """
    Given
    - Get incidents command with arguments.
    When
    - Run get incidents list command
    Then
    - Ensure response
    """
    from SymantecDLPV2 import Client, list_incidents_command

    client = Client(base_url='https://SymantecDLPV2.com/', auth=("test", "pass"), verify=False, proxy=False,
                    headers={"Content-type": "application/json"})
    args = {'severity': 'High, Medium', 'status_id': '21, 42'}
    mock_response = util_load_json('test_data/incidents_list_response_with_filters.json')

    mocker.patch.object(client, 'get_incidents_request', return_value=mock_response)

    incidents_response = list_incidents_command(client, args)
    expected_response = util_load_json('test_data/incidents_list_context_with_filters.json')
    assert incidents_response.outputs == expected_response


def test_get_incident_details_command(mocker):
    """
    Given
    - Get incidents details.
    When
    - Run get incident details command
    Then
    - Ensure response
    """
    from SymantecDLPV2 import Client, get_incident_details_command

    client = Client(base_url='https://SymantecDLPV2.com/', auth=("test", "pass"), verify=False, proxy=False,
                    headers={"Content-type": "application/json"})
    args = {'incident_id': '3620', 'custom_attributes': 'all'}
    incident_static_attributes_res = copy.deepcopy(FIRST_STATIC_ATT_MOCK_RESPONSE)
    incident_editable_attributes_res = copy.deepcopy(FIRST_EDITABLE_ATT_MOCK_RESPONSE)
    mocker.patch.object(client, 'get_incident_static_attributes_request', return_value=incident_static_attributes_res)
    mocker.patch.object(client, 'get_incident_editable_attributes_request',
                        return_value=incident_editable_attributes_res)

    incidents_response = get_incident_details_command(client, args)
    expected_response = util_load_json('test_data/incident_details_context.json')
    assert incidents_response.outputs == expected_response


def test_get_incident_details_unauthorized_command(mocker):
    """
    Given
    - Get incidents details.
    When
    - Run get incident details commandnfailed on 401 error
    Then
    - Ensure getting error
    """
    from SymantecDLPV2 import Client, get_incident_details_command

    client = Client(base_url='https://SymantecDLPV2.com/', auth=("test", "pass"), verify=False, proxy=False,
                    headers={"Content-type": "application/json"})
    args = {'incident_id': '3620', 'custom_attributes': 'all'}
    mock_response = util_load_json('test_data/incident_details_error.json')
    mocker.patch.object(client, '_http_request', side_effect=DemistoException(mock_response, res=mock_response))

    with pytest.raises(DemistoException):
        get_incident_details_command(client, args)


def test_list_incident_status_command(mocker):
    """
    Given
    - Get incidents status command
    When
    - Run get incidents status command
    Then
    - Ensure response
    """
    from SymantecDLPV2 import Client, list_incident_status_command

    client = Client(base_url='https://SymantecDLPV2.com/', auth=("test", "pass"), verify=False, proxy=False,
                    headers={"Content-type": "application/json"})
    mock_response = util_load_json('test_data/incidents_status_response.json')

    mocker.patch.object(client, 'get_incidents_status_request', return_value=mock_response)

    incidents_response = list_incident_status_command(client)
    expected_response = util_load_json('test_data/incidents_status_context.json')
    assert incidents_response.outputs == expected_response


def test_get_incident_history_command(mocker):
    """
    Given
    - Get incident history command with arguments.
    When
    - Run get incident history command
    Then
    - Ensure response
    """
    from SymantecDLPV2 import Client, get_incident_history_command

    client = Client(base_url='https://SymantecDLPV2.com/', auth=("test", "pass"), verify=False, proxy=False,
                    headers={"Content-type": "application/json"})
    args = {'incident_id': '3536'}

    mock_response = util_load_json('test_data/incident_history_response.json')

    mocker.patch.object(client, 'get_incident_history_request', return_value=mock_response)

    history_response = get_incident_history_command(client, args)
    expected_response = util_load_json('test_data/incident_history_context.json')
    assert history_response.outputs == expected_response


def test_get_list_remediation_status(mocker):
    """
    Given
    - Get remediation status command
    When
    - Run get remediation status command
    Then
    - Ensure response
    """
    from SymantecDLPV2 import Client, get_list_remediation_status

    client = Client(base_url='https://SymantecDLPV2.com/', auth=("test", "pass"), verify=False, proxy=False,
                    headers={"Content-type": "application/json"})
    mock_response = util_load_json('test_data/remediation_status_response.json')

    mocker.patch.object(client, 'get_list_remediation_status_request', return_value=mock_response)

    incidents_response = get_list_remediation_status(client)
    expected_response = util_load_json('test_data/remediation_status_context.json')
    assert incidents_response.outputs == expected_response


@freeze_time("2022-03-07T13:34:14Z")
def test_fetch_incidents_single(requests_mock):
    """Tests the fetch-incidents function single incident
    """
    from SymantecDLPV2 import Client, fetch_incidents
    # mock responses
    incident_static_attributes_res = FIRST_STATIC_ATT_MOCK_RESPONSE
    incident_editable_attributes_res = FIRST_EDITABLE_ATT_MOCK_RESPONSE
    requests_mock.post(
        'https://SymantecDLPV2.com/ProtectManager/webservices/v2/incidents', json=SINGLE_INCIDENTS_MOCK_RESPONSE)
    requests_mock.get(
        'https://SymantecDLPV2.com/ProtectManager/webservices/v2/incidents/3620/staticAttributes',
        json=incident_static_attributes_res)
    requests_mock.get(
        'https://SymantecDLPV2.com/ProtectManager/webservices/v2/incidents/3620/editableAttributes',
        json=incident_editable_attributes_res)

    client = Client(base_url="https://SymantecDLPV2.com", auth=("test", "pass"), verify=False, proxy=False,
                    headers={"Content-type": "application/json"})

    incidents = fetch_incidents(client, fetch_time='3 days', fetch_limit='1', last_run={})
    assert len(incidents) == 1
    assert incidents[0].get('rawJSON') == FIRST_INCIDENT_DETAILS


@freeze_time("2022-03-07T13:34:14Z")
def test_fetch_incidents_multiple(requests_mock):
    """Tests the fetch-incidents function with multiple incidents
    """
    from SymantecDLPV2 import Client, fetch_incidents

    # mock responses
    first_incident_static_attributes_res = copy.deepcopy(FIRST_STATIC_ATT_MOCK_RESPONSE)
    first_incident_editable_attributes_res = copy.deepcopy(FIRST_EDITABLE_ATT_MOCK_RESPONSE)
    second_incident_static_attributes_res = copy.deepcopy(SECOND_STATIC_ATT_MOCK_RESPONSE)
    second_incident_editable_attributes_res = copy.deepcopy(SECOND_EDITABLE_ATT_MOCK_RESPONSE)
    requests_mock.post(
        'https://SymantecDLPV2.com/ProtectManager/webservices/v2/incidents', json=MULTIPLE_INCIDENTS_MOCK_RESPONSE)
    requests_mock.get(
        'https://SymantecDLPV2.com/ProtectManager/webservices/v2/incidents/3620/staticAttributes',
        json=first_incident_static_attributes_res)
    requests_mock.get(
        'https://SymantecDLPV2.com/ProtectManager/webservices/v2/incidents/3620/editableAttributes',
        json=first_incident_editable_attributes_res)
    requests_mock.get(
        'https://SymantecDLPV2.com/ProtectManager/webservices/v2/incidents/3629/staticAttributes',
        json=second_incident_static_attributes_res)
    requests_mock.get(
        'https://SymantecDLPV2.com/ProtectManager/webservices/v2/incidents/3629/editableAttributes',
        json=second_incident_editable_attributes_res)

    client = Client(base_url="https://SymantecDLPV2.com", auth=("test", "pass"), verify=False, proxy=False,
                    headers={"Content-type": "application/json"})

    incidents = fetch_incidents(client, fetch_time='3 days', fetch_limit='1', last_run={})
    assert len(incidents) == 2
    assert incidents[0].get('rawJSON') == FIRST_INCIDENT_DETAILS
    assert incidents[1].get('rawJSON') == SECOND_INCIDENT_DETAILS


def test_fetch_incidents_last_run(requests_mock):
    """
    Given:
        Fetch incident with last run (not first time fetch)
    When:
        Fetching incidents with last run
    Then:
        Make sure to fetch the relevant incident
    """
    from SymantecDLPV2 import Client, fetch_incidents

    last_run = {'last_incident_creation_time': '2022-03-06T15:23:53.245'}
    # mock responses
    first_incident_static_attributes_res = copy.deepcopy(FIRST_STATIC_ATT_MOCK_RESPONSE)
    first_incident_editable_attributes_res = copy.deepcopy(FIRST_EDITABLE_ATT_MOCK_RESPONSE)
    second_incident_static_attributes_res = copy.deepcopy(SECOND_STATIC_ATT_MOCK_RESPONSE)
    second_incident_editable_attributes_res = copy.deepcopy(SECOND_EDITABLE_ATT_MOCK_RESPONSE)
    requests_mock.post(
        'https://SymantecDLPV2.com/ProtectManager/webservices/v2/incidents', json=MULTIPLE_INCIDENTS_MOCK_RESPONSE)
    requests_mock.get(
        'https://SymantecDLPV2.com/ProtectManager/webservices/v2/incidents/3620/staticAttributes',
        json=first_incident_static_attributes_res)
    requests_mock.get(
        'https://SymantecDLPV2.com/ProtectManager/webservices/v2/incidents/3620/editableAttributes',
        json=first_incident_editable_attributes_res)
    requests_mock.get(
        'https://SymantecDLPV2.com/ProtectManager/webservices/v2/incidents/3629/staticAttributes',
        json=second_incident_static_attributes_res)
    requests_mock.get(
        'https://SymantecDLPV2.com/ProtectManager/webservices/v2/incidents/3629/editableAttributes',
        json=second_incident_editable_attributes_res)

    client = Client(base_url="https://SymantecDLPV2.com", auth=("test", "pass"), verify=False, proxy=False,
                    headers={"Content-type": "application/json"})

    incidents = fetch_incidents(client, fetch_time='3 days', fetch_limit='1', last_run=last_run)
    assert len(incidents) == 1
    assert incidents[0].get('rawJSON') == SECOND_INCIDENT_DETAILS


def test_fetch_incidents_last_run_no_fetch(requests_mock):
    """
    Given:
        Fetch incident with last run (not first time fetch)
    When:
        Fetching incidents with last run and no new incidents
    Then:
        Make sure that the fetch is not getting more incidents.
    """
    from SymantecDLPV2 import Client, fetch_incidents

    last_run = {'last_incident_creation_time': '2022-03-06T15:23:53.246'}
    # mock responses
    requests_mock.post(
        'https://SymantecDLPV2.com/ProtectManager/webservices/v2/incidents', json=MULTIPLE_INCIDENTS_MOCK_RESPONSE)

    client = Client(base_url="https://SymantecDLPV2.com", auth=("test", "pass"), verify=False, proxy=False,
                    headers={"Content-type": "application/json"})

    incidents = fetch_incidents(client, fetch_time='3 days', fetch_limit='1', last_run=last_run)
    assert len(incidents) == 0


def test_get_incident_details_fetch(mocker):
    """
    Given:
        Fetch incident with 401 error
    When:
        Fetching incidents
    Then:
        Make sure that the fetch is not getting an error and return partial data on this incident.
    """
    from SymantecDLPV2 import Client, get_incident_details_fetch
    incident_data = {
        "policyVersion": 4,
        "messageType": "HTTP",
        "policyId": 2,
        "detectionDate": "2022-03-06T15:23:39.197",
        "messageTypeId": 3,
        "messageSource": "NETWORK",
        "detectionServerId": 1,
        "matchCount": 3,
        "severityId": 1,
        "creationDate": "2022-03-06T15:23:53.245",
        "incidentId": 3620,
        "incidentStatusId": 1
    }
    mock_response = util_load_json('test_data/incident_details_error.json')

    client = Client(base_url="https://SymantecDLPV2.com", auth=("test", "pass"), verify=False, proxy=False,
                    headers={"Content-type": "application/json"})
    mocker.patch.object(client, '_http_request', side_effect=DemistoException(mock_response, res=mock_response))
    response = get_incident_details_fetch(client, incident_data)
    assert response == {'ID': 3620, 'creationDate': '2022-03-06T15:23:53.245', 'policyId': 2, 'severity': 'High',
                        'incidentStatusId': 1, 'detectionDate': '2022-03-06T15:23:39.197', 'policyVersion': 4,
                        'messageSource': 'NETWORK', 'messageType': 'HTTP', 'matchCount': 3,
                        'errorMessage': 'Notice: Incident contains partial data only'}


def test_get_incident_original_message_command(requests_mock):
    """
    Given:
        file content of an incident

    When:
        running get_incident_original_message_command

    Then:
        Make sure the file gets created as excpected
    """
    from SymantecDLPV2 import Client, get_incident_original_message_command

    requests_mock.get(
        'https://SymantecDLPV2.com/ProtectManager/webservices/v2/incidents/1234/originalMessage',
        content='123'.encode()
    )

    client = Client(
        base_url="https://SymantecDLPV2.com",
        auth=("test", "pass"),
        verify=False,
        proxy=False,
        headers={"Content-type": "application/json"}
    )

    assert get_incident_original_message_command(client, {'incident_id': '1234'})


def test_get_report_filters_command(requests_mock):
    """
    Given:
        report id

    When:
        running get_report_filters_command

    Then:
        Make sure the context output is returned as expected
    """
    from SymantecDLPV2 import Client, get_report_filters_command

    requests_mock.get(
        'https://SymantecDLPV2.com/ProtectManager/webservices/v2/savedReport/1234',
        json={"test": "test"}
    )

    client = Client(
        base_url="https://SymantecDLPV2.com",
        auth=("test", "pass"),
        verify=False,
        proxy=False,
        headers={"Content-type": "application/json"}
    )

    result = get_report_filters_command(client, {'report_id': '1234'})
    assert result.outputs == {'test': 'test', 'filterString': '{"test": "test"}'}


@pytest.mark.parametrize('exception_error', ['error, 401 unauthorized', 'error occurred'])
def test_get_report_filters_command_error(mocker, exception_error):
    """
    Given:
        api error

    When:
        running get_report_filters_command

    Then:
        Make sure an exception is raised
    """
    from SymantecDLPV2 import Client, get_report_filters_command

    client = Client(
        base_url="https://SymantecDLPV2.com",
        auth=("test", "pass"),
        verify=False,
        proxy=False,
        headers={"Content-type": "application/json"}
    )

    mocker.patch.object(client, '_http_request', side_effect=DemistoException(exception_error))

    with pytest.raises(DemistoException):
        get_report_filters_command(client, {'incident_id': '1234'})


def test_list_users_command(requests_mock):
    """
    Given:
        a user

    When:
        running list_users_command

    Then:
        Make sure the context output is returned as expected
    """
    from SymantecDLPV2 import Client, list_users_command

    mocked_response = [
        {
            "userId": 241, "userName": "User1", "emailAddress": "test@gmail.com",
            "accountDisabled": "no", "roles": ["API Web"]
        }
    ]

    requests_mock.get(
        'https://SymantecDLPV2.com/ProtectManager/webservices/v2/users',
        json=mocked_response
    )

    client = Client(
        base_url="https://SymantecDLPV2.com",
        auth=("test", "pass"),
        verify=False,
        proxy=False,
        headers={"Content-type": "application/json"}
    )

    result = list_users_command(client)
    assert result.outputs == mocked_response


def test_get_sender_recipient_pattern_command(requests_mock):
    """
    Given:
        pattern id

    When:
        running get_sender_recipient_pattern_command

    Then:
        Make sure the context output is returned as expected
    """
    from SymantecDLPV2 import Client, get_sender_recipient_pattern_command

    mocked_response = {
        "id": 503,
        "name": "XSOAR Sender Block Example",
        "description": "demo",
        "ruleType": 4,
        "modifiedDate": "05/16/23 12:20 PM",
        "modifiedBy": {
            "id": 343,
            "name": "AdminUsername "
        },
        "userPatterns": [
            "domain-jsmith",
            "domain-jdoe"
        ],
        "ipAddresses": [
            "1.1.1.1",
            "2.2.2.2"
        ]
    }

    requests_mock.get(
        'https://SymantecDLPV2.com/ProtectManager/webservices/v2/senderRecipientPattern/1234',
        json=mocked_response
    )

    client = Client(
        base_url="https://SymantecDLPV2.com",
        auth=("test", "pass"),
        verify=False,
        proxy=False,
        headers={"Content-type": "application/json"}
    )

    result = get_sender_recipient_pattern_command(client, {'pattern_id': '1234'})
    assert result.outputs == mocked_response
    assert result.outputs_prefix == 'SymantecDLP.SenderRecipientPattern'


def test_list_sender_recipient_patterns_command(requests_mock):
    """
    Given:
        list of patterns

    When:
        running list_sender_recipient_patterns_command

    Then:
        Make sure the context output is returned as expected
    """
    from SymantecDLPV2 import Client, list_sender_recipient_patterns_command

    mocked_response = [
        {
            "id": 503,
            "name": "XSOAR Sender Block Example",
            "description": "demo",
            "ruleType": 4,
            "modifiedDate": "05/16/23 12:20 PM",
            "modifiedBy": {
                "id": 343,
                "name": "AdminUsername "
            },
            "userPatterns": [
                "domain-jsmith",
                "domain-jdoe"
            ],
            "ipAddresses": [
                "1.1.1.1",
                "2.2.2.2"
            ]
        }
    ]

    requests_mock.get(
        'https://SymantecDLPV2.com/ProtectManager/webservices/v2/senderRecipientPattern/list',
        json=mocked_response
    )

    client = Client(
        base_url="https://SymantecDLPV2.com",
        auth=("test", "pass"),
        verify=False,
        proxy=False,
        headers={"Content-type": "application/json"}
    )

    result = list_sender_recipient_patterns_command(client)
    assert result.outputs == mocked_response


def test_update_sender_pattern_command(requests_mock):
    """
    Given:
        pattern id

    When:
        running update_sender_pattern_command

    Then:
        Make sure the context output is returned as expected
    """
    from SymantecDLPV2 import Client, update_sender_pattern_command

    mocked_response = {
        "id": 503,
        "name": "XSOAR Sender Block Example",
        "description": "demo",
        "ruleType": 4,
        "modifiedDate": "05/16/23 12:20 PM",
        "modifiedBy": {
            "id": 343,
            "name": "AdminUsername "
        },
        "userPatterns": [
            "domain-jsmith",
            "domain-jdoe"
        ],
        "ipAddresses": [
            "1.1.1.1",
            "2.2.2.2"
        ]
    }

    requests_mock.put(
        'https://SymantecDLPV2.com/ProtectManager/webservices/v2/senderRecipientPattern/1234',
        json=mocked_response
    )

    client = Client(
        base_url="https://SymantecDLPV2.com",
        auth=("test", "pass"),
        verify=False,
        proxy=False,
        headers={"Content-type": "application/json"}
    )

    result = update_sender_pattern_command(client, {'pattern_id': '1234'})
    assert result.outputs == mocked_response
    assert result.outputs_prefix == 'SymantecDLP.SenderUpdate'


def test_update_recipient_pattern_command(requests_mock):
    """
    Given:
        pattern id

    When:
        running update_recipient_pattern_command

    Then:
        Make sure the context output is returned as expected
    """
    from SymantecDLPV2 import Client, update_recipient_pattern_command

    mocked_response = {
        "id": 503,
        "name": "XSOAR Sender Block Example",
        "description": "demo",
        "ruleType": 4,
        "modifiedDate": "05/16/23 12:20 PM",
        "modifiedBy": {
            "id": 343,
            "name": "AdminUsername "
        },
        "userPatterns": [
            "domain-jsmith",
            "domain-jdoe"
        ],
        "ipAddresses": [
            "1.1.1.1",
            "2.2.2.2"
        ]
    }

    requests_mock.put(
        'https://SymantecDLPV2.com/ProtectManager/webservices/v2/senderRecipientPattern/1234',
        json=mocked_response
    )

    client = Client(
        base_url="https://SymantecDLPV2.com",
        auth=("test", "pass"),
        verify=False,
        proxy=False,
        headers={"Content-type": "application/json"}
    )

    result = update_recipient_pattern_command(client, {'pattern_id': '1234'})
    assert result.outputs == mocked_response
    assert result.outputs_prefix == 'SymantecDLP.RecipientUpdate'


def test_get_message_body_command(requests_mock):
    """
    Given:
        pattern id

    When:
        running get_message_body_command

    Then:
        Make sure the context output is returned as expected
    """
    from SymantecDLPV2 import Client, get_message_body_command

    requests_mock.get(
        'https://SymantecDLPV2.com/ProtectManager/webservices/v2/incidents/1234/messageBody',
        json={'test': 'test'}
    )

    client = Client(
        base_url="https://SymantecDLPV2.com",
        auth=("test", "pass"),
        verify=False,
        proxy=False,
        headers={"Content-type": "application/json"}
    )

    result = get_message_body_command(client, {'incident_id': '1234'})
    assert result.outputs == {'IncidentID': '1234', 'MessageBody': {'test': 'test'}}


@pytest.mark.parametrize('exception_error', ['error, 401 unauthorized', 'error occurred'])
def test_get_message_body_error(mocker, exception_error):
    """
    Given:
        api error

    When:
        running get_message_body_command

    Then:
        Make sure an exception is raised
    """
    from SymantecDLPV2 import Client, get_message_body_command

    client = Client(
        base_url="https://SymantecDLPV2.com",
        auth=("test", "pass"),
        verify=False,
        proxy=False,
        headers={"Content-type": "application/json"}
    )

    mocker.patch.object(client, '_http_request', side_effect=DemistoException(exception_error))

    with pytest.raises(DemistoException):
        get_message_body_command(client, {'incident_id': '1234'})
