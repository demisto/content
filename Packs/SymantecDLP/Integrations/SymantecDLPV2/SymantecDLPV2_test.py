import pytest
from freezegun import freeze_time
from pytest import raises
from CommonServerPython import *
import io


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


SINGLE_INCIDENTS_MOCK_RESPONSE = util_load_json('test_data/fetch_single_incident.json')
MULTIPLE_INCIDENTS_MOCK_RESPONSE = util_load_json('test_data/fetch_multiple_incident.json')
FIRST_STATIC_ATT_MOCK_RESPONSE = util_load_json('test_data/incident_static_attributes_first.json')
FIRST_EDITABLE_ATT_MOCK_RESPONSE = util_load_json('test_data/incident_editable_attributes_first.json')
SECOND_STATIC_ATT_MOCK_RESPONSE = util_load_json('test_data/incident_static_attributes_second.json')
SECOND_EDITABLE_ATT_MOCK_RESPONSE = util_load_json('test_data/incident_editable_attributes_second.json')


FIRST_INCIDENT_DETAILS = json.dumps({"ID": 3620, "creationDate": "2022-03-06T15:23:53.245", "policyId": 2,
                                     "severity": "High",
                                     "incidentStatusId": 1, "detectionDate": "2022-03-06T15:23:39.197",
                                     "senderIPAddress": "1.1.1.1",
                                     "endpointMachineIpAddress": "1.1.1.1", "policyName": "Network Test policy",
                                     "policyVersion": 4,
                                     "messageSource": "NETWORK", "messageType": "HTTP",
                                     "detectionServerName": "Detection - Network monitor",
                                     "policyGroupName": "policy_group.default.name", "matchCount": 3,
                                     "preventOrProtectStatusId": 0,
                                     "customAttributeGroup": [
                                         {"name": "custom_attribute_group.default",
                                          "customAttribute": [{"name": "Custom Attribue1", "index": 1},
                                                              {"name": "cust2", "index": 2},
                                                              {"name": "bla", "index": 3}]},
                                         {"name": "att group2", "customAttribute": [{"name": "kjv", "index": 4}]}],
                                     "messageSubject": "HTTP incident", "networkSenderPort": 59637,
                                     "recipientInfo": {"recipientDomain": "2.2.2.254", "recipientPort": 80,
                                                       "recipientUrl": "http://2.2.2.254/latest/api/token"}})

SECOND_INCIDENT_DETAILS = json.dumps(
    {"ID": 3629, "creationDate": "2022-03-06T15:23:53.246", "policyId": 43, "severity": "High",
     "incidentStatusId": 1, "detectionDate": "2022-03-06T15:23:39.197", "policyName": "Illegal Drugs",
     "policyVersion": 1, "messageSource": "DISCOVER", "messageType": "RAW",
     "detectionServerName": "Detection - Discovery", "policyGroupName": "Test Policy group for Endpoint Discover",
     "matchCount": 100, "preventOrProtectStatusId": 0,
     "customAttributeGroup": [{"name": "custom_attribute_group.default",
                               "customAttribute": [{"name": "Custom Attribue1", "index": 1},
                                                   {"name": "cust2", "index": 2},
                                                   {"name": "bla", "index": 3}]},
                              {"name": "att group2",
                               "customAttribute": [{"name": "kjv", "index": 4}]}],
     "discoverName": "423.txt", "discoverRepositoryLocation": "c:/das/423.txt",
     "fileOwner": "BUILTIN\\Administrators", "fileAccessDate": "2022-01-05T14:10:04.798", "discoverServer": "c:",
     "discoverTargetName": "Discovery server - File system", "discoverScanStartDate": "2022-03-06T07:00:00"})


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

    mocker.patch.object(client, 'get_incident_static_attributes_request', return_value=FIRST_STATIC_ATT_MOCK_RESPONSE)
    mocker.patch.object(client, 'get_incident_editable_attributes_request',
                        return_value=FIRST_EDITABLE_ATT_MOCK_RESPONSE)

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
    requests_mock.post(
        'https://SymantecDLPV2.com/ProtectManager/webservices/v2/incidents', json=SINGLE_INCIDENTS_MOCK_RESPONSE)
    requests_mock.get(
        'https://SymantecDLPV2.com/ProtectManager/webservices/v2/incidents/3620/staticAttributes',
        json=FIRST_STATIC_ATT_MOCK_RESPONSE)
    requests_mock.get(
        'https://SymantecDLPV2.com/ProtectManager/webservices/v2/incidents/3620/editableAttributes',
        json=FIRST_EDITABLE_ATT_MOCK_RESPONSE)

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
    requests_mock.post(
        'https://SymantecDLPV2.com/ProtectManager/webservices/v2/incidents', json=MULTIPLE_INCIDENTS_MOCK_RESPONSE)
    requests_mock.get(
        'https://SymantecDLPV2.com/ProtectManager/webservices/v2/incidents/3620/staticAttributes',
        json=FIRST_STATIC_ATT_MOCK_RESPONSE)
    requests_mock.get(
        'https://SymantecDLPV2.com/ProtectManager/webservices/v2/incidents/3620/editableAttributes',
        json=FIRST_EDITABLE_ATT_MOCK_RESPONSE)
    requests_mock.get(
        'https://SymantecDLPV2.com/ProtectManager/webservices/v2/incidents/3629/staticAttributes',
        json=SECOND_STATIC_ATT_MOCK_RESPONSE)
    requests_mock.get(
        'https://SymantecDLPV2.com/ProtectManager/webservices/v2/incidents/3629/editableAttributes',
        json=SECOND_EDITABLE_ATT_MOCK_RESPONSE)

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
    requests_mock.post(
        'https://SymantecDLPV2.com/ProtectManager/webservices/v2/incidents', json=MULTIPLE_INCIDENTS_MOCK_RESPONSE)
    requests_mock.get(
        'https://SymantecDLPV2.com/ProtectManager/webservices/v2/incidents/3620/staticAttributes',
        json=FIRST_STATIC_ATT_MOCK_RESPONSE)
    requests_mock.get(
        'https://SymantecDLPV2.com/ProtectManager/webservices/v2/incidents/3620/editableAttributes',
        json=FIRST_EDITABLE_ATT_MOCK_RESPONSE)
    requests_mock.get(
        'https://SymantecDLPV2.com/ProtectManager/webservices/v2/incidents/3629/staticAttributes',
        json=SECOND_STATIC_ATT_MOCK_RESPONSE)
    requests_mock.get(
        'https://SymantecDLPV2.com/ProtectManager/webservices/v2/incidents/3629/editableAttributes',
        json=SECOND_EDITABLE_ATT_MOCK_RESPONSE)

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
