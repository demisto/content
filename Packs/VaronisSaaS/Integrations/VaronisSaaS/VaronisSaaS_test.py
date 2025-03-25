import json

import demistomock as demisto
from pytest_mock import MockerFixture
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa
from VaronisSaaS import Client


def util_load_json(file):
    __location__ = os.path.realpath(os.path.join(os.getcwd(), os.path.dirname(__file__)))
    full_path = os.path.join(__location__, file)
    with open(full_path, encoding='utf-8') as f:
        return json.loads(f.read())


''' COMMAND UNIT TESTS '''


def test_check_module_command_success(mocker: MockerFixture):
    from VaronisSaaS import check_module_command

    client = Client(
        base_url='https://test.com',
        verify=False,
        proxy=False
    )

    mocker.patch.object(client, 'varonis_get_enum', return_value=None)

    result = check_module_command(client)
    assert result.readable_output == 'ok'


def test_update_remote_system_command(mocker: MockerFixture):
    from VaronisSaaS import update_remote_system_command, CLOSE_REASONS, ALERT_STATUSES
    from unittest.mock import ANY

    varonis_update_alert_mock = mocker.patch('VaronisSaaS.varonis_update_alert', return_value=None)

    # Test case 1: Incident not changed, no remote incident ID
    args = {
        'incidentChanged': False,
        'remoteId': None
    }
    assert update_remote_system_command(None, args) is None

    # Test case 2: Incident not changed, with remote incident ID
    args = {
        'incidentChanged': False,
        'remoteId': '12345'
    }
    assert update_remote_system_command(None, args) == '12345'

    # Test case 3: Incident changed, delta keys present
    args = {
        'incidentChanged': True,
        'remoteId': '12345',
        'data': {'Status': 'closed'},
        'delta': ['Status']
    }
    assert update_remote_system_command(None, args) == '12345'
    varonis_update_alert_mock\
        .assert_called_with(ANY,
                            CLOSE_REASONS['other'],
                            ALERT_STATUSES['closed'],
                            ['12345'],
                            'Closed from XSOAR')

    # Test case 4: Incident changed, status not closed
    args = {
        'incidentChanged': True,
        'remoteId': '12345',
        'delta': ['Status'],
        'data': {'Status': 'under investigation'}
    }
    assert update_remote_system_command(None, args) == '12345'
    varonis_update_alert_mock\
        .assert_called_with(ANY,
                            CLOSE_REASONS['none'],
                            ALERT_STATUSES['under investigation'],
                            ['12345'],
                            'Status changed from XSOAR')


def test_get_mapping_fields_command():
    from VaronisSaaS import get_mapping_fields_command, strEqual, INCIDENT_FIELDS

    response = get_mapping_fields_command()

    # Assert that the response is an instance of GetMappingFieldsResponse
    assert isinstance(response, GetMappingFieldsResponse)

    # Assert that the incident type scheme is added to the response
    assert len(response.scheme_types_mappings) == 1
    assert strEqual(response.scheme_types_mappings[0].type_name, 'Varonis SaaS Incident')

    # Assert that all the fields are added to the incident type scheme
    expected_fields = INCIDENT_FIELDS
    assert len(response.scheme_types_mappings[0].fields) == len(expected_fields)
    for field in expected_fields:
        assert field in response.scheme_types_mappings[0].fields


def test_varonis_get_alerts_command(requests_mock: MockerFixture):
    """
        When:
            - Get alerts from Varonis api
        Then
            - Assert output prefix data is as expected
            - Assert mapping works as expected
    """
    from VaronisSaaS import varonis_get_alerts_command

    requests_mock.post(
        'https://test.com/app/dataquery/api/search/v2/search',
        json=util_load_json('test_data/varonis_get_alerts_create_search_response.json'))
    requests_mock.get(
        'https://test.com/app/dataquery/api/search/v2/rows/af6a26a1d70e4be182adc148b831f476/',
        json=util_load_json('test_data/varonis_get_alerts_execute_search_response.json'))

    args = util_load_json("test_data/demisto_search_alerts_args.json")

    client = Client(
        base_url='https://test.com',
        verify=False,
        proxy=False
    )
    result = varonis_get_alerts_command(client, args)

    expected_outputs = util_load_json('test_data/varonis_get_alerts_command_output.json')
    assert result.outputs_prefix == 'Varonis'
    assert result.outputs == expected_outputs


def test_varonis_update_alert_status_command(requests_mock):
    from VaronisSaaS import varonis_update_alert_status_command

    requests_mock.post('https://test.com/api/alert/alert/SetStatusToAlerts', json=True)

    client = Client(
        base_url='https://test.com',
        verify=False,
        proxy=False
    )

    args = {
        'status': 'Under Investigation',
        'alert_id': "C8CF4194-133F-4F5A-ACB1-FFFB00573468, F8F608A7-0256-42E0-A527-FFF4749C1A8B"
    }

    resp = varonis_update_alert_status_command(client, args)

    assert resp is True


def test_varonis_close_alert_command(requests_mock):
    from VaronisSaaS import varonis_close_alert_command

    requests_mock.post('https://test.com/api/alert/alert/SetStatusToAlerts', json=True)

    client = Client(
        base_url='https://test.com',
        verify=False,
        proxy=False
    )

    args = {
        'close_reason': 'other',
        'alert_id': "C8CF4194-133F-4F5A-ACB1-FFFB00573468, F8F608A7-0256-42E0-A527-FFF4749C1A8B"
    }

    resp = varonis_close_alert_command(client, args)

    assert resp is True


def test_varonis_get_alerted_events_command(requests_mock: MockerFixture):
    """
        When:
            - Get alerted events from Varonis api
        Then
            - Assert output prefix data is as expected
            - Assert mapping works as expected
    """

    from VaronisSaaS import varonis_get_alerted_events_command

    client = Client(
        base_url='https://test.com',
        verify=False,
        proxy=False
    )
    requests_mock.post(
        'https://test.com/app/dataquery/api/search/v2/search',
        json=util_load_json('test_data/varonis_get_alerted_events_create_search_response.json'))
    requests_mock.get(
        'https://test.com/app/dataquery/api/search/v2/rows/af6a26a1d70e4be182adc148b831f476/',
        json=util_load_json('test_data/varonis_get_alerted_events_execute_search_response.json'))

    args = util_load_json("test_data/demisto_alerted_events_args.json")
    expected_outputs = util_load_json('test_data/varonis_get_alerted_events_command_output.json')

    result = varonis_get_alerted_events_command(client, args)

    assert result.outputs_prefix == 'Varonis'
    assert result.outputs == expected_outputs


def test_fetch_incidents(mocker: MockerFixture, requests_mock: MockerFixture):
    from VaronisSaaS import fetch_incidents_command, AlertAttributes

    create_search_result = util_load_json('test_data/fetch_incidents_create_search_response.json')
    alerts = util_load_json('test_data/fetch_incidents_execute_search_response.json')

    requests_mock.post(
        'https://test.com/app/dataquery/api/search/v2/search',
        json=create_search_result)
    requests_mock.get(
        'https://test.com/app/dataquery/api/search/v2/rows/af6a26a1d70e4be182adc148b831f476/',
        json=alerts)

    client = Client(
        base_url='https://test.com',
        verify=False,
        proxy=False
    )
    mocker.patch.object(demisto, 'debug', return_value=None)

    max_fetch = 1000
    last_run = {'last_fetched_id': datetime.now() - timedelta(days=1)}
    first_fetch_time = datetime.now() - timedelta(weeks=1)

    next_run, incidents = fetch_incidents_command(
        client=client,
        alert_status=None,
        severity=None,
        threat_model=None,
        last_run=last_run,
        first_fetch_time=first_fetch_time,
        max_fetch=max_fetch
    )

    expected_alerts = util_load_json('test_data/fetch_incidents_output.json')

    expected_incidents = [{
        'name': f'Varonis alert {alert[AlertAttributes.Alert_Rule_Name]}',
        'occurred': f'{alert[AlertAttributes.Alert_Time]}Z',
        'rawJSON': json.dumps(alert),
        'type': 'Varonis SaaS Incident',
        'severity': IncidentSeverity.MEDIUM,
    } for alert in expected_alerts]

    assert incidents == expected_incidents


def test_varonis_authenticate(requests_mock: MockerFixture):

    fetch_output = {
        "access_token": "token_here",
        "token_type": "bearer",
        "expires_in": 599
    }
    auth_url = 'https://test.com/api/authentication/api_keys/token'

    requests_mock.post(
        auth_url,
        json=fetch_output)

    client = Client(
        base_url='https://test.com',
        verify=False,
        proxy=False
    )

    client.varonis_authenticate('mock_api_key')

    assert client.headers['authorization'] == 'bearer token_here'


def test_enrich_with_url():
    from VaronisSaaS import enrich_with_url
    obj = {}
    baseUrl = 'http://test.com'
    id = '1'
    expectedUrl = f'{baseUrl}/analytics/entity/Alert/{id}'

    enrich_with_url(obj, baseUrl, id)
    assert obj['Url'] == expectedUrl

    baseUrl = 'http://test.com/'
    enrich_with_url(obj, baseUrl, id)
    assert obj['Url'] == expectedUrl


def test_case_insensitive():
    from VaronisSaaS import strEqual

    assert strEqual(None, None)
    assert not strEqual(None, 'None')
    assert not strEqual('None', None)
    assert not strEqual('None', 'None1')
    assert strEqual('', None)
    assert strEqual(None, '')
    assert strEqual('None', 'None')
    assert strEqual('None', 'none')
    assert strEqual('none', 'None')


def test_convert_to_demisto_severity():
    from VaronisSaaS import convert_to_demisto_severity, IncidentSeverity

    assert convert_to_demisto_severity(None) == IncidentSeverity.LOW
    assert convert_to_demisto_severity('Low') == IncidentSeverity.LOW
    assert convert_to_demisto_severity('Medium') == IncidentSeverity.MEDIUM
    assert convert_to_demisto_severity('High') == IncidentSeverity.HIGH


def test_get_excluded_severitires():
    from VaronisSaaS import get_included_severitires

    assert get_included_severitires(None) == []
    assert get_included_severitires('Low') == ['high', 'medium', 'low']
    assert get_included_severitires('Medium') == ['high', 'medium']
    assert get_included_severitires('High') == ['high']
