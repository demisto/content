import json
import demistomock as demisto
from pytest_mock import MockerFixture

from VaronisDataSecurityPlatform import Client


def util_load_json(path):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


''' COMMAND UNIT TESTS '''


def test_varonis_get_alerts_command(mocker: MockerFixture):
    """
        When:
            - Get alerts from Varonis api
        Then
            - Assert output prefix data is as expected
            - Assert mapping works as expected
    """
    from VaronisDataSecurityPlatform import varonis_get_alerts_command

    client = Client(
        base_url='https://test.com',
        verify=False,
        proxy=False
    )
    mocker.patch.object(
        client,
        'varonis_get_alerts',
        return_value=util_load_json('test_data/varonis_get_alerts_api_response.json')
    )
    mocker.patch.object(
        client,
        'varonis_get_enum',
        return_value=util_load_json('test_data/varonis_get_enum_response.json')
    )
    mocker.patch.object(
        client,
        'varonis_get_users',
        return_value=util_load_json('test_data/varonis_get_users_api_response.json')
    )

    args = util_load_json("test_data/demisto_search_alerts_args.json")
    expected_outputs = util_load_json('test_data/varonis_get_alerts_command_output.json')

    result = varonis_get_alerts_command(client, args)

    assert result.outputs_prefix == 'Varonis'
    assert result.outputs == expected_outputs


def test_varonis_update_alert_status_command(requests_mock):
    from VaronisDataSecurityPlatform import varonis_update_alert_status_command

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
    from VaronisDataSecurityPlatform import varonis_close_alert_command

    requests_mock.post('https://test.com/api/alert/alert/SetStatusToAlerts', json=True)

    client = Client(
        base_url='https://test.com',
        verify=False,
        proxy=False
    )

    args = {
        'close_reason': 'Account misclassification',
        'alert_id': "C8CF4194-133F-4F5A-ACB1-FFFB00573468, F8F608A7-0256-42E0-A527-FFF4749C1A8B"
    }

    resp = varonis_close_alert_command(client, args)

    assert resp is True


def test_varonis_get_alerted_events_command(mocker: MockerFixture):
    """
        When:
            - Get alerted events from Varonis api
        Then
            - Assert output prefix data is as expected
            - Assert mapping works as expected
    """

    from VaronisDataSecurityPlatform import varonis_get_alerted_events_command

    client = Client(
        base_url='https://test.com',
        verify=False,
        proxy=False
    )
    mocker.patch.object(
        client,
        'varonis_get_alerted_events',
        return_value=util_load_json('test_data/varonis_get_alerted_events_response.json')
    )

    args = util_load_json("test_data/demisto_alerted_events_args.json")
    expected_outputs = util_load_json('test_data/varonis_get_alerted_events_command_output.json')

    result = varonis_get_alerted_events_command(client, args)

    assert result.outputs_prefix == 'Varonis'
    assert result.outputs == expected_outputs


def test_fetch_incidents(mocker: MockerFixture, requests_mock: MockerFixture):
    from VaronisDataSecurityPlatform import fetch_incidents

    fetch_output = util_load_json('test_data/varonis_fetch_incidents_response.json')

    requests_mock.get(
        'https://test.com/api/alert/alert/GetAlerts'
        '?ruleName=Suspicious&fromAlertSeqId=150&status=Open&severity=high&severity=medium&descendingOrder=True'
        '&aggregate=True&offset=0&maxResult=50',
        json=fetch_output)

    client = Client(
        base_url='https://test.com',
        verify=False,
        proxy=False
    )

    mocker.patch.object(
        client,
        'varonis_get_enum',
        return_value=util_load_json('test_data/varonis_get_enum_response.json')
    )

    mocker.patch.object(demisto, 'debug', return_value=None)

    last_run = {
        'last_fetched_id': 150
    }

    next_run, incidents = fetch_incidents(
        client=client,
        max_results=50,
        alert_status='Open',
        severity='Medium',
        threat_model='Suspicious',
        last_run=last_run,
        first_fetch_time='3 days'
    )

    expected_outputs = util_load_json('test_data/varonis_fetch_incidents_output.json')

    assert next_run == {'last_fetched_id': 152}
    assert incidents == [
        {
            'name': 'Varonis alert DNS CUSTOM - Copy(2)',
            'occurred': '2022-04-13T10:01:35Z',
            'rawJSON': json.dumps(expected_outputs[0]),
            'type': 'Varonis DSP Incident',
            'severity': 3,
        },
        {
            'name': 'Varonis alert DNS CUSTOM',
            'occurred': '2022-04-13T10:01:33Z',
            'rawJSON': json.dumps(expected_outputs[1]),
            'type': 'Varonis DSP Incident',
            'severity': 3,
        }
    ]


def test_enrich_with_url():
    from VaronisDataSecurityPlatform import enrich_with_url
    obj = dict()
    baseUrl = 'http://test.com'
    id = '1'
    expectedUrl = f'{baseUrl}/#/app/analytics/entity/Alert/{id}'

    enrich_with_url(obj, baseUrl, id)
    assert obj['Url'] == expectedUrl

    baseUrl = 'http://test.com/'
    enrich_with_url(obj, baseUrl, id)
    assert obj['Url'] == expectedUrl


def test_case_insensitive():
    from VaronisDataSecurityPlatform import strEqual

    assert strEqual(None, None)
    assert not strEqual(None, 'None')
    assert not strEqual('None', None)
    assert not strEqual('None', 'None1')
    assert strEqual('', None)
    assert strEqual(None, '')
    assert strEqual('None', 'None')
    assert strEqual('None', 'none')
    assert strEqual('none', 'None')


def test_get_sids_user(mocker: MockerFixture):
    from VaronisDataSecurityPlatform import get_sids, NON_EXISTENT_SID, DISPLAY_NAME_KEY
    client = Client(
        base_url='https://test.com',
        verify=False,
        proxy=False
    )
    mocker.patch.object(
        client,
        'varonis_get_users',
        return_value=util_load_json('test_data/varonis_get_users_api_response.json')
    )

    result = get_sids(client, ['not_exist'], None, DISPLAY_NAME_KEY)
    assert result[0] == NON_EXISTENT_SID

    result = get_sids(client, [], None, DISPLAY_NAME_KEY)
    assert len(result) == 0

    result = get_sids(client, ['Administrator'], None, DISPLAY_NAME_KEY)
    assert result[0] == 509


def test_convert_to_demisto_severity():
    from VaronisDataSecurityPlatform import convert_to_demisto_severity, IncidentSeverity

    assert convert_to_demisto_severity(None) == IncidentSeverity.LOW
    assert convert_to_demisto_severity('Low') == IncidentSeverity.LOW
    assert convert_to_demisto_severity('Medium') == IncidentSeverity.MEDIUM
    assert convert_to_demisto_severity('High') == IncidentSeverity.HIGH


def test_get_excluded_severitires():
    from VaronisDataSecurityPlatform import get_included_severitires

    assert get_included_severitires(None) == []
    assert get_included_severitires('Low') == ['high', 'medium', 'low']
    assert get_included_severitires('Medium') == ['high', 'medium']
    assert get_included_severitires('High') == ['high']


def test_varonis_get_auth_url(requests_mock: MockerFixture):
    client = Client(
        base_url='https://test.com',
        verify=False,
        proxy=False
    )

    fetch_output = util_load_json('test_data/demisto_auth_configuration_response.json')

    requests_mock.get(
        'https://test.com/auth/configuration',
        json=fetch_output)

    assert client.varonis_get_auth_url() == 'https://test.com/DatAdvantage/api/authentication/win'


def test_varonis_authenticate(requests_mock: MockerFixture):
    client = Client(
        base_url='https://test.com',
        verify=False,
        proxy=False
    )

    fetch_output = util_load_json('test_data/demisto_auth_response.json')
    auth_url = 'https://test.com/DatAdvantage/api/authentication/win'

    requests_mock.post(
        auth_url,
        json=fetch_output)

    client.varonis_authenticate('user', 'password', auth_url)

    assert client._headers['Authorization'] == 'bearer token_here'
