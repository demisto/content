import json
import io
import demistomock as demisto
from pytest_mock import MockerFixture
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa
from VaronisDataSecurityPlatformSaaS import Client


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
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
    from VaronisDataSecurityPlatformSaaS import varonis_get_alerts_command

    client = Client(
        base_url='https://test.com',
        verify=False,
        proxy=False
    )
    mocker.patch.object(
        client,
        'varonis_get_alerts',
        return_value=util_load_json('test_data/test_varonis_get_alerts_command/varonis_get_alerts_api_response.json')
    )
    mocker.patch.object(
        client,
        'varonis_get_enum',
        return_value=util_load_json('test_data/varonis_get_enum_response.json')
    )

    args = util_load_json("test_data/test_varonis_get_alerts_command/demisto_search_alerts_args.json")
    expected_outputs = util_load_json('test_data/test_varonis_get_alerts_command/varonis_get_alerts_command_output.json')

    result = varonis_get_alerts_command(client, args)

    assert result.outputs_prefix == 'Varonis'
    assert result.outputs == expected_outputs


def test_varonis_update_alert_status_command(requests_mock):
    from VaronisDataSecurityPlatformSaaS import varonis_update_alert_status_command

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
    from VaronisDataSecurityPlatformSaaS import varonis_close_alert_command

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

    from VaronisDataSecurityPlatformSaaS import varonis_get_alerted_events_command

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
    from VaronisDataSecurityPlatformSaaS import fetch_incidents_command

    threat_models = util_load_json('test_data/varonis_get_enum_response.json')
    threat_model = threat_models[0]["ruleName"]
    ingest_time = datetime.now() - timedelta(hours=1)
    alerts = [
        {
            "ID": "e74df045-e525-4ec3-b54f-ad46434c5281",
            "Name": threat_model,
            "Severity": "High",
            "EventUTC": "2023-10-07T20:46:00",
            "IngestTime": ingest_time.isoformat()
        },
        {
            "ID": "29ef57c6-817a-49f5-be34-bdd6c5358379",
            "Name": threat_model,
            "Severity": "High",
            "EventUTC": "2023-10-07T17:43:00",
            "IngestTime": ingest_time.isoformat()
        }
    ]

    requests_mock.post(
        'https://test.com/api/alert/search/alerts',
        json=alerts)

    client = Client(
        base_url='https://test.com',
        verify=False,
        proxy=False
    )

    mocker.patch.object(
        client,
        'varonis_get_enum',
        return_value=threat_models
    )

    mocker.patch.object(demisto, 'debug', return_value=None)

    last_run = {'last_fetched_id': datetime.now() - timedelta(days=1)}
    first_fetch_time = datetime.now() - timedelta(weeks=1)

    next_run, incidents = fetch_incidents_command(
        client=client,
        alert_status=None,
        severity=None,
        threat_model=threat_model,
        last_run=last_run,
        first_fetch_time=first_fetch_time
    )
    
    assert next_run == {'last_fetched_ingest_time': (ingest_time + timedelta(minutes=1)).isoformat()}

    for output in alerts:
        id = output["ID"]
        output.update({"Url": f"https://test.com/#/app/analytics/entity/Alert/{id}"})
        output.update({"Locations": []})
        output.update({"Sources": []})
        output.update({"Devices": []})
        output.update({"Users": []})
    
    expected_incidents = list(map(lambda alert: 
                                  {
                                    'name': f'Varonis alert {alert["Name"]}',
                                    'occurred': f'{alert["EventUTC"]}Z',
                                    'rawJSON': json.dumps(alert),
                                    'type': 'Varonis DSP Incident',
                                    'severity': IncidentSeverity.HIGH,
                                }, alerts))

    assert incidents == expected_incidents


def test_enrich_with_url():
    from VaronisDataSecurityPlatformSaaS import enrich_with_url
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
    from VaronisDataSecurityPlatformSaaS import strEqual

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
    from VaronisDataSecurityPlatformSaaS import convert_to_demisto_severity, IncidentSeverity

    assert convert_to_demisto_severity(None) == IncidentSeverity.LOW
    assert convert_to_demisto_severity('Low') == IncidentSeverity.LOW
    assert convert_to_demisto_severity('Medium') == IncidentSeverity.MEDIUM
    assert convert_to_demisto_severity('High') == IncidentSeverity.HIGH


def test_get_excluded_severitires():
    from VaronisDataSecurityPlatformSaaS import get_included_severitires

    assert get_included_severitires(None) == []
    assert get_included_severitires('Low') == ['high', 'medium', 'low']
    assert get_included_severitires('Medium') == ['high', 'medium']
    assert get_included_severitires('High') == ['high']


def test_varonis_authenticate(requests_mock: MockerFixture):
    
    client = Client(
        base_url='https://test.com',
        verify=False,
        proxy=False
    )

    # fetch_output = util_load_json('test_data/test_varonis_authenticate/demisto_auth_response.json')
    fetch_output = {
        "access_token": "token_here",
        "token_type": "bearer",
        "expires_in": 599
    }
    auth_url = 'https://test.com/api/authentication/api_keys/token'

    requests_mock.post(
        auth_url,
        json=fetch_output)

    client.varonis_authenticate('mock_api_key')

    assert client.headers['authorization'] == 'bearer token_here'
