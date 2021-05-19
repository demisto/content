import io
import json

import pytest

from FireEyeCM import Client, get_alerts, get_quarantined_emails, alert_severity_to_dbot_score, \
    to_fe_datetime_converter,fetch_incidents
from test_data.result_constants import QUARANTINED_EMAILS_CONTEXT, GET_ALERTS_CONTEXT


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def test_get_alerts(mocker):
    """Unit test
    Given
    - get_alerts command
    - command args
    - command raw response
    When
    - mock the Client's token generation.
    - mock the Client's get_alerts_request response.
    Then
    - Validate The entry context
    """
    mocker.patch.object(Client, '_generate_token', return_value='token')
    client = Client(base_url="https://fireeye.cm.com/", username='user', password='pass', verify=False, proxy=False)
    mocker.patch.object(Client, 'get_alerts_request',
                        return_value=util_load_json('test_data/get_alerts.json'))
    command_results = get_alerts(client=client,
                                 args={'limit': '2', 'start_time': '8 days', 'src_ip': '2.2.2.2'})
    assert command_results.outputs == GET_ALERTS_CONTEXT


def test_get_quarantined_emails(mocker):
    """Unit test
    Given
    - get_quarantined_emails command
    - command args
    - command raw response
    When
    - mock the Client's token generation.
    - mock the Client's get_quarantined_emails_request response.
    Then
    - Validate The entry context
    """
    mocker.patch.object(Client, '_generate_token', return_value='token')
    client = Client(base_url="https://fireeye.cm.com/", username='user', password='pass', verify=False, proxy=False)
    mocker.patch.object(Client, 'get_quarantined_emails_request',
                        return_value=util_load_json('test_data/quarantined_emails.json'))
    command_results = get_quarantined_emails(client=client, args={})
    assert command_results.outputs == QUARANTINED_EMAILS_CONTEXT


def test_fetch_incidents(mocker):
    """Unit test
    Given
    - fetch incidents command
    - command args
    - command raw response
    When
    - mock the Client's token generation.
    - mock the Client's get_alerts_request.
    Then
    - run the fetch incidents command using the Client
    Validate The length of the results and the last_run.
    """
    mocker.patch.object(Client, '_generate_token', return_value='token')
    client = Client(base_url="https://fireeye.cm.com/", username='user', password='pass', verify=False, proxy=False)
    mocker.patch.object(Client, 'get_alerts_request', return_value=util_load_json('test_data/alerts.json'))
    last_run, incidents = fetch_incidents(client=client,
                                          last_run={},
                                          first_fetch='1 year',
                                          max_fetch=50,
                                          info_level='concise')
    assert len(incidents) == 11
    assert last_run.get('time') == '2021-05-18 12:02:54 +0000'  # occurred time of the last alert


def test_fetch_incidents_with_limit(mocker):
    """Unit test
    Given
    - fetch incidents command
    - command args with a harsh limit
    - command raw response
    When
    - mock the Client's token generation.
    - mock the Client's get_alerts_request.
    Then
    - run the fetch incidents command using the Client
    Validate The length of the results and the last_run of the limited incident.
    """
    mocker.patch.object(Client, '_generate_token', return_value='token')
    client = Client(base_url="https://fireeye.cm.com/", username='user', password='pass', verify=False, proxy=False)
    mocker.patch.object(Client, 'get_alerts_request', return_value=util_load_json('test_data/alerts.json'))
    last_run, incidents = fetch_incidents(client=client,
                                          last_run={},
                                          first_fetch='1 year',
                                          max_fetch=5,
                                          info_level='concise')
    assert len(incidents) == 5
    assert last_run.get('time') == '2021-05-18 05:04:36 +0000'  # occurred time of the last alert


def test_fetch_incidents_last_alert_ids(mocker):
    """Unit test
    Given
    - fetch incidents command
    - command args
    - command raw response
    When
    - mock the Client's token generation.
    - mock the last_event_alert_ids
    - mock the Client's get_alerts_request.
    Then
    - Validate that no incidents will be returned.
    - Validate that the last_run is "now"
    """
    mocker.patch.object(Client, '_generate_token', return_value='token')
    client = Client(base_url="https://fireeye.cm.com/", username='user', password='pass', verify=False, proxy=False)
    mocker.patch.object(Client, 'get_alerts_request', return_value=util_load_json('test_data/alerts.json'))
    last_run = {
        'time': "whatever",
        'last_alert_ids': [
            "35267", "35268", "35269", "35272", "35273", "35274", "35275", "35276", "35277", "35278", "35279"
        ]
    }
    last_run, incidents = fetch_incidents(client=client,
                                          last_run=last_run,
                                          first_fetch='1 year',
                                          max_fetch=50,
                                          info_level='concise')

    assert len(incidents) == 0
    # trim miliseconds to avoid glitches such as 2021-05-19T10:21:52.121+00:00 != 2021-05-19T10:21:52.123+00:00
    assert last_run.get('time')[:-8] == to_fe_datetime_converter('now')[:-8]


@pytest.mark.parametrize('severity_str, dbot_score', [
    ('minr', 1),
    ('majr', 2),
    ('crit', 3),
    ('kookoo', 0)
])
def test_alert_severity_to_dbot_score(severity_str: str, dbot_score: int):
    """Unit test
    Given
    - alert_severity_to_dbot_score command
    - severity string
    When
    - running alert_severity_to_dbot_score
    Then
    - Validate that the dbot score is as expected
    """
    assert alert_severity_to_dbot_score(severity_str) == dbot_score
