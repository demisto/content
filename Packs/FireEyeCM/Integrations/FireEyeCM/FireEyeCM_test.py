import io
import json

from FireEyeCM import Client, fetch_incidents


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


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
    - run the fetch incidents command using the Client
    Validate that no incidents will be returned.
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
