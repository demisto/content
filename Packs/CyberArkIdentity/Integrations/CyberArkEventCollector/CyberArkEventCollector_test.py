import json
import io
import requests_mock
from freezegun import freeze_time
import demistomock as demisto


URL = 'https://aam4730.my.idaptive.app/'
DEMISTO_PARAMS = {
    'url': URL,
    'credentials': {
        'identifier': 'siemuser@paloaltonetworks.com.98',
        'password': 'q123456Q',
    },
    'from': '1 year',
    'verify': True,
    'proxy': False,
    'app_id': 'oauthsiem',
    'limit': 6000,
}
# FIRST_REQUESTS_PARAMS = 'from=2022-04-11T00:00:00.000000&limit=1000&offset=0'
# SECOND_REQUESTS_PARAMS = 'from=2022-04-11T00:00:00.000000&limit=1000&offset=1000'


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def calculate_next_run(time):
    next_time = time.removesuffix('+0000')
    next_time_with_delta = next_time[:-1] + str(int(next_time[-1]) + 1)
    return next_time_with_delta


@freeze_time('2022-04-14T00:00:00Z')
def test_fetch_incidents_few_incidents(mocker):
    """
    Given
        - 3 events was created in Jira side in the last 3 days.
    When
        - fetch-events is running (with max_fetch set to 100).
    Then
        - Verify that all 3 events were created in XSIAM.
        - Verify last_run was set as expected.
    """

    mocker.patch.object(demisto, 'params', return_value=DEMISTO_PARAMS)
    mocker.patch.object(demisto, 'args', return_value={})
    mocker.patch.object(demisto, 'command', return_value='jira-get-events')
    last_run = mocker.patch.object(demisto, 'getLastRun', return_value={})
    results = mocker.patch.object(demisto, 'results')
    mocker.patch('JiraEventCollector.send_events_to_xsiam')

    with requests_mock.Mocker() as m:
        m.get(f'{URL}?{FIRST_REQUESTS_PARAMS}', json=util_load_json('test_data/events.json'))
        m.get(f'{URL}?{SECOND_REQUESTS_PARAMS}', json={})

        from JiraEventCollector import main
        main()

    events = results.call_args[0][0]['Contents']
    assert last_run.return_value.get('from') == calculate_next_run(events[0]['created'])
    assert not last_run.return_value.get('next_time')
    assert last_run.return_value.get('offset') == 0
    assert len(events) == 3


@freeze_time('2022-04-14T00:00:00Z')
def test_fetch_events_no_incidents(mocker):
    """
    Given
        - No events was created in Jira side in the last 3 days.
    When
        - fetch-events is running.
    Then
        - Make sure no events was created in XSIAM.
        - Make sure last_run was set as expected.
    """

    mocker.patch.object(demisto, 'params', return_value=DEMISTO_PARAMS)
    mocker.patch.object(demisto, 'args', return_value={})
    mocker.patch.object(demisto, 'command', return_value='jira-get-events')
    last_run = mocker.patch.object(demisto, 'getLastRun', return_value={})
    incidents = mocker.patch.object(demisto, 'incidents')
    mocker.patch('JiraEventCollector.send_events_to_xsiam')

    with requests_mock.Mocker() as m:
        m.get(f'{URL}?{FIRST_REQUESTS_PARAMS}', json={})

        from JiraEventCollector import main
        main()

    assert not last_run.return_value.get('from')
    assert last_run.return_value.get('offset') == 0
    assert not incidents.call_args


@freeze_time('2022-04-14T00:00:00Z')
def test_fetch_events_max_fetch_set_to_one(mocker):
    """
    Given
        - 3 events was created in Jira side in the last 3 days.
    When
        - fetch-events is running (with max_fetch set to 1).
    Then
        - Verify that only 1 event were created in XSIAM.
        - Verify last_run was set as expected.
    """

    params = DEMISTO_PARAMS
    params['max_fetch'] = 1

    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'args', return_value={})
    mocker.patch.object(demisto, 'command', return_value='jira-get-events')
    last_run = mocker.patch.object(demisto, 'getLastRun', return_value={})
    results = mocker.patch.object(demisto, 'results')
    mocker.patch('JiraEventCollector.send_events_to_xsiam')

    with requests_mock.Mocker() as m:
        m.get(f'{URL}?{FIRST_REQUESTS_PARAMS}', json=util_load_json('test_data/events.json'))
        m.get(f'{URL}?{SECOND_REQUESTS_PARAMS}', json={})

        from JiraEventCollector import main
        main()

    events = results.call_args[0][0]['Contents']
    assert not last_run.return_value.get('from')
    assert last_run.return_value.get('next_time') == calculate_next_run(events[0]['created'])
    assert last_run.return_value.get('offset') == 1
    assert len(events) == 1
