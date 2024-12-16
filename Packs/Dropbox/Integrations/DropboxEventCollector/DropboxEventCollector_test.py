import json
import requests_mock
from freezegun import freeze_time
import demistomock as demisto


DEMISTO_PARAMS = {
    'limit': 100,
    'credentials': {
        'identifier': 'admin@your.domain',
        'password': '123456',
    }
}
DATETIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
AUTH_URL = 'https://api.dropbox.com/oauth2/token'
EVENTS_URL = 'https://api.dropbox.com/2/team_log/get_events'


def util_load_json(path):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


def mock_set_last_run(last_run):
    return last_run


@freeze_time('2022-05-17T00:00:00Z')
def test_fetch_incidents_few_incidents(mocker):
    """
    Given
        - 6 events was created in Dropbox side in the last 7 days.
    When
        - fetch-events is running (with max_fetch set to 100).
    Then
        - Verify that all 6 events were created in XSIAM.
        - Verify last_run was set as expected.
    """

    mocker.patch.object(demisto, 'params', return_value=DEMISTO_PARAMS)
    mocker.patch.object(demisto, 'args', return_value={'should_push_events': True})
    mocker.patch.object(demisto, 'getIntegrationContext', return_value={'refresh_token': '111111'})
    mocker.patch('DropboxEventCollector.send_events_to_xsiam')
    last_run = mocker.patch.object(demisto, 'setLastRun', side_effect=mock_set_last_run) or {}
    results = mocker.patch.object(demisto, 'results')

    with requests_mock.Mocker() as m:
        m.post(AUTH_URL, json={'access_token': '222222'})
        m.post(EVENTS_URL, json=util_load_json('test_data/events_1_.json'))
        m.post(f'{EVENTS_URL}/continue', json=util_load_json('test_data/events_2_.json'))

        from DropboxEventCollector import main
        main('dropbox-get-events', demisto.params() | demisto.args())

    events = results.call_args[0][0]['Contents']
    assert last_run.call_args[0][0].get('start_time') == '2022-05-16T11:48:29Z'
    assert len(events) == 6


@freeze_time('2022-05-17T00:00:00Z')
def test_fetch_events_no_incidents(mocker):
    """
    Given
        - No events was created in Dropbox side in the last 7 days.
    When
        - fetch-events is running.
    Then
        - Make sure no events was created in XSIAM.
        - Make sure last_run was set as expected.
    """

    mocker.patch.object(demisto, 'params', return_value=DEMISTO_PARAMS)
    mocker.patch.object(demisto, 'args', return_value={'should_push_events': True})
    mocker.patch.object(demisto, 'getIntegrationContext', return_value={'refresh_token': '111111'})
    mocker.patch('DropboxEventCollector.send_events_to_xsiam')
    last_run = mocker.patch.object(demisto, 'setLastRun', side_effect=mock_set_last_run)
    results = mocker.patch.object(demisto, 'results')

    with requests_mock.Mocker() as m:
        m.post(AUTH_URL, json={'access_token': '222222'})
        m.post(EVENTS_URL, json={})

        from DropboxEventCollector import main
        main('dropbox-get-events', demisto.params() | demisto.args())

    events = results.call_args[0][0]['Contents']
    assert not last_run.call_args
    assert not events


@freeze_time('2022-05-17T00:00:00Z')
def test_fetch_events_max_fetch_set_to_one(mocker):
    """
    Given
        - 3 events was created in Jira side in the last 7 days.
    When
        - fetch-events is running (with max_fetch set to 1).
    Then
        - Verify that only 1 event were created in XSIAM.
        - Verify last_run was set as expected.
    """

    params = DEMISTO_PARAMS
    params['limit'] = 1

    mocker.patch.object(demisto, 'params', return_value=DEMISTO_PARAMS)
    mocker.patch.object(demisto, 'args', return_value={'should_push_events': True})
    mocker.patch.object(demisto, 'getIntegrationContext', return_value={'refresh_token': '111111'})
    mocker.patch('DropboxEventCollector.send_events_to_xsiam')
    last_run = mocker.patch.object(demisto, 'setLastRun', side_effect=mock_set_last_run)
    results = mocker.patch.object(demisto, 'results')

    with requests_mock.Mocker() as m:
        m.post(AUTH_URL, json={'access_token': '222222'})
        m.post(EVENTS_URL, json=util_load_json('test_data/events_1_.json'))
        m.post(f'{EVENTS_URL}/continue', json=util_load_json('test_data/events_2_.json'))

        from DropboxEventCollector import main
        main('dropbox-get-events', demisto.params() | demisto.args())

    events = results.call_args[0][0]['Contents']
    assert last_run.call_args[0][0].get('start_time') == '2022-05-16T11:34:30Z'
    assert len(events) == 1
