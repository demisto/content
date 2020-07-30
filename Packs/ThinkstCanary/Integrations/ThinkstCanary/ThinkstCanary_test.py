import demistomock as demisto


MOCK_PARAMS = {
    'access-key': 'fake_access_key',
    'secret-key': 'fake_access_key',
    'server': 'http://123-fake-api.com/',
    'unsecure': True,
    'proxy': True
}


def test_fetch_incidents(mocker, requests_mock):
    mocker.patch.object(demisto, 'params', return_value=MOCK_PARAMS)
    mocker.patch.object(demisto, 'getLastRun', return_value={'time': '2020-01-07-07:58:18'})
    requests_mock.get('http://123-fake-api.com/api/v1/incidents/unacknowledged?newer_than=2020-01-07-07%3A58%3A18',
                      json={'incidents': [{'description': {'created': 1593579498}}]})
    from ThinkstCanary import fetch_incidents_command
    fetch_incidents_command()

    assert demisto.setLastRun.call_args[0][0]['2020-01-07-07:58:19'] is True

    assert 1 == 2
