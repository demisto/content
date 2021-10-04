import pytest
from freezegun import freeze_time

import demistomock as demisto

integration_params = {
    'url': 'http://test.com',
    'credentials': {'identifier': 'test', 'password': 'pass'},
    'fetch_time': '3 days',
    'proxy': 'false',
    'unsecure': 'false',
}


@pytest.fixture(autouse=True)
def set_mocks(mocker):
    mocker.patch.object(demisto, 'params', return_value=integration_params)


@freeze_time("2021-07-10T16:34:14.758295 UTC+1")
def test_fetch_incidents_first_time_fetch(mocker):
    """Unit test
    Given
    - fetch incidents command
    - command args
    When
    - mock the integration parameters
    Then
    - Validate that the last_time is as the now time(not changed, not of the incident)
    """
    mocker.patch.object(demisto, 'command', return_value='fetch-incidents')
    from RedLock import fetch_incidents
    mocker.patch('RedLock.req', return_value=[])

    _, next_run = fetch_incidents()
    assert next_run == 1625938454758
