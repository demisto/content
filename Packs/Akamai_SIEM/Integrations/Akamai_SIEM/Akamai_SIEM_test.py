"""Imports"""
# STD packages
import time
import json

# 3-rd party packages
import pytest
from freezegun import freeze_time

# Local imports
from CommonServerPython import urljoin

"""Helper functions and fixrtures"""
BASE_URL = urljoin('https://akab-hnanog6ge5or6biz-ukavvo4zvqliqhlw.cloudsecurity.akamaiapis.net', '/siem/v1/configs')
with open('./Akamai_SIEM_test/TestCommandsFunctions/sec_events_empty.txt', 'r') as sec_events_empty:
    SEC_EVENTS_EMPTY_TXT = sec_events_empty.read()
with open('./Akamai_SIEM_test/TestCommandsFunctions/sec_events.txt', 'r') as sec_events:
    SEC_EVENTS_TXT = sec_events.read()


def load_params_from_json(json_path, type=''):
    with open(json_path) as f:
        file = json.load(f)
        if type == "incidents":
            for incident in file:
                incident['rawJSON'] = json.dumps(incident.get('rawJSON', {}))
    return file


@pytest.fixture(scope='module')
def client():
    from Akamai_SIEM import Client

    return Client(base_url=BASE_URL)


'''Tests'''


@pytest.mark.commands
@freeze_time(time.ctime(1576009202))
class TestCommandsFunctions:
    @pytest.mark.fetch
    def test_fetch_incidents_command_1(self, client, datadir, requests_mock):
        """Test - No last time exsits and event available"""
        from Akamai_SIEM import fetch_incidents_command
        requests_mock.get(f'{BASE_URL}/50170?limit=5&from=1575966002', text=SEC_EVENTS_TXT)
        tested_incidents, tested_last_run = fetch_incidents_command(client=client,
                                                                    fetch_time='12 hours',
                                                                    fetch_limit=5,
                                                                    config_ids='50170',
                                                                    last_run={})
        expected_incidents = load_params_from_json(datadir['expected_fetch.json'], type='incidents')
        expected_last_run = {'lastRun': "1576002507"}
        assert expected_incidents == tested_incidents, "Incidents - No last time exsits and event available"
        assert tested_last_run == expected_last_run, "Last run - No last time exsits and event available"

    @pytest.mark.fetch
    def test_fetch_incidents_command_2(self, client, datadir, requests_mock):
        """Test - Last time exsits and events available"""
        from Akamai_SIEM import fetch_incidents_command
        requests_mock.get(f'{BASE_URL}/50170?from=1575966002&limit=5', text=SEC_EVENTS_TXT)
        tested_incidents, tested_last_run = fetch_incidents_command(client=client,
                                                                    fetch_time='12 hours',
                                                                    fetch_limit='5',
                                                                    config_ids='50170',
                                                                    last_run='1575966002')
        expected_incidents = load_params_from_json(datadir['expected_fetch.json'], type='incidents')
        expected_last_run = {'lastRun': "1576002507"}
        assert expected_incidents == tested_incidents, "Incidents - Last time exsits and events available"
        assert tested_last_run == expected_last_run, "Last run - No last time exsits and event available"

    @pytest.mark.fetch
    def test_fetch_incidents_command_3(self, client, datadir, requests_mock):
        """Test - Last time exsits and no available data"""
        from Akamai_SIEM import fetch_incidents_command
        requests_mock.get(f'{BASE_URL}/50170?from=1575966002&limit=5', text=SEC_EVENTS_EMPTY_TXT)
        tested_incidents, tested_last_run = fetch_incidents_command(client=client,
                                                                    fetch_time='12 hours',
                                                                    fetch_limit=5,
                                                                    config_ids='50170',
                                                                    last_run='1575966002')
        expected_last_run = {'lastRun': "1575966002"}
        expected_incidents = []
        assert expected_incidents == tested_incidents, "Incidents - Last time exsits and no available data"
        assert tested_last_run == expected_last_run, "Last run - No last time exsits and event available"

    @pytest.mark.fetch
    def test_fetch_incidents_command_4(self, client, datadir, requests_mock):
        """Test - No last time exsits and no available data"""
        from Akamai_SIEM import fetch_incidents_command
        requests_mock.get(f'{BASE_URL}/50170?from=1575966002&limit=5', text=SEC_EVENTS_EMPTY_TXT)
        tested_incidents, tested_last_run = fetch_incidents_command(client=client,
                                                                    fetch_time='12 hours',
                                                                    fetch_limit=5,
                                                                    config_ids='50170',
                                                                    last_run={})
        expected_last_run = {'lastRun': "1575966002"}
        expected_incidents = []
        assert expected_incidents == tested_incidents, "Incidents - No last time exsits and no available data"
        assert tested_last_run == expected_last_run, "Last run - No last time exsits and no available data"

    @pytest.mark.get_events
    def test_get_events_command_1(self, client, datadir, requests_mock):
        """Test query response without security events - check only enrty context"""
        from Akamai_SIEM import get_events_command
        requests_mock.get(f'{BASE_URL}/50170?from=1575966002&limit=5', text=SEC_EVENTS_EMPTY_TXT)
        # About the drop some mean regex right now disable-secrets-detection-start
        human_readable, entry_context_tested, raw_response = get_events_command(client=client,
                                                                                config_ids='50170',
                                                                                from_epoch='1575966002',
                                                                                limit='5')
        # Drops the mic disable-secrets-detection-end

        assert entry_context_tested == {}, "Test query response without security events - check only enrty context"

    @pytest.mark.get_events
    def test_get_events_command_2(self, client, datadir, requests_mock):
        """Test query response with security events - check only entry context"""
        from Akamai_SIEM import get_events_command
        # About the drop some mean regex right now disable-secrets-detection-start
        requests_mock.get(f'{BASE_URL}/50170?from=1575966002&limit=5', text=SEC_EVENTS_TXT)
        human_readable, entry_context_tested, raw_response = get_events_command(client=client,
                                                                                config_ids='50170',
                                                                                from_epoch='1575966002',
                                                                                limit='5')
        # Drops the mic disable-secrets-detection-end
        expected_ec = load_params_from_json(json_path=datadir['get_events_expected_ec_2.json'])

        assert entry_context_tested == expected_ec, "Test query response with security events - check only entry context"
