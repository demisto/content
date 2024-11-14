"""Imports"""
# STD packages
import time
import json

# 3-rd party packages
import pytest
from freezegun import freeze_time

# Local imports
import Akamai_SIEM
from CommonServerPython import urljoin


"""Helper functions and fixrtures"""
BASE_URL = urljoin('https://akab-hnanog6ge5or6biz-ukavvo4zvqliqhlw.cloudsecurity.akamaiapis.net', '/siem/v1/configs')
with open('./Akamai_SIEM_test/TestCommandsFunctions/sec_events_empty.txt') as sec_events_empty:
    SEC_EVENTS_EMPTY_TXT = sec_events_empty.read()
with open('./Akamai_SIEM_test/TestCommandsFunctions/sec_events.txt') as sec_events:
    SEC_EVENTS_TXT = sec_events.read()
with open('./Akamai_SIEM_test/TestCommandsFunctions/sec_events_six_results.txt') as sec_events_six_results:
    SEC_EVENTS_SIX_RESULTS_TXT = sec_events_six_results.read()
with open('./Akamai_SIEM_test/TestCommandsFunctions/sec_events_two_results.txt') as sec_events_two_results:
    SEC_EVENTS_TWO_RESULTS_TXT = sec_events_two_results.read()


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

    def test_fetch_events_command__sanity(self, client, mocker):
        """
        Given:
        - A client object
        - 500 events to pull in the 3rd party
        - A fetch_limit of 220
        When:
        - Calling fetch_events_command()
        Then:
        - Ensure offset is updated in each iteration by checking its value
        - Ensure 250 events are pulled (fetch_limit, rounded up to the nearest multiple of page_size=50)
        """
        num_of_results = 500
        page_size = 50
        num_of_pages = num_of_results // page_size
        mocker.patch.object(Akamai_SIEM.Client, "get_events_with_offset", side_effect=[
            (
                [{"id": i + 1, "httpMessage": {"start": i + 1}} for i in range(page_size * j, page_size * (j + 1))],
                f"offset_{page_size * (j + 1)}",
            )
            for j in range(num_of_pages)
        ])
        total_events_count = 0

        for events, offset, total_events_count, _ in Akamai_SIEM.fetch_events_command(client,  # noqa: B007
                                                                                      '3 days',
                                                                                      220,
                                                                                      '',
                                                                                      {},
                                                                                      5000
                                                                                      ):
            assert offset == f"offset_{events[-1]['id']}" if events else True
        assert total_events_count == 250

    def test_fetch_events_command__no_results(self, client, requests_mock):
        """
        Given:
        - A client object
        - no events to pull from the 3rd party
        - offset is 11111
        When:
        - Calling fetch_events_command()
        Then:
        - Ensure no events are returned and the offset is the same
        """
        from Akamai_SIEM import FETCH_EVENTS_PAGE_SIZE as size
        total_events_count = 0
        last_offset = "11111"
        requests_mock.get(f'{BASE_URL}/50170?limit={size}&offset={last_offset}', text=SEC_EVENTS_EMPTY_TXT)

        for _, offset, total_events_count, _ in Akamai_SIEM.fetch_events_command(client, '12 hours', 6,  # noqa: B007
                                                                              '50170', {"offset": last_offset}, size):
            last_offset = offset
        assert total_events_count == 0
        assert last_offset == "318d8"

    def test_fetch_events_command__limit_is_smaller_than_page_size(self, client, requests_mock, mocker):
        """
        Given:
        - A client object
        - 8 events to pull from the 3rd party
        - page size is 6
        - limit is 4
        When:
        - Calling fetch_events_command()
        Then:
        - Ensure 6 events are returned
        """
        mocker.patch.object(Akamai_SIEM, "FETCH_EVENTS_PAGE_SIZE", new=6, autospec=False)
        total_events_count = 0
        last_offset = None
        requests_mock.get(f'{BASE_URL}/50170?limit=6&from=1575966002', text=SEC_EVENTS_SIX_RESULTS_TXT)
        requests_mock.get(f'{BASE_URL}/50170?limit=6&from=1575966002&offset=218d9', text=SEC_EVENTS_TXT)
        requests_mock.get(f'{BASE_URL}/50170?limit=6&from=1575966002&offset=318d8', text=SEC_EVENTS_EMPTY_TXT)

        for _, offset, total_events_count, _ in Akamai_SIEM.fetch_events_command(client,  # noqa: B007
                                                                                             '12 hours',
                                                                                             4, '50170',
                                                                                             {}, 6):
            last_offset = offset
        assert total_events_count == 6
        assert last_offset == "218d9"

    def test_fetch_events_command__limit_is_higher_than_page_size(self, client, requests_mock, mocker):
        """
        Given:
        - A client object
        - 8 events to pull from the 3rd party
        - page size is 6
        - limit is 20
        When:
        - Calling fetch_events_command()
        Then:
        - Ensure 8 events are returned
        """
        mocker.patch.object(Akamai_SIEM, "FETCH_EVENTS_PAGE_SIZE", new=6, autospec=False)
        total_events_count = 0
        last_offset = None
        requests_mock.get(f'{BASE_URL}/50170?limit=6&from=1575966002', text=SEC_EVENTS_SIX_RESULTS_TXT)
        requests_mock.get(f'{BASE_URL}/50170?limit=6&offset=218d9', text=SEC_EVENTS_TXT)
        requests_mock.get(f'{BASE_URL}/50170?limit=6&offset=318d8', text=SEC_EVENTS_EMPTY_TXT)

        for _, offset, total_events_count, _ in Akamai_SIEM.fetch_events_command(client,  # noqa: B007
                                                                                             '12 hours',
                                                                                             20,
                                                                                             '50170',
                                                                                             {}, 6
                                                                                            ):
            last_offset = offset
        assert total_events_count == 8
        assert last_offset == "318d8"

    def test_fetch_events_command__limit_reached(self, client, requests_mock, mocker):
        """
        Given:
        - A client object
        - 4 events to pull from the 3rd party
        - page size is 2
        - limit is 2
        When:
        - Calling fetch_events_command()
        Then:
        - Ensure 2 events are returned
        - Ensure last_offset is the one returned from the last page we pulled events from (the 1st one)
        """
        mocker.patch.object(Akamai_SIEM, "FETCH_EVENTS_PAGE_SIZE", new=2, autospec=False)
        total_events_count = 0
        last_offset = None
        requests_mock.get(f'{BASE_URL}/50170?limit=2&from=1575966002', text=SEC_EVENTS_TWO_RESULTS_TXT)
        requests_mock.get(f'{BASE_URL}/50170?limit=2&offset=117d9', text=SEC_EVENTS_TXT)

        for _, offset, total_events_count, _ in Akamai_SIEM.fetch_events_command(client,  # noqa: B007
                                                                                 '12 hours',
                                                                                 2,
                                                                                 '50170',
                                                                                 {}, 2
                                                                                ):
            last_offset = offset
        assert total_events_count == 2
        assert last_offset == "117d9"

    def test_deduplication(self, mocker, client):
        """
        Given:
        - A client object
        - 250 events.
        - hashed events from previous run list with 4 events, 3 events which will appear in the response and one event that won't.
        When:
        - Calling fetch_events_command()
        Then:
        - Ensure that the events list returned doesn't include the filtered events and that the length of the list is 247.
        - Ensure that on each iteration, the number of events in the hashed events is 50
        (even in intervals where some events were deduped).
        - Ensure the returned offset and hashed events are json serializable.
        """
        num_of_results = 500
        page_size = 50
        num_of_pages = num_of_results // page_size
        events = [
            (
                [{"id": i + 1, "httpMessage": {"start": i + 1}} for i in range(page_size * j, page_size * (j + 1))],
                f"offset_{page_size * (j + 1)}",
            )
            for j in range(num_of_pages)
        ]
        events_not_in_list = [events[0][0][0], events[0][0][2], events[0][0][4]]
        mocker.patch.object(Akamai_SIEM.Client, "get_events_with_offset", side_effect=events)
        total_events_count = 0
        hashed = {"506353d42f4aaac34493bdfff026ea0c4463a3bc510fb7aa038df8cea7aabbd1",
                  "fce8004cc56a8fb1131f30d2715412d4dcc90be0564c375d1c6b9aee2103b360",
                  "5075434ef4e7e1d0b6c1922e180653e18481aee76674966ae5de876faefc62d3",
                  "fce8004cc56a8fb1131f30d2715412d4dcc90be0564c375d1c6b9aee2103b3ds"}
        for events, offset, total_events_count, hashed in Akamai_SIEM.fetch_events_command(client,  # noqa: B007
                                                                                      '3 days',
                                                                                      220,
                                                                                      '',
                                                                                      {"hashed_events_from_previous_run": hashed},
                                                                                      5000
                                                                                      ):
            assert offset == f"offset_{events[-1]['id']}" if events else True
            assert len(hashed) == 50
        assert total_events_count == 247
        for event_not_in_list in events_not_in_list:
            assert event_not_in_list not in events
        ctx = {"offset": offset, "hashed_events_from_previous_run": list(hashed)}
        assert isinstance(json.dumps(ctx), str)


@pytest.mark.parametrize(
    "header",
    [
        (
            'Content-Type%3A%20application/json%3Bcharset%3DUTF-8%0D%0Auser%3A%20test%40test.com%0D%0Aclient%3A%'
            '20test_client%0D%0AX-Kong-Upstream-Latency%3A%2066%0D%0AX-Kong-Proxy-Latency%3A%202%0D%0AX-Kong-Request-Id%3A%20X'
            '_request_id%0D%0AEPM-Request-ID%3A%20EPM_request_id%0D%0AContent-Length%3A%20157%0D%0ADate%3A%20Mon%2C%2025%20Mar'
            '%202024%2013%3A52%3A11%20GMT%0D%0AConnection%3A%20keep-alive%0D%0AServer-Timing%3A%20cdn-cache%3B%20desc%3DMISS%0'
            'D%0AServer-Timing%3A%20edge%3B%20dur%3D23%0D%0AServer-Timing%3A%20origin%3B%20dur%3D72%0D%0AServer-Timing%3A%20int'
            'id%3Bdesc%3Ddd%0D%0AStrict-Transport-Security%3A%20max-age%3D31536000%20%3B%20includeSubDomains%20%3B%20preload%0D'
            '%0A'
        ),
        (
            'Content-Type%3A%20application/json%3Bcharset%3DUTF-8%0Auser%3A%20test%40test.com%0Aclient%3A%20'
            'test_client%0AX-Kong-Upstream-Latency%3A%2066%0AX-Kong-Proxy-Latency%3A%202%0AX-Kong-Request-Id%3A%20X_request_id%'
            '0AEPM-Request-ID%3A%20EPM_request_id%0AContent-Length%3A%20157%0ADate%3A%20Mon%2C%2025%20Mar%202024%2013%3A52%3A11'
            '%20GMT%0AConnection%3A%20keep-alive%0AServer-Timing%3A%20cdn-cache%3B%20desc%3DMISS%0AServer-Timing%3A%20edge%3B'
            '%20dur%3D23%0AServer-Timing%3A%20origin%3B%20dur%3D72%0AServer-Timing%3A%20intid%3Bdesc%3Ddd%0A'
            'Strict-Transport-Security%3A%20max-age%3D31536000%20%3B%20includeSubDomains%20%3B%20preload%0A'
        )
    ],
)
def test_decode_url(header):
    """
    Given: A url decoded string.
        - Case 1: Each key separated by '\r\n'.
        - Case 2: Each key is separated by '\n'.
    When: Calling Akamai_SIEM.decode_url.
    Then: Ensure that the dict was decoded correctly and the same dict was extracted in both cases.
    """
    expected_decoded_dict = {'Content_Type': 'application/json;charset=UTF-8', 'user': 'test@test.com', 'client': 'test_client',
                             'X_Kong_Upstream_Latency': '66', 'X_Kong_Proxy_Latency': '2', 'X_Kong_Request_Id': 'X_request_id',
                             'EPM_Request_ID': 'EPM_request_id', 'Content_Length': '157', 'Date': 'Mon, 25 Mar 2024 13:52:11 GMT',
                             'Connection': 'keep-alive', 'Server_Timing': 'intid;desc=dd',
                             'Strict_Transport_Security': 'max-age=31536000 ; includeSubDomains ; preload'}
    assert Akamai_SIEM.decode_url(header) == expected_decoded_dict


@pytest.mark.parametrize(
    "hashed_events_mapping, hashed_events_from_previous_run, expected_deduped_list",
    [
        ({"a": {"id": 1}, "b": {"id": 2}, "c": {"id": 3}}, {"a", "b", "c"}, []),
        ({"a": {"id": 1}, "b": {"id": 2}, "c": {"id": 3}}, {"d", "e", "f"}, [{"id": 1}, {"id": 2}, {"id": 3}]),
        ({"a": {"id": 1}, "b": {"id": 2}, "c": {"id": 3}}, set(), [{"id": 1}, {"id": 2}, {"id": 3}]),
        ({"a": {"id": 1}, "b": {"id": 2}, "c": {"id": 3}}, {"a", "d", "e"}, [{"id": 2}, {"id": 3}]),
    ],
)
def test_dedup_events(hashed_events_mapping, hashed_events_from_previous_run, expected_deduped_list):
    """
    Given: hashed_events_mapping dict, and hashed_events_from_previous_run set
        - Case 1: dictionary with 3 events with all 3 events hashes appears in the hashed_events_from_previous_run set.
        - Case 2: dictionary with 3 events with none of the 3 events hashes appears in the hashed_events_from_previous_run set.
        - Case 3: dictionary with 3 events with an empty hashed_events_from_previous_run set.
        - Case 4: dictionary with 3 events with only 1 event hash appears in the hashed_events_from_previous_run set,
                  along with 2 hashes that doesn't appear in the dict.
    When: Running dedup_events on them.
    Then: Ensure that the whole set of keys was returned as hashed_events_from_current_run for the next interval,
          and that the right events were filtered out.
          - Case 1: should filter all events.
          - Case 2: shouldn't filter any events.
          - Case 3: shouldn't filter any events.
          - Case 4: should filter only the one event that appears in the hashed_events_from_previous_run set.
    """
    deduped_events, hashed_events_from_current_run = Akamai_SIEM.dedup_events(hashed_events_mapping,
                                                                              hashed_events_from_previous_run)
    assert hashed_events_from_current_run == set(hashed_events_mapping.keys())
    assert deduped_events == expected_deduped_list
