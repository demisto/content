"""Imports"""
# STD packages
import asyncio
from datetime import datetime
import time
import json

import demistomock as demisto

# 3-rd party packages
import pytest
from freezegun import freeze_time

# Local imports
import Akamai_SIEM
from CommonServerPython import urljoin, DemistoException


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

    def test_fetch_events_command_with_break_before_timeout(self, client, mocker):
        """
        Given:
        - A client object
        - 2 mock responses each one with one has 50 events (total 100).
        When:
        - Calling fetch_events_command() and getting is_interval_doesnt_have_enough_time_to_run in the second execution.
        Then:
        - Ensure there are only 50 total events received and auto_trigger_next_run = True.
        """
        page_size = 50
        events = [
            (
                [{"id": i + 1, "httpMessage": {"start": i + 1}} for i in range(page_size * j, page_size * (j + 1))],
                f"offset_{page_size * (j + 1)}",
            )
            for j in range(2)
        ]
        mocker.patch.object(Akamai_SIEM.Client, "get_events_with_offset", side_effect=events)
        mocker.patch.object(Akamai_SIEM, "is_interval_doesnt_have_enough_time_to_run", return_value=(False, 1))
        total_events_count = 0
        for events, _, total_events_count, auto_trigger_next_run in Akamai_SIEM.fetch_events_command(client,  # noqa: B007
                                                                                      '3 days',
                                                                                      220,
                                                                                      '',
                                                                                      {},
                                                                                      50,
                                                                                      False
                                                                                      ):
            mocker.patch.object(Akamai_SIEM, "is_interval_doesnt_have_enough_time_to_run", return_value=(True, 1))
        assert total_events_count == 50
        assert auto_trigger_next_run

    def test_fetch_events_command_with_break_for_page_too_small(self, client, mocker):
        """
        Given:
        - A client object
        - 2 mock responses each one with one has 50 events (total 100).
        When:
        - Calling fetch_events_command() with page_size > amount of events obtained in first execution.
        Then:
        - Ensure there are only 50 total events received.
        """
        page_size = 50
        events = [
            (
                [{"id": i + 1, "httpMessage": {"start": i + 1}} for i in range(page_size * j, page_size * (j + 1))],
                f"offset_{page_size * (j + 1)}",
            )
            for j in range(2)
        ]
        mocker.patch.object(Akamai_SIEM.Client, "get_events_with_offset", side_effect=events)
        mocker.patch.object(Akamai_SIEM, "is_interval_doesnt_have_enough_time_to_run", return_value=(False, 1))
        total_events_count = 0
        for events, _, total_events_count, _ in Akamai_SIEM.fetch_events_command(client,  # noqa: B007
                                                                                      '3 days',
                                                                                      220,
                                                                                      '',
                                                                                      {},
                                                                                      page_size=60,
                                                                                      should_skip_decode_events=False
                                                                                      ):
            pass
        assert total_events_count == 50

    def test_fetch_events_command_sanity(self, client, mocker):
        """
        Given:
        - A client object
        - 500 events to pull in the 3rd party
        - A fetch_limit of 260
        When:
        - Calling fetch_events_command()
        Then:
        - Ensure offset is updated in each iteration by checking its value
        - Ensure 250 events are pulled (fetch_limit, rounded up to the nearest multiple of page_size=50)
        """
        num_of_results = 500
        page_size = 50
        limit = 250
        num_of_pages = num_of_results // page_size
        mocker.patch.object(Akamai_SIEM, "is_interval_doesnt_have_enough_time_to_run", return_value=(False, 1))
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
                                                                                      limit,
                                                                                      '',
                                                                                      {},
                                                                                      page_size,
                                                                                      False
                                                                                      ):
            assert offset == f"offset_{events[-1]['id']}" if events else True
        assert total_events_count == 250

    def test_fetch_events_command_no_results(self, mocker, client, requests_mock):
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
        from Akamai_SIEM import FETCH_EVENTS_MAX_PAGE_SIZE as size
        total_events_count = 0
        last_offset = "11111"
        requests_mock.get(f'{BASE_URL}/50170?limit={size}&offset={last_offset}', text=SEC_EVENTS_EMPTY_TXT)
        mocker.patch.object(Akamai_SIEM, "is_interval_doesnt_have_enough_time_to_run", return_value=(False, 1))

        for _, offset, total_events_count, _ in Akamai_SIEM.fetch_events_command(client, '12 hours', size,  # noqa: B007
                                                                              '50170', {"offset": last_offset}, size, False):
            last_offset = offset
        assert total_events_count == 0
        assert last_offset == "318d8"

    def test_fetch_events_command_limit_is_smaller_than_page_size(self, client, requests_mock, mocker):
        """
        Given:
        - A client object
        - 8 events to pull from the 3rd party
        - page size is 6
        - limit is 6
        When:
        - Calling fetch_events_command()
        Then:
        - Ensure 6 events are returned
        """
        mocker.patch.object(Akamai_SIEM, "FETCH_EVENTS_MAX_PAGE_SIZE", new=6, autospec=False)
        mocker.patch.object(Akamai_SIEM, "is_interval_doesnt_have_enough_time_to_run", return_value=(False, 1))
        total_events_count = 0
        last_offset = None
        requests_mock.get(f'{BASE_URL}/50170?limit=6&from=1575966002', text=SEC_EVENTS_SIX_RESULTS_TXT)
        requests_mock.get(f'{BASE_URL}/50170?limit=6&from=1575966002&offset=218d9', text=SEC_EVENTS_TXT)
        requests_mock.get(f'{BASE_URL}/50170?limit=6&from=1575966002&offset=318d8', text=SEC_EVENTS_EMPTY_TXT)

        for _, offset, total_events_count, _ in Akamai_SIEM.fetch_events_command(client,  # noqa: B007
                                                                                             '12 hours',
                                                                                             6, '50170',
                                                                                             {}, 6,
                                                                                             False):
            last_offset = offset
        assert total_events_count == 6
        assert last_offset == "218d9"

    def test_fetch_events_command_limit_is_higher_than_page_size(self, client, requests_mock, mocker):
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
        mocker.patch.object(Akamai_SIEM, "FETCH_EVENTS_MAX_PAGE_SIZE", new=6, autospec=False)
        mocker.patch.object(Akamai_SIEM, "is_interval_doesnt_have_enough_time_to_run", return_value=(False, 1))
        total_events_count = 0
        last_offset = None
        requests_mock.get(f'{BASE_URL}/50170?limit=6&from=1575966002', text=SEC_EVENTS_SIX_RESULTS_TXT)
        requests_mock.get(f'{BASE_URL}/50170?limit=6&offset=218d9', text=SEC_EVENTS_TXT)
        requests_mock.get(f'{BASE_URL}/50170?limit=6&offset=318d8', text=SEC_EVENTS_EMPTY_TXT)

        for _, offset, total_events_count, _ in Akamai_SIEM.fetch_events_command(client,  # noqa: B007
                                                                                             '12 hours',
                                                                                             20,
                                                                                             '50170',
                                                                                             {}, 6,
                                                                                             False
                                                                                            ):
            last_offset = offset
        assert total_events_count == 8
        assert last_offset == "318d8"

    def test_fetch_events_command_limit_reached(self, client, requests_mock, mocker):
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
        mocker.patch.object(Akamai_SIEM, "FETCH_EVENTS_MAX_PAGE_SIZE", new=2, autospec=False)
        mocker.patch.object(Akamai_SIEM, "is_interval_doesnt_have_enough_time_to_run", return_value=(False, 1))
        total_events_count = 0
        last_offset = None
        requests_mock.get(f'{BASE_URL}/50170?limit=2&from=1575966002', text=SEC_EVENTS_TWO_RESULTS_TXT)
        requests_mock.get(f'{BASE_URL}/50170?limit=2&offset=117d9', text=SEC_EVENTS_TXT)

        for _, offset, total_events_count, _ in Akamai_SIEM.fetch_events_command(client,  # noqa: B007
                                                                                 '12 hours',
                                                                                 2,
                                                                                 '50170',
                                                                                 {}, 2,
                                                                                 False
                                                                                ):
            last_offset = offset
        assert total_events_count == 2
        assert last_offset == "117d9"

    def test_fetch_events_command_with_page_truncated(self, mocker, client, requests_mock):
        """
        Given:
        - A client object
        - page_size = 2, fetch_limit = 3, and two requests_mock.
        When:
        - Calling fetch_events_command()
        Then:
        - The request was called correctly in the first fetch_events_command execution with limit = 2 and from_time.
        - The request was called correctly in the second fetch_events_command execution with limit = 1 and offset.
        - A total of 3 events received with offset = the offset from the second response.
        """
        page_size = 2
        fetch_limit = 3
        first_response_mock = '{"id": 1, "httpMessage": {"start": 1}}\n{"id": 2, "httpMessage": {"start": 2}}\n{"offset": "a"}'
        second_response_mock = '{"id": 3, "httpMessage": {"start": 3}}\n{"offset": "b"}'
        mocker.patch('CommonServerPython.parse_date_range', return_value='1575966002')
        requests_mock.get(f"{BASE_URL}/50170?limit=2&from=1575750002", text=first_response_mock)
        mocker.patch.object(Akamai_SIEM, "is_interval_doesnt_have_enough_time_to_run", return_value=(False, 1))
        total_events_count = 0
        for _, offset, total_events_count, _ in Akamai_SIEM.fetch_events_command(client,  # noqa: B007
                                                                                      fetch_time='3 days',
                                                                                      fetch_limit=fetch_limit,
                                                                                      config_ids='50170',
                                                                                      ctx={},
                                                                                      page_size=page_size,
                                                                                      should_skip_decode_events=False
                                                                                      ):
            requests_mock.get(f"{BASE_URL}/50170?limit=1&offset={offset}", text=second_response_mock)
        assert total_events_count == fetch_limit
        assert offset == 'b'

    @pytest.mark.parametrize(
        "error_entry, error_message, expect_extra_info",
        [
            ({
                "clientIp": "192.0.2.228",
                "detail": "Expired offset parameter in the request",
                "instance": "https://test.akamaiapis.net/siem/v1/configs=12345?offset=123",
                "method": "GET",
                "requestId": "test",
                "requestTime": "2023-06-20T15:02:30Z",
                "serverIp": "1.1.1.1",
                "title": "Expired offset parameter in the request",
            }, "Error in API call [416] - Requested Range Not Satisfiable", True),
            ({
                "clientIp": "192.0.2.85",
                "detail": "The specified user is unauthorized to access the requested data",
                "instance": "https://test.akamaiapis.net/siem/v1/configs=12345?offset=123",
                "method": "GET",
                "requestId": "9cf2274",
                "requestTime": "2023-06-20T15:01:11Z",
                "serverIp": "1.1.1.1",
                "title": "Unauthorized",
            }, "Error in API call [403] - Unauthorized", False)
        ],
    )
    def test_response_errors(self, mocker, client, error_entry, error_message, expect_extra_info):
        """
        Given:
        - A client object and an error entry
        - Case 1: Mock error entry for 416 error.
        - Case 2: Mock error entry for 403 error.
        When:
        - Calling fetch_events_command and get_events_with_offset throw that error.
        Then:
        - Ensure that the error was caught by the fetch_events_command and the relevant message was added along the error itself.
        - Case 1: Should add extra information to the message.
        - Case 2: Shouldn't add extra information to the message.
        """
        err_msg = f'{error_message}\n{json.dumps(error_entry)}'
        mocker.patch.object(Akamai_SIEM.Client, "get_events_with_offset", side_effect=DemistoException(err_msg, res={}))
        mocker.patch.object(Akamai_SIEM, "is_interval_doesnt_have_enough_time_to_run", return_value=False)
        error_log_mocker = mocker.patch.object(demisto, 'error')
        with pytest.raises(DemistoException) as e:
            for _, _, _ in Akamai_SIEM.fetch_events_command(client,  # noqa: B007
                                                                                        '3 days',
                                                                                        220,
                                                                                        '',
                                                                                        {},
                                                                                        5000,
                                                                                        False
                                                                                        ):
                pass
        error_log_mocker.assert_called_with(f"Got an error when trying to request for new events from Akamai\n{err_msg}")
        assert ('Got offset out of range error when attempting to fetch events from Akamai.' in str(e)) == expect_extra_info
        assert ('Expired offset parameter in the request' in str(e)) == expect_extra_info


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
    "freeze_mock, min_allowed_delta, worst_case_time, expected_time, expected_should_break",
    [
        (datetime(2024, 4, 10, 10, 4, 10), 30, 0, 250, True),
        (datetime(2024, 4, 10, 10, 4, 10), 310, 50, 50, True),
        (datetime(2024, 4, 10, 10, 1, 10), 30, 50, 50, False),
        (datetime(2024, 4, 10, 10, 1, 10), 30, 0, 70, False)
    ],
)
def test_is_interval_doesnt_have_enough_time_to_run(mocker, freeze_mock,
                                                    min_allowed_delta, worst_case_time, expected_time, expected_should_break):
    """
    Given: min_allowed_delta
        - Case 1: min_allowed_delta = 30, no worst_case_time set yet, and 50 seconds to timeout.
        - Case 2: min_allowed_delta = 310, worst_case_time = 50, and 50 seconds to timeout.
        - Case 3: min_allowed_delta = 30, worst_case_time = 50, and 230 seconds to timeout.
        - Case 4: min_allowed_delta = 30, no worst_case_time set yet, and 230 seconds to timeout.
    When: Running is_interval_doesnt_have_enough_time_to_run
    Then: Ensure that the right results and worst_case_time are returned.
        - Case 1: should return True (meaning we should break) and worst_case_time = 250.
        - Case 2: should return True (meaning we should break) and worst_case_time = 50.
        - Case 3: should return False (meaning we shouldn't break yet) and worst_case_time = 50.
        - Case 4: Should return False (meaning we shouldn't break yet) and worst_case_time = 70.
    """
    import demistomock as demisto
    mocker.patch.object(demisto, 'callingContext', {'context': {'TimeoutDuration': 300000000000}})
    setattr(Akamai_SIEM, 'EXECUTION_START_TIME', datetime(2024, 4, 10, 10, 0, 0))
    with freeze_time(freeze_mock):
        should_break, worst_case_time = Akamai_SIEM.is_interval_doesnt_have_enough_time_to_run(min_allowed_delta, worst_case_time)
        assert expected_time == worst_case_time
        assert should_break == expected_should_break


@pytest.mark.parametrize(
    "num_events_from_previous_request, page_size, expected_results",
    [
        (300, 400, True),
        (380, 400, False),
        (400, 400, False),
    ],
)
def test_is_last_request_smaller_than_page_size(num_events_from_previous_request, page_size, expected_results):
    """
    Given: num_events_from_previous_request, and page_size
        - Case 1: num_events_from_previous_request = 300, page_size = 400.
        - Case 2: num_events_from_previous_request = 380, page_size = 400.
        - Case 3: num_events_from_previous_request = 400, page_size = 400.
    When: Running is_last_request_smaller_than_page_size with ALLOWED_PAGE_SIZE_DELTA_RATIO = 0.95
    Then: Ensure that the right results and worst_case_time are returned.
        - Case 1: should return True (meaning we should break).
        - Case 2: should return False (meaning we shouldn't break yet).
        - Case 3: Should return False (meaning we shouldn't break yet).
    """
    assert Akamai_SIEM.is_last_request_smaller_than_page_size(num_events_from_previous_request, page_size) is expected_results


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "offset, request_query",
    [
        (None, "50170?limit=100&from=1691303422"),
        ("test_offset", "50170?limit=100&offset=test_offset")
    ],
)
async def test_get_events_with_offset_concurrently_success(client, offset, request_query, requests_mock):
    """
        Given:
        - A successful mock http call response with 2 events and offset context.
        When:
        - Calling get_events_with_offset_concurrently().
        Then:
        - Ensure the right log type and text returned. And the right length of events, and offset returned.
    """
    response_mock = '{"id": 1, "httpMessage": {"start": 1}}\n{"id": 2, "httpMessage": {"start": 2}}\n{"offset": "a"}'
    requests_mock.get(f"{BASE_URL}/{request_query}", text=response_mock)
    events, response_offset = await client.get_events_with_offset_concurrently("50170", offset, 100, "1691303422", 2)
    assert len(events) == 2
    assert response_offset == "a"


@pytest.mark.asyncio
async def test_get_events_with_offset_concurrently_failure(client, requests_mock):
    """
        Given:
        - An error mock http response.
        When:
        - Calling get_events_with_offset_concurrently().
        Then:
        - Ensure the right log type and text returned.
    """
    requests_mock.get(f"{BASE_URL}/50170?limit=100&offset=offset", status_code=416, text="Requested Range Not Satisfiable")
    with pytest.raises(DemistoException) as e:
        await client.get_events_with_offset_concurrently("50170", "offset", 100, "1691303422", 2)
    assert 'Error in API call [416]' in str(e.value)
    assert "Requested Range Not Satisfiable" in str(e.value)


@pytest.mark.asyncio
async def test_get_events_from_akamai_success(mocker, client, requests_mock):
    """
        Given:
        - A successful mock http request response with 2 events and offset context.
        When:
        - Calling get_events_from_akamai().
        Then:
        - Ensure the right log type and text returned. And the right length of events, offset, and counter returned.
    """
    response_mock = '{"id": 1, "httpMessage": {"start": 1}}\n{"id": 2, "httpMessage": {"start": 2}}\n{"offset": "a"}'
    demisto_info = mocker.patch.object(demisto, 'info')
    requests_mock.get(f"{BASE_URL}/50170?limit=100&offset=test_offset", text=response_mock)
    async for events, counter, response_offset in Akamai_SIEM.get_events_from_akamai(client=client,
                                                                                     config_ids="50170",
                                                                                     from_time="1 day",
                                                                                     page_size=100,
                                                                                     offset="test_offset",
                                                                                     max_concurrent_tasks=300):
        assert counter == 1
        assert len(events) == 2
        assert response_offset == "a"
        demisto_info.assert_called_with("Running in interval = 1. got 2 events and offset='a'.")
        break


@pytest.mark.asyncio
async def test_get_events_from_akamai_failure(mocker, client, requests_mock):
    """
        Given:
        - An error mock http response.
        When:
        - Calling get_events_from_akamai().
        Then:
        - Ensure the right log type and text returned.
    """
    requests_mock.get(f"{BASE_URL}/50170?limit=100&offset=test_offset", status_code=416, text="Requested Range Not Satisfiable")
    mocker.patch.object(demisto, 'error')
    # cause an exception to break endless loop.
    update_module_health = mocker.patch.object(demisto, 'updateModuleHealth', side_effect=Exception("Interrupted execution"))
    with pytest.raises(Exception) as e:
        async for _, _, _ in Akamai_SIEM.get_events_from_akamai(client=client,
                                                                config_ids="50170",
                                                                from_time="1 day",
                                                                page_size=100,
                                                                offset="test_offset",
                                                                max_concurrent_tasks=300):
            pass
    assert str(e.value) == "Interrupted execution"  # Ensure the exception indeed was the planned one.
    expected_error_msg = "Running in interval = 1. Got offset out of range error when attempting to fetch events from Akamai.\n" \
        "This occurred due to offset pointing to events older than 12 hours which isn't supported by akamai.\nRestarting" \
        " fetching events to start from 1 day ago. For more information, please refer to the Troubleshooting section in the" \
        " integration documentation.\noriginal error: [Error in API call [416] - None\nRequested Range Not Satisfiable]"

    assert expected_error_msg in update_module_health.mock_calls[0][1]
    assert {'is_error': True} in update_module_health.mock_calls[0]


@pytest.mark.asyncio
async def test_get_events_from_akamai_no_events(mocker, client, requests_mock):
    """
        Given:
        - A successful mock http response with no events.
        When:
        - Calling get_events_from_akamai().
        Then:
        - Ensure the right log type and text returned.
    """
    response_mock = '{"offset": "a"}'
    requests_mock.get(f"{BASE_URL}/50170?limit=100&offset=test_offset", text=response_mock)
    demisto_debug = mocker.patch.object(demisto, 'debug')
    # cause an exception to break endless loop.
    mocker.patch.object(asyncio, 'sleep', side_effect=Exception("Interrupted execution"))
    with pytest.raises(Exception) as e:
        async for _, _, _ in Akamai_SIEM.get_events_from_akamai(client=client,
                                                                config_ids="50170",
                                                                from_time="1 day",
                                                                page_size=100,
                                                                offset="test_offset",
                                                                max_concurrent_tasks=300):
            pass
    assert str(e.value) == "Interrupted execution"  # Ensure the exception indeed was the planned one.
    demisto_debug.assert_called_with("Running in interval = 1. No events were received from Akamai,going"
                                     " to sleep for 60 seconds.")


@pytest.mark.asyncio
async def test_process_and_send_events_to_xsiam_skip_events_decoding(mocker):
    """
        Given:
        - 2 non serialized events
        When:
        - Calling process_and_send_events_to_xsiam() with should_skip_decode_events=True.
        Then:
        - Ensure the events were not modified, and the right logs were printed.
    """
    requestHeaders = "Content-Type%3A%20application/json%3Bcharset%3DUTF-8%0Auser%3A%20test%40test.com%0Aclient%3A%20"
    "test_client%0AX-Kong-Upstream-Latency%3A%2066%0AX-Kong-Proxy-Latency%3A%202%0AX-Kong-Request-Id%3A%20X_request_id%"
    "0AEPM-Request-ID%3A%20EPM_request_id%0AContent-Length%3A%20157%0ADate%3A%20Mon%2C%2025%20Mar%202024%2013%3A52%3A11"
    "%20GMT%0AConnection%3A%20keep-alive%0AServer-Timing%3A%20cdn-cache%3B%20desc%3DMISS%0AServer-Timing%3A%20edge%3B"
    "%20dur%3D23%0AServer-Timing%3A%20origin%3B%20dur%3D72%0AServer-Timing%3A%20intid%3Bdesc%3Ddd%0A"
    "Strict-Transport-Security%3A%20max-age%3D31536000%20%3B%20includeSubDomains%20%3B%20preload%0A"
    events = [f'{{"id": 1, "httpMessage": {{"start": 1591303422, "requestHeaders": "{requestHeaders}"}}}}',
              f'{{"id": 2, "httpMessage": {{"start": 1591303422, "requestHeaders": "{requestHeaders}"}}}}']
    demisto_info = mocker.patch.object(demisto, 'info')
    send_events_to_xsiam_akamai = mocker.patch("Akamai_SIEM.send_events_to_xsiam_akamai",
                                               side_effect=Exception("Interrupted execution"))  # to break endless loop.
    with pytest.raises(Exception) as e:
        await Akamai_SIEM.process_and_send_events_to_xsiam(events, should_skip_decode_events=True, offset="test", counter=1)
    assert str(e.value) == "Interrupted execution"  # Ensure the exception indeed was the planned one.
    assert send_events_to_xsiam_akamai.call_args_list[0][0][0] == events
    assert isinstance(send_events_to_xsiam_akamai.call_args_list[0][0][0][0], str)
    demisto_info.assert_has_calls([
        mocker.call(f"Running in interval = 1. got {len(events)} events, moving to processing events data."),
        mocker.call("Running in interval = 1. Skipping decode events."),
        mocker.call(f"Running in interval = 1. Sending {len(events)} events to xsiam. "
                    "latest event time is: 2020-06-04T20:43:42Z")
    ])


@pytest.mark.asyncio
async def test_process_and_send_events_to_xsiam_with_events_decoding(mocker):
    """
        Given:
        - 2 non serialized events
        When:
        - Calling process_and_send_events_to_xsiam() with should_skip_decode_events=False.
        Then:
        - Ensure the events were loaded decoded correctly, and the right logs were printed.
    """
    requestHeaders = "Content-Type%3A%20application/json%3Bcharset%3DUTF-8%0Auser%3A%20test%40test.com%0Aclient%3A%20"
    "test_client%0AX-Kong-Upstream-Latency%3A%2066%0AX-Kong-Proxy-Latency%3A%202%0AX-Kong-Request-Id%3A%20X_request_id%"
    "0AEPM-Request-ID%3A%20EPM_request_id%0AContent-Length%3A%20157%0ADate%3A%20Mon%2C%2025%20Mar%202024%2013%3A52%3A11"
    "%20GMT%0AConnection%3A%20keep-alive%0AServer-Timing%3A%20cdn-cache%3B%20desc%3DMISS%0AServer-Timing%3A%20edge%3B"
    "%20dur%3D23%0AServer-Timing%3A%20origin%3B%20dur%3D72%0AServer-Timing%3A%20intid%3Bdesc%3Ddd%0A"
    "Strict-Transport-Security%3A%20max-age%3D31536000%20%3B%20includeSubDomains%20%3B%20preload%0A"
    events = [f'{{"id": 1, "httpMessage": {{"start": 1491303422, "requestHeaders": "{requestHeaders}"}}}}',
              f'{{"id": 2, "httpMessage": {{"start": 1591303422, "requestHeaders": "{requestHeaders}"}}}}']
    demisto_info = mocker.patch.object(demisto, 'info')
    send_events_to_xsiam_akamai = mocker.patch("Akamai_SIEM.send_events_to_xsiam_akamai",
                                               side_effect=Exception("Interrupted execution"))  # to break endless loop.
    with pytest.raises(Exception) as e:
        await Akamai_SIEM.process_and_send_events_to_xsiam(events, should_skip_decode_events=False, offset="test", counter=1)
    assert str(e.value) == "Interrupted execution"  # Ensure the exception indeed was the planned one.
    processed_events = [
        {"id": 1, "httpMessage": {"start": 1491303422, "requestHeaders": {'Content_Type': 'application/json;charset=UTF-8',
                                                                          'user': 'test@test.com', 'client': ''},
                                  "responseHeaders": {}}},
        {"id": 2, "httpMessage": {"start": 1591303422, "requestHeaders": {'Content_Type': 'application/json;charset=UTF-8',
                                                                          'user': 'test@test.com', 'client': ''},
                                  "responseHeaders": {}}}
    ]
    assert send_events_to_xsiam_akamai.call_args_list[0][0][0] == processed_events
    assert isinstance(send_events_to_xsiam_akamai.call_args_list[0][0][0][0], dict)
    demisto_info.assert_has_calls([
        mocker.call(f"Running in interval = 1. got {len(events)} events, moving to processing events data."),
        mocker.call("Running in interval = 1. decoding events."),
        mocker.call(f"Running in interval = 1. Sending {len(events)} events to xsiam. "
                    "latest event time is: 2020-06-04T20:43:42Z")
    ])


@pytest.mark.asyncio
@pytest.mark.filterwarnings("ignore::RuntimeWarning")
async def test_fetch_events_long_running_command_flow(mocker, client):
    """
        Given:
        - 2 mock response for 2 consecutive requests, one with 2 events, and one with 1 event.
        When:
        - Calling fetch_events_long_running_command() with page_size=2.
        Then:
        - Ensure the events were fetched and moved to send_events_to_xsiam as expected.
        The send_events_to_xsiam_akamai function was called once and the 2 requests were sent.
        The execution went into sleep after the second request as there were less the limit events to fetch.
        The right log was printed.
    """
    from Akamai_SIEM import Client
    requestHeaders = "Content-Type%3A%20application/json%3Bcharset%3DUTF-8%0Auser%3A%20test%40test.com%0Aclient%3A%20"
    "test_client%0AX-Kong-Upstream-Latency%3A%2066%0AX-Kong-Proxy-Latency%3A%202%0AX-Kong-Request-Id%3A%20X_request_id%"
    "0AEPM-Request-ID%3A%20EPM_request_id%0AContent-Length%3A%20157%0ADate%3A%20Mon%2C%2025%20Mar%202024%2013%3A52%3A11"
    "%20GMT%0AConnection%3A%20keep-alive%0AServer-Timing%3A%20cdn-cache%3B%20desc%3DMISS%0AServer-Timing%3A%20edge%3B"
    "%20dur%3D23%0AServer-Timing%3A%20origin%3B%20dur%3D72%0AServer-Timing%3A%20intid%3Bdesc%3Ddd%0A"
    "Strict-Transport-Security%3A%20max-age%3D31536000%20%3B%20includeSubDomains%20%3B%20preload%0A"
    event_1 = f'{{"id": 1, "httpMessage": {{"start": 1, "requestHeaders": "{requestHeaders}"}}}}'
    event_2 = f'{{"id": 2, "httpMessage": {{"start": 2, "requestHeaders": "{requestHeaders}"}}}}'
    event_3 = f'{{"id": 3, "httpMessage": {{"start": 3, "requestHeaders": "{requestHeaders}"}}}}'
    response_mock_1 = f'{event_1}\n{event_2}\n{{"offset": "a"}}'
    response_mock_2 = f'{event_3}\n{{"offset": "b"}}'
    execution_count = 0

    def count_execution(*args, **kwargs):
        nonlocal execution_count
        execution_count += 1
        if execution_count == 1:
            return response_mock_1
        else:
            return response_mock_2
    mocker.patch.object(Client, '_http_request', side_effect=count_execution)

    async def mock_func():
        return 2
    demisto_debug = mocker.patch.object(demisto, 'debug')
    send_events_to_xsiam_akamai = mocker.patch("Akamai_SIEM.send_events_to_xsiam_akamai",
                                               side_effect=asyncio.create_task(mock_func()))  # to break endless loop.
    mocker.patch.object(asyncio, "sleep", side_effect=Exception("Interrupted execution"))  # to break endless loop.
    with pytest.raises(Exception) as e:
        await Akamai_SIEM.fetch_events_long_running_command(client, "5 minutes", 2, "50170", {}, True, 5)
    assert str(e.value) == "Interrupted execution"  # Ensure the exception indeed was the planned one.
    assert send_events_to_xsiam_akamai.call_count == 1
    assert execution_count == 2
    assert send_events_to_xsiam_akamai.call_args_list[0][0][0] == [event_1, event_2]
    demisto_debug.assert_called_with(
        'Running in interval = 2. got 1 events which is less than 0.95 % of the page_size=2, going to sleep for 60 seconds.')
