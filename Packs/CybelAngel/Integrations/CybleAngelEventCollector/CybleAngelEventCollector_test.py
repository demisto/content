"""Base Integration for Cortex XSOAR - Unit Tests file

Pytest Unit Tests: all funcion names must start with "test_"

More details: https://xsoar.pan.dev/docs/integrations/unit-testing

MAKE SURE YOU REVIEW/REPLACE ALL THE COMMENTS MARKED AS "TODO"

You must add at least a Unit Test function for every XSOAR command
you are implementing with your integration
"""

import json
import random

from unittest.mock import MagicMock
from CybleAngelEventCollector import DATE_FORMAT, Client
from CommonServerPython import *
import pytest


TEST_URL = "https://test.com/api"


@pytest.fixture()
def client() -> Client:
    return Client(
        TEST_URL,
        client_id="1234",
        client_secret="1234",
        verify=False,
        proxy=False,
    )


class HttpRequestsMocker:

    def __init__(self, num_of_events: int):
        self.num_of_events = num_of_events
        self.num_of_calls = 0

    def valid_http_request_side_effect(self, method: str, url_suffix: str, params: Dict | None = None, **kwargs):
        if method == "GET" and url_suffix == "/api/v2/reports":
            start_date = params.get("start-date")
            events = create_events(1, amount_of_events=self.num_of_events, start_date=start_date)
            return create_mocked_response(events)
        return None

    def expired_token_http_request_side_effect(
        self, method: str, url_suffix: Optional[str] = None, params: Dict | None = None, **kwargs
    ):
        if method == "GET" and url_suffix == "/api/v2/reports":
            if self.num_of_calls == 0:
                self.num_of_calls += 1
                return create_mocked_response([], status_code=401)
            start_date = params.get("start-date")
            return create_events(1, amount_of_events=self.num_of_events, start_date=start_date)
        if method == "POST" and kwargs.get("full_url") == "https://auth.cybelangel.com/oauth/token":
            return {"access_token": "new_access_token"}
        return None


def create_events(start_id: int, amount_of_events: int, start_date: str) -> Dict[str, List[Dict]]:
    events = [
        {
            "id": i,
            "created_at": (dateparser.parse(start_date) + timedelta(seconds=i)).strftime(DATE_FORMAT)
        }
        for i in range(start_id, start_id + amount_of_events)
    ]
    random.shuffle(events)
    return {"reports": events}


def create_mocked_response(response: List[Dict] | Dict, status_code: int = 200) -> requests.Response:
    mocked_response = requests.Response()
    mocked_response._content = json.dumps(response).encode('utf-8')
    mocked_response.status_code = status_code
    return mocked_response


def test_http_request_token_expired(client: Client, mocker):
    """
    Given:
     - expired token from integration context

    When:
     - retrieving events by a http-request

    Then:
     - make sure token is replaced with a new access token
     - make sure events are still returned even when token has expired
    """
    http_mocker = HttpRequestsMocker(1)
    mocker.patch.object(client, "_http_request", side_effect=http_mocker.expired_token_http_request_side_effect)
    mocker.patch.object(demisto, 'getIntegrationContext', return_value={"access_token": "old_access_token"})
    set_integration_context_mocker: MagicMock = mocker.patch.object(demisto, "setIntegrationContext")

    result = client.http_request(method="GET", url_suffix="/api/v2/reports", params={"start-date": "2021-01-10T00:00:00"})
    events = result["reports"]
    assert len(events) == 1
    assert set_integration_context_mocker.call_args[0][0] == {'access_token': 'new_access_token'}


def test_the_test_module(mocker):
    """
    Given:
     - valid credentials

    When:
     - running the test-module

    Then:
     - make sure "ok" is returned
    """
    import CybleAngelEventCollector

    demisto_results_mocker: MagicMock = mocker.patch.object(demisto, 'results')
    mocker.patch.object(
        demisto, 'params',
        return_value={
            "url": TEST_URL,
            "credentials": {
                "identifier": "1234",
                "password": "1234",
            },
            "max_fetch": 100
        }
    )
    mocker.patch.object(demisto, 'command', return_value='test-module')

    http_mocker = HttpRequestsMocker(100)

    mocker.patch.object(
        CybleAngelEventCollector.Client,
        "_http_request",
        side_effect=http_mocker.valid_http_request_side_effect
    )

    CybleAngelEventCollector.main()
    assert demisto_results_mocker.called
    assert demisto_results_mocker.call_args[0][0] == "ok"


def test_fetch_events_no_last_run(mocker):
    """
    Given:
     - no last run (first time of the fetch)

    When:
     - running the fetch-events

    Then:
     - make sure events are sent into xsiam
     - make sure all the 100 events are fetched
     - make sure last run is updated
    """
    import CybleAngelEventCollector

    send_events_mocker: MagicMock = mocker.patch.object(CybleAngelEventCollector, 'send_events_to_xsiam')
    set_last_run_mocker: MagicMock = mocker.patch.object(demisto, 'setLastRun', return_value={})
    mocker.patch.object(demisto, 'getLastRun', return_value={})
    mocker.patch.object(
        demisto, 'params',
        return_value={
            "url": TEST_URL,
            "credentials": {
                "identifier": "1234",
                "password": "1234",
            },
            "max_fetch": 100
        }
    )

    mocker.patch.object(demisto, 'command', return_value='fetch-events')

    http_mocker = HttpRequestsMocker(100)

    mocker.patch.object(
        CybleAngelEventCollector.Client,
        "_http_request",
        side_effect=http_mocker.valid_http_request_side_effect
    )

    CybleAngelEventCollector.main()
    assert send_events_mocker.called
    fetched_events = send_events_mocker.call_args[0][0]
    assert len(fetched_events) == 100
    for i in range(1, 101):
        assert fetched_events[i - 1]["id"] == i

    assert set_last_run_mocker.called
    last_run = set_last_run_mocker.call_args[0][0]
    assert last_run[CybleAngelEventCollector.LastRun.LATEST_REPORT_TIME] == fetched_events[-1]["created_at"]
    assert last_run[CybleAngelEventCollector.LastRun.LATEST_FETCHED_REPORTS][0]["id"] == fetched_events[-1]["id"]


def test_fetch_events_token_expired(mocker):
    """
    Given:
     - token that has expired

    When:
     - running the fetch-events

    Then:
     - make sure events are sent into xsiam
     - make sure all the 100 events are fetched
     - make sure last run is updated
     - make sure the new access token is getting into the integration context
    """
    import CybleAngelEventCollector

    send_events_mocker: MagicMock = mocker.patch.object(CybleAngelEventCollector, 'send_events_to_xsiam')
    set_last_run_mocker: MagicMock = mocker.patch.object(demisto, 'setLastRun', return_value={})
    mocker.patch.object(demisto, 'getLastRun', return_value={})
    mocker.patch.object(
        demisto, 'params',
        return_value={
            "url": TEST_URL,
            "credentials": {
                "identifier": "1234",
                "password": "1234",
            },
            "max_fetch": 100
        }
    )
    mocker.patch.object(demisto, 'command', return_value='fetch-events')
    mocker.patch.object(demisto, 'getIntegrationContext', return_value={"access_token": "old_access_token"})
    set_integration_context_mocker: MagicMock = mocker.patch.object(demisto, "setIntegrationContext")

    http_mocker = HttpRequestsMocker(100)

    mocker.patch.object(
        CybleAngelEventCollector.Client,
        "_http_request",
        side_effect=http_mocker.expired_token_http_request_side_effect
    )

    CybleAngelEventCollector.main()
    assert send_events_mocker.called
    fetched_events = send_events_mocker.call_args[0][0]
    assert len(fetched_events) == 100
    for i in range(1, 101):
        assert fetched_events[i - 1]["id"] == i

    assert set_last_run_mocker.called
    last_run = set_last_run_mocker.call_args[0][0]
    assert last_run[CybleAngelEventCollector.LastRun.LATEST_REPORT_TIME] == fetched_events[-1]["created_at"]
    assert last_run[CybleAngelEventCollector.LastRun.LATEST_FETCHED_REPORTS][0]["id"] == fetched_events[-1]["id"]

    assert set_integration_context_mocker.call_args[0][0] == {'access_token': 'new_access_token'}