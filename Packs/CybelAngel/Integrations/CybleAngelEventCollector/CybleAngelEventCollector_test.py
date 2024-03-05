"""Base Integration for Cortex XSOAR - Unit Tests file

Pytest Unit Tests: all funcion names must start with "test_"

More details: https://xsoar.pan.dev/docs/integrations/unit-testing

MAKE SURE YOU REVIEW/REPLACE ALL THE COMMENTS MARKED AS "TODO"

You must add at least a Unit Test function for every XSOAR command
you are implementing with your integration
"""

import json
import io
import random

import dateparser
from CybleAngelEventCollector import DATE_FORMAT, Client
from CommonServerPython import *
import pytest


TEST_URL = "https://test.com/api"

@pytest.fixture()
def client() -> Client:
    return Client(
        url=TEST_URL,
        account_id="1234",
        username="test",
        password="test",
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

    def expired_token_http_request_side_effect(
        self, method: str, url_suffix: str, params: Dict | None = None, **kwargs
    ):
        if method == "GET" and url_suffix == "/api/v2/reports":
            if self.num_of_calls == 0:
                self.num_of_calls += 1
                return create_mocked_response([], status_code=401)
            start_date = params.get("start-date")
            events = create_events(1, amount_of_events=self.num_of_events, start_date=start_date)
            return create_mocked_response(events)


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

    # send_events_mocker = mocker.patch.object(CybleAngelEventCollector, 'send_events_to_xsiam')
    # set_last_run_mocker = mocker.patch.object(demisto, 'setLastRun', return_value={})
    # mocker.patch.object(demisto, 'getLastRun', return_value={})
    demisto_results_mocker = mocker.patch.object(demisto, 'results')
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
    assert demisto_results_mocker.call_args[0][0] == "ok"

