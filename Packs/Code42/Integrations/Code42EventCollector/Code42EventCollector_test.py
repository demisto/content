from unittest.mock import MagicMock

import requests_toolbelt.sessions

from CommonServerPython import *


TEST_URL = "https://test.com"


def create_mocked_response(response: List[Dict] | Dict, status_code: int = 200) -> requests.Response:
    mocked_response = requests.Response()
    mocked_response._content = json.dumps(response).encode('utf-8')
    mocked_response.status_code = status_code
    return mocked_response


# class HttpRequestsMocker:
#
#     def __init__(self, num_of_events: int):
#         self.num_of_events = num_of_events
#         self.num_of_calls = 0
#
#     def valid_http_request_side_effect(self, method: str, url_suffix: str = "", params: Dict | None = None, **kwargs):
#         mocker.patch.object(Session, "get", return_value="bla")
#         if method == "GET" and url_suffix == "/api/v2/reports":
#             start_date = params.get("start-date")
#             events = create_events(1, amount_of_events=self.num_of_events, start_date=start_date)
#             return create_mocked_response(events)
#         if method == "POST" and kwargs.get("full_url") == "https://auth.cybelangel.com/oauth/token":
#             return {"access_token": "new_access_token"}
#         return None


def test_the_test_module(mocker):
    from requests import Session
    import Code42EventCollector

    return_results_mocker: MagicMock = mocker.patch.object(Code42EventCollector, 'return_results')
    mocker.patch.object(
        demisto,
        'params',
        return_value={
            "url": TEST_URL,
            "credentials": {
                "identifier": "1234",
                "password": "1234",
            },
        }
    )
    mocker.patch.object(demisto, 'command', return_value='test-module')

    mocker.patch.object(requests_toolbelt.sessions.BaseUrlSession, "request", return_value=create_mocked_response(response=[]))

    mocker.patch.object(
        Session,
        "get",
        return_value="ok"
    )

    Code42EventCollector.main()
    assert return_results_mocker.called
    assert return_results_mocker.call_args[0][0] == "ok"
