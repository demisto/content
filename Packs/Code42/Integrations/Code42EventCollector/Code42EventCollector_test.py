import json
from unittest.mock import MagicMock

import requests_toolbelt.sessions

from CommonServerPython import *


TEST_URL = "https://test.com"


def create_mocked_response(response: List[Dict] | Dict, status_code: int = 200) -> requests.Response:
    mocked_response = requests.Response()
    mocked_response._content = json.dumps(response).encode('utf-8')
    mocked_response.status_code = status_code
    return mocked_response


class HttpRequestsMocker:

    def __init__(self, num_of_audit_logs: int = 0, num_of_file_events: int = 0):
        self.num_of_audit_logs = num_of_audit_logs
        self.num_of_file_events = num_of_file_events
        self.fetched_audit_logs = 0
        self.fetched_file_events = 0

    def valid_http_request_side_effect(self, method: str, url: str, *args, **kwargs):
        if method == "POST" and "v1/oauth" in url:
            return create_mocked_response(
                response={
                    "access_token": "1234",
                    "token_type": "bearer",
                    "expires_in": 10000000
                }
            )

        if method == "POST" and "/v1/audit/search-audit-log" in url:
            return create_mocked_response(
                response={
                    "events": []
                }
            )

        if method == "POST" and "/v2/file-events" in url:
            return create_mocked_response(
                response={
                    "fileEvents": []
                }
            )


def test_the_test_module(mocker):
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

    mocker.patch.object(
        requests_toolbelt.sessions.BaseUrlSession,
        "request",
        side_effect=HttpRequestsMocker().valid_http_request_side_effect
    )

    Code42EventCollector.main()
    assert return_results_mocker.called
    assert return_results_mocker.call_args[0][0] == "ok"
