import pytest
from demisto_sdk.commands.common.handlers import JSON_Handler
from CommonServerPython import *
from freezegun import freeze_time

import json

MOCK_BASEURL = "https://example.com"
MOCK_API = "api_key"

from AdminByRequestEventCollector import (
    Client,
    EventType,
    remove_first_run_params,
    validate_fetch_events_params,
    EVENT_TYPES
)


@pytest.fixture
def client():
    """
    A dummy client fixture for testing.
    """
    return Client(
        base_url=MOCK_BASEURL,
        api_key=MOCK_API,
        verify=False,
        use_proxy=False,
    )


def util_load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


class TestHelperFunction:
    audit_log_event = EVENT_TYPES["Auditlog"]
    events_event = EVENT_TYPES["Events"]
    requests_event = EVENT_TYPES["Requests"]

    @pytest.mark.parametrize(
        "input_params, expected_params",
        [
            ({"startdate": "2024-01-01", "enddate": "2024-01-31", "other": 1}, {"other": 1}),
            ({"startdate": "2024-01-01", "other": 1}, {"other": 1}),
            ({"enddate": "2024-01-31", "other": 1}, {"other": 1}),
            ({"other": 1}, {"other": 1}),
            # Case 5: empty dict
            ({}, {}),
        ]
    )
    def test_remove_first_run_params(self, input_params: Dict[str, Any], expected_params: Dict[str, Any]):
        # make a copy to avoid modifying original test data
        params_copy = input_params.copy()
        remove_first_run_params(params_copy)
        assert params_copy == expected_params

    result_param = {"startid": 1, "take": 1}

    case1_validate_fetch_events_params = (({"start_id_auditlog": 1}, audit_log_event, False),
                                          ({
                                               **audit_log_event.default_params,
                                               **result_param
                                           }, "auditlog", "start_id_auditlog"))
    case2_validate_fetch_events_params = (({"start_id_events": 1}, events_event, False),
                                          ({
                                               **events_event.default_params,
                                               **result_param
                                           }, "events", "start_id_events"))
    case3_validate_fetch_events_params = (({"start_id_requests": 1}, requests_event, False),
                                          ({
                                               **requests_event.default_params,
                                               **result_param
                                           }, "requests", "start_id_requests"))

    # cases where we dont have key then use date 2025-01-01 01:00:00
    date_params = {"startdate": "2025-01-01", "enddate": "2025-01-01"}
    result_param_no_start_id = {"take": 1}


    case4_validate_fetch_events_params = (({}, audit_log_event, False),
                                          ({
                                               **date_params,
                                               **result_param_no_start_id
                                           }, "auditlog", "start_id_auditlog"))
    case5_validate_fetch_events_params = (({}, events_event, False),
                                          ({
                                               **date_params,
                                               **result_param_no_start_id
                                           }, "events", "start_id_events"))
    case6_validate_fetch_events_params = (({}, requests_event, False),
                                          ({
                                               **requests_event.default_params,
                                               **result_param_no_start_id
                                           }, "requests", "start_id_requests"))

    # cases where we dont have key then use date 2025-01-01 01:00:00
    last_run_start_date = {"startdate": "2025-01-01"}

    # using
    case7_validate_fetch_events_params = ((last_run_start_date, audit_log_event, True),
                                          ({
                                               **last_run_start_date,
                                               **result_param_no_start_id
                                           }, "auditlog", "start_id_auditlog"))

    @pytest.mark.parametrize(
        "input_params, expected_results",
        [
            case1_validate_fetch_events_params,
            case2_validate_fetch_events_params,
            case3_validate_fetch_events_params,
            case4_validate_fetch_events_params,
            case5_validate_fetch_events_params,
            case6_validate_fetch_events_params,
            case7_validate_fetch_events_params,
        ]
    )
    @freeze_time("2025-01-01 01:00:00")
    def test_validate_fetch_events_params(self, input_params: tuple[dict, EventType, bool], expected_results: tuple[dict, str, str]):
        results = validate_fetch_events_params(*input_params)
        assert results == expected_results

# TODO: ADD HERE unit tests for every command
