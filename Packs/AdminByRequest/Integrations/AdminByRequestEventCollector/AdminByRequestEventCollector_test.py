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
    set_event_type_fetch_limit,
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
    def test_validate_fetch_events_params(self, input_params: tuple[dict, EventType, bool],
                                          expected_results: tuple[dict, str, str]) -> None:
        results = validate_fetch_events_params(*input_params)
        assert results == expected_results

    case1_set_event_type_fetch_limit = (
        {"event_types_to_fetch": ["Auditlog", "Events", "Requests"], "max_auditlog_per_fetch": 50000,
         "max_events_per_fetch": 50000, "max_requests_per_fetch": 5000}, 3, (50000, 50000, 5000))
    case2_set_event_type_fetch_limit = (
        {"event_types_to_fetch": ["Auditlog", "Events"], "max_auditlog_per_fetch": 50000,
         "max_events_per_fetch": 50000, "max_requests_per_fetch": 5000}, 2, (50000, 50000))
    case3_set_event_type_fetch_limit = (
        {"event_types_to_fetch": ["Auditlog", "Requests"], "max_auditlog_per_fetch": 50000,
         "max_events_per_fetch": 10, "max_requests_per_fetch": 10}, 2, (50000, 10))
    case4_set_event_type_fetch_limit = (
        {"event_types_to_fetch": [], "max_auditlog_per_fetch": 50000,
         "max_events_per_fetch": 50000, "max_requests_per_fetch": 5000}, 0, ())

    @pytest.mark.parametrize(
        "input_params, expected_len, expected_limits",
        [
            case1_set_event_type_fetch_limit,
            case2_set_event_type_fetch_limit,
            case3_set_event_type_fetch_limit,
            case4_set_event_type_fetch_limit
        ]
    )
    def test_set_event_type_fetch_limit(self, input_params: Dict[str, Any], expected_len: int,
                                        expected_limits: tuple[int, int, int]) -> None:
        event_types = set_event_type_fetch_limit(input_params)
        assert len(event_types) == expected_len
        for i in range(expected_len):
            assert event_types[i].max_fetch == expected_limits[i]

class TestFetchEvents:
    pass

