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
    fetch_events_list,
    fetch_events,
    get_events,
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
    event_requests = EVENT_TYPES["Requests"]
    event_events = EVENT_TYPES["Events"]
    event_audit = EVENT_TYPES["Auditlog"]

    raw_detections_audit = util_load_json("test_data/auditlogs_response.json")
    raw_detections_events = util_load_json("test_data/events_response.json")
    raw_detections_requests = util_load_json("test_data/requests_response.json")

    def test_fetch_events_update_last_run(self, client, mocker):
        """
        Given: A mock raw response containing audit logs.
        When: fetching events.
        Then: Make sure that the last run object was updated as expected
        """
        self.event_audit.max_fetch = 3
        raw_detections = self.raw_detections_audit
        mocker.patch("AdminByRequestEventCollector.Client.retrieve_from_api", return_value=raw_detections)
        last_run = {}

        output = fetch_events_list(client, last_run=last_run, event_type=self.event_audit, use_last_run_as_params=False)

        assert len(output) == 3
        assert last_run.get("start_id_auditlog") == raw_detections[-1]["id"] + 1

    def test_fetch_events_update_last_run_with_old_params(self, client, mocker):
        """
        Given: A mock raw response containing audit logs.
        When: fetching events.
        Then: Make sure that the last run object was updated as expected
        """
        self.event_audit.max_fetch = 3
        raw_detections = self.raw_detections_audit
        mocker.patch("AdminByRequestEventCollector.Client.retrieve_from_api", return_value=raw_detections)
        last_run = {"start_id_auditlog": 1, "start_id_events": 1, "start_id_requests": 1}

        output = fetch_events_list(client, last_run=last_run, event_type=self.event_audit, use_last_run_as_params=False)

        assert len(output) == 3
        assert last_run.get("start_id_auditlog") == raw_detections[-1]["id"] + 1
        assert last_run.get("start_id_events") == 1
        assert last_run.get("start_id_requests") == 1

    def test_fetch_response_bigger_then_limit(self, client, mocker):
        """
        Given: A mock raw response containing audit logs.
        When: fetching events.
        Then: Make sure that the last run object was updated as expected
        """
        self.event_events.max_fetch = 2
        raw_detections = self.raw_detections_events
        mocker.patch("AdminByRequestEventCollector.Client.retrieve_from_api", return_value=raw_detections)
        last_run = {"start_id_auditlog": 1, "start_id_events": 1, "start_id_requests": 1}

        output = fetch_events_list(client, last_run=last_run, event_type=self.event_events, use_last_run_as_params=False)

        assert len(output) == 2
        assert last_run.get("start_id_events") == raw_detections[-1]["id"]

    def test_fetch_limit_bigger_then_response(self, client, mocker):
        """
        Given: A mock raw response containing audit logs.
        When: fetching events.
        Then: Make sure that the last run object was updated as expected
        """
        self.event_requests.max_fetch = 3
        raw_detections = self.raw_detections_requests[:-1]
        first_response = raw_detections
        second_response = []

        mocker.patch(
            "AdminByRequestEventCollector.Client.retrieve_from_api",
            side_effect=[first_response, second_response]
        )
        last_run = {"start_id_auditlog": 1, "start_id_events": 1, "start_id_requests": 1}

        output = fetch_events_list(client, last_run=last_run, event_type=self.event_requests, use_last_run_as_params=False)

        assert len(output) == len(raw_detections)
        assert last_run.get("start_id_requests") == raw_detections[-1]["id"] + 1

    def test_fetch_all_types(self, client, mocker):
        """
        Given: A mock raw response containing audit logs.
        When: fetching events.
        Then: Make sure that the last run object was updated as expected
        """
        self.event_requests.max_fetch = 3
        self.event_events.max_fetch = 3
        self.event_audit.max_fetch = 3

        raw_detections = (
            self.raw_detections_audit +
            self.raw_detections_events +
            self.raw_detections_requests
        )

        first_response = self.raw_detections_audit
        second_response = self.raw_detections_events
        third_response = self.raw_detections_requests

        events_types = [self.event_audit, self.event_events, self.event_requests]

        mocker.patch(
            "AdminByRequestEventCollector.Client.retrieve_from_api",
            side_effect=[first_response, second_response, third_response]
        )

        output, last_run = fetch_events(client, last_run={}, fetch_events_types=events_types,
                                        use_last_run_as_params=False)

        assert len(output) == len(raw_detections)
        assert last_run.get("start_id_auditlog") == self.raw_detections_audit[-1]["id"] + 1
        assert last_run.get("start_id_events") == self.raw_detections_events[-1]["id"] + 1
        assert last_run.get("start_id_requests") == self.raw_detections_requests[-1]["id"] + 1

    def test_fetch_all_types_different_lengths(self, client, mocker):
        """
        Given: A mock raw response containing audit logs.
        When: fetching events.
        Then: Make sure that the last run object was updated as expected
        """
        self.event_audit.max_fetch = 3
        self.event_events.max_fetch = 2
        self.event_requests.max_fetch = 1

        raw_detections = (
            self.raw_detections_audit +
            self.raw_detections_events[:-1] +
            self.raw_detections_requests[:-2]
        )

        first_response = self.raw_detections_audit
        second_response = self.raw_detections_events
        third_response = self.raw_detections_requests

        events_types = [self.event_audit, self.event_events, self.event_requests]

        mocker.patch(
            "AdminByRequestEventCollector.Client.retrieve_from_api",
            side_effect=[first_response, second_response, third_response]
        )

        output, last_run = fetch_events(client, last_run={}, fetch_events_types=events_types,
                                        use_last_run_as_params=False)

        assert len(output) == len(raw_detections)
        assert last_run.get("start_id_auditlog") == self.raw_detections_audit[-1]["id"] + 1
        assert last_run.get("start_id_events") == self.raw_detections_events[-2]["id"] + 1
        assert last_run.get("start_id_requests") == self.raw_detections_requests[-3]["id"] + 1

    def test_fetch_all_types_field_values_audits(self, client, mocker):
        """
        Given: A mock raw response containing audit logs.
        When: fetching events.
        Then: Make sure that the last run object was updated as expected
        """
        self.event_audit.max_fetch = 3
        raw_detections = self.raw_detections_audit
        mocker.patch("AdminByRequestEventCollector.Client.retrieve_from_api", return_value=raw_detections)
        last_run = {}

        output = fetch_events_list(client, last_run=last_run, event_type=self.event_audit, use_last_run_as_params=False)

        for i in range(len(output)):
            assert output[i].get(self.event_audit.time_field) == raw_detections[i]['startTimeUTC']
            assert output[i].get("source_log_type") == self.event_audit.source_log_type

    def test_fetch_all_types_field_values_events(self, client, mocker):
        """
        Given: A mock raw response containing audit logs.
        When: fetching events.
        Then: Make sure that the last run object was updated as expected
        """
        self.event_events.max_fetch = 3
        raw_detections = self.raw_detections_events
        mocker.patch("AdminByRequestEventCollector.Client.retrieve_from_api", return_value=raw_detections)
        last_run = {}

        output = fetch_events_list(client, last_run=last_run, event_type=self.event_events, use_last_run_as_params=False)

        for i in range(len(output)):
            assert output[i].get(self.event_events.time_field) == raw_detections[i]['eventTimeUTC']
            assert output[i].get("source_log_type") == self.event_events.source_log_type

    def test_fetch_all_types_field_values_requests(self, client, mocker):
        """
        Given: A mock raw response containing audit logs.
        When: fetching events.
        Then: Make sure that the last run object was updated as expected
        """
        self.event_requests.max_fetch = 3
        raw_detections = self.raw_detections_requests
        mocker.patch("AdminByRequestEventCollector.Client.retrieve_from_api", return_value=raw_detections)
        last_run = {}

        output = fetch_events_list(client, last_run=last_run, event_type=self.event_requests, use_last_run_as_params=False)

        for i in range(len(output)):
            assert output[i].get(self.event_requests.time_field) == raw_detections[i]['requestTime']
            assert output[i].get("source_log_type") == self.event_requests.source_log_type

    @freeze_time("2025-01-01 01:00:00")
    def test_get_events(self, client, mocker):
        """
        Given: A mock raw response containing audit logs.
        When: fetching events.
        Then: Make sure that the last run object was updated as expected
        """

        raw_detections = self.raw_detections_events[:-1]

        first_response = self.raw_detections_events
        second_response = []

        args = {"limit": 2, "event_type": "Events"}

        mocker.patch(
            "AdminByRequestEventCollector.Client.retrieve_from_api",
            side_effect=[first_response, second_response]
        )

        output = get_events(client, args=args)

        assert len(output.outputs) == len(raw_detections)
        assert output.outputs_prefix == "AdminByRequest." + "Events"
