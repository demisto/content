from urllib.parse import parse_qs, urlparse

import demistomock as demisto
import pytest
import pytz
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from freezegun import freeze_time
from TrendMicroVisionOneEventCollector import (
    DATE_FORMAT,
    DEFAULT_MAX_LIMIT,
    Client,
    LastRunLogsStartTimeFields,
    LogTypes,
    UrlSuffixes,
)

from CommonServerUserPython import *  # noqa

BASE_URL = "https://api.xdr.trendmicro.com"


@pytest.fixture()
def client() -> Client:
    return Client(base_url=BASE_URL, api_key="api-key", proxy=False, verify=True)


class TestHttpRequestRetryPolicy:
    """
    Verifies every HTTP request goes through the retry policy configured in Client.http_request, so
    transient Vision One errors (502/500/503/504, connection drops, read timeouts) get retried instead
    of aborting the whole fetch round and leaving last_run unpersisted.
    """

    @pytest.mark.parametrize(
        "url_suffix,method,next_link",
        [
            (UrlSuffixes.OBSERVED_ATTACK_TECHNIQUES.value, "GET", None),
            (UrlSuffixes.SEARCH_DETECTIONS.value, "GET", None),
            (UrlSuffixes.AUDIT.value, "GET", f"{BASE_URL}/v3.0{UrlSuffixes.AUDIT.value}?next=token"),
        ],
    )
    def test_http_request_forwards_retry_policy(self, mocker, client: Client, url_suffix, method, next_link):
        captured = {}

        def _side_effect(**kwargs):
            captured.update(kwargs)
            return {"items": []}

        mocker.patch.object(BaseClient, "_http_request", side_effect=_side_effect)

        client.http_request(url_suffix=url_suffix, method=method, next_link=next_link)

        assert captured["retries"] == 3
        assert captured["status_list_to_retry"] == (500, 502, 503, 504)
        assert captured["backoff_factor"] == 2
        assert captured["backoff_jitter"] == 1.0


def get_url_params(url: str) -> Dict[str, str]:
    parsed_url = urlparse(url)
    query_parameters = parse_qs(parsed_url.query)
    return {key: value[0] for key, value in query_parameters.items()}


def create_any_type_logs(
    start: int,
    end: int,
    created_time_field: str,
    id_field_name: str,
    last_event_fetch_time: str | None,
    extra_seconds: int = 0,
    ascending_order: bool = False,
):
    """
    Create mocks of any type of log based on multiple parameters
    """
    last_event_fetch_time = last_event_fetch_time or (datetime.now() - timedelta(minutes=1)).strftime(DATE_FORMAT)
    if ascending_order:
        return [
            {
                id_field_name: i,
                created_time_field: (  # type: ignore
                    dateparser.parse(last_event_fetch_time) + timedelta(seconds=i + extra_seconds)  # type: ignore
                ).strftime(DATE_FORMAT)
                if created_time_field != "eventTime"
                else int(
                    (dateparser.parse(last_event_fetch_time) + timedelta(seconds=i + extra_seconds)).timestamp()  # type: ignore
                )
                * 1000,
            }
            for i in range(start + 1, end + 1)
        ]
    # descending order
    return [
        {
            id_field_name: end - i + 1,
            created_time_field: (datetime.now(tz=pytz.utc) - timedelta(seconds=i + start + extra_seconds)).strftime(DATE_FORMAT)
            if created_time_field != "eventTime"
            else int((datetime.now(tz=pytz.utc) - timedelta(seconds=i + start + extra_seconds)).timestamp()) * 1000,
        }
        for i in range(start + 1, end + 1)
    ]


def create_logs_mocks(
    url: str,
    num_of_events: int,
    created_time_field: str,
    id_field_name: str,
    last_event_fetch_time: str | None,
    url_suffix,
    top: int = 10,
    extra_seconds: int = 0,
) -> Dict:
    """
    Create mocks of any type of log, then returns the logs and pagination link if needed to proceed.
    """
    url_params = get_url_params(url)
    top = arg_to_number(url_params.get("top")) or top
    fetched_amount_of_events = arg_to_number(url_params.get("fetchedAmountOfEvents")) or 0

    if fetched_amount_of_events >= num_of_events:
        return {"items": []}

    logs = create_any_type_logs(
        start=fetched_amount_of_events,
        end=min(fetched_amount_of_events + top, num_of_events),
        created_time_field=created_time_field,
        id_field_name=id_field_name,
        last_event_fetch_time=last_event_fetch_time,
        extra_seconds=extra_seconds,
        ascending_order=url_suffix in [UrlSuffixes.AUDIT.value, UrlSuffixes.WORKBENCH.value],
    )
    fetched_amount_of_events += len(logs)

    response = {
        "items": logs,
    }

    if fetched_amount_of_events < num_of_events:
        response["nextLink"] = f"{BASE_URL}/v3.0{url_suffix}?top={top}&fetchedAmountOfEvents={fetched_amount_of_events}"

    return response


def _http_request_side_effect_decorator(
    last_workbench_time: str | None = None,
    last_oat_time: str | None = None,
    last_search_detection_logs: str | None = None,
    last_audit_log_time: str | None = None,
    num_of_workbench_logs: int = 0,
    num_of_oat_logs: int = 0,
    num_of_search_detection_logs: int = 0,
    num_of_audit_logs: int = 0,
):
    """
    general side effect function for creating logs from any type.
    """

    def _http_request_side_effect(**kwargs):
        full_url = kwargs.get("full_url") or ""
        params = kwargs.get("params") or {}
        if UrlSuffixes.WORKBENCH.value in full_url:
            return create_logs_mocks(
                url=full_url,
                num_of_events=num_of_workbench_logs,
                url_suffix=UrlSuffixes.WORKBENCH.value,
                created_time_field="createdDateTime",
                id_field_name="id",
                top=10,
                last_event_fetch_time=last_workbench_time,
            )
        if UrlSuffixes.OBSERVED_ATTACK_TECHNIQUES.value in full_url:
            return create_logs_mocks(
                url=full_url,
                num_of_events=num_of_oat_logs,
                url_suffix=UrlSuffixes.OBSERVED_ATTACK_TECHNIQUES.value,
                created_time_field="detectedDateTime",
                id_field_name="uuid",
                top=params.get("top") or 200,
                last_event_fetch_time=last_oat_time,
            )
        if UrlSuffixes.SEARCH_DETECTIONS.value in full_url:
            return create_logs_mocks(
                url=full_url,
                num_of_events=num_of_search_detection_logs,
                url_suffix=UrlSuffixes.SEARCH_DETECTIONS.value,
                created_time_field="eventTime",
                id_field_name="uuid",
                top=params.get("top") or DEFAULT_MAX_LIMIT,
                last_event_fetch_time=last_search_detection_logs,
            )
        else:
            return create_logs_mocks(
                url=full_url,
                num_of_events=num_of_audit_logs,
                url_suffix=UrlSuffixes.AUDIT.value,
                created_time_field="loggedDateTime",
                id_field_name="loggedUser",
                top=params.get("top") or 200,
                last_event_fetch_time=last_audit_log_time,
            )

    return _http_request_side_effect


def start_freeze_time(timestamp):
    _start_freeze_time = freeze_time(timestamp)
    _start_freeze_time.start()


class TestTopClamping:
    """
    The OAT (top enum: 50/100/200) and Search Detections (ase-top enum: 50/100/500/1000/5000) endpoints only
    accept a fixed set of 'top' (page size) values per the public API schema. Since the fetch-events timeout
    backoff logic (see `fetch_events`) repeatedly halves the fetch limit on timeout, and that limit is used
    directly to build the 'top' request parameter, it can end up computing a value the API rejects. These tests
    make sure the client always sends a schema-valid 'top', regardless of what was requested.
    """

    @pytest.mark.parametrize(
        "requested_top,expected_top",
        [
            (1000, 200),  # above the max valid value -> clamped down to the max
            (200, 200),  # already valid -> unchanged
            (150, 100),  # between valid values -> clamped down to the closest lower valid value
            (10, 50),  # below the min valid value -> clamped up to the min
        ],
    )
    def test_get_observed_attack_techniques_logs_clamps_top(self, mocker, client: Client, requested_top, expected_top):
        captured_params = {}

        def _side_effect(**kwargs):
            captured_params.update(kwargs.get("params") or {})
            return {"items": []}

        mocker.patch.object(BaseClient, "_http_request", side_effect=_side_effect)

        client.get_observed_attack_techniques_logs(
            detected_start_datetime="2023-01-01T00:00:00Z",
            detected_end_datetime="2023-01-02T00:00:00Z",
            top=requested_top,
        )

        assert captured_params["top"] == expected_top

    @pytest.mark.parametrize(
        "requested_top,expected_top",
        [
            (1000, 1000),  # already valid -> unchanged
            (250, 100),  # e.g. a fetch limit of 1000 halved twice by the timeout backoff logic -> not a valid enum value
            (5000000, 5000),  # above the max valid value -> clamped down to the max
            (10, 50),  # below the min valid value -> clamped up to the min
        ],
    )
    def test_get_search_detection_logs_clamps_top(self, mocker, client: Client, requested_top, expected_top):
        captured_params = {}

        def _side_effect(**kwargs):
            captured_params.update(kwargs.get("params") or {})
            return {"items": []}

        mocker.patch.object(BaseClient, "_http_request", side_effect=_side_effect)

        client.get_search_detection_logs(start_datetime="2023-01-01T00:00:00Z", top=requested_top)

        assert captured_params["top"] == expected_top


class TestFetchEvents:
    def test_fetch_events_main_flow_no_new_logs(self, mocker):
        """
        Given:
           - no logs from any kind
           - last_run = {
                'workbench_start_time': '2023-01-01T14:00:00Z',
                'found_workbench_logs': [],
                'oat_detection_start_time': '2023-01-01T14:00:00Z',
                'dedup_found_oat_logs': [],
                'pagination_found_oat_logs': [],
                'oat_detection_next_link': '',
                'search_detection_start_time': '2023-01-01T14:00:00Z',
                'dedup_found_search_detection_logs': [],
                'pagination_found_search_detection_logs': [],
                'search_detection_next_link': '',
                'audit_start_time': '2023-01-01T14:00:00Z',
                'found_audit_logs': []
            }
           - max_fetch = 1000

        When:
           - running fetch-events through the main flow

        Then:
           - make sure no events are returned
           - make sure no last run time remains the same for every log.

        """
        from TrendMicroVisionOneEventCollector import main

        start_freeze_time("2023-01-01T15:00:00Z")

        mocker.patch.object(demisto, "params", return_value={"max_fetch": 1000})
        mocker.patch.object(demisto, "command", return_value="fetch-events")
        mocker.patch.object(
            demisto,
            "getLastRun",
            return_value={
                "workbench_start_time": "2023-01-01T14:00:00Z",
                "found_workbench_logs": [],
                "oat_detection_start_time": "2023-01-01T14:00:00Z",
                "dedup_found_oat_logs": [],
                "pagination_found_oat_logs": [],
                "oat_detection_next_link": "",
                "search_detection_start_time": "2023-01-01T14:00:00Z",
                "dedup_found_search_detection_logs": [],
                "pagination_found_search_detection_logs": [],
                "search_detection_next_link": "",
                "audit_start_time": "2023-01-01T14:00:00Z",
                "found_audit_logs": [],
            },
        )
        mocker.patch.object(
            BaseClient,
            "_http_request",
            side_effect=_http_request_side_effect_decorator(
                last_workbench_time="2023-01-01T14:00:00Z",
                last_audit_log_time="2023-01-01T14:00:00Z",
                last_oat_time="2023-01-01T14:00:00Z",
                last_search_detection_logs="2023-01-01T14:00:00Z",
            ),
        )

        set_last_run_mocker = mocker.patch.object(demisto, "setLastRun")
        send_events_to_xsiam_mocker = mocker.patch("TrendMicroVisionOneEventCollector.send_events_to_xsiam")
        main()

        assert set_last_run_mocker.call_args.args[0] == {
            "workbench_start_time": "2023-01-01T14:00:01Z",
            "found_workbench_logs": [],
            "oat_detection_start_time": "2023-01-01T15:00:00Z",
            "dedup_found_oat_logs": [],
            "pagination_found_oat_logs": [],
            "oat_detection_next_link": "",
            "oat_detection_window_end_time": "",
            "search_detection_start_time": "2023-01-01T15:00:00Z",
            "dedup_found_search_detection_logs": [],
            "pagination_found_search_detection_logs": [],
            "search_detection_next_link": "",
            "search_detection_window_end_time": "",
            "audit_start_time": "2023-01-01T14:00:01Z",
            "found_audit_logs": [],
        }

        assert send_events_to_xsiam_mocker.call_count == 0  # no events fetched -> nothing pushed
        assert not send_events_to_xsiam_mocker.called

    def test_fetch_events_main_flow_no_last_run(self, mocker):
        """
        Given:
           - 1000 workbench + 1000 oat + 500 search detections + 500 audit logs
           - no last run
           - max_fetch = 1000

        When:
           - running fetch-events through the main flow

        Then:
           - make sure last run is correct
           - make sure 3000 logs were sent

        """
        from TrendMicroVisionOneEventCollector import main

        start_freeze_time("2023-01-01T15:00:00Z")

        mocker.patch.object(demisto, "params", return_value={"max_fetch": 1000})
        mocker.patch.object(demisto, "command", return_value="fetch-events")
        mocker.patch.object(demisto, "getLastRun", return_value={})
        mocker.patch.object(
            BaseClient,
            "_http_request",
            side_effect=_http_request_side_effect_decorator(
                num_of_workbench_logs=1500,
                num_of_oat_logs=1500,
                num_of_search_detection_logs=500,
                num_of_audit_logs=500,
                last_workbench_time="2023-01-01T14:00:00Z",
                last_audit_log_time="2023-01-01T14:00:00Z",
            ),
        )

        set_last_run_mocker = mocker.patch.object(demisto, "setLastRun")
        send_events_to_xsiam_mocker = mocker.patch("TrendMicroVisionOneEventCollector.send_events_to_xsiam")
        main()

        assert set_last_run_mocker.call_args.args[0] == {
            "workbench_start_time": "2023-01-01T14:16:40Z",
            "found_workbench_logs": [1000],
            "oat_detection_start_time": "2022-12-29T15:00:00Z",
            "dedup_found_oat_logs": [200],
            "pagination_found_oat_logs": [200],
            "oat_detection_next_link": "https://api.xdr.trendmicro.com/v3.0/oat/detections?top=200&fetchedAmountOfEvents=1000",
            "oat_detection_window_end_time": "2023-01-01T15:00:00Z",
            "search_detection_start_time": "2023-01-01T15:00:00Z",
            "dedup_found_search_detection_logs": [500],
            "pagination_found_search_detection_logs": [],
            "search_detection_next_link": "",
            "search_detection_window_end_time": "",
            "audit_start_time": "2023-01-01T14:08:20Z",
            "found_audit_logs": ["77b363584231085e7909d48e0e103a07b6c10127e00da6e4739f07248eee7682"],
        }

        assert send_events_to_xsiam_mocker.call_count == 4  # one push per log type
        total_sent = sum(len(call.kwargs["events"]) for call in send_events_to_xsiam_mocker.call_args_list)
        # 1000 workbench + 1000 oat + 500 search detections + 500 audit logs
        assert total_sent == 3000

    def test_fetch_events_main_flow_timeout(self, mocker):
        """
        Given:
           - get_observed_attack_techniques_logs times out
           - last_run = {"oat_detection_start_time": "2023-01-01T14:59:59Z", "dedup_found_oat_logs": [1000]}
           - max_fetch = 1000 and log_types = "Observed Attack Techniques"

        When:
           - running fetch-events through the main flow

        Then:
           - Assert last run updated with half max_fetch and nextTrigger 30
           - Assert no events were sent to XSIAM
        """
        from TrendMicroVisionOneEventCollector import main

        mocker.patch.object(demisto, "params", return_value={"max_fetch": 1000, "log_types": ["Observed Attack Techniques"]})
        mocker.patch.object(demisto, "command", return_value="fetch-events")

        last_run = {"oat_detection_start_time": "2023-01-01T14:59:59Z", "dedup_found_oat_logs": [1000]}
        mocker.patch.object(demisto, "getLastRun", return_value=last_run)

        get_observed_attack_techniques_logs_mocker = mocker.patch(
            "TrendMicroVisionOneEventCollector.get_observed_attack_techniques_logs",
            side_effect=SignalTimeoutError,  # assume logic times out and timeout handler in ExecutionTimeout class throws error
        )

        set_last_run_mocker = mocker.patch.object(demisto, "setLastRun")
        send_events_to_xsiam_mocker = mocker.patch("TrendMicroVisionOneEventCollector.send_events_to_xsiam")

        main()

        assert get_observed_attack_techniques_logs_mocker.call_count == 1

        assert set_last_run_mocker.call_args.args[0] == {**last_run, "max_fetch": 500, "nextTrigger": "30"}

        assert send_events_to_xsiam_mocker.call_count == 0  # timeout -> nothing pushed
        assert not send_events_to_xsiam_mocker.called

    def test_fetch_events_one_type_failure_keeps_other_checkpoints(self, mocker):
        """
        Given:
         - multiple log types configured; the Observed Attack Techniques fetch raises an HTTP error
           (non-timeout), simulating a Vision One API failure that survives retries.

        When:
         - running fetch-events through the main flow

        Then:
         - the failing type's checkpoint stays unchanged (not advanced, not lost)
         - the other types still fetch and commit their own checkpoints
         - setLastRun is called (fetch does not abort entirely)
        """
        from TrendMicroVisionOneEventCollector import main

        mocker.patch.object(demisto, "command", return_value="fetch-events")
        mocker.patch.object(
            demisto, "params", return_value={"max_fetch": 1000, "log_types": ["Workbench", "Observed Attack Techniques"]}
        )

        last_run = {
            "workbench_start_time": "2023-01-01T10:00:00Z",
            "found_workbench_logs": [],
            "oat_detection_start_time": "2023-01-01T09:00:00Z",
            "dedup_found_oat_logs": [],
            "pagination_found_oat_logs": [],
            "oat_detection_next_link": "",
        }
        mocker.patch.object(demisto, "getLastRun", return_value=last_run)

        # Workbench succeeds; OAT fails with a transient HTTP error (retries exhausted).
        mocker.patch(
            "TrendMicroVisionOneEventCollector.get_workbench_logs",
            return_value=([{}], {"workbench_start_time": "2023-01-01T11:00:00Z", "found_workbench_logs": [1]}),
        )
        mocker.patch.object(demisto, "error")  # swallow the expected failure log (stdout check in conftest)
        mocker.patch(
            "TrendMicroVisionOneEventCollector.get_observed_attack_techniques_logs",
            side_effect=DemistoException("Error in API call [502]"),
        )

        set_last_run_mocker = mocker.patch.object(demisto, "setLastRun")
        mocker.patch("TrendMicroVisionOneEventCollector.send_events_to_xsiam")

        main()

        saved = set_last_run_mocker.call_args.args[0]
        # Workbench advanced, OAT kept its previous checkpoint.
        assert saved["workbench_start_time"] == "2023-01-01T11:00:00Z"
        assert saved["oat_detection_start_time"] == "2023-01-01T09:00:00Z"
        assert "oat_detection_next_link" in saved

    def test_get_workbench_logs_no_last_run(self, mocker, client: Client):
        """
        Given:
         - no last run
         - limit = 500
         - 1000 workbench events

        When:
         - running get_workbench_logs function

        Then:
         - make sure only 500 events are returned
         - make sure latest workbench event is saved in the workbench_logs_time without adding 1 second to it.
         - make sure in the cache we will have event with 500 id as its the event that happened in the last second.
        """
        from TrendMicroVisionOneEventCollector import get_workbench_logs

        start_freeze_time("2023-01-01T15:00:00Z")

        mocker.patch.object(
            BaseClient, "_http_request", side_effect=_http_request_side_effect_decorator(num_of_workbench_logs=1000)
        )

        workbench_logs, updated_last_run = get_workbench_logs(client=client, first_fetch="1 month ago", last_run={}, limit=500)

        assert len(workbench_logs) == 500
        assert updated_last_run == {
            LastRunLogsStartTimeFields.WORKBENCH.value: "2023-01-01T15:07:20Z",
            "found_workbench_logs": [500],
        }
        assert workbench_logs[-1]["_time"] == "2023-01-01T15:07:20Z"

    def test_get_workbench_logs_with_last_run(self, mocker, client: Client):
        """
        Given:
         - last_run={'workbench_logs_time': '2023-01-01T14:00:00Z', 'found_workbench_logs': [1, 2, 3, 4, 5, 6, 7, 8]}
         - limit = 500
         - 200 workbench events

        When:
         - running get_workbench_logs function

        Then:
         - make sure only 192 events are returned as there are 8 events in cache from last run
         - make sure latest workbench event is saved in the workbench_logs_time without adding 1 second to it.
        """
        from TrendMicroVisionOneEventCollector import get_workbench_logs

        start_freeze_time("2023-01-01T15:00:00Z")

        mocker.patch.object(
            BaseClient,
            "_http_request",
            side_effect=_http_request_side_effect_decorator(
                num_of_workbench_logs=200, last_workbench_time="2023-01-01T14:00:00Z"
            ),
        )

        workbench_logs, updated_last_run = get_workbench_logs(
            client=client,
            first_fetch="1 month ago",
            last_run={
                LastRunLogsStartTimeFields.WORKBENCH.value: "2023-01-01T14:00:00Z",
                "found_workbench_logs": [1, 2, 3, 4, 5, 6, 7, 8],
            },
            limit=500,
        )

        assert len(workbench_logs) == 192
        assert updated_last_run == {
            LastRunLogsStartTimeFields.WORKBENCH.value: "2023-01-01T14:03:20Z",
            "found_workbench_logs": [200],
        }
        assert workbench_logs[-1]["_time"] == "2023-01-01T14:03:20Z"

    def test_get_observed_attack_techniques_logs_no_last_run(self, mocker, client: Client):
        """
        Given:
         - no last run
         - limit = 500
         - 1000 oat events

        When:
         - running get_observed_attack_techniques_logs function

        Then:
         - make sure the pagination chain is not truncated to `limit` mid-way (since the API returns events
           newest-first, truncating an in-progress chain would risk skipping backlog), so more than 500
           events are returned once the fetched page boundary (multiples of 200, the max valid `top`) exceeds it.
         - make sure the checkpoint stays pinned to the window's own start_time while pagination is still
           in progress (next_link is non-empty), instead of jumping ahead based on already-fetched log timestamps.
        """
        from TrendMicroVisionOneEventCollector import get_observed_attack_techniques_logs

        start_freeze_time("2023-01-01T15:00:00Z")

        mocker.patch.object(BaseClient, "_http_request", side_effect=_http_request_side_effect_decorator(num_of_oat_logs=1000))

        observed_attack_techniques_logs, updated_last_run = get_observed_attack_techniques_logs(
            client=client, first_fetch="1 month ago", last_run={}, limit=500
        )

        assert len(observed_attack_techniques_logs) == 600
        assert updated_last_run == {
            "oat_detection_start_time": "2022-12-01T15:00:00Z",
            "dedup_found_oat_logs": [200],
            "pagination_found_oat_logs": [200],
            "oat_detection_next_link": "https://api.xdr.trendmicro.com/v3.0/oat/detections?top=200&fetchedAmountOfEvents=600",
            "oat_detection_window_end_time": "2023-01-01T15:00:00Z",
        }

    def test_get_observed_attack_techniques_logs_with_last_run(self, mocker, client: Client):
        """
        Given:
         - last_run={
                'oat_detection_start_time': '2023-01-01T14:00:00Z',
                'dedup_found_oat_logs': [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
                'pagination_found_oat_logs': [],
                'oat_detection_next_link': f'{BASE_URL}/v3.0{UrlSuffixes.OBSERVED_ATTACK_TECHNIQUES.value}'
                                           f'?top=1000&fetchedAmountOfEvents=100'
            }
         - limit = 500
         - 300 oat events

        When:
         - running get_observed_attack_techniques_logs function

        Then:
         - make sure only 185 events are returned
         - make sure latest observed attack technique event is saved in the oat_detection_logs_time without adding 1 second to it.
        """
        from TrendMicroVisionOneEventCollector import get_observed_attack_techniques_logs

        start_freeze_time("2023-01-01T15:00:00Z")

        mocker.patch.object(
            BaseClient,
            "_http_request",
            side_effect=_http_request_side_effect_decorator(num_of_oat_logs=300, last_oat_time="2023-01-01T14:00:00Z"),
        )

        observed_attack_techniques_logs, updated_last_run = get_observed_attack_techniques_logs(
            client=client,
            first_fetch="1 month ago",
            last_run={
                "oat_detection_start_time": "2023-01-01T14:00:00Z",
                "dedup_found_oat_logs": [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
                "pagination_found_oat_logs": [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
                "oat_detection_next_link": f"{BASE_URL}/v3.0{UrlSuffixes.OBSERVED_ATTACK_TECHNIQUES.value}"
                f"?top=1000&fetchedAmountOfEvents=100",
            },
            limit=500,
        )

        assert len(observed_attack_techniques_logs) == 185
        assert updated_last_run == {
            "oat_detection_start_time": "2023-01-01T14:00:00Z",
            "dedup_found_oat_logs": [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
            "pagination_found_oat_logs": [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
            "oat_detection_next_link": "",
            "oat_detection_window_end_time": "",
        }

    def test_get_observed_attack_techniques_logs_expired_token_mid_pagination_does_not_skip_backlog(self, mocker, client: Client):
        """
        Given:
         - a pagination chain that started long ago (window is [02:00:00, 07:00:00]) is mid-way through
           (last_run_next_link points at a token that has now expired), so the connector must restart
           the query using the ORIGINAL start_time (a checkpoint that must never be skipped forward).
         - the current time (when the restart happens) is much later (2023-01-02T09:00:00Z), simulating a
           connector that has fallen far behind real time.

        When:
         - running get_observed_attack_techniques_logs and getting a "request token expired" error on the
           very first request (the one using the stale next_link)

        Then:
         - the new query must be issued with detectedStartDateTime == the ORIGINAL start time (02:00:00),
           not some later time derived from already-processed log timestamps - otherwise, any backlog
           between the original start and "now" that hasn't been fetched yet would be silently skipped.
        """
        from TrendMicroVisionOneEventCollector import get_observed_attack_techniques_logs

        start_freeze_time("2023-01-02T09:00:00Z")

        original_start_time = "2023-01-01T02:00:00Z"
        expired_next_link = f"{BASE_URL}/v3.0{UrlSuffixes.OBSERVED_ATTACK_TECHNIQUES.value}?top=1000&fetchedAmountOfEvents=100"

        requested_params: list[dict] = []

        def _side_effect(**kwargs):
            full_url = kwargs.get("full_url") or ""
            if full_url == expired_next_link:
                raise DemistoException("Request token expired")
            requested_params.append(kwargs.get("params") or {})
            return create_logs_mocks(
                url=full_url,
                num_of_events=5000,
                url_suffix=UrlSuffixes.OBSERVED_ATTACK_TECHNIQUES.value,
                created_time_field="detectedDateTime",
                id_field_name="uuid",
                top=1000,
                last_event_fetch_time="2023-01-01T06:00:00Z",
            )

        mocker.patch.object(BaseClient, "_http_request", side_effect=_side_effect)

        _, updated_last_run = get_observed_attack_techniques_logs(
            client=client,
            first_fetch="1 month ago",
            last_run={
                "oat_detection_start_time": original_start_time,
                "dedup_found_oat_logs": [],
                "pagination_found_oat_logs": [1, 2, 3],
                "oat_detection_next_link": expired_next_link,
            },
            limit=500,
        )

        # the restarted query must have used the original (not-yet-fully-covered) start time
        assert requested_params[0]["detectedStartDateTime"] == original_start_time
        # the checkpoint must not have jumped ahead past events that were never actually fetched
        assert updated_last_run["oat_detection_start_time"] == original_start_time

    def test_get_search_detection_logs_no_last_run(self, mocker, client: Client):
        """
        Given:
         - no last run
         - limit = 500
         - 1000 search detection events

        When:
         - running get_search_detection_logs function

        Then:
         - make sure only 500 events are returned
         - make sure latest observed attack technique event is saved in
           the search_detection_logs_time without adding 1 second to it.
        """
        from TrendMicroVisionOneEventCollector import get_search_detection_logs

        start_freeze_time("2023-01-01T15:00:00Z")

        mocker.patch.object(
            BaseClient, "_http_request", side_effect=_http_request_side_effect_decorator(num_of_search_detection_logs=1000)
        )

        search_detection_logs, updated_last_run = get_search_detection_logs(
            client=client, first_fetch="1 month ago", last_run={}, limit=500
        )

        assert len(search_detection_logs) == 500
        assert updated_last_run == {
            "search_detection_start_time": "2022-12-01T15:00:00Z",
            "dedup_found_search_detection_logs": [500],
            "pagination_found_search_detection_logs": [500],
            "search_detection_next_link": "https://api.xdr.trendmicro.com/v3.0/search/detections?top=500"
            "&fetchedAmountOfEvents=500",
            "search_detection_window_end_time": "2023-01-01T15:00:00Z",
        }

    def test_get_search_detection_logs_with_last_run(self, mocker, client: Client):
        """
        Given:
         - last_run = {
                'search_detection_start_time': '2023-01-01T14:00:00Z',
                'dedup_found_search_detection_logs': [1, 2, 3, 4, 5, 6, 7],
                'pagination_found_search_detection_logs': [],
                'search_detection_next_link': 'https://api.xdr.trendmicro.com/v3.0/search/detections?top=200'
                                              '&fetchedAmountOfEvents=500'
            }
         - limit = 500
         - 200 detection events

        When:
         - running get_search_detection_logs function

        Then:
         - make sure only 193 events are returned
         - make sure latest search detection log event time is saved in
           the search_detection_logs_time without adding 1 second to it.
        """
        from TrendMicroVisionOneEventCollector import get_search_detection_logs

        start_freeze_time("2023-01-01T15:00:00Z")

        mocker.patch.object(
            BaseClient,
            "_http_request",
            side_effect=_http_request_side_effect_decorator(
                num_of_search_detection_logs=700, last_search_detection_logs="2023-01-01T14:00:00Z"
            ),
        )

        search_detection_logs, updated_last_run = get_search_detection_logs(
            client=client,
            first_fetch="1 month ago",
            last_run={
                "search_detection_start_time": "2023-01-01T14:00:00Z",
                "dedup_found_search_detection_logs": [1, 2, 3, 4, 5, 6, 7],
                "pagination_found_search_detection_logs": [1, 2, 3, 4, 5, 6, 7],
                "search_detection_next_link": "https://api.xdr.trendmicro.com/v3.0/search/detections?top=200"
                "&fetchedAmountOfEvents=500",
            },
            limit=500,
        )

        assert len(search_detection_logs) == 193
        assert updated_last_run == {
            "search_detection_start_time": "2023-01-01T14:00:00Z",
            "dedup_found_search_detection_logs": [1, 2, 3, 4, 5, 6, 7],
            "pagination_found_search_detection_logs": [1, 2, 3, 4, 5, 6, 7],
            "search_detection_next_link": "",
            "search_detection_window_end_time": "",
        }

    def test_get_audit_logs_no_last_run(self, mocker, client: Client):
        """
        Given:
         - no last run
         - limit = 500
         - 200 audit logs

        When:
         - running get_audit_logs function

        Then:
         - make sure only 500 events are returned
         - make sure in the cache we will have event with hash of the 500 id as its the event that happened in the last second.
        """
        from TrendMicroVisionOneEventCollector import get_audit_logs

        start_freeze_time("2023-01-01T15:00:00Z")

        mocker.patch.object(
            BaseClient,
            "_http_request",
            side_effect=_http_request_side_effect_decorator(num_of_audit_logs=1000, last_audit_log_time="2023-01-01T14:00:00Z"),
        )

        audit_logs, updated_last_run = get_audit_logs(client=client, first_fetch="1 month ago", last_run={}, limit=500)

        assert len(audit_logs) == 500
        assert updated_last_run == {
            LastRunLogsStartTimeFields.AUDIT.value: "2023-01-01T14:08:20Z",
            "found_audit_logs": ["77b363584231085e7909d48e0e103a07b6c10127e00da6e4739f07248eee7682"],
        }

    def test_get_audit_logs_with_last_run(self, mocker, client: Client):
        """
        Given:
         - last_run={'audit_logs_time': '2023-01-01T14:00:00Z'}
         - limit = 500
         - 200 audit logs

        When:
         - running get_audit_logs function

        Then:
         - make sure only 200 events are returned
         - make sure in the cache we will have event with hash of the 200 id as its the event that happened in the last second.
        """
        from TrendMicroVisionOneEventCollector import get_audit_logs

        start_freeze_time("2023-01-01T15:00:00Z")

        mocker.patch.object(
            BaseClient,
            "_http_request",
            side_effect=_http_request_side_effect_decorator(num_of_audit_logs=200, last_audit_log_time="2023-01-01T14:00:00Z"),
        )

        audit_logs, updated_last_run = get_audit_logs(
            client=client,
            first_fetch="1 month ago",
            last_run={LastRunLogsStartTimeFields.AUDIT.value: "2023-01-01T14:00:00Z"},
            limit=500,
        )

        assert len(audit_logs) == 200
        assert updated_last_run == {
            LastRunLogsStartTimeFields.AUDIT.value: "2023-01-01T14:03:20Z",
            "found_audit_logs": ["4410bac4975e15bc234ee627129e46665744349bb59830968a2e4769fe0afc0e"],
        }


@pytest.mark.parametrize(
    "last_run_time, first_fetch, log_type_time_field_name, start_time, expected_start_and_end_date_times",
    [
        (
            None,
            "3 years",
            LastRunLogsStartTimeFields.WORKBENCH.value,
            "2023-01-01T15:20:45Z",
            ("2020-01-01T15:20:45Z", "2023-01-01T15:20:45Z"),
        ),
        (
            None,
            "3 years",
            LastRunLogsStartTimeFields.AUDIT.value,
            "2023-01-01T15:20:45Z",
            ("2022-07-05T15:20:45Z", "2023-01-01T15:20:45Z"),
        ),
        (
            None,
            "3 years ago",
            LastRunLogsStartTimeFields.OBSERVED_ATTACK_TECHNIQUES.value,
            "2023-01-01T15:20:45Z",
            ("2020-01-01T15:20:45Z", "2020-12-31T15:20:45Z"),
        ),
        (
            None,
            "1 month ago",
            LastRunLogsStartTimeFields.OBSERVED_ATTACK_TECHNIQUES.value,
            "2023-01-01T15:20:45Z",
            ("2022-12-01T15:20:45Z", "2023-01-01T15:20:45Z"),
        ),
        (
            "2023-01-01T15:00:00Z",
            "1 month ago",
            LastRunLogsStartTimeFields.SEARCH_DETECTIONS.value,
            "2023-01-01T15:20:45Z",
            ("2023-01-01T15:00:00Z", "2023-01-01T15:20:45Z"),
        ),
    ],
)
def test_get_datetime_range(
    last_run_time: str | None,
    first_fetch: str,
    log_type_time_field_name: str,
    start_time: str,
    expected_start_and_end_date_times: tuple[str, str],
):
    """
    Given:
        - Case A: last_run_time=None, first_fetch=3 years ago, log_type_time_field_name=workbench_logs_time,
                  start_time=2023-01-01T15:20:45Z
        - Case B: last_run_time=None, first_fetch=3 years ago, log_type_time_field_name=audit_logs_time,
                  start_time=2023-01-01T15:20:45Z
        - Case C: last_run_time=None, first_fetch=3 years ago, log_type_time_field_name=oat_detection_logs_time,
                  start_time=2023-01-01T15:20:45Z
        - Case D: last_run_time=None, first_fetch=1 month ago, log_type_time_field_name=oat_detection_logs_time,
                  start_time=2023-01-01T15:20:45Z
        - Case E: last_run_time=2023-01-01T15:00:00Z, first_fetch=1 month ago,
                  log_type_time_field_name=search_detection_logs_time, start_time=2023-01-01T15:20:45Z
    When:
        - running get datetime range
    Then:
        - Case A: make sure start time is 3 years ago and end time is "now".
        - Case B: make sure the start time is 180 days ago and end time is "now"
        - Case C: make sure the start time is 3 years ago and the time is 1 day after.
        - Case D: make sure the start time is 1 month ago and end time is "now"
        - Case E: make sure the start time is the last_run_time and end time is "now"
    """
    from TrendMicroVisionOneEventCollector import get_datetime_range

    start_freeze_time(start_time)

    assert (
        get_datetime_range(
            last_run_time=last_run_time, first_fetch=first_fetch, log_type_time_field_name=log_type_time_field_name
        )
        == expected_start_and_end_date_times
    )


def test_module_main_flow(mocker):
    """
    Given:
        - 1 log of each type
    When:
        - test-module through main
    Then:
        - make sure that test-module returns 'ok'
        - make sure send_events_to_xsiam function was not called
    """
    from TrendMicroVisionOneEventCollector import main

    start_freeze_time("2023-01-01T15:20:45Z")

    mocker.patch.object(demisto, "params", return_value={"first_fetch": "1 year ago"})
    mocker.patch.object(demisto, "command", return_value="test-module")
    mocker.patch.object(
        BaseClient,
        "_http_request",
        side_effect=_http_request_side_effect_decorator(
            num_of_workbench_logs=1, num_of_oat_logs=1, num_of_search_detection_logs=1, num_of_audit_logs=1
        ),
    )

    return_results_mocker = mocker.patch("TrendMicroVisionOneEventCollector.return_results")
    send_events_to_xsiam_mocker = mocker.patch("TrendMicroVisionOneEventCollector.send_events_to_xsiam")

    main()

    assert not send_events_to_xsiam_mocker.called
    assert return_results_mocker.call_args.args[0] == "ok"


@pytest.mark.parametrize(
    "args, expected_outputs",
    [
        (
            {
                "from_time": "2023-01-01T15:00:45Z",
                "to_time": "2023-01-01T15:20:45Z",
                "log_type": f"{LogTypes.AUDIT.value},{LogTypes.SEARCH_DETECTIONS.value},"
                f"{LogTypes.OBSERVED_ATTACK_TECHNIQUES.value},{LogTypes.WORKBENCH.value}",
            },
            [
                {"Id": 1, "Time": "2023-01-01T15:19:46Z", "Type": "Workbench"},
                {"Id": 1, "Time": "2023-01-01T15:20:44Z", "Type": "Observed Attack Technique"},
                {"Id": 1, "Time": "2023-01-01T15:20:44Z", "Type": "Search Detection"},
                {"Id": 1, "Time": "2023-01-01T15:19:46Z", "Type": "Audit"},
            ],
        ),
        (
            {"from_time": "2023-01-01T15:00:45Z", "to_time": "2023-01-01T15:20:45Z", "log_type": LogTypes.AUDIT.value},
            [{"Id": 1, "Time": "2023-01-01T15:19:46Z", "Type": "Audit"}],
        ),
        (
            {
                "from_time": "2023-01-01T15:00:45Z",
                "to_time": "2023-01-01T15:20:45Z",
                "log_type": LogTypes.OBSERVED_ATTACK_TECHNIQUES.value,
            },
            [{"Id": 1, "Time": "2023-01-01T15:20:44Z", "Type": "Observed Attack Technique"}],
        ),
        (
            {
                "from_time": "2023-01-01T15:00:45Z",
                "to_time": "2023-01-01T15:20:45Z",
                "log_type": LogTypes.SEARCH_DETECTIONS.value,
            },
            [{"Id": 1, "Time": "2023-01-01T15:20:44Z", "Type": "Search Detection"}],
        ),
        (
            {"from_time": "2023-01-01T15:00:45Z", "to_time": "2023-01-01T15:20:45Z", "log_type": LogTypes.WORKBENCH.value},
            [{"Id": 1, "Time": "2023-01-01T15:19:46Z", "Type": "Workbench"}],
        ),
    ],
)
def test_get_events_command_main_flow(mocker, args: Dict, expected_outputs: List[Dict]):
    """
    Given:
        - Case A: log_type=all
        - Case B: log_type=audit_logs
        - Case C: log_type=oat_detection_logs
        - Case D: log_type=search_detection_logs
        - Case E: log_type=workbench_logs
    When:
        - running trend-micro-vision-one-get-events through main
    Then:
        - make sure when log_type=all, all events are returned.
        - make sure for each log type only the correct log will be returned.
    """
    from TrendMicroVisionOneEventCollector import main

    start_freeze_time("2023-01-01T15:20:45Z")

    mocker.patch.object(demisto, "params", return_value={"first_fetch": "1 year ago"})
    mocker.patch.object(demisto, "args", return_value=args)
    mocker.patch.object(demisto, "command", return_value="trend-micro-vision-one-get-events")
    mocker.patch.object(
        BaseClient,
        "_http_request",
        side_effect=_http_request_side_effect_decorator(
            num_of_workbench_logs=1, num_of_oat_logs=1, num_of_search_detection_logs=1, num_of_audit_logs=1
        ),
    )

    return_results_mocker = mocker.patch("TrendMicroVisionOneEventCollector.return_results")

    main()

    assert return_results_mocker.call_args.args[0].outputs == expected_outputs
    assert "events for log_types=" in return_results_mocker.call_args.args[0].readable_output
