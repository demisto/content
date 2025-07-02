import random

from unittest.mock import MagicMock
from CybelAngelEventCollector import Client, DATE_FORMAT, REPORT, DOMAIN, CREDENTIALS, LATEST_TIME, LATEST_FETCHED_IDS, EVENT_TYPE
from CommonServerPython import *
import pytest


TEST_URL = "https://test.com/api"

DEFAULT_PARAMS = {
    "url": TEST_URL,
    "credentials": {"identifier": "1234", "password": "1234"},
    "max_fetch": 100,
    "max_fetch_domain": 100,
    "max_fetch_creds": 100,
    "event_types_to_fetch": [REPORT.name],
    "is_fetch_events": True,
}


@pytest.fixture
def params_mocker(monkeypatch):
    """
    Patch demisto.params so tests can mutate a single dict in-place.
    """
    params_holder: dict = DEFAULT_PARAMS.copy()
    monkeypatch.setattr(demisto, "params", lambda: params_holder)
    return params_holder


@pytest.fixture()
def client() -> Client:
    return Client(
        TEST_URL,
        client_id="1234",
        client_secret="1234",
        verify=False,
        proxy=False,
    )


def load_test_data(file_name):
    with open(f"test_data/{file_name}.json") as file:
        return json.load(file)


class HttpRequestsMocker:
    """
    Mocker for the HttpRequests.
    Uses examples of real response structures with mocked data.
    """

    def __init__(self, num_of_events: int):
        self.num_of_events = num_of_events
        self.num_of_calls = 0

    def valid_http_request_side_effect(self, method: str, url_suffix: str = "", params: Dict | None = None, **kwargs):
        """
        Create Response with the relevant data depend on the params.
        """
        if method == "GET":
            if url_suffix == REPORT.url_suffix:
                start_date = params.get("start-date")
                events = create_report_events(1, amount_of_events=self.num_of_events, start_date=start_date)
            elif url_suffix == DOMAIN.url_suffix:
                skip = int(params.get("skip", 0))
                limit = int(params.get("limit", 0))
                events = create_domain_events(limit, skip)
            elif url_suffix == CREDENTIALS.url_suffix:
                limit = int(params.get("limit", 0))
                events = create_creds_events(limit)
            return create_mocked_response(events)
        elif method == "POST" and kwargs.get("full_url") == "https://auth.cybelangel.com/oauth/token":
            return {"access_token": "new_access_token"}
        return None

    def valid_http_request_zero_events_side_effect(self, method: str, url_suffix: str = "", params: Dict | None = None, **kwargs):
        """
        Return Empty response
        """
        if method == "GET":
            if url_suffix == REPORT.url_suffix:
                events = {"reports": []}
            elif url_suffix == DOMAIN.url_suffix:
                events = {"results": [], "total": 0}
            elif url_suffix == CREDENTIALS.url_suffix:
                events = []
            return create_mocked_response(events)
        elif method == "POST" and kwargs.get("full_url") == "https://auth.cybelangel.com/oauth/token":
            return {"access_token": "new_access_token"}
        return None

    def expired_token_http_request_side_effect(
        self, method: str, url_suffix: Optional[str] = None, params: Dict | None = None, **kwargs
    ):
        """
        Mock the behavior of first call is with expired token.
        """
        if method == "GET" and url_suffix == "/api/v2/reports":
            if self.num_of_calls == 0:
                self.num_of_calls += 1
                return create_mocked_response([], status_code=401)
            start_date = params.get("start-date")
            return create_report_events(1, amount_of_events=self.num_of_events, start_date=start_date)
        if method == "POST" and kwargs.get("full_url") == "https://auth.cybelangel.com/oauth/token":
            return {"access_token": "new_access_token"}
        return None


def create_report_events(start_id: int, amount_of_events: int, start_date: str) -> dict[str, list[dict]]:
    """Return {"reports": [...]} with shuffled `_time` and `id` fields."""
    events = [
        {
            REPORT.id_key: str(i),
            "updated_at": (dateparser.parse(start_date) + timedelta(seconds=i)).strftime(DATE_FORMAT),
        }
        for i in range(start_id, start_id + amount_of_events)
    ]
    random.shuffle(events)
    return {"reports": events}


def create_domain_events(limit: int, skip: int) -> dict[str, Any]:
    """Return {"results": [...]} with reversed chronological order."""
    response = load_test_data("domain_response")
    events = response["results"]
    total = response["total"]
    return {"results": events[skip : skip + limit], "total": total}


def create_creds_events(limit: int) -> list[dict]:
    """Return a plain list of credential-watchlist events in ascending order."""
    return load_test_data("credentials_response")[:limit]


@pytest.fixture(autouse=True)
def mock_get_id(monkeypatch):
    def mock_get_id(self, event):
        # Use the last key in id_key list, or id_key itself if it's a string
        if isinstance(self.id_key, list):
            return str(event.get(self.id_key[-1], ""))
        return str(event.get(self.id_key, ""))

    monkeypatch.setattr("CybelAngelEventCollector.EventType.get_id", mock_get_id)


def create_mocked_response(response: List[Dict] | Dict, status_code: int = 200) -> requests.Response:
    mocked_response = requests.Response()
    mocked_response._content = json.dumps(response).encode("utf-8")
    mocked_response.status_code = status_code
    return mocked_response


# --------- Test get last run logics --------------------------------------
def test_get_last_run_no_previous(mocker):
    """
    Given:
    -  demisto.getLastRun() is empty or None.

    When:
    - calling get_last_run()

    Then:
    - return dict with REPORT, DOMAIN and CREDENTIALS all initialized
    to now - 1 minute and empty ID lists.
    """
    from CybelAngelEventCollector import get_last_run

    mocker.patch.object(demisto, "getLastRun", return_value={})
    now = datetime(2025, 5, 15, 12, 0, 0)
    result = get_last_run(now, [REPORT, DOMAIN, CREDENTIALS])
    expected_time = (now - timedelta(minutes=1)).strftime(DATE_FORMAT)

    for event_type in (REPORT, DOMAIN, CREDENTIALS):
        assert event_type.name in result
        assert result[event_type.name][LATEST_TIME] == expected_time
        assert result[event_type.name][LATEST_FETCHED_IDS] == []


def test_get_last_run_partial_existing(mocker):
    """
    Given:
    -  demisto.getLastRun() contain some events types.

    When:
    - Calling get_last_run()

    Then:
    - Only non existent types will get now - 1 minute and empty ID lists.
    """
    from CybelAngelEventCollector import get_last_run

    existing_time = "2025-05-14T11:59:00"
    existing_ids = ["x", "y"]
    now = datetime(2025, 5, 15, 12, 0, 0)
    mocker.patch.object(
        demisto,
        "getLastRun",
        return_value={REPORT.name: {LATEST_TIME: existing_time, LATEST_FETCHED_IDS: existing_ids}},
    )

    result = get_last_run(now, [REPORT, DOMAIN, CREDENTIALS])
    # REPORT must be unchanged
    assert result[REPORT.name][LATEST_TIME] == existing_time
    assert result[REPORT.name][LATEST_FETCHED_IDS] == existing_ids

    # DOMAIN and CREDENTIALS must now be set to now-1min
    expected_time = (now - timedelta(minutes=1)).strftime(DATE_FORMAT)
    for event_type in (DOMAIN, CREDENTIALS):
        assert result[event_type.name][LATEST_TIME] == expected_time
        assert result[event_type.name][LATEST_FETCHED_IDS] == []


def test_get_last_run_all_present(mocker):
    """
    Given:
    -  demisto.getLastRun() got all events.

    When:
    - Calling get_last_run()

    Then:
    - get_lat_run will not change any of the existent.
    """
    from CybelAngelEventCollector import get_last_run

    now = datetime(2025, 5, 15, 12, 0, 0)
    initial = {
        REPORT.name: {LATEST_TIME: "2025-05-14T11:00:00", LATEST_FETCHED_IDS: [1]},
        DOMAIN.name: {LATEST_TIME: "2025-05-14T11:01:00", LATEST_FETCHED_IDS: [2]},
        CREDENTIALS.name: {LATEST_TIME: "2025-05-14T11:02:00", LATEST_FETCHED_IDS: [3]},
    }
    mocker.patch.object(demisto, "getLastRun", return_value=initial.copy())

    result = get_last_run(now, [REPORT, DOMAIN, CREDENTIALS])
    # Should be exactly the same dict we passed in
    assert result == initial


def test_get_last_run_all_present_one_removed(mocker):
    """
    Given:
    - getLastRun() already contains all three types
    - event_types_to_fetch have one less event.

    When:
    - Calling get_last_run().

    Then:
    - Reset the time and id of the event who removed, other as usual.
    """
    from CybelAngelEventCollector import get_last_run

    now = datetime(2025, 5, 15, 12, 0, 0)
    last_time = now - timedelta(minutes=1)
    initial = {
        REPORT.name: {LATEST_TIME: "2025-05-14T11:00:00", LATEST_FETCHED_IDS: [1]},
        DOMAIN.name: {LATEST_TIME: "2025-05-14T11:01:00", LATEST_FETCHED_IDS: [2]},
        CREDENTIALS.name: {LATEST_TIME: "2025-05-14T11:02:00", LATEST_FETCHED_IDS: [3]},
    }
    mocker.patch.object(demisto, "getLastRun", return_value=initial.copy())

    result = get_last_run(now, [REPORT, DOMAIN])
    initial[CREDENTIALS.name] = {LATEST_TIME: last_time.strftime(DATE_FORMAT), LATEST_FETCHED_IDS: []}
    assert result == initial


# --------- Test Token --------------------------------------
def test_http_request_token_expired(client: Client, mocker):
    """
    When calling http_request and the token is expired, will ask for a new one.
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
    mocker.patch.object(demisto, "getIntegrationContext", return_value={"access_token": "old_access_token"})
    set_integration_context_mocker: MagicMock = mocker.patch.object(demisto, "setIntegrationContext")

    result = client.http_request(method="GET", url_suffix="/api/v2/reports", params={"start-date": "2021-01-10T00:00:00"})
    events = result["reports"]
    assert len(events) == 1
    assert set_integration_context_mocker.call_args[0][0] == {"access_token": "new_access_token"}


def test_get_token_request_raises(monkeypatch):
    """
    Given:
      - A Client whose _http_request returns {} (no access_token)

    When:
      - Calling get_token_request()

    Then:
      - RuntimeError is raised with the correct message
    """
    client = Client("u", "i", "s", verify=False, proxy=False)
    monkeypatch.setattr(client, "_http_request", lambda *a, **k: {})
    with pytest.raises(RuntimeError) as ei:
        client.get_token_request()
    assert "Could not retrieve token" in str(ei.value)


# --------- Test Commands --------------------------------------
def test_the_test_module(mocker, params_mocker):
    """
    Given:
     - valid credentials

    When:
     - running the test-module

    Then:
     - make sure "ok" is returned
    """
    import CybelAngelEventCollector

    return_results_mocker: MagicMock = mocker.patch.object(CybelAngelEventCollector, "return_results")
    params_mocker["max_fetch"] = 10
    params_mocker["event_types_to_fetch"] = [REPORT.name, CREDENTIALS.name, DOMAIN.name]
    mocker.patch.object(demisto, "command", return_value="test-module")

    http_mocker = HttpRequestsMocker(10)

    mocker.patch.object(CybelAngelEventCollector.Client, "_http_request", side_effect=http_mocker.valid_http_request_side_effect)

    CybelAngelEventCollector.main()
    assert return_results_mocker.called
    assert return_results_mocker.call_args[0][0] == "ok"


def test_get_events_command_command(mocker, params_mocker):
    """
    Given:
     - limit is 9.
     - server holds 10 events.
     - should_push_events = true.
     - fetching reports.

    When:
     - running the fetch-events

    Then:
     - all first 9 events are sent to xsiam.
    """
    import CybelAngelEventCollector

    mocker.patch.object(demisto, "getLastRun", return_value={})
    params_mocker["event_types_to_fetch"] = [REPORT.name]
    params_mocker["max_fetch"] = 100

    mocker.patch.object(
        demisto,
        "args",
        return_value={"start_date": "2024-02-29T13:48:32", "limit": 9, "should_push_events": True},
    )
    mocker.patch.object(demisto, "command", return_value="cybelangel-get-events")

    http_mocker = HttpRequestsMocker(10)

    mocker.patch.object(CybelAngelEventCollector.Client, "_http_request", side_effect=http_mocker.valid_http_request_side_effect)
    mock_send_events = mocker.patch.object(CybelAngelEventCollector, "send_events_to_xsiam")
    CybelAngelEventCollector.main()
    mock_send_events.assert_called_once()

    _, call_kwargs = mock_send_events.call_args
    events_sent_to_xsiam = call_kwargs["events"]
    assert len(events_sent_to_xsiam) == 9
    assert [f"{i}" for i in range(1, 10)] == [event.get(REPORT.id_key) for event in events_sent_to_xsiam]
    assert call_kwargs["vendor"] == CybelAngelEventCollector.VENDOR
    assert call_kwargs["product"] == CybelAngelEventCollector.PRODUCT


def test_cybelangel_report_list_command(mocker, client: Client):
    """
    Given:
     - A start date and an end date.

    When:
     - Retrieving a list of reports within the specified date range.

    Then:
     - Ensure the command returns a valid list of reports.
     - Validate that the outputs are correctly formatted.
    """
    from CybelAngelEventCollector import cybelangel_report_list_command

    data = load_test_data("report_list")
    reports = data["reports"]

    mocker.patch.object(
        client,
        "get_reports_list",
        return_value=reports,
    )
    args = {"start_date": "2024-01-01", "end_date": "2024-02-01"}

    result = cybelangel_report_list_command(client, args)

    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == "CybelAngel.Report"
    assert result.outputs == reports
    assert "Reports list" in result.readable_output


def test_cybelangel_report_get_command(mocker, client: Client):
    """
    Given:
     - A specific report ID.

    When:
     - Retrieving the details of the report.

    Then:
     - Ensure the command returns the correct report details.
     - Validate that the readable output includes the report ID.
    """
    from CybelAngelEventCollector import cybelangel_report_get_command

    mocker.patch.object(
        client,
        "_http_request",
        return_results=load_test_data("report_list").get("reports")[0],
    )
    args = {"report_id": "test"}

    result = cybelangel_report_get_command(client, args)

    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == "CybelAngel.Report"
    assert result.outputs is not None
    assert "Report ID" in result.readable_output


def test_cybelangel_report_get_command_to_pdf(mocker, client: Client):
    """
    Given:
     - A report ID and the 'pdf' flag set to true.

    When:
     - Requesting to export the report as a PDF.

    Then:
     - Ensure the command returns a valid file result in PDF format.
    """
    from CybelAngelEventCollector import cybelangel_report_get_command

    mocker.patch.object(
        client,
        "_http_request",
        return_results=load_test_data("report_list").get("reports")[0],
    )
    # test get report to pdf
    args = {"report_id": "test", "pdf": "true"}
    mocker.patch(
        "CybelAngelEventCollector.fileResult",
        return_value={
            "Contents": "",
            "ContentsFormat": "text",
            "Type": 9,
            "File": "cybelangel_report_<report_id>.pdf",
            "FileID": "<report_id>",
        },
    )
    result = cybelangel_report_get_command(client, args)
    assert isinstance(result, dict)


def test_cybelangel_mirror_report_get_command(mocker, client: Client):
    """
    Given:
     - A report ID with the 'csv' flag set to false.

    When:
     - Fetching mirror report details.

    Then:
     - Ensure the command returns a CommandResults object with the expected report data.
    """
    from CybelAngelEventCollector import cybelangel_mirror_report_get_command

    mocker.patch.object(
        client,
        "_http_request",
        return_results=load_test_data("mirror-report"),
    )
    args = {"csv": "false", "report_id": "test"}

    result = cybelangel_mirror_report_get_command(client, args)

    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == "CybelAngel.ReportMirror"
    assert result.outputs is not None
    assert "Mirror details for Report ID" in result.readable_output


def test_cybelangel_mirror_report_get_command_to_csv(mocker, client: Client):
    """
    Given:
     - A report ID with the 'csv' flag set to true.

    When:
     - Requesting to export the mirror report as a CSV file.

    Then:
     - Ensure the command returns a valid file result in CSV format.
    """
    from CybelAngelEventCollector import cybelangel_mirror_report_get_command

    mocker.patch.object(
        client,
        "_http_request",
        return_results=load_test_data("mirror-report"),
    )
    args = {"report_id": "test", "csv": "true"}
    mocker.patch(
        "CybelAngelEventCollector.fileResult",
        return_value={
            "Contents": "",
            "ContentsFormat": "text",
            "Type": 9,
            "File": "cybelangel_mirror_report_<report_id>.csv",
            "FileID": "<report_id>",
        },
    )
    result = cybelangel_mirror_report_get_command(client, args)
    assert isinstance(result, dict)


def test_cybelangel_report_comment_create_command(mocker, client: Client):
    """
    Given:
     - A discussion ID, comment content, and additional metadata.

    When:
     - Creating a new comment for the report.

    Then:
     - Ensure the command successfully adds the comment and returns the expected output.
    """
    from CybelAngelEventCollector import cybelangel_report_comment_create_command, Client

    report_id = "11223344"

    mocker.patch.object(
        Client,
        "get_report_comment",
        return_value=load_test_data("create_comment_result"),
    )

    args = {"discussion_id": f"{report_id}:tenant id", "content": "Test func", "parent_id": "55667788", "assigned": "true"}
    response = cybelangel_report_comment_create_command(client, args)

    assert f"Comment created successfully for report ID: {report_id}" in response.readable_output


def test_cybelangel_report_comment_create_command_invalid(mocker, client: Client):
    """
    Given:
     - An invalid discussion ID that does not follow the 'report_id:tenant_id' format.

    When:
     - Attempting to create a comment with the invalid discussion ID.

    Then:
     - Ensure the command raises a ValueError with the correct error message.
    """
    from CybelAngelEventCollector import cybelangel_report_comment_create_command

    report_id = "11223344"

    # Case: Invalid discussion_id format (no colon)
    args_invalid = {"discussion_id": report_id, "content": "Test func"}
    with pytest.raises(ValueError, match="Invalid discussion_id format. Expected format: 'report_id:tenant_id'."):
        cybelangel_report_comment_create_command(client, args_invalid)


def test_cybelangel_archive_report_by_id_get_command(mocker, client: Client):
    """
    Given:
     - A report ID to retrieve the archived version of the report.

    When:
     - Requesting the archived report in ZIP format.

    Then:
     - Ensure the command returns a file result containing the ZIP archive.
     - Validate that the returned file name follows the expected format.
    """
    from CybelAngelEventCollector import cybelangel_archive_report_by_id_get_command

    mocker.patch.object(
        client,
        "_http_request",
        return_results=load_test_data("mirror-report"),
    )
    args = {"report_id": "test"}
    mocker.patch(
        "CybelAngelEventCollector.fileResult",
        return_value={
            "Contents": "",
            "ContentsFormat": "text",
            "Type": 9,
            "File": "cybelangel_archive_report_<report_id>.zip",
            "FileID": "<report_id>",
        },
    )
    result = cybelangel_archive_report_by_id_get_command(client, args)
    assert isinstance(result, dict)


def test_cybelangel_report_comments_get_command(mocker, client: Client):
    """
    Given:
     - A report ID for which comments need to be retrieved.
     - A response containing existing comments for the report.

    When:
     - Running the `cybelangel_report_comments_get_command`.

    Then:
     - Ensure the command successfully retrieves comments for the given report.
     - Validate that the `discussion_id` starts with the report ID.
     - Validate that the `discussion_id` ends with 'Tenant id'.
    """
    from CybelAngelEventCollector import cybelangel_report_comments_get_command, Client

    # case No previous comments exist in this report
    mocker.patch.object(
        Client,
        "get_report_comment",
        return_value=load_test_data("get_comments_res"),
    )
    report_id = "11223344"
    args = {"report_id": report_id}
    response = cybelangel_report_comments_get_command(client, args)
    assert response.outputs.get("Comment")[0].get("discussion_id").startswith(report_id)  # type: ignore
    assert response.outputs.get("Comment")[0].get("discussion_id").endswith("Tenant id")  # type: ignore


def test_cybelangel_report_attachment_get_command(mocker, client: Client):
    """
    Given:
     - report ID and attachment ID

    When:
     - running the cybelangel_report_attachment_get_command with the given arguments

    Then:
     - ensure the function returns a dictionary containing the expected file details
        and the text of the attachment starts with "sep=" for CSV file.
    """
    from CybelAngelEventCollector import cybelangel_report_attachment_get_command, Client

    response = mocker.patch.object(
        Client,
        "get_report_attachment",
        return_value=type(
            "StringWrapper", (object,), {"text": "sep=,\nkeyword,email,password\nTest1,Test2,Test3\nTest1,Test2"}
        )(),
    )
    report_id = "11223344"
    attachment_id = "55667788"
    args = {"report_id": report_id}
    mocker.patch(
        "CybelAngelEventCollector.fileResult",
        return_value={
            "Contents": "",
            "ContentsFormat": "text",
            "Type": 9,
            "File": f"cybelangel_report_{report_id}_attachment_{attachment_id}.csv",
            "FileID": "<report_id>",
        },
    )
    result = cybelangel_report_attachment_get_command(client, args)
    assert isinstance(result, dict)
    assert response.text.startswith("sep=")


# --------- Test Fetching Logics --------------------------------------
@pytest.mark.parametrize(
    "event_type, max_fetch_key",
    [
        (REPORT.name, "max_fetch"),
        (CREDENTIALS.name, "max_fetch_creds"),
        (DOMAIN.name, "max_fetch_domain"),
    ],
)
def test_fetch_events_no_last_run(mocker, event_type, max_fetch_key, params_mocker):
    """
    Given:
     - no last run (first time of the fetch).
     - server holds 10 events from each type.

    When:
     - running the fetch-events.

    Then:
     - make sure events are sent into xsiam.
     - make sure all the 10 events are fetched.
     - make sure last run is updated.
    """
    import CybelAngelEventCollector
    from CybelAngelEventCollector import normalize_date_format

    send_events_mocker = mocker.patch.object(CybelAngelEventCollector, "send_events_to_xsiam")
    set_last_run_mocker = mocker.patch.object(demisto, "setLastRun", return_value={})
    params_mocker["event_types_to_fetch"] = event_type
    params_mocker[max_fetch_key] = 10

    mocker.patch.object(demisto, "command", return_value="fetch-events")

    http_mocker = HttpRequestsMocker(10)

    mocker.patch.object(CybelAngelEventCollector.Client, "_http_request", side_effect=http_mocker.valid_http_request_side_effect)

    CybelAngelEventCollector.main()

    assert send_events_mocker.called
    fetched_events = send_events_mocker.call_args[0][0]
    assert len(fetched_events) == 10

    assert set_last_run_mocker.called
    last_run = set_last_run_mocker.call_args[0][0]

    max_event_index = EVENT_TYPE[event_type].max_index
    assert last_run[event_type][LATEST_TIME] == normalize_date_format(fetched_events[max_event_index]["_time"])
    last_id = EVENT_TYPE[event_type].get_id(fetched_events[max_event_index])
    assert last_run[event_type][LATEST_FETCHED_IDS][0] == last_id


def test_fetch_events_token_expired(mocker):
    """
    Given:
     - token that has expired.

    When:
     - running the fetch-events.

    Then:
     - make sure events are sent into xsiam
     - make sure all the 10 events are fetched.
     - make sure last run is updated.
     - make sure the new access token is getting into the integration context.
    """
    import CybelAngelEventCollector
    from CybelAngelEventCollector import REPORT, LATEST_TIME, LATEST_FETCHED_IDS

    send_events_mocker: MagicMock = mocker.patch.object(CybelAngelEventCollector, "send_events_to_xsiam")
    set_last_run_mocker: MagicMock = mocker.patch.object(demisto, "setLastRun", return_value={})
    mocker.patch.object(demisto, "getLastRun", return_value={})

    mocker.patch.object(demisto, "command", return_value="fetch-events")
    mocker.patch.object(demisto, "getIntegrationContext", return_value={"access_token": "old_access_token"})
    set_integration_context_mocker: MagicMock = mocker.patch.object(demisto, "setIntegrationContext")

    http_mocker = HttpRequestsMocker(10)

    mocker.patch.object(
        CybelAngelEventCollector.Client, "_http_request", side_effect=http_mocker.expired_token_http_request_side_effect
    )

    CybelAngelEventCollector.main()
    assert send_events_mocker.called
    fetched_events = send_events_mocker.call_args[0][0]
    assert len(fetched_events) == 10

    assert set_last_run_mocker.called
    last_run = set_last_run_mocker.call_args[0][0]

    assert last_run[REPORT.name][LATEST_TIME] == fetched_events[-1]["_time"]
    assert last_run[REPORT.name][LATEST_FETCHED_IDS][0] == fetched_events[-1]["id"]

    assert set_integration_context_mocker.call_args[0][0] == {"access_token": "new_access_token"}


@pytest.mark.parametrize(
    "event_type, max_fetch_key",
    [
        (REPORT.name, "max_fetch_reports"),
        (CREDENTIALS.name, "max_fetch_creds"),
        (DOMAIN.name, "max_fetch_domain"),
    ],
)
def test_fetch_events_with_last_run(mocker, max_fetch_key, event_type, params_mocker):
    """
    Given:
     - last run of fetched events IDs [1, 2].
     - server holds 20 events for each type.

    When:
     - running the fetch-events.

    Then:
     - make sure events are sent into xsiam.
     - make sure all the 18 events are fetched, the rest were not fetched because they were fetched in previous fetch.
     - make sure last run is updated.
    """
    import CybelAngelEventCollector
    from CybelAngelEventCollector import normalize_date_format

    send_events_mocker: MagicMock = mocker.patch.object(CybelAngelEventCollector, "send_events_to_xsiam")
    set_last_run_mocker: MagicMock = mocker.patch.object(demisto, "setLastRun", return_value={})
    mocker.patch.object(
        demisto,
        "getLastRun",
        return_value={
            event_type: {
                LATEST_TIME: "2024-02-29T13:48:32",
                LATEST_FETCHED_IDS: ["1", "2"],
            }
        },
    )
    params_mocker["event_types_to_fetch"] = [event_type]
    mocker.patch.object(demisto, "command", return_value="fetch-events")

    http_mocker = HttpRequestsMocker(20)

    mocker.patch.object(CybelAngelEventCollector.Client, "_http_request", side_effect=http_mocker.valid_http_request_side_effect)

    CybelAngelEventCollector.main()
    assert send_events_mocker.called
    fetched_events = send_events_mocker.call_args[0][0]
    assert len(fetched_events) == 18

    assert set_last_run_mocker.called

    last_run = set_last_run_mocker.call_args[0][0]
    max_event_index = EVENT_TYPE[event_type].max_index
    assert last_run[event_type][LATEST_TIME] == normalize_date_format(fetched_events[max_event_index]["_time"])

    last_id = EVENT_TYPE[event_type].get_id(fetched_events[max_event_index])
    assert last_run[event_type][LATEST_FETCHED_IDS][0] == last_id

    assert all(event["SOURCE_LOG_TYPE"] == EVENT_TYPE[event_type].source_log_type for event in fetched_events)


@pytest.mark.parametrize(
    "last_run",
    [
        {},  # Empty Last run
        {
            REPORT.name: {LATEST_TIME: "2024-02-29T13:48:32", LATEST_FETCHED_IDS: [1, 2]},
            CREDENTIALS.name: {LATEST_TIME: "2024-02-29T13:48:32", LATEST_FETCHED_IDS: [1, 2]},
            DOMAIN.name: {LATEST_TIME: "2024-02-29T13:48:32", LATEST_FETCHED_IDS: [1, 2]},
        },
    ],
)
def test_fetch_events_no_events(mocker, last_run):
    """
    Given:
     - no last run.
     - no new events have been received from the api.

    When:
     - running the fetch-events.

    Then:
     - make sure no events are sent into xsiam.
     - make sure last run is returned with the last run updated.
    """
    import CybelAngelEventCollector

    send_events_mocker: MagicMock = mocker.patch.object(CybelAngelEventCollector, "send_events_to_xsiam")
    set_last_run_mocker: MagicMock = mocker.patch.object(demisto, "setLastRun", return_value={})

    mocker.patch.object(demisto, "command", return_value="fetch-events")

    http_mocker = HttpRequestsMocker(0)

    mocker.patch.object(
        CybelAngelEventCollector.Client, "_http_request", side_effect=http_mocker.valid_http_request_zero_events_side_effect
    )

    CybelAngelEventCollector.main()

    assert send_events_mocker.called
    fetched_events = send_events_mocker.call_args[0][0]
    assert len(fetched_events) == 0

    assert set_last_run_mocker.called
    actual_last_run = set_last_run_mocker.call_args[0][0]

    for event_type in (REPORT, CREDENTIALS, DOMAIN):
        assert event_type.name in actual_last_run

        ts = actual_last_run[event_type.name][LATEST_TIME]
        assert ts
        assert isinstance(ts, str)

        assert actual_last_run[event_type.name][LATEST_FETCHED_IDS] == []


@pytest.mark.parametrize(
    "event_type, max_fetch_key",
    [
        (REPORT.name, "max_fetch_reports"),
        (CREDENTIALS.name, "max_fetch_creds"),
        (DOMAIN.name, "max_fetch_domain"),
    ],
)
def test_fetch_events_with_last_run_dedup_event(mocker, event_type, max_fetch_key, params_mocker):
    """
    Given:
     - last run with events that was already fetched.
     - API return events already fetched last time.
     - no "new" events have been received from the api.

    When:
     - running the fetch-events.

    Then:
     - make sure no events are sent into xsiam.
     - make sure last run does not get updated.
    """
    import CybelAngelEventCollector

    send_events_mocker: MagicMock = mocker.patch.object(CybelAngelEventCollector, "send_events_to_xsiam")
    set_last_run_mocker: MagicMock = mocker.patch.object(demisto, "setLastRun")

    num_events = 5
    last_ids = [str(i) for i in range(1, 21)]
    initial_time = "2025-01-01T00:00:00"
    mocker.patch.object(
        demisto,
        "getLastRun",
        return_value={
            event_type: {
                LATEST_TIME: initial_time,
                LATEST_FETCHED_IDS: last_ids,
            }
        },
    )

    params_mocker[max_fetch_key] = 5
    params_mocker["event_types_to_fetch"] = event_type

    mocker.patch.object(demisto, "command", return_value="fetch-events")

    http_mocker = HttpRequestsMocker(num_events)

    mocker.patch.object(CybelAngelEventCollector.Client, "_http_request", side_effect=http_mocker.valid_http_request_side_effect)

    CybelAngelEventCollector.main()

    assert send_events_mocker.called
    fetched_events = send_events_mocker.call_args[0][0]
    assert len(fetched_events) == 0

    assert set_last_run_mocker.called
    actual_last_run = set_last_run_mocker.call_args[0][0]

    assert event_type in actual_last_run
    assert actual_last_run[event_type][LATEST_FETCHED_IDS] == []

    new_time = actual_last_run[event_type][LATEST_TIME]
    assert new_time != initial_time


def test_fetch_events_domain_two_call_paging(mocker, params_mocker):
    """
    Given:
      - Last run holds ids [1,2].
      - 10 total domain events in the 1-minute window.
      - max_fetch_domain = 6.

    When:
      - running fetch-events.

    Then:
      - send_events_to_xsiam is called with exactly 6 events.
      - Those 6 are with IDs 3..8.
      - lastRun is set to the time & ID of event 8.
    """
    import CybelAngelEventCollector

    send_events = mocker.patch.object(CybelAngelEventCollector, "send_events_to_xsiam")
    set_last_run = mocker.patch.object(demisto, "setLastRun")
    mocker.patch.object(
        demisto,
        "getLastRun",
        return_value={DOMAIN.name: {LATEST_TIME: datetime.now().isoformat(), LATEST_FETCHED_IDS: ["1", "2"]}},
    )
    params_mocker["event_types_to_fetch"] = DOMAIN.name
    params_mocker["max_fetch_domain"] = 6

    mocker.patch.object(demisto, "command", return_value="fetch-events")

    http_mocker = HttpRequestsMocker(10)
    mocker.patch.object(Client, "_http_request", side_effect=http_mocker.valid_http_request_side_effect)

    CybelAngelEventCollector.main()

    assert send_events.called, "events should have been sent"
    fetched = send_events.call_args[0][0]

    assert len(fetched) == 6
    assert fetched[0]["SOURCE_LOG_TYPE"] == DOMAIN.source_log_type

    returend_ids = [DOMAIN.get_id(event) for event in fetched]
    assert returend_ids == [str(i) for i in range(8, 2, -1)]

    lr = set_last_run.call_args[0][0]
    assert lr[DOMAIN.name][LATEST_TIME] == fetched[0]["_time"]
    last_id = DOMAIN.get_id(fetched[0])
    assert lr[DOMAIN.name][LATEST_FETCHED_IDS][0] == last_id


def test_get_latest_event_time_and_ids():
    """
    Given:
      - Server holds 6 events with the same timestamp.
      - 3 events already fetched.
      - fetching 3 additional events.

    When:
      - Calling get_latest_event_time_and_ids.

    Then:
    - last_ids holds all 6 events.
    - last_time does not changes.
    """
    from CybelAngelEventCollector import get_latest_event_time_and_ids

    last_run_time = "2024-02-29T13:48:32"
    events = [
        {
            REPORT.id_key: f"{i}",  # type: ignore
            "_time": last_run_time,
        }
        for i in range(4, 7)
    ]
    last_run_ids = ["1", "2", "3"]
    last_time, last_ids = get_latest_event_time_and_ids(
        events=events, event_type=REPORT, last_run_time=last_run_time, last_run_ids=last_run_ids
    )
    assert last_time == last_run_time
    assert len(last_ids) == 6
    assert set(last_ids) == {"1", "2", "3", "4", "5", "6"}


def test_fetch_events_same_timestamp(client, mocker):
    """
    Given:
      - Server holds 6 events with the same timestamp.
      - 3 events already fetched in the last run.

    When:
      - Calling fetch_events

    Then:
      - get_domain_watchlist called with limit = 6.
      - Only events 4,5,6 are sent back from the function.
      - lastRun is set to the same time with all 6 ids.
    """
    from CybelAngelEventCollector import fetch_events, DOMAIN, LATEST_TIME, LATEST_FETCHED_IDS

    last_run_time = "2024-02-29T13:48:32"
    last_run_ids = ["1", "2", "3"]

    mocker.patch.object(
        demisto, "getLastRun", return_value={DOMAIN.name: {LATEST_TIME: last_run_time, LATEST_FETCHED_IDS: last_run_ids}}
    )
    captured = {}

    def fake_get_domain_watchlist(start_date, end_date, limit, event_type=None):  # noqa: D401
        captured["limit"] = limit
        # six synthetic events, all with identical _time
        return [{"domain": str(i), "_time": last_run_time} for i in range(1, limit + 1)]

    mocker.patch.object(client, "get_domain_watchlist", side_effect=fake_get_domain_watchlist)

    DOMAIN.max_fetch = 3

    events, new_last_run = fetch_events(client, [DOMAIN])

    assert captured["limit"] == 6

    assert [DOMAIN.get_id(e) for e in events] == ["4", "5", "6"]

    assert new_last_run[DOMAIN.name][LATEST_TIME] == last_run_time + "Z"
    assert set(new_last_run[DOMAIN.name][LATEST_FETCHED_IDS]) == {str(i) for i in range(1, 7)}
