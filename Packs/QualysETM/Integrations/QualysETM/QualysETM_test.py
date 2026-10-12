"""Unit tests for the Qualys ETM integration."""

import io
import json
import os
import zipfile

import pytest
from CommonServerPython import DemistoException

from QualysETM import (
    Client,
    active_reports_list_command,
    build_report_generate_body,
    calculate_pagination,
    extract_records,
    is_failure_status,
    report_download_command,
    report_generate_command,
    report_get_details_command,
    reports_delete_command,
)
from QualysETM import test_module as run_test_module

BASE_URL = "https://gateway.qg1.apps.qualys.com"
API_BASE = f"{BASE_URL}/etm/api/rest/v1"
AUTH_URL = f"{BASE_URL}/auth"
REPORT_ID = "0b127284-e128-4d02-a720-2748240c9f1a"


TEST_DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "test_data")


def load_test_data(file_name: str):
    with open(os.path.join(TEST_DATA_DIR, file_name)) as data_file:
        return json.load(data_file)


@pytest.fixture
def client() -> Client:
    return Client(base_url=BASE_URL, username="user", password="pass", verify=False, proxy=False)


@pytest.fixture(autouse=True)
def clear_integration_context(mocker):
    """Isolate each test from the JWT cached in the integration context by a previous test."""
    context: dict = {}
    mocker.patch("QualysETM.get_integration_context", side_effect=lambda: context)
    mocker.patch("QualysETM.set_integration_context", side_effect=context.update)
    return context


""" HELPER FUNCTION TESTS """


@pytest.mark.parametrize(
    "response, expected",
    [
        ([{"id": "a"}], [{"id": "a"}]),
        ({"data": [{"id": "a"}]}, [{"id": "a"}]),
        ({"items": [{"id": "a"}]}, [{"id": "a"}]),
        ({"reports": [{"id": "a"}]}, [{"id": "a"}]),
        ({"id": "a"}, [{"id": "a"}]),
        (None, []),
    ],
)
def test_extract_records(response, expected):
    """
    Given: An API response in one of the shapes the vendor may return.
    When: Normalizing the response into a list of records.
    Then: A list of record dictionaries is returned.
    """
    assert extract_records(response) == expected


@pytest.mark.parametrize(
    "args, expected_offset, expected_limit",
    [
        ({}, 0, 50),
        ({"limit": "10"}, 0, 10),
        ({"page": "1", "page_size": "20"}, 0, 20),
        ({"page": "3", "page_size": "20"}, 40, 20),
        ({"page": "2"}, 50, 50),
        ({"page_size": "15"}, 0, 15),
        ({"page": "2", "page_size": "20", "limit": "5"}, 20, 20),
    ],
)
def test_calculate_pagination(args, expected_offset, expected_limit):
    """
    Given: Pagination arguments in automatic or manual mode.
    When: Translating them to the vendor's offset and limit parameters.
    Then: The offset and limit are computed, and page/page_size take precedence over limit.
    """
    offset, limit, _ = calculate_pagination(args)
    assert offset == expected_offset
    assert limit == expected_limit


@pytest.mark.parametrize("args", [{"page": "0", "page_size": "10"}, {"page_size": "0"}, {"limit": "0"}])
def test_calculate_pagination_invalid(args):
    """
    Given: A pagination argument that is lower than 1.
    When: Translating the arguments to the vendor's parameters.
    Then: A DemistoException is raised.
    """
    with pytest.raises(DemistoException, match="greater than or equal to 1"):
        calculate_pagination(args)


@pytest.mark.parametrize(
    "status, expected",
    [
        ("FAILED", True),
        ("ERROR", True),
        ("CANCELED", True),
        ("EXPIRED", True),
        ("COMPLETED", False),
        ("RUNNING", False),
        ("", False),
    ],
)
def test_is_failure_status(status, expected):
    """
    Given: A report status returned by the API.
    When: Checking whether the status represents a terminal failure.
    Then: Only terminal failure statuses are identified as failures.
    """
    assert is_failure_status(status) is expected


def test_build_report_generate_body():
    """
    Given: Report generation arguments where some are not provided.
    When: Building the submit-findings-report request body.
    Then: The arguments are mapped to the vendor field names and empty values are removed.
    """
    body = build_report_generate_body({"name": "My Report", "findings_qql": "finding.severity: 5", "description": ""})
    assert body == {"name": "My Report", "reportFormat": "JSON", "findingsQql": "finding.severity: 5"}


""" AUTHENTICATION TESTS """


def test_token_is_cached_between_requests(requests_mock, client):
    """
    Given: A client performing two consecutive API requests.
    When: The first request has already obtained and cached a JWT.
    Then: The authentication endpoint is called only once.
    """
    auth_mock = requests_mock.post(AUTH_URL, text="jwt-token")
    requests_mock.get(f"{API_BASE}/reports/{REPORT_ID}", json={"id": REPORT_ID})

    client.get_report_details(REPORT_ID)
    client.get_report_details(REPORT_ID)

    assert auth_mock.call_count == 1


def test_expired_token_triggers_reauthentication_and_retry(requests_mock, client):
    """
    Given: A cached JWT that the API rejects with a 401 response.
    When: An API request is performed.
    Then: The client re-authenticates once and replays the request successfully.
    """
    auth_mock = requests_mock.post(AUTH_URL, text="jwt-token")
    details_mock = requests_mock.get(
        f"{API_BASE}/reports/{REPORT_ID}",
        [{"status_code": 401, "json": {"error": "expired"}}, {"status_code": 200, "json": {"id": REPORT_ID}}],
    )

    assert client.get_report_details(REPORT_ID) == {"id": REPORT_ID}
    assert auth_mock.call_count == 2
    assert details_mock.call_count == 2


def test_persistent_401_is_raised(requests_mock, client):
    """
    Given: An API that keeps rejecting the request with a 401 response.
    When: An API request is performed.
    Then: The retry is not repeated indefinitely and a credentials error is raised.
    """
    requests_mock.post(AUTH_URL, text="jwt-token")
    requests_mock.get(
        f"{API_BASE}/reports/{REPORT_ID}", status_code=401, json=load_test_data("error_401_invalid_credentials.json")
    )

    with pytest.raises(DemistoException, match="Authorization Error"):
        client.get_report_details(REPORT_ID)


def test_empty_token_raises(requests_mock, client):
    """
    Given: An authentication endpoint that returns an empty body.
    When: Authenticating.
    Then: A DemistoException is raised.
    """
    requests_mock.post(AUTH_URL, text="")
    with pytest.raises(DemistoException, match="empty token"):
        client.get_token()


""" COMMAND TESTS """


def test_test_module_verifies_etm_access(requests_mock, client):
    """
    Given: Valid credentials and a subscription with ETM access.
    When: Running the test-module command.
    Then: 'ok' is returned and the report listing endpoint is called.
    """
    requests_mock.post(AUTH_URL, text="jwt-token")
    list_mock = requests_mock.post(f"{API_BASE}/reports/list", json=load_test_data("reports_list_empty.json"))

    assert run_test_module(client) == "ok"
    assert list_mock.call_count == 1


def test_test_module_missing_etm_module(requests_mock, client):
    """
    Given: Valid credentials on a subscription without the ETM module enabled.
    When: Running the test-module command.
    Then: An error explaining the ETM module and API Access requirements is raised.
    """
    requests_mock.post(AUTH_URL, text="jwt-token")
    requests_mock.post(f"{API_BASE}/reports/list", status_code=403, json=load_test_data("error_403_module_access_denied.json"))

    with pytest.raises(DemistoException, match="ETM module is enabled"):
        run_test_module(client)


def test_active_reports_list_command(requests_mock, client):
    """
    Given: A subscription with active reports.
    When: Running the active reports list command.
    Then: The reports are returned to the QualysETM.Report context path.
    """
    requests_mock.post(AUTH_URL, text="jwt-token")
    requests_mock.post(f"{API_BASE}/reports/list", json=load_test_data("reports_list.json"))

    result = active_reports_list_command(client, {})

    assert result.outputs_prefix == "QualysETM.Report"
    assert result.outputs_key_field == "id"
    assert len(result.outputs) == 2
    assert result.outputs[0]["id"] == REPORT_ID
    assert "Qualys ETM Active Reports" in result.readable_output


def test_active_reports_list_truncates_to_limit(requests_mock, client):
    """
    Given: An API that returns more results than the requested limit.
    When: Running the active reports list command with a limit.
    Then: The results are truncated client-side to the requested limit.
    """
    requests_mock.post(AUTH_URL, text="jwt-token")
    requests_mock.post(f"{API_BASE}/reports/list", json=load_test_data("reports_list.json"))

    result = active_reports_list_command(client, {"limit": "1"})

    assert len(result.outputs) == 1


def test_active_reports_list_command_no_results(requests_mock, client):
    """
    Given: A subscription that has no active reports.
    When: Running the active reports list command.
    Then: The command succeeds with empty outputs rather than raising an error.
    """
    requests_mock.post(AUTH_URL, text="jwt-token")
    requests_mock.post(f"{API_BASE}/reports/list", json=load_test_data("reports_list_empty.json"))

    result = active_reports_list_command(client, {})

    assert result.outputs == []
    assert "Qualys ETM Active Reports" in result.readable_output


def test_active_reports_list_sends_computed_offset(requests_mock, client):
    """
    Given: Manual pagination arguments.
    When: Running the active reports list command.
    Then: The computed offset and limit are sent in the request body.
    """
    requests_mock.post(AUTH_URL, text="jwt-token")
    list_mock = requests_mock.post(f"{API_BASE}/reports/list", json=[])

    active_reports_list_command(client, {"page": "3", "page_size": "20"})

    assert list_mock.last_request.json() == {"offset": 40, "limit": 20}


def test_report_get_details_command(requests_mock, client):
    """
    Given: An existing report ID.
    When: Running the report get details command.
    Then: The full report details are returned with a readable output table.
    """
    requests_mock.post(AUTH_URL, text="jwt-token")
    requests_mock.get(f"{API_BASE}/reports/{REPORT_ID}", json=load_test_data("report_details.json"))

    result = report_get_details_command(client, {"report_id": REPORT_ID})

    assert result.outputs_prefix == "QualysETM.Report"
    assert result.outputs["status"] == "COMPLETED"
    assert "john_doe" in result.readable_output
    assert "part_15097524224131306.json" in result.readable_output


def test_report_download_command(requests_mock, client, mocker):
    """
    Given: A completed report with a downloadable resource.
    When: Running the report download command.
    Then: The resource content is returned to the War Room as a file.
    """
    resource_name = "part_15097524224131306.json"
    with open(os.path.join(TEST_DATA_DIR, resource_name), "rb") as resource_file:
        resource_content = resource_file.read()

    requests_mock.post(AUTH_URL, text="jwt-token")
    requests_mock.get(f"{API_BASE}/reports/{REPORT_ID}/resources/{resource_name}", content=resource_content)
    file_result_mock = mocker.patch("QualysETM.fileResult", return_value={"File": resource_name})

    report_download_command(client, {"report_id": REPORT_ID, "resource_name": resource_name})

    file_result_mock.assert_called_once_with(filename=resource_name, data=resource_content)


def test_reports_delete_command(requests_mock, client):
    """
    Given: Report IDs to delete.
    When: Running the reports delete command.
    Then: The IDs are sent as a bare JSON array and the deletion results are returned to the context.
    """
    requests_mock.post(AUTH_URL, text="jwt-token")
    delete_response = load_test_data("delete_reports_response.json")
    deleted_id = delete_response[0]["reportId"]
    delete_mock = requests_mock.delete(f"{API_BASE}/reports", json=delete_response)

    result = reports_delete_command(client, {"report_ids": deleted_id})

    assert delete_mock.last_request.json() == [deleted_id]
    assert result.outputs_prefix == "QualysETM.ReportDeletion"
    assert result.outputs[0]["reportId"] == deleted_id


def test_reports_delete_command_single_object_response(requests_mock, client):
    """
    Given: A delete endpoint that returns a single object instead of a list.
    When: Running the reports delete command.
    Then: The response is normalized into a list.
    """
    requests_mock.post(AUTH_URL, text="jwt-token")
    delete_response = load_test_data("delete_reports_response_single_object.json")
    requests_mock.delete(f"{API_BASE}/reports", json=delete_response)

    result = reports_delete_command(client, {"report_ids": delete_response["reportId"]})

    assert result.outputs == [delete_response]


def test_reports_delete_command_empty_ids(client):
    """
    Given: An empty report_ids argument.
    When: Running the reports delete command.
    Then: A DemistoException is raised before any request is sent.
    """
    with pytest.raises(DemistoException, match="at least one report ID"):
        reports_delete_command(client, {"report_ids": ""})


""" POLLING TESTS """


def test_report_generate_first_run_submits_and_polls(requests_mock, client, mocker):
    """
    Given: A report generation request on its first invocation.
    When: Running the report generate command.
    Then: The report is submitted and the command schedules itself with the returned report ID.
    """
    mocker.patch("CommonServerPython.ScheduledCommand.raise_error_if_not_supported", return_value=None)
    requests_mock.post(AUTH_URL, text="jwt-token")
    submit_mock = requests_mock.post(f"{API_BASE}/reports/findings", json=load_test_data("submit_report_response.json"))

    result = report_generate_command({"name": "My Report"}, client)

    assert submit_mock.last_request.json() == {"name": "My Report", "reportFormat": "JSON"}
    assert result.scheduled_command is not None
    assert result.scheduled_command._args["report_id"] == REPORT_ID


def test_report_generate_submission_without_id(requests_mock, client, mocker):
    """
    Given: A report submission that does not return a report ID.
    When: Running the report generate command.
    Then: A DemistoException is raised.
    """
    mocker.patch("CommonServerPython.ScheduledCommand.raise_error_if_not_supported", return_value=None)
    requests_mock.post(AUTH_URL, text="jwt-token")
    requests_mock.post(f"{API_BASE}/reports/findings", json={})

    with pytest.raises(DemistoException, match="did not return a report ID"):
        report_generate_command({}, client)


def test_report_generate_continues_polling_while_in_progress(requests_mock, client, mocker):
    """
    Given: A report that is still being generated.
    When: Running a polling iteration of the report generate command.
    Then: The command schedules another polling iteration.
    """
    mocker.patch("CommonServerPython.ScheduledCommand.raise_error_if_not_supported", return_value=None)
    requests_mock.post(AUTH_URL, text="jwt-token")
    requests_mock.get(f"{API_BASE}/reports/{REPORT_ID}", json=load_test_data("report_in_progress.json"))

    result = report_generate_command({"report_id": REPORT_ID}, client)

    assert result.scheduled_command is not None
    assert "RUNNING" in result.readable_output


def test_report_generate_fails_fast_on_terminal_status(requests_mock, client, mocker):
    """
    Given: A report whose generation failed on the Qualys side.
    When: Running a polling iteration of the report generate command.
    Then: The command fails immediately instead of polling until the timeout.
    """
    mocker.patch("CommonServerPython.ScheduledCommand.raise_error_if_not_supported", return_value=None)
    requests_mock.post(AUTH_URL, text="jwt-token")
    requests_mock.get(f"{API_BASE}/reports/{REPORT_ID}", json=load_test_data("report_failed.json"))

    with pytest.raises(DemistoException, match="ended with status 'FAILED'"):
        report_generate_command({"report_id": REPORT_ID}, client)


def test_report_generate_downloads_on_completion(requests_mock, client, mocker):
    """
    Given: A report that has completed generation.
    When: Running a polling iteration of the report generate command.
    Then: The report details are returned to the context and the ZIP archive is returned as a file.
    """
    mocker.patch("CommonServerPython.ScheduledCommand.raise_error_if_not_supported", return_value=None)
    archive_buffer = io.BytesIO()
    with zipfile.ZipFile(archive_buffer, "w") as archive:
        archive.writestr("part_1.json", '{"findings": []}')
    archive_bytes = archive_buffer.getvalue()

    requests_mock.post(AUTH_URL, text="jwt-token")
    requests_mock.get(f"{API_BASE}/reports/{REPORT_ID}", json=load_test_data("report_details.json"))
    requests_mock.get(f"{API_BASE}/reports/{REPORT_ID}/download", content=archive_bytes)
    file_result_mock = mocker.patch("QualysETM.fileResult", return_value={"File": f"report_{REPORT_ID}.zip"})

    results = report_generate_command({"report_id": REPORT_ID}, client)

    assert results[0].outputs_prefix == "QualysETM.Report"
    assert results[0].outputs["status"] == "COMPLETED"
    file_result_mock.assert_called_once_with(filename=f"report_{REPORT_ID}.zip", data=archive_bytes)
