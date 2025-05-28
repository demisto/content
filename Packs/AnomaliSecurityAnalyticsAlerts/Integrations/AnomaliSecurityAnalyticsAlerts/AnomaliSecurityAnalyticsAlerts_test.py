from AnomaliSecurityAnalyticsAlerts import (
    Client,
    command_create_search_job,
    command_get_search_job_status,
    command_get_search_job_results,
    command_update_alert,
    fetch_incidents,
)
from CommonServerPython import *
from CommonServerUserPython import *
from freezegun import freeze_time
import pytest


@freeze_time("2025-03-01")
def test_command_create_search_job(mocker):
    """
    Given:
        - Valid query, source, from, to and timezone parameters

    When:
        - client.create_search_job returns a job id

    Then:
        - Validate that command_create_search_job returns a CommandResults object
          with outputs containing the correct job_id and a status of "in progress"

    """
    client = Client(server_url="https://test.com", username="test_user", api_key="test_api_key", verify=True, proxy=False)

    return_data = {"job_id": "1234"}
    mocker.patch.object(client, "_http_request", return_value=return_data)

    args = {"query": "alert", "source": "source", "from": "1 day", "to": "1 hour"}

    result = command_create_search_job(client, args)
    assert isinstance(result, CommandResults)
    outputs = result.outputs
    assert outputs.get("job_id") == "1234"
    assert "Search Job Created" in result.readable_output


def test_command_get_search_job_status_running(mocker):
    """
    Given:
        - A job_id whose search job is still RUNNING.

    When:
        - client.get_search_job_status returns a non-DONE status.

    Then:
        - Validate that CommandResults is returned with correct status and job_id.
    """
    client = Client(server_url="https://test.com", username="test_user", api_key="test_api_key", verify=True, proxy=False)

    status_response = {"status": "RUNNING", "progress": 0.5}
    mocker.patch.object(client, "_http_request", return_value=status_response)

    args = {"job_id": "job_running"}
    results = command_get_search_job_status(client, args)

    assert isinstance(results, list)
    assert len(results) == 1
    assert results[0].outputs["status"] == "RUNNING"
    assert results[0].outputs["job_id"] == "job_running"
    assert "Search Job Status" in results[0].readable_output


def test_command_get_search_job_results_completed_with_fields(mocker):
    """
    Given:
        - A valid job_id with a status of DONE.

    When:
        - client.get_search_job_status returns DONE and client.get_search_job_results returns a response with fields and records.

    Then:
        - Validate that command_get_search_job_results returns a CommandResults object with a markdown table.

    """
    client = Client(server_url="https://test.com", username="test_user", api_key="test_api_key", verify=True, proxy=False)

    results_response = {
        "fields": ["event_time", "sourcetype", "dcid", "src"],
        "records": [
            ["1727647847687", "myexamplesourcetype", "78", "1.2.3.4"],
            ["1727647468096", "aws_cloudtrail", "1", "1.2.3.5"],
        ],
        "types": ["timestamp", "string", "string", "string"],
        "result_row_count": 2,
        "status": "DONE",
    }
    mocker.patch.object(client, "_http_request", return_value=results_response)

    args = {"job_id": "job_done", "offset": 0, "fetch_size": 2}

    results = command_get_search_job_results(client, args)
    assert isinstance(results, list)
    assert len(results) == 1
    outputs = results[0].outputs
    assert outputs.get("job_id") == "job_done"

    expected_records = [
        {"event_time": "1727647847687", "sourcetype": "myexamplesourcetype", "dcid": "78", "src": "1.2.3.4"},
        {"event_time": "1727647468096", "sourcetype": "aws_cloudtrail", "dcid": "1", "src": "1.2.3.5"},
    ]
    assert outputs.get("records") == expected_records

    readable_output = results[0].readable_output
    assert "Search Job Results" in readable_output
    for header in ["event_time", "sourcetype", "dcid", "src"]:
        assert header in readable_output


def test_command_get_search_job_status_invalid(mocker):
    """
    Given:
        - An invalid job_id

    When:
        - client.get_search_job_status returns an error message

    Then:
        - Validate that CommandResults is returned with error in readable_output.
    """
    client = Client(server_url="https://test.com", username="test_user", api_key="test_api_key", verify=True, proxy=False)

    error_response = {"error": "Invalid Job ID"}
    mocker.patch.object(client, "_http_request", return_value=error_response)

    args = {"job_id": "invalid_job"}
    results = command_get_search_job_status(client, args)

    assert isinstance(results, list)
    assert len(results) == 1
    assert "Failed to retrieve status" in results[0].readable_output
    assert "Invalid Job ID" in results[0].readable_output


def test_command_get_search_job_results_no_fields_records(mocker):
    """
    Given:

        - A valid job_id

    When:
        - client.get_search_job_results returns a response without 'fields' and 'records'

    Then:
        - Validate that command_get_search_job_results returns a list of CommandResults
          with the expected output from the fallback branch
    """
    client = Client(server_url="https://test.com", username="test_user", api_key="test_api_key", verify=True, proxy=False)

    results_response = {"result": "raw data", "complete": True}
    mocker.patch.object(client, "_http_request", return_value=results_response)

    args = {"job_id": "job_no_fields", "offset": 0, "fetch_size": 2}

    results = command_get_search_job_results(client, args)

    assert isinstance(results, list)
    assert len(results) == 1
    outputs = results[0].outputs
    assert outputs == results_response

    human_readable = results[0].readable_output
    assert "Search Job Results" in human_readable
    assert "raw data" in human_readable


def test_command_update_alert_status_and_comment(mocker):
    """
    Given:
        - 'status', 'comment' and 'uuid' parameters

    When:
        - client.update_alert returns a response

    Then:
        - Validate that command_update_alert returns a CommandResults object
          with outputs equal to the mocked response

    """
    client = Client(server_url="https://test.com", username="test_user", api_key="test_api_key", verify=True, proxy=False)

    return_data = {"updated": True}
    mocker.patch.object(client, "_http_request", return_value=return_data)

    args = {"status": "IN_PROGRESS", "comment": "Test comment", "uuid": "alert-uuid-123"}

    result = command_update_alert(client, args)
    assert isinstance(result, CommandResults)
    assert "Alert Updated Successfully" in result.readable_output
    assert result.outputs["updated_fields"] == {"status": "IN_PROGRESS", "comment": "Test comment"}


def test_command_update_alert_with_unsupported_fields(mocker):
    """
    Given:
        - 'status', 'uuid' and an unsupported field 'foo', 'foo' will be ingored

    When:
        - client.update_alert returns a response

    Then:
        - Validate that unsupported field is ignored and appears in ignored_fields.
    """
    client = Client(server_url="https://test.com", username="test_user", api_key="test_api_key", verify=True, proxy=False)

    mocker.patch.object(client, "_http_request", return_value={"updated": True})

    args = {"uuid": "alert-uuid-456", "status": "CLOSED", "foo": "bar"}

    result = command_update_alert(client, args)

    assert isinstance(result, CommandResults)
    assert "Alert Updated Successfully" in result.readable_output
    assert result.outputs["updated_fields"] == {"status": "CLOSED"}


def test_command_update_alert_no_supported_fields(mocker):
    """
    Given:
        - Only 'uuid' and unsupported field
    When:
        - command_update_alert is invoked
    Then:
        - Validate that DemistoException is raised for having no valid fields to update.
    """
    client = Client(server_url="https://test.com", username="test_user", api_key="test_api_key", verify=True, proxy=False)

    args = {"uuid": "1234", "foo": "bar"}

    with pytest.raises(DemistoException, match="No valid fields provided to update"):
        command_update_alert(client, args)


def test_command_update_alert_no_uuid(mocker):
    """
    Given:
        - No 'uuid' parameter provided
    When:
        - command_update_alert is invoked
    Then:
        - Validate that DemistoException is raised for missing UUID parameter
    """
    client = Client(server_url="https://test.com", username="test_user", api_key="test_api_key", verify=True, proxy=False)

    args = {"status": "closed"}

    with pytest.raises(DemistoException) as e:
        command_update_alert(client, args)
    assert "Please provide 'uuid' parameter" in str(e.value)


@freeze_time("2025-03-01T12:00:00Z")
def test_fetch_incidents(mocker):
    """
    Given:
        - Valid parameters
    When:
        - fetch_incidents is invoked
    Then:
        - Validate that fetch_incidents returns a list of incidents
    """
    client = Client(server_url="https://test.com", username="test_user", api_key="test_api_key", verify=True, proxy=False)
    mocker.patch.object(client, "create_search_job", return_value={"job_id": "12345"})

    mocker.patch.object(client, "get_search_job_status", return_value={"status": "DONE"})

    mocker.patch.object(
        client,
        "get_search_job_results",
        return_value={"fields": ["uuid_", "event_time", "severity"], "records": [["abc-123", "1727613600000", "high"]]},
    )

    mocker.patch("CommonServerPython.demisto.params", return_value={"first_fetch": "3 days"})
    mocker.patch("CommonServerPython.demisto.getLastRun", return_value={})
    mocker.patch("CommonServerPython.demisto.setLastRun")

    incidents = fetch_incidents(client)

    assert isinstance(incidents, list)
    assert len(incidents) == 1
    incident = incidents[0]
    assert "rawJSON" in incident
    assert "occurred" in incident
    assert "name" in incident
    assert incident["name"].startswith("Anomali Alert")


@freeze_time("2025-03-01T12:00:00Z")
def test_fetch_incidents_with_offset(mocker):
    """
    Given:
        - A last run state with a non-zero offset
        - A full page of results equal to fetch_limit
    When:
        - fetch_incidents is invoked
    Then:
        - Validate that offset is incremented and last_fetch is unchanged
    """
    client = Client(server_url="https://test.com", username="test_user", api_key="test_api_key", verify=True, proxy=False)

    mocker.patch.object(client, "create_search_job", return_value={"job_id": "job-id-456"})
    mocker.patch.object(client, "get_search_job_status", return_value={"status": "DONE"})

    fetch_limit = 3
    sample_records = [
        ["abc-001", "1727613600000", "low"],
        ["abc-002", "1727613610000", "medium"],
        ["abc-003", "1727613620000", "high"],
    ]
    mocker.patch.object(
        client,
        "get_search_job_results",
        return_value={"fields": ["uuid_", "event_time", "severity"], "records": sample_records},
    )

    mocker.patch("CommonServerPython.demisto.params", return_value={"first_fetch": "3 days", "fetch_limit": fetch_limit})
    mocker.patch("CommonServerPython.demisto.getLastRun", return_value={"last_fetch": "2024-01-01T00:00:00Z", "offset": 3})
    set_last_run_mock = mocker.patch("CommonServerPython.demisto.setLastRun")

    incidents = fetch_incidents(client)

    assert isinstance(incidents, list)
    assert len(incidents) == 3
    for incident in incidents:
        assert "name" in incident
        assert "occurred" in incident
        assert "rawJSON" in incident

    args, _ = set_last_run_mock.call_args
    new_last_run = args[0]
    assert new_last_run["offset"] == 6
    assert "last_fetch" in new_last_run
