from AnomaliSecurityAnalyticsAlerts import Client, command_create_search_job, command_get_search_job_results, command_update_alert
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


def test_command_get_search_job_results_running(mocker):
    """
    Given:
        - A valid job_id with a status that is not DONE.

    When:
        - client.get_search_job_status returns a status like "RUNNING".

    Then:
        - Validate that command_get_search_job_results returns a CommandResults object
          with a message indicating that the job is still running.

    """
    client = Client(server_url="https://test.com", username="test_user", api_key="test_api_key", verify=True, proxy=False)

    status_response = {"status": "RUNNING"}
    mocker.patch.object(client, "_http_request", return_value=status_response)

    args = {"job_id": "job_running", "offset": 0, "fetch_size": 2}

    results = command_get_search_job_results(client, args)
    assert isinstance(results, list)
    assert len(results) == 1
    outputs = results[0].outputs
    assert outputs.get("job_id") == "job_running"
    assert outputs.get("status") == "RUNNING"
    readable_output = results[0].readable_output
    assert "is still running" in readable_output


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

    status_response = {"status": "DONE"}
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
    mocker.patch.object(client, "_http_request", side_effect=[status_response, results_response])

    args = {"job_id": "job_done", "offset": 0, "fetch_size": 2}

    results = command_get_search_job_results(client, args)
    assert isinstance(results, list)
    assert len(results) == 1
    outputs = results[0].outputs
    assert outputs.get("job_id") == "job_done"
    assert "fields" not in outputs
    expected_records = [
        {"event_time": "1727647847687", "sourcetype": "myexamplesourcetype", "dcid": "78", "src": "1.2.3.4"},
        {"event_time": "1727647468096", "sourcetype": "aws_cloudtrail", "dcid": "1", "src": "1.2.3.5"},
    ]
    assert outputs.get("records") == expected_records

    readable_output = results[0].readable_output
    assert "Search Job Results" in readable_output
    for header in ["event_time", "sourcetype", "dcid", "src"]:
        assert header in readable_output


def test_command_get_search_job_results_invalid(mocker):
    """
    Given:
        - An invalid job_id.

    When:
        - client.get_search_job_status returns a response with an error.

    Then:
        - Validate that command_get_search_job_results returns a CommandResults
        object with a friendly message and no context data.
    """
    client = Client(server_url="https://test.com", username="test_user", api_key="test_api_key", verify=True, proxy=False)

    status_response = {"error": "Invalid Job ID"}
    mocker.patch.object(client, "_http_request", return_value=status_response)

    args = {"job_id": "invalid_job", "offset": 0, "fetch_size": 2}

    results = command_get_search_job_results(client, args)
    assert isinstance(results, list)
    assert len(results) == 1
    readable_output = results[0].readable_output
    assert "No results found for Job ID: invalid_job" in readable_output
    assert "Error message: Invalid Job ID" in readable_output
    assert "Please verify the Job ID and try again." in readable_output


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

    status_response = {"status": "DONE"}
    results_response = {"result": "raw data", "complete": True}
    mocker.patch.object(client, "_http_request", side_effect=[status_response, results_response])

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
