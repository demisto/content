import copy
import json
from datetime import datetime, timedelta
from unittest.mock import Mock, patch

import Cyberint
import pytest
from CommonServerPython import DemistoException, EntryType, GetModifiedRemoteDataResponse, GetRemoteDataResponse
from Packs.Cyberint.Integrations.Cyberint.CommonServerPython import IncidentStatus

BASE_URL = "https://test.cyberint.io/alert"
DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


def load_mock_response(file_name: str) -> str:
    """
    Load one of the mock responses to be used for assertion.
    Args:
        file_name (str): Name of the mock response JSON file to return.
    """
    with open(f"test_data/{file_name}", encoding="utf-8") as mock_file:
        return mock_file.read()


@pytest.fixture()
def client():
    from Cyberint import Client

    return Client(
        base_url=BASE_URL,
        access_token="xxx",
        verify_ssl=False,
        proxy=False,
    )


def test_cyberint_alerts_fetch_command(requests_mock, client):
    """
    Scenario: List alerts
    Given:
     - User has provided valid credentials.
    When:
     - cyberint_alert_list is called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    from Cyberint import cyberint_alerts_fetch_command

    mock_response = load_mock_response("csv_example.csv")
    requests_mock.get(f"{BASE_URL}/api/v1/alerts/ARG-3/attachments/X", json=mock_response)
    mock_response = json.loads(load_mock_response("list_alerts.json"))
    requests_mock.post(f"{BASE_URL}/api/v1/alerts", json=mock_response)

    result = cyberint_alerts_fetch_command(client, {})
    assert len(result.outputs) == 3
    assert result.outputs_prefix == "Cyberint.Alert"
    assert result.outputs[0].get("ref_id") == "ARG-3"


def test_cyberint_alerts_fetch_command_invalid_page_size(client):
    from Cyberint import cyberint_alerts_fetch_command

    with pytest.raises(DemistoException, match="Page size must be between 10 and 100."):
        cyberint_alerts_fetch_command(client, {"page_size": "5"})

    with pytest.raises(DemistoException, match="Page size must be between 10 and 100."):
        cyberint_alerts_fetch_command(client, {"page_size": "101"})


def test_cyberint_alerts_status_update_command(requests_mock, client):
    """
    Scenario: Update alert statuses.
    Given:
     - User has provided valid credentials.
    When:
     - cyberint_alert_update is called.
     - Fetch incidents - for each incident
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    from Cyberint import cyberint_alerts_status_update

    mock_response = {}
    requests_mock.put(f"{BASE_URL}/api/v1/alerts/status", json=mock_response)

    result = cyberint_alerts_status_update(client, {"alert_ref_ids": "alert1", "status": "acknowledged"})
    assert len(result.outputs) == 1
    assert result.outputs_prefix == "Cyberint.Alert"
    assert result.outputs[0].get("ref_id") == "alert1"
    result = cyberint_alerts_status_update(client, {"alert_ref_ids": "alert1,alert2", "status": "acknowledged"})
    assert len(result.outputs) == 2
    assert result.outputs_prefix == "Cyberint.Alert"
    assert result.outputs[1].get("ref_id") == "alert2"


def test_cyberint_alerts_status_update_closing_without_reason(client):
    """
    Scenario: Attempt to close an alert without providing a closure reason.
    Given:
     - User attempts to close an alert.
    When:
     - No closure reason is provided.
    Then:
     - Ensure an exception is raised with an appropriate message.
    """

    with pytest.raises(DemistoException, match="You must supply a closure reason when closing an alert."):
        Cyberint.cyberint_alerts_status_update(client, {"alert_ref_ids": "alert1", "status": "closed"})


def test_cyberint_alerts_status_update_other_reason_without_description(client):
    """
    Scenario: Attempt to close an alert with closure_reason='Other' but without closure_reason_description.
    Given:
     - User sets closure_reason to 'Other'.
    When:
     - No closure_reason_description is provided.
    Then:
     - Ensure an exception is raised with an appropriate message.
    """

    with pytest.raises(
        DemistoException, match="You must supply a closure_reason_description when specify closure_reason to 'Other'."
    ):
        Cyberint.cyberint_alerts_status_update(client, {"alert_ref_ids": "alert1", "status": "closed", "closure_reason": "Other"})


@pytest.mark.parametrize(
    "duplicate_alerts",
    [
        (True),
        (False),
    ],
)
def test_fetch_incidents(requests_mock, duplicate_alerts, client) -> None:
    """
    Scenario: Fetch incidents.
    Given:
     - User has provided valid credentials.
     - Headers and JWT token have been set.
    When:
     - Every time fetch_incident is called (either timed or by command).
    Then:
     - Ensure number of incidents is correct.
     - Ensure last_fetch is correctly configured according to mock response.
    """
    from Cyberint import fetch_incidents

    mock_response = load_mock_response("csv_example.csv")
    requests_mock.get(f"{BASE_URL}/api/v1/alerts/ARG-3/attachments/X", json=mock_response)

    with open("test_data/expert_analysis_mock.pdf", "rb") as pdf_content_mock:
        requests_mock.get(f"{BASE_URL}/api/v1/alerts/ARG-4/analysis_report", content=pdf_content_mock.read())
    requests_mock.get(f"{BASE_URL}/api/v1/alerts/ARG-4/attachments/X", json=mock_response)

    mock_response = json.loads(load_mock_response("list_alerts.json"))
    requests_mock.post(f"{BASE_URL}/api/v1/alerts", json=mock_response)

    last_fetch, incidents = fetch_incidents(
        client, {"last_fetch": 100000000}, "3 days", [], [], [], [], 50, duplicate_alerts, "Incoming And Outgoing", False
    )
    wanted_time = datetime.timestamp(datetime.strptime("2020-12-30T00:00:57Z", DATE_FORMAT))
    assert last_fetch.get("last_fetch") == wanted_time * 1000
    assert len(incidents) == 3
    assert incidents[0].get("name") == "Cyberint alert ARG-3: Company Customer Credentials Exposed"


def test_fetch_incidents_no_last_fetch(requests_mock, client):
    """
    Scenario: Fetch incidents for the first time, so there is no last_fetch available.
    Given:
     - User has provided valid credentials.
     - Headers and JWT token have been set.
     - First time running fetch incidents.
    When:
     - Every time fetch_incident is called (either timed or by command).
    Then:
     - Ensure number of incidents is correct.
     - Ensure last_fetch is correctly configured according to mock response.
    """
    from Cyberint import fetch_incidents

    mock_response = load_mock_response("csv_example.csv")
    requests_mock.get(f"{BASE_URL}/api/v1/alerts/ARG-3/attachments/X", json=mock_response)

    with open("test_data/expert_analysis_mock.pdf", "rb") as pdf_content_mock:
        requests_mock.get(f"{BASE_URL}/api/v1/alerts/ARG-4/analysis_report", content=pdf_content_mock.read())
    requests_mock.get(f"{BASE_URL}/api/v1/alerts/ARG-4/attachments/X", json=mock_response)

    mock_response = json.loads(load_mock_response("list_alerts.json"))
    requests_mock.post(f"{BASE_URL}/api/v1/alerts", json=mock_response)

    last_fetch, incidents = fetch_incidents(client, {}, "3 days", [], [], [], [], 50, False, "Incoming And Outgoing", False)
    wanted_time = datetime.timestamp(datetime.strptime("2020-12-30T00:00:57Z", DATE_FORMAT))
    assert last_fetch.get("last_fetch") == wanted_time * 1000
    assert len(incidents) == 3
    assert incidents[0].get("name") == "Cyberint alert ARG-3: Company Customer Credentials Exposed"


def test_fetch_incidents_empty_response(requests_mock, client):
    """
    Scenario: Fetch incidents but there are no incidents to return.
    Given:
     - User has provided valid credentials.
     - Headers and JWT token have been set.
    When:
     - Every time fetch_incident is called (either timed or by command).
     - There are no incidents to return.
    Then:
     - Ensure number of incidents is correct (None).
     - Ensure last_fetch is correctly configured according to mock response.
    """
    from Cyberint import fetch_incidents

    mock_response = json.loads(load_mock_response("empty.json"))
    requests_mock.post(f"{BASE_URL}/api/v1/alerts", json=mock_response)

    last_fetch, incidents = fetch_incidents(
        client, {"last_fetch": 100000000}, "3 days", [], [], [], [], 50, False, "Incoming And Outgoing", False
    )
    assert last_fetch.get("last_fetch") == 100001000
    assert len(incidents) == 0


def test_set_date_pair():
    """
    Scenario: Set date_start and date_end for both creation and modification.
    Given:
     - User has provided valid credentials.
    When:
     - Every time cyberint_list_alerts is called.
    Then:
     - Ensure dates return match what is needed (correct format)
    """
    from Cyberint import set_date_pair

    start_time = "2020-12-01T00:00:00Z"
    end_time = "2020-12-05T00:00:00Z"
    assert set_date_pair(start_time, end_time, None) == (start_time, end_time)
    new_range = "3 Days"
    three_days_ago = datetime.strftime(datetime.now() - timedelta(days=3), DATE_FORMAT)
    current_time = datetime.strftime(datetime.now(), DATE_FORMAT)
    assert set_date_pair(start_time, end_time, new_range) == (three_days_ago, current_time)

    assert set_date_pair(start_time, None, None) == (start_time, datetime.strftime(datetime.now(), DATE_FORMAT))
    assert set_date_pair(None, end_time, None) == (
        datetime.strftime(datetime.fromisocalendar(2020, 2, 1), DATE_FORMAT),
        end_time,
    )


def test_extract_data_from_csv_stream(requests_mock, client):
    """
    Scenario: Extract data out of a downloaded csv file.
    Given:
     - User has provided valid credentials.
    When:
     - A fetch command is called and there is a CSV file reference in the response.
    Then:
     - Ensure all fields in the CSV are returned.
     - Ensure the wanted fields are found when downloaded.
     - Ensure a sample value matches what is in the sample CSV.
    """
    from Cyberint import CSV_FIELDS_TO_EXTRACT, extract_data_from_csv_stream

    mock_response = load_mock_response("csv_no_username.csv")
    requests_mock.get(f"{BASE_URL}/api/v1/alerts/alert_id/attachments/123", json=mock_response)
    result = extract_data_from_csv_stream(client, "alert_id", "123")
    assert len(result) == 0
    mock_response = load_mock_response("csv_example.csv")
    requests_mock.get(f"{BASE_URL}/api/v1/alerts/alert_id/attachments/123", json=mock_response)
    result = extract_data_from_csv_stream(client, "alert_id", "123", delimiter=b"\\n")
    assert len(result) == 6
    assert list(result[0].keys()) == [value.lower() for value in CSV_FIELDS_TO_EXTRACT]
    assert result[0]["username"] == "l1"


def test_cyberint_alerts_analysis_report_command(requests_mock, client):
    """
    Scenario: Retrieve expert analysis report.
    Given:
     - User has provided valid credentials and arguments.
    When:
     - A alerts-analysis-report is called and there analysis report reference in the response.
    Then:
     - Ensure that the return ContentsFormat of the file is 'text'.
     - Ensure that the return Type is file.
     - Ensure the name of the file.
    """
    from Cyberint import cyberint_alerts_get_analysis_report_command

    with open("test_data/expert_analysis_mock.pdf", "rb") as pdf_content_mock:
        requests_mock.get(f"{BASE_URL}/api/v1/alerts/ARG-4/analysis_report", content=pdf_content_mock.read())

    result = cyberint_alerts_get_analysis_report_command(client, "ARG-4", "expert_analysis_mock.pdf")
    assert result["ContentsFormat"] == "text"
    assert result["Type"] == EntryType.FILE
    assert result["File"] == "expert_analysis_mock.pdf"


def test_cyberint_alerts_get_attachment_command(requests_mock, client):
    """
    Scenario: Retrieve alert attachment.
    Given:
     - User has provided valid credentials and arguments.
    When:
     - A alerts-get-attachment called and there attachments reference in the response.
    Then:
     - Ensure that the return ContentsFormat of the file is 'text'.
     - Ensure that the return Type is file.
     - Ensure the name of the file.
    """
    from Cyberint import cyberint_alerts_get_attachment_command

    with open("test_data/attachment_file_mock.png", "rb") as png_content_mock:
        requests_mock.get(f"{BASE_URL}/api/v1/alerts/ARG-3/attachments/X", content=png_content_mock.read())

    result = cyberint_alerts_get_attachment_command(client, "ARG-3", "X", "attachment_file_mock.png")
    assert result["ContentsFormat"] == "text"
    assert result["Type"] == EntryType.FILE
    assert result["File"] == "attachment_file_mock.png"


def test_verify_input_date_format():
    """
    Scenario: Verify date format.
    Given:
     - User has provided valid credentials and arguments (date).
    When:
     - Using date for commands.
    Then:
     - Ensure that the return date is according to Cyberint format.
    """
    from Cyberint import verify_input_date_format

    result1 = verify_input_date_format("2023-02-14 00:00:57")
    result2 = verify_input_date_format("2023-02-15 00:00:57Z")
    result3 = verify_input_date_format(None)

    assert result1 == "2023-02-14 00:00:57Z"
    assert result2 == "2023-02-15 00:00:57Z"
    assert result3 is None


def test_test_module_ok(requests_mock, client):
    """
    Scenario: Verify date format.
    Given:
     - User has provided valid credentials and arguments (date).
    When:
     - Using date for commands.
    Then:
     - Ensure that the return date is according to Cyberint format.
    """
    from Cyberint import test_module

    mock_response = json.loads(load_mock_response("list_alerts.json"))
    requests_mock.post(f"{BASE_URL}/api/v1/alerts", json=mock_response)

    result = test_module(client)

    assert result is not None


def test_test_module_invalid_token(requests_mock, client):
    """
    Scenario: API returns an error for an invalid or expired token.
    Given:
     - User provides invalid or expired credentials.
    When:
     - A request is made to the Cyberint API.
    Then:
     - A DemistoException is raised with an appropriate error message.
    """

    error_response = {"error": "Invalid token or token expired"}
    requests_mock.post(f"{BASE_URL}/api/v1/alerts", status_code=401, json=error_response)

    assert (
        Cyberint.test_module(client)
        == "Error verifying access token and / or URL, make sure the configuration parameters are correct."
    )


def test_test_module_error(requests_mock, client):
    """
    Scenario: API returns an error for an invalid or expired token.
    Given:
     - User provides invalid or expired credentials.
    When:
     - A request is made to the Cyberint API.
    Then:
     - A DemistoException is raised with an appropriate error message.
    """

    error_response = {"error": "Not found"}
    requests_mock.post(f"{BASE_URL}/api/v1/alerts", status_code=404, json=error_response)

    assert Cyberint.test_module(client) == 'Error in API call [404] - None\n{"error": "Not found"}'


def test_get_alert_attachments_with_analysis_report(requests_mock, client):
    alert_id = "ARG-3"
    with open("test_data/expert_analysis_mock.pdf", "rb") as pdf_content_mock:
        requests_mock.get(f"{BASE_URL}/api/v1/alerts/{alert_id}/analysis_report", content=pdf_content_mock.read())

    attachment_list = [{"id": "123", "name": "report.pdf", "mimetype": "application/pdf"}]

    result = Cyberint.get_alert_attachments(client, attachment_list, "analysis_report", alert_id)

    assert result is not None


@patch("Cyberint.get_attachment_name")
@patch("Cyberint.fileResult")
def test_create_fetch_incident_attachment(mock_file_result, mock_get_attachment_name):
    # Mock the raw_response content
    mock_raw_response = Mock()
    mock_raw_response.content = b"mock binary content"

    # Define the input attachment file name
    attachment_file_name = "example_attachment.pdf"

    # Mock the get_attachment_name function to return a processed attachment name
    mock_get_attachment_name.return_value = "processed_example_attachment.pdf"

    # Mock the fileResult function to simulate a successful file save with a FileID
    mock_file_result.return_value = {"FileID": "file_12345"}

    # Call the function
    result = Cyberint.create_fetch_incident_attachment(mock_raw_response, attachment_file_name)

    # Expected result
    expected_result = {
        "path": "file_12345",
        "name": "processed_example_attachment.pdf",
        "showMediaFile": True,
    }

    # Assertions
    assert result == expected_result
    mock_get_attachment_name.assert_called_once_with(attachment_file_name)
    mock_file_result.assert_called_once_with(filename="processed_example_attachment.pdf", data=b"mock binary content")


def test_get_alert_attachments_with_attachment_type(requests_mock, client):
    alert_id = "ARG-3"

    attachment_list = [{"id": "456", "name": "file.txt", "mimetype": "text/plain"}]
    mock_response = load_mock_response("csv_example.csv")

    requests_mock.get(f"{BASE_URL}/api/v1/alerts/{alert_id}/attachments/456", json=mock_response)

    result = Cyberint.get_alert_attachments(client, attachment_list, "attachment", alert_id)

    assert result is not None


def test_get_alert_attachments_with_empty_attachment_list(client):
    alert_id = "ARG-3"
    result = Cyberint.get_alert_attachments(client, [], "attachment", alert_id)

    # Assertions
    assert result == []


def test_get_alert_attachments_with_none_in_attachment_list(requests_mock, client):
    alert_id = "ARG-3"
    attachment_list = [{"id": "789", "name": "image.png", "mimetype": "image/png"}]
    mock_response = load_mock_response("csv_example.csv")

    requests_mock.get(f"{BASE_URL}/api/v1/alerts/ARG-3/attachments/789", json=mock_response)

    result = Cyberint.get_alert_attachments(client, attachment_list, "attachment", alert_id)

    assert result is not None


def test_get_attachment_name(client):
    """
    Scenario: Retrieve attachment name.
    Given:
    - User has provided valid credentials and arguments.
    """
    from Cyberint import get_attachment_name

    assert get_attachment_name("dummy") == "dummy"
    assert get_attachment_name("") == "xsoar_untitled_attachment"


def test_get_remote_data_command_with_open_incident(requests_mock, client):
    from Cyberint import get_remote_data_command

    args = {"id": 123, "lastUpdate": "2024-06-10T12:00:00Z", "remote_incident_id": 123, "last_update": "2024-06-10T12:00:00Z"}
    params = {"close_incident": False}
    mock_response = load_mock_response("alert_open.json")
    requests_mock.get(f"{BASE_URL}/api/v1/alerts/{args['id']}", json=mock_response)

    response = get_remote_data_command(client, args, params)

    assert response is not None


def test_get_remote_data_command_with_closed_incident(requests_mock, client):
    from Cyberint import get_remote_data_command

    args = {"id": 124, "lastUpdate": "2024-06-10T12:00:00Z", "remote_incident_id": 124, "last_update": "2024-06-10T12:00:00Z"}
    params = {"close_incident": True}
    mock_response = load_mock_response("alert_closed.json")
    requests_mock.get(f"{BASE_URL}/api/v1/alerts/{args['id']}", json=mock_response)

    response = get_remote_data_command(client, args, params)

    assert response is not None


def test_get_remote_data_command_with_missing_update_date(requests_mock, client):
    from Cyberint import get_remote_data_command

    args = {"id": 125, "lastUpdate": "2024-06-10T12:00:00Z", "remote_incident_id": 125, "last_update": "2024-06-10T12:00:00Z"}
    params = {"close_incident": True}

    mock_response = {
        "alert": {"id": "125", "status": "closed", "closure_reason": "Resolved", "closure_reason_description": "Issue mitigated"}
    }
    requests_mock.get(f"{BASE_URL}/api/v1/alerts/{args['id']}", json=mock_response)

    response = get_remote_data_command(client, args, params)

    assert isinstance(response, GetRemoteDataResponse)
    assert response.mirrored_object["cyberintstatus"] is None
    assert response.entries[0]["Contents"]["dbotIncidentClose"] is True


def test_get_remote_data_command_with_none_response(requests_mock, client, capfd):
    from Cyberint import get_remote_data_command

    args = {"id": 125, "lastUpdate": "2024-06-10T12:00:00Z", "remote_incident_id": 125, "last_update": "2024-06-10T12:00:00Z"}
    params = {"close_incident": True}

    mock_response = "null"
    requests_mock.get(f"{BASE_URL}/api/v1/alerts/{args['id']}", json=mock_response)

    response = get_remote_data_command(client, args, params)

    captured = capfd.readouterr()
    assert captured.out == "Invalid response from Cyberint\n"
    assert isinstance(response, GetRemoteDataResponse)


def test_get_remote_data_command_invalid_response(requests_mock, client):
    from Cyberint import get_remote_data_command

    args = {"id": 126, "lastUpdate": "2024-06-10T12:00:00Z", "remote_incident_id": 126, "last_update": "2024-06-10T12:00:00Z"}
    params = {"close_incident": True}

    requests_mock.get(f"{BASE_URL}/api/v1/alerts/{args['id']}", text='{"invalid": "response"}')

    response = get_remote_data_command(client, args, params)

    assert isinstance(response, GetRemoteDataResponse)
    assert response.mirrored_object == {}
    assert len(response.entries) == 0


def test_convert_date_time_args():
    """
    Test the convert_date_time_args function to ensure it correctly converts date arguments.
    """
    args = "2024-01-01T12:00:00Z"

    result = Cyberint.convert_date_time_args(args)
    assert result == args


def test_convert_date_time_args_empty():
    """
    Test the convert_date_time_args function to ensure it returns an empty string for invalid or missing date arguments.
    """
    # Test with None
    with patch("Cyberint.arg_to_datetime", return_value=None):
        result_none = Cyberint.convert_date_time_args(None)
        assert result_none == ""

    # Test with an invalid date string
    with patch("Cyberint.arg_to_datetime", return_value=None):
        invalid_date = "invalid-date-format"
        result_invalid = Cyberint.convert_date_time_args(invalid_date)
        assert result_invalid == ""


def test_get_mapping_fields_command():
    """
    Test the get_mapping_fields_command function to ensure it returns the correct response.
    """
    result = Cyberint.get_mapping_fields_command()
    not_expected = {}
    assert result is not not_expected


def test_date_to_epoch_for_fetch():
    """
    Test date_to_epoch_for_fetch for converting ISO date to epoch.
    """
    result = Cyberint.date_to_epoch_for_fetch("2024-11-06T08:56:41")
    assert result is not None


def test_cyberint_alerts_fetch_command_empty_response(requests_mock, client):
    """
    Scenario: Fetch alerts when the API returns an empty response.
    Given:
     - User has provided valid credentials.
    When:
     - The API returns an empty list of alerts.
    Then:
     - Ensure the result outputs are an empty list.
    """
    from Cyberint import cyberint_alerts_fetch_command

    mock_response = {"alerts": []}
    requests_mock.post(f"{BASE_URL}/api/v1/alerts", json=mock_response)

    result = cyberint_alerts_fetch_command(client, {})
    assert result.outputs == []


def test_extract_data_from_csv_stream_malformed_csv(requests_mock, client):
    """
    Scenario: Extract data from a malformed CSV.
    Given:
     - The CSV file content is not formatted properly.
    When:
     - extract_data_from_csv_stream is called.
    Then:
     - Ensure an empty list is returned.
    """
    from Cyberint import extract_data_from_csv_stream

    malformed_csv_content = "username,email\ninvalid_row"
    requests_mock.get(f"{BASE_URL}/api/v1/alerts/alert_id/attachments/123", text=malformed_csv_content)

    result = extract_data_from_csv_stream(client, "alert_id", "123")
    assert len(result) == 0


def test_cyberint_alerts_get_attachment_command_not_found(requests_mock, client):
    """
    Scenario: Retrieve an attachment that does not exist.
    Given:
     - User has provided valid credentials.
    When:
     - The attachment ID does not exist.
    Then:
     - Ensure a DemistoException is raised with a 404 error.
    """
    from Cyberint import cyberint_alerts_get_attachment_command

    requests_mock.get(f"{BASE_URL}/api/v1/alerts/ARG-3/attachments/invalid", status_code=404)

    with pytest.raises(DemistoException, match="Error in API call \\[404\\]"):
        cyberint_alerts_get_attachment_command(client, "ARG-3", "invalid", "missing_file.png")


def test_date_formatting():
    """
    Test date formatting handling within the script.
    """
    from Cyberint import convert_date_time_args

    invalid_date = "2024-13-40T25:61:00.000000Z"

    with pytest.raises(ValueError, match='"2024-13-40T25:61:00.000000Z" is not a valid date'):
        convert_date_time_args(invalid_date)


def test_edge_case_handling(requests_mock, client):
    """
    Test that edge cases are handled correctly, such as empty responses.
    """
    from Cyberint import cyberint_alerts_fetch_command

    requests_mock.post(f"{BASE_URL}/api/v1/alerts", json={})  # Empty response

    result = cyberint_alerts_fetch_command(client, {})

    assert result is not None


@pytest.mark.parametrize(
    "last_update, api_response, expected_tickets",
    [
        (
            "2024-12-25T10:00:00Z",
            {"alerts": [{"ref_id": "123"}, {"ref_id": "456"}, {"ref_id": "789"}]},
            ["123", "456", "789"],
        ),
        (
            "2024-12-26T10:00:00Z",
            {"alerts": []},  # No modified alerts
            [],
        ),
    ],
)
@patch("Cyberint.convert_date_time_args")
@patch("Cyberint.Client.list_alerts")
def test_get_modified_remote_data(
    mock_list_alerts, mock_convert_date_time_args, last_update, api_response, expected_tickets, client
):
    """
    Test the get_modified_remote_data function to ensure it correctly retrieves and processes modified incidents.
    """
    from Cyberint import get_modified_remote_data

    # Mock the dependencies
    mock_convert_date_time_args.return_value = "2024-12-25T10:00:00Z"  # Simulate converted date
    mock_list_alerts.return_value = api_response  # Simulate API response

    # Prepare arguments
    args = {"last_update": last_update, "lastUpdate": last_update}

    # Call the function
    result = get_modified_remote_data(client, args)

    # Validate the result
    assert isinstance(result, GetModifiedRemoteDataResponse)
    assert result.modified_incident_ids == expected_tickets

    # Validate mocked dependencies were called correctly
    mock_convert_date_time_args.assert_called_once_with(last_update)
    mock_list_alerts.assert_called_once_with(
        page="1",
        page_size=50,
        update_date_from="2024-12-25T10:00:00Z",
        update_date_to=datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ"),  # DATE_FORMAT
        created_date_from=None,
        created_date_to=None,
        modification_date_from=None,
        modification_date_to=None,
        environments=None,
        statuses=None,
        severities=None,
        types=None,
    )


def test_update_remote_system_xsoar_incident_closed(requests_mock, client):
    """
    Test update_remote_system when XSOAR incident is closed (inc_status=2).
    """
    from Cyberint import update_remote_system

    requests_mock.put(f"{BASE_URL}/api/v1/alerts/status", json={})

    args = {
        "remoteId": "INT-123",
        "status": IncidentStatus.DONE,  # XSOAR closed status
        "incidentChanged": True,
        "delta": {"closure_reason": "Resolved"},  # Human-readable display value from XSOAR
        "data": {},
    }

    result = update_remote_system(client, args)
    req = requests_mock.last_request

    assert req.method == "PUT"
    assert req.url == f"{BASE_URL}/api/v1/alerts/status"

    payload = req.json()
    assert payload == {
        "alert_ref_ids": ["INT-123"],
        "data": {
            "closure_reason": "resolved",  # API value (converted from display value)
            "closure_reason_description": "Closed from XSOAR",
            "status": "closed",
        },
    }

    assert result == "INT-123"


def test_update_remote_system_status_closed_in_delta(requests_mock, client):
    """
    Test update_remote_system when status is closed in delta.
    """
    from Cyberint import update_remote_system

    requests_mock.put(f"{BASE_URL}/api/v1/alerts/status", json={})

    args = {
        "remoteId": "INT-124",
        "status": 1,
        "incidentChanged": True,
        "delta": {"status": "closed", "closure_reason": "Other"},  # Human-readable display value
        "data": {},
    }

    result = update_remote_system(client, args)
    assert result == "INT-124"


def test_update_remote_system_no_description_uses_default(requests_mock, client):
    """
    Test update_remote_system falls back to 'Closed from XSOAR' when no description provided.
    """
    from Cyberint import update_remote_system

    requests_mock.put(f"{BASE_URL}/api/v1/alerts/status", json={})

    args = {
        "remoteId": "INT-126",
        "status": IncidentStatus.DONE,
        "incidentChanged": True,
        "delta": {"closure_reason": "False Positive"},  # No description provided
        "data": {},
    }

    result = update_remote_system(client, args)
    req = requests_mock.last_request

    payload = req.json()
    assert payload == {
        "alert_ref_ids": ["INT-126"],
        "data": {
            "closure_reason": "false_positive",
            "closure_reason_description": "Closed from XSOAR",  # Default fallback
            "status": "closed",
        },
    }

    assert result == "INT-126"


def test_update_remote_system_cyberint_alert_already_closed(requests_mock, client):
    """
    Test update_remote_system when Cyberint alert is already closed.
    """
    from Cyberint import update_remote_system

    mock_alert = {"alert": {"status": "closed", "closure_reason": "resolved", "closure_reason_description": "Already resolved"}}
    requests_mock.get(f"{BASE_URL}/api/v1/alerts/INT-125", json=mock_alert)
    requests_mock.put(f"{BASE_URL}/api/v1/alerts/status", json={})

    args = {
        "remoteId": "INT-125",
        "status": 1,
        "incidentChanged": True,
        "delta": {},  # No status change
        "data": {},
    }

    result = update_remote_system(client, args)
    assert result == "INT-125"


def load_employee_credentials_alert() -> dict:
    return json.loads(load_mock_response("employee_credentials_alert.json"))["alerts"][0]


def test_add_login_url_fields_employee_credentials():
    """
    Given:
     - A compromised employee credentials alert with a related asset and no designated_url.
    When:
     - add_login_url_fields is called.
    Then:
     - login_url, related_asset_name and related_asset_id hold the related asset values in full.
     - designated_url is added to alert_data and to every exposed credential.
     - alert_data.domain is unchanged.
    """
    from Cyberint import add_login_url_fields

    alert = load_employee_credentials_alert()
    add_login_url_fields(alert)

    assert alert["login_url"] == "corp.example.com"
    assert alert["related_asset_name"] == "corp.example.com"
    assert alert["related_asset_id"] == "/Example/corp.example.com"
    assert alert["alert_data"]["domain"] == "example.com"
    assert alert["alert_data"]["designated_url"] == "corp.example.com"
    assert all(row["designated_url"] == "corp.example.com" for row in alert["alert_data"]["csv"]["content"])


def test_add_login_url_fields_customer_credentials_keeps_designated_url():
    """
    Given:
     - A compromised customer credentials alert that already has alert_data.designated_url.
    When:
     - add_login_url_fields is called.
    Then:
     - login_url is the existing designated_url and alert_data is not changed.
    """
    from Cyberint import add_login_url_fields

    alert = json.loads(load_mock_response("list_alerts.json"))["alerts"][0]
    alert_data_before = copy.deepcopy(alert["alert_data"])
    add_login_url_fields(alert)

    assert alert["login_url"] == "https://www.barclaycardus.com/servicing/authenticate"
    assert alert["related_asset_name"] == ""
    assert alert["related_asset_id"] == ""
    assert alert["alert_data"] == alert_data_before


@pytest.mark.parametrize(
    "related_assets, alert_data",
    [
        (None, None),
        ([], {}),
        ([None], {"domain": "example.com"}),
        ([{"id": None, "name": None}], {"csv": {"content": None}}),
    ],
)
def test_add_login_url_fields_missing_values(related_assets, alert_data):
    """
    Given:
     - An employee credentials alert with missing, empty or null related assets and alert data.
    When:
     - add_login_url_fields is called.
    Then:
     - The new keys are empty strings and no error is raised.
     - designated_url is not added.
    """
    from Cyberint import add_login_url_fields

    alert = {"type": "compromised_employee_credentials", "related_assets": related_assets, "alert_data": alert_data}
    add_login_url_fields(alert)

    assert alert["login_url"] == ""
    assert alert["related_asset_name"] == ""
    assert alert["related_asset_id"] == ""
    assert "designated_url" not in (alert["alert_data"] or {})


@pytest.mark.parametrize("duplicate_alerts", [True, False])
def test_fetch_incidents_employee_credentials_login_url(requests_mock, client, duplicate_alerts):
    """
    Given:
     - The API returns a compromised employee credentials alert with a related asset.
    When:
     - fetch_incidents is called, with and without splitting the alert per credential.
    Then:
     - Every incident rawJSON holds login_url, related_asset_name, related_asset_id and alert_data.domain.
     - In split mode, attachments.content.designated_url is set, like in customer credentials incidents.
    """
    from Cyberint import fetch_incidents

    requests_mock.post(f"{BASE_URL}/api/v1/alerts", json=json.loads(load_mock_response("employee_credentials_alert.json")))
    requests_mock.get(f"{BASE_URL}/api/v1/alerts/ARG-10/attachments/19879773", text="Username,Password\r\nuser1,*****")

    _, incidents = fetch_incidents(
        client, {"last_fetch": 100000000}, "3 days", [], [], [], [], 50, duplicate_alerts, "Incoming And Outgoing", False
    )

    assert len(incidents) == (2 if duplicate_alerts else 1)
    for incident in incidents:
        raw_alert = json.loads(incident["rawJSON"])
        assert raw_alert["login_url"] == "corp.example.com"
        assert raw_alert["related_asset_name"] == "corp.example.com"
        assert raw_alert["related_asset_id"] == "/Example/corp.example.com"
        assert raw_alert["alert_data"]["domain"] == "example.com"
        if duplicate_alerts:
            assert raw_alert["attachments"]["content"]["designated_url"] == "corp.example.com"


@pytest.mark.parametrize(
    "related_assets, expected_login_url",
    [
        ([{"id": "keyword/Example/example asset", "name": "example asset", "type": "keyword"}], ""),
        (
            [
                {"id": "keyword/Example/example asset", "name": "example asset", "type": "keyword"},
                {"id": "subdomain/Example/login.example.com", "name": "login.example.com", "type": "subdomain"},
            ],
            "login.example.com",
        ),
        ([{"id": "url/Example/https://example.com/login", "name": "https://example.com/login", "type": "url"}], "https://example.com/login"),
        ([{"id": "/Example/corp.example.com", "name": "corp.example.com"}], "corp.example.com"),
        ([{"id": "/Example/", "name": "", "type": ""}], ""),
        (
            [
                {"id": "keyword/Example/example asset", "name": "example asset", "type": "keyword"},
                {"id": "domain/Example/example.com", "name": "example.com", "type": "domain"},
                {"id": "employee login interface/Example/Login page", "name": "Login page", "type": "employee login interface"},
            ],
            "Login page",
        ),
    ],
)
def test_add_login_url_fields_asset_types(related_assets, expected_login_url):
    """
    Given:
     - An employee credentials alert whose related assets have different types.
    When:
     - add_login_url_fields is called.
    Then:
     - login_url is the first asset that can be a login address. Keyword assets are skipped.
     - related_asset_name and related_asset_id always hold the first asset, whatever its type.
    """
    from Cyberint import add_login_url_fields

    alert = {"type": "compromised_employee_credentials", "related_assets": related_assets, "alert_data": {"domain": "example.com"}}
    add_login_url_fields(alert)

    assert alert["login_url"] == expected_login_url
    assert alert["related_asset_name"] == related_assets[0]["name"]
    assert alert["related_asset_id"] == related_assets[0]["id"]
    assert alert["alert_data"].get("designated_url", "") == expected_login_url


LOGIN_ASSET = {"id": "employee login interface/Example/Login page", "name": "Login page", "type": "employee login interface"}
KEYWORD_ASSET = {"id": "keyword/Example/example asset", "name": "example asset", "type": "keyword"}
GROUP = {"id": 1, "name": "Example Group"}


@pytest.mark.parametrize(
    "related_assets, expected_login_url",
    [
        ([{"id": "company/Example/Example", "name": "Example", "type": "company"}], ""),
        ([{"id": "product/Example/Example App", "name": "Example App", "type": "product"}], "Example App"),
        ([KEYWORD_ASSET, {"id": "Employee Login Interface/Example/Portal", "name": "Portal", "type": "Employee Login Interface"}], "Portal"),
    ],
)
def test_add_login_url_fields_skips_keyword_and_company(related_assets, expected_login_url):
    """
    Given:
     - An employee credentials alert with company, product or mixed-case login interface assets.
    When:
     - add_login_url_fields is called.
    Then:
     - Company and keyword assets are never used as the login URL, other types are, and type matching ignores case.
    """
    from Cyberint import add_login_url_fields

    alert = {"type": "compromised_employee_credentials", "related_assets": related_assets, "alert_data": {}}
    add_login_url_fields(alert)

    assert alert["login_url"] == expected_login_url


def test_merge_related_assets():
    """
    Given:
     - Alert related assets, one with an empty name, and fetched related assets with groups and an extra asset.
    When:
     - merge_related_assets is called.
    Then:
     - Assets are matched by ID, non-empty fetched values win, and the extra fetched asset is appended.
    """
    from Cyberint import merge_related_assets

    alert_assets = [{**LOGIN_ASSET, "name": ""}, KEYWORD_ASSET]
    fetched_assets = [{**LOGIN_ASSET, "asset_groups": [GROUP]}, {"id": "domain/Example/example.com", "name": "example.com"}]

    merged = merge_related_assets(alert_assets, fetched_assets)

    assert merged == [
        {**LOGIN_ASSET, "asset_groups": [GROUP]},
        KEYWORD_ASSET,
        {"id": "domain/Example/example.com", "name": "example.com"},
    ]


def test_format_asset_groups():
    """
    Given:
     - Related assets with and without asset groups.
    When:
     - format_asset_groups is called.
    Then:
     - Only assets in a group are listed, as "<name> (<type>): <groups>".
    """
    from Cyberint import format_asset_groups

    related_assets = [{**LOGIN_ASSET, "asset_groups": [GROUP, {"id": 2, "name": "Other"}]}, {**KEYWORD_ASSET, "asset_groups": []}]

    assert format_asset_groups(related_assets) == "Login page (employee login interface): Example Group, Other"
    assert format_asset_groups(None) == ""


def test_enrich_alerts_with_asset_groups(requests_mock, client):
    """
    Given:
     - Three alerts: the related-assets endpoint answers 200, 404 and 503.
    When:
     - enrich_alerts_with_asset_groups is called.
    Then:
     - The first alert gets asset groups and a summary, the others are left unchanged.
    """
    from Cyberint import enrich_alerts_with_asset_groups

    requests_mock.get(
        f"{BASE_URL}/api/v1/alerts/ARG-1/related-assets", json={"related_assets": [{**LOGIN_ASSET, "asset_groups": [GROUP]}]}
    )
    requests_mock.get(f"{BASE_URL}/api/v1/alerts/ARG-2/related-assets", status_code=404, json={"error": True})
    requests_mock.get(f"{BASE_URL}/api/v1/alerts/ARG-3/related-assets", status_code=503, json={"error": True})
    alerts = [{"ref_id": f"ARG-{index}", "related_assets": [LOGIN_ASSET]} for index in (1, 2, 3)]

    enrich_alerts_with_asset_groups(client, alerts)

    assert alerts[0]["related_assets"] == [{**LOGIN_ASSET, "asset_groups": [GROUP]}]
    assert alerts[0]["asset_groups"] == "Login page (employee login interface): Example Group"
    for alert in alerts[1:]:
        assert alert["related_assets"] == [LOGIN_ASSET]
        assert "asset_groups" not in alert


def test_enrich_alerts_with_asset_groups_stops_on_error(requests_mock, client):
    """
    Given:
     - The related-assets endpoint answers 401 for the first alert.
    When:
     - enrich_alerts_with_asset_groups is called.
    Then:
     - No error is raised and no further requests are sent.
    """
    from Cyberint import enrich_alerts_with_asset_groups

    first = requests_mock.get(f"{BASE_URL}/api/v1/alerts/ARG-1/related-assets", status_code=401, json={"error": True})
    second = requests_mock.get(f"{BASE_URL}/api/v1/alerts/ARG-2/related-assets", json={"related_assets": []})
    alerts = [{"ref_id": "ARG-1"}, {"ref_id": "ARG-2"}]

    enrich_alerts_with_asset_groups(client, alerts)

    assert first.call_count == 1
    assert second.call_count == 0
    assert all("asset_groups" not in alert for alert in alerts)


@pytest.mark.parametrize("fetch_asset_groups", [True, False])
def test_fetch_incidents_asset_groups(requests_mock, client, fetch_asset_groups):
    """
    Given:
     - The API returns an employee credentials alert, and its related-assets endpoint returns asset groups.
    When:
     - fetch_incidents is called with fetch_asset_groups enabled or disabled.
    Then:
     - The endpoint is called only when enabled, and only then the incident rawJSON holds asset_groups.
    """
    from Cyberint import fetch_incidents

    requests_mock.post(f"{BASE_URL}/api/v1/alerts", json=json.loads(load_mock_response("employee_credentials_alert.json")))
    requests_mock.get(f"{BASE_URL}/api/v1/alerts/ARG-10/attachments/19879773", text="Username,Password\r\nuser1,*****")
    related_assets_mock = requests_mock.get(
        f"{BASE_URL}/api/v1/alerts/ARG-10/related-assets",
        json={"related_assets": [{"id": "/Example/corp.example.com", "name": "corp.example.com", "type": "domain", "asset_groups": [GROUP]}]},
    )

    _, incidents = fetch_incidents(
        client, {"last_fetch": 100000000}, "3 days", [], [], [], [], 50, False, "Incoming And Outgoing", False, fetch_asset_groups
    )

    raw_alert = json.loads(incidents[0]["rawJSON"])
    assert related_assets_mock.called == fetch_asset_groups
    assert raw_alert["login_url"] == "corp.example.com"
    if fetch_asset_groups:
        assert raw_alert["asset_groups"] == "corp.example.com (domain): Example Group"
    else:
        assert "asset_groups" not in raw_alert
