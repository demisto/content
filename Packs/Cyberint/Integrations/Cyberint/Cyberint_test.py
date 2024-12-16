import json
from datetime import datetime, timedelta
from unittest.mock import Mock, patch

import pytest

from CommonServerPython import EntryType, DemistoException
from Cyberint import cyberint_alerts_status_update, test_module, get_alert_attachments, create_fetch_incident_attachment, \
    convert_date_time_args, get_mapping_fields_command, date_to_epoch_for_fetch

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
        cyberint_alerts_status_update(client, {"alert_ref_ids": "alert1", "status": "closed"})


def test_cyberint_alerts_status_update_other_reason_without_description(client):
    """
    Scenario: Attempt to close an alert with closure_reason='other' but without closure_reason_description.
    Given:
     - User sets closure_reason to 'other'.
    When:
     - No closure_reason_description is provided.
    Then:
     - Ensure an exception is raised with an appropriate message.
    """

    with pytest.raises(DemistoException,
                       match="You must supply a closure_reason_description when specify closure_reason to 'other'."):
        cyberint_alerts_status_update(client, {"alert_ref_ids": "alert1", "status": "closed", "closure_reason": "other"})


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

    last_fetch, incidents = fetch_incidents(
        client, {"last_fetch": 100000000}, "3 days", [], [], [], [], 50, False, "Incoming And Outgoing", False
    )
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

    with pytest.raises(DemistoException,
                       match="Error verifying access token and / or URL, make sure the configuration parameters are correct."):
        test_module(client)


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

    error_response = {"error": "Unexpected error"}
    requests_mock.post(f"{BASE_URL}/api/v1/alerts", status_code=503, json=error_response)

    with pytest.raises(DemistoException, match="Unexpected error"):
        test_module(client)


def test_get_alert_attachments_with_analysis_report(requests_mock, client):
    alert_id = "ARG-3"
    with open("test_data/expert_analysis_mock.pdf", "rb") as pdf_content_mock:
        requests_mock.get(f"{BASE_URL}/api/v1/alerts/{alert_id}/analysis_report", content=pdf_content_mock.read())

    attachment_list = [{"id": "123", "name": "report.pdf", "mimetype": "application/pdf"}]

    result = get_alert_attachments(client, attachment_list, "analysis_report", alert_id)

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
    result = create_fetch_incident_attachment(mock_raw_response, attachment_file_name)

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

    result = get_alert_attachments(client, attachment_list, "attachment", alert_id)

    assert result is not None


def test_get_alert_attachments_with_empty_attachment_list(client):
    alert_id = "ARG-3"
    result = get_alert_attachments(client, [], "attachment", alert_id)

    # Assertions
    assert result == []


def test_get_alert_attachments_with_none_in_attachment_list(requests_mock, client):
    alert_id = "ARG-3"
    attachment_list = [{"id": "789", "name": "image.png", "mimetype": "image/png"}]
    mock_response = load_mock_response("csv_example.csv")

    requests_mock.get(f"{BASE_URL}/api/v1/alerts/ARG-3/attachments/789", json=mock_response)

    result = get_alert_attachments(client, attachment_list, "attachment", alert_id)

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


def test_get_remote_data_command_with_closed_incident(requests_mock, client):

    from Cyberint import get_remote_data_command

    args = {
        "id": 123,
        "lastUpdate": "2024-06-10T12:00:00Z",
        "remote_incident_id": 123,
        "last_update": "2024-06-10T12:00:00Z"
    }
    params = {
        "close_incident": True
    }
    mock_response = load_mock_response("alert.json")
    requests_mock.get(f"{BASE_URL}/api/v1/alerts/{args['id']}", json=mock_response)

    response = get_remote_data_command(client, args, params)

    assert response is not None


def test_convert_date_time_args():
    """
    Test the convert_date_time_args function to ensure it correctly converts date arguments.
    """
    args = "2024-01-01T12:00:00Z"

    result = convert_date_time_args(args)
    assert result == args


def test_get_mapping_fields_command():
    """
    Test the get_mapping_fields_command function to ensure it returns the correct response.
    """
    result = get_mapping_fields_command()
    not_expected = {}
    assert result is not not_expected


def test_date_to_epoch_for_fetch():
    """
    Test date_to_epoch_for_fetch for converting ISO date to epoch.
    """
    expected = 1730883401
    result = date_to_epoch_for_fetch("2024-11-06T08:56:41")
    assert result == expected
