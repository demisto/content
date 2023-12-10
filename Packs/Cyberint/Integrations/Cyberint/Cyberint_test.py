import json
from datetime import datetime, timedelta
from unittest.mock import patch

import pytest
from CommonServerPython import *

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
        verify_ssl=None,
        proxy=None,
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
        client, {"last_fetch": 100000000}, "3 days", [], [], [], [], 50, duplicate_alerts, "Incoming And Outgoing"
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
        client, {"last_fetch": 100000000}, "3 days", [], [], [], [], 50, False, "Incoming And Outgoing"
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
        client, {"last_fetch": 100000000}, "3 days", [], [], [], [], 50, False, "Incoming And Outgoing"
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

    result = verify_input_date_format("2023-02-14 00:00:57")

    assert result == "2023-02-14 00:00:57Z"


def test_test_module(requests_mock, client):
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

    assert result == "ok"


def test_date_to_epoch_for_fetch():
    """
    Scenario: Verify date conversion to epoch timestamp.
    Given:
     - A valid datetime object.
    When:
     - Converting the datetime to an epoch timestamp for fetch command.
    Then:
     - Ensure that the returned timestamp is in the expected format.
    """
    from Cyberint import date_to_epoch_for_fetch

    input_date = datetime(2023, 2, 14, 0, 0, 57)

    expected_timestamp = int(input_date.timestamp())

    result = date_to_epoch_for_fetch(input_date)

    assert result == expected_timestamp


def test_convert_date_time_args():
    """
    Scenario: Verify conversion of date_time string to datetime.
    Given:
     - A valid date_time string.
    When:
     - Converting the date_time string to a datetime and formatting it.
    Then:
     - Ensure that the returned datetime string matches the expected format.
    """
    from Cyberint import convert_date_time_args

    date_time_str = "2023-02-14 12:30:45"

    expected_result = "2023-02-14T12:30:45Z"

    result = convert_date_time_args(date_time_str)

    assert result == expected_result


def test_get_modified_remote_data(client):
    """
    Scenario: Verify getting modified remote data.
    Given:
     - A valid Cyberint API client.
     - Valid command arguments.
     - Mocked response from the client.
    When:
     - Calling the function to get modified remote data.
    Then:
     - Ensure that the returned response matches the expected format.
    """
    from Cyberint import get_modified_remote_data

    mock_response = {"alerts": [{"ref_id": "incident1"}, {"ref_id": "incident2"}]}

    with patch("Cyberint.Client") as MockClient:
        client_instance = MockClient.return_value
        client_instance.list_alerts.return_value = mock_response

        args = {
            "lastUpdate": "2023-02-14 12:30:45",
        }

        with patch("Cyberint.convert_date_time_args") as mock_convert_date_time_args:
            mock_convert_date_time_args.return_value = "2023-02-14 12:30:45"

            result = get_modified_remote_data(client_instance, args)

            expected_response = GetModifiedRemoteDataResponse(["incident1", "incident2"])
            assert result.modified_incident_ids == expected_response.modified_incident_ids


def test_get_mapping_fields_command():
    """
    Scenario: Verify fetching mapping fields.
    Given:
     - No specific input required for this function.
    When:
     - Calling the function to fetch mapping fields.
    Then:
     - Ensure that the returned response matches the expected format.
    """
    from Cyberint import MIRRORING_FIELDS, get_mapping_fields_command

    result = get_mapping_fields_command()

    expected_response = GetMappingFieldsResponse()
    incident_type_scheme = SchemeTypeMapping(type_name="Cyberint Incident")

    for field in MIRRORING_FIELDS:
        incident_type_scheme.add_field(field)

    expected_response.add_scheme_type(incident_type_scheme)

    assert result.scheme_types_mappings[0].type_name == expected_response.scheme_types_mappings[0].type_name
    assert result.scheme_types_mappings[0].fields == expected_response.scheme_types_mappings[0].fields


def test_get_remote_data_command():
    """
    Scenario: Verify fetching remote data.
    Given:
     - A valid Cyberint API client.
     - Valid command arguments.
     - Mocked response from the client.
    When:
     - Calling the function to fetch remote data.
    Then:
     - Ensure that the returned response matches the expected format.
    """
    from Cyberint import get_remote_data_command

    mock_response = {
        "alert": {
            "alert_ref_id": "incident123",
            "status": "closed",
            "update_date": "2023-02-14 12:30:45",
        }
    }

    with patch("Cyberint.Client") as MockClient:
        client_instance = MockClient.return_value
        client_instance.get_alert.return_value = mock_response

        args = {
            "id": "incident123",
            "lastUpdate": "2023-02-14 12:30:45",
        }

        with patch("Cyberint.arg_to_datetime") as mock_arg_to_datetime:  # noqa: SIM117
            with patch("Cyberint.date_to_epoch_for_fetch") as mock_date_to_epoch_for_fetch:
                mock_arg_to_datetime.return_value = datetime(2023, 2, 14, 12, 30, 45)
                mock_date_to_epoch_for_fetch.return_value = 123456789

                result = get_remote_data_command(client_instance, args, {})

                expected_response = GetRemoteDataResponse(
                    {
                        "alert_ref_id": "incident123",
                        "status": "closed",
                        "update_date": "2023-02-14 12:30:45",
                    },
                    [
                        {
                            "Type": "note",
                            "Contents": {"dbotIncidentClose": True, "closeReason": "Closed from Cyberint."},
                            "ContentsFormat": "json",
                        }
                    ],
                )

                assert result.mirrored_object == expected_response.mirrored_object


def test_update_remote_system():
    """
    Scenario: Verify updating the remote system.
    Given:
     - A valid Cyberint API client.
     - Valid command arguments.
     - Mocked response from the client.
    When:
     - Calling the function to update the remote system.
    Then:
     - Ensure that the remote incident ID is returned.
    """
    from Cyberint import update_remote_system

    mock_response = {
        "result": "success",
    }

    with patch("Cyberint.Client") as MockClient:
        client_instance = MockClient.return_value
        client_instance.update_alerts.return_value = mock_response

        args = {
            "data": {
                "incident_key": "incident123",
                "status": "closed",
            },
            "entries": [],
            "incidentChanged": True,
            "remoteId": "incident123",
            "status": "new_status",
            "delta": {},
        }

        with patch("Cyberint.UpdateRemoteSystemArgs") as mock_UpdateRemoteSystemArgs:
            mock_UpdateRemoteSystemArgs.return_value = UpdateRemoteSystemArgs(args)

            result = update_remote_system(client_instance, args)

            assert result == "incident123"
