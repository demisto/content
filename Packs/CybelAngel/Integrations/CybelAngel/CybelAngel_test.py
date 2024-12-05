import json
from datetime import datetime, timedelta
from unittest.mock import patch

import pytest
from CommonServerPython import *
from CybelAngel import Client, test_module, fetch_incidents, get_report_by_id_command, post_comment_command, get_comments_command, remediate_command, get_report_pdf_command

BASE_URL = "https://platform.cybelangel.com/"
DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


def load_mock_response(file_name: str) -> str:
    """
    Load mock response JSON files for use in tests.
    Args:
        file_name (str): Name of the mock response JSON file to return.
    """
    with open(f"test_data/{file_name}", encoding="utf-8") as mock_file:
        return mock_file.read()


@pytest.fixture
def client():
    """Fixture to create a CybelAngel Client instance."""
    return Client(
        client_id="test_id",
        client_secret="test_secret",
        auth_token="test_token",
    )



def test_fetch_incidents(client, requests_mock):
    """
    Test the `fetch_incidents` function for fetching incidents from the API.
    """
    mock_response = load_mock_response("fetch_incidents.json")
    requests_mock.get(f"{BASE_URL}api/v2/reports", json=json.loads(mock_response))

    last_run = {"start_time": (datetime.utcnow() - timedelta(days=1)).strftime(DATE_FORMAT)}
    incidents = fetch_incidents(client, first_fetch=True, last_run=last_run, first_fetch_interval=1440)

    assert len(incidents) == 4
    raw_json = json.loads(incidents[0]["rawJSON"])
    assert raw_json["id"] == "8bb43081-3349-4c89-b301-8dff0dcca56e"
    assert incidents[1]["severity"] == 3


def test_get_report_by_id_command(client, requests_mock):
    """
    Test the `get_report_by_id_command` function for retrieving a report by ID.
    """
    mock_response = load_mock_response("get_report_by_id.json")
    requests_mock.get(f"{BASE_URL}api/v2/reports/test-report-id", json=json.loads(mock_response))

    args = {"report_id": "test-report-id"}
    result = get_report_by_id_command(client, args)

    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == "CybelAngel.Report"
    assert result.outputs["id"] == "test-report-id"
    assert result.outputs["title"] == "Test Report Title"


def test_fetch_incidents_empty_response(client, requests_mock):
    """
    Test the `fetch_incidents` function when there are no incidents to return.
    """
    mock_response = load_mock_response("empty_response.json")
    requests_mock.get(f"{BASE_URL}api/v2/reports", json=json.loads(mock_response))

    last_run = {"start_time": (datetime.utcnow() - timedelta(days=1)).strftime(DATE_FORMAT)}
    incidents = fetch_incidents(client, first_fetch=True, last_run=last_run, first_fetch_interval=1440)

    assert len(incidents) == 0


def test_fetch_incidents_no_last_run(client, requests_mock):
    """
    Test the `fetch_incidents` function when fetching incidents for the first time.
    """
    mock_response = load_mock_response("fetch_incidents.json")
    requests_mock.get(f"{BASE_URL}api/v2/reports", json=json.loads(mock_response))

    last_run = ""
    incidents = fetch_incidents(client, first_fetch=True, last_run=last_run, first_fetch_interval=1440)

    assert len(incidents) == 4
    raw_json = json.loads(incidents[0]["rawJSON"])
    assert raw_json["id"] == "8bb43081-3349-4c89-b301-8dff0dcca56e"
    assert incidents[1]["severity"] == 3


def test_get_report_attachment(client, requests_mock):
    """
    Test the `get_report_attachment` function for retrieving a report attachment.
    """
    mock_file_content = b"Sample Attachment Content"
    requests_mock.get(f"{BASE_URL}api/v1/reports/test-report-id/attachments/test-attachment-id", content=mock_file_content)

    attachment = client.get_report_attachment("test-report-id", "test-attachment-id")
    assert attachment == mock_file_content


def test_update_status(client, requests_mock):
    """
    Test the `update_status` function for updating the status of a report.
    """
    mock_response = {"status": "success"}
    requests_mock.put(f"{BASE_URL}api/v1/reports/test-report-id/status", json=mock_response)

    status, status_code = client.update_status("resolved", "test-report-id")
    assert status_code == 200
    output_status = json.loads(status)
    assert output_status["status"] == "success"
    
    
    
    
    ### NEW Tests
def test_remediate_command(client, requests_mock):
    """
    Test the `remediate_command` function for submitting a remediation request.
    """
    mock_response = {"status": "remediation_requested"}
    requests_mock.post(f"{BASE_URL}api/v1/reports/remediation-request", json=mock_response)

    args = {
        "report_id": "test-report-id",
        "email": "user@example.com",
        "requester_fullname": "John Doe"
    }
    result = remediate_command(client, args)

    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == "CybelAngel.Remediation"
    assert result.readable_output == "Remediation Status test-report-id : 200"


def test_get_comments_command(client, requests_mock):
    """
    Test the `get_comments_command` function for retrieving comments on a report.
    """
    mock_response = load_mock_response("get_comments.json")
    requests_mock.get(f"{BASE_URL}api/v1/reports/test-report-id/comments", json=json.loads(mock_response))

    args = {"report_id": "test-report-id"}
    result = get_comments_command(client, args)

    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == "CybelAngel.Comments"
    assert len(result.outputs) == 1
    assert result.outputs[0]["content"] == "Body of the comment"
    assert result.outputs[0]["author"]["firstname"] == "John"
    assert result.outputs[0]["author"]["lastname"] == "Doe"
    assert result.outputs[0]["id"] == "3500bb64-6081-4cf5-8e6f-dca82dab4982"


def test_post_comment_command(client, requests_mock):
    """
    Test the `post_comment_command` function for adding a comment to a report.
    """
    mock_response = {"status": "comment_posted"}
    requests_mock.post(f"{BASE_URL}api/v1/reports/test-report-id/comments", json=mock_response)

    args = {
        "report_id": "test-report-id",
        "comment": "This is a test comment",
        "tenant_id": "test-tenant-id"
    }
    result = post_comment_command(client, args["tenant_id"], args)

    assert isinstance(result, CommandResults)
    assert result.readable_output == "Comment added to report test-report-id: This is a test comment : STATUS: 200"


def test_get_report_pdf_command(client, requests_mock):
    """
    Test the `get_report_pdf_command` function for retrieving a report PDF.
    """
    mock_pdf_content = b"%PDF-1.4 Sample PDF content"
    requests_mock.get(f"{BASE_URL}api/v1/reports/test-report-id/pdf", content=mock_pdf_content)

    args = {"report_id": "test-report-id"}
    result = get_report_pdf_command(client, args)

    assert isinstance(result, dict)
    assert result["Type"] == EntryType.FILE
    assert result["File"] == "test-report-id.pdf"
    # Validate the returned data matches what was mocked
    assert result["FileID"] is not None  # Ensure that FileID is generated for the PDF