import json
from datetime import datetime, timedelta, UTC
import pytest
from CommonServerPython import *
from CybelAngel import (
    Client, get_report_by_id_command, post_comment_command,
    get_comments_command, remediate_command,
    get_report_pdf_command, _datetime_helper, _set_context, get_report_attachment_command, update_status_command,
    fetch_incidents, test_module)

BASE_URL = "https://platform.cybelangel.com/"
DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


def load_mock_response(file_name: str) -> str:

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
    mock_response = load_mock_response("fetch_incidents.json")
    requests_mock.get(f"{BASE_URL}api/v2/reports", json=json.loads(mock_response))

    last_run = {"start_time": (datetime.now(UTC) - timedelta(days=1)).strftime(DATE_FORMAT)}
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

    last_run = {"start_time": (datetime.now(UTC) - timedelta(days=1)).strftime(DATE_FORMAT)}
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

    # NEW Tests


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


def test_token_error_handling(client, requests_mock):
    requests_mock.post("https://auth.cybelangel.com/oauth/token", status_code=500)
    result = client.fetch_token()
    assert "Error fetching token" in result["msg"]


def test_check_token_initial(client):
    """Test initial token check when token_time is None"""
    client.token_time = None
    client.check_token()
    assert client.token is not None


def test_post_comment_with_parent(client, requests_mock):
    """Test posting a comment with a parent_id"""
    mock_response = {"status": "comment_posted"}
    requests_mock.post(f"{BASE_URL}api/v1/reports/test-report-id/comments", json=mock_response)

    response, status_code = client.post_comment(
        comment="Reply comment",
        report_id="test-report-id",
        tenant_id="test-tenant-id",
        parent_id="parent-comment-id"
    )
    assert status_code == 200


def test_get_report_by_id_error(client, requests_mock):
    """Test error handling in get_report_by_id"""
    requests_mock.get(f"{BASE_URL}api/v2/reports/invalid-id", status_code=404)
    result = client.get_report_by_id("invalid-id")
    assert isinstance(result, list)
    assert "Error getting report" in result[0]["msg"]


def test_get_comments_error(client, requests_mock):
    """Test error handling in get_comments"""
    requests_mock.get(f"{BASE_URL}api/v1/reports/test-id/comments",
                      exc=requests.exceptions.HTTPError)
    with pytest.raises(SystemExit):
        client.get_comments("test-id")


def test_test_module(client, requests_mock):
    mock_response = {"reports": [{"id": "test"}]}
    requests_mock.get(f"{BASE_URL}api/v2/reports", json=mock_response)
    assert test_module(client) == "ok"


def test_test_module_error(client, requests_mock):
    """Testing error case for test_module"""
    requests_mock.get(f"{BASE_URL}api/v2/reports", status_code=403)
    client.token = None  # Force auth error
    assert test_module(client) == "ok"


def test_datetime_helper():
    """Test the datetime helper function"""
    past_date = (datetime.now(UTC) - timedelta(minutes=30)).strftime(DATE_FORMAT)
    minutes = _datetime_helper(past_date)
    assert 29 <= minutes <= 31  # Allow small timing differences


def test_set_context(client):
    client.new_token_fetched = True
    client.token = "test-token"
    client.token_time = "2024-02-06 12:00:00.000000"
    _set_context(client)
    context = demisto.getIntegrationContext()
    assert context["token"] == "test-token"
    assert context.get("first_pull") == "False"  # Comparing strings


# --- Command tests

def test_get_report_attachment_command(client, requests_mock):
    mock_content = b"test attachment content"
    requests_mock.get(f"{BASE_URL}api/v1/reports/test-id/attachments/att-id", content=mock_content)

    result = get_report_attachment_command(client, {
        'report_id': 'test-id',
        'attachment_id': 'att-id',
        'filename': 'test.txt'
    })
    assert result['Type'] == EntryType.FILE
    assert result['File'] == 'test.txt'


def test_get_report_attachment_error(client, requests_mock):
    requests_mock.get(f"{BASE_URL}api/v1/reports/test-id/attachments/att-id", exc=Exception("Download failed"))

    result = get_report_attachment_command(client, {
        'report_id': 'test-id',
        'attachment_id': 'att-id',
        'filename': 'test.txt'
    })
    assert result.readable_output == 'Error downloading attachment: Download failed'


def test_update_status_command(client, requests_mock):
    mock_response = {"status": "updated"}
    requests_mock.put(f"{BASE_URL}api/v1/reports/test-id/status", json=mock_response)

    result = update_status_command(client, {
        'report_id': 'test-id',
        'status': 'resolved'
    })
    assert result.outputs_prefix == 'CybelAngel.StatusUpdate'
    assert 'updated' in result.raw_response[0]


def test_update_status_error(client, requests_mock):
    requests_mock.put(f"{BASE_URL}api/v1/reports/test-id/status", exc=Exception("Update failed"))

    result = update_status_command(client, {
        'report_id': 'test-id',
        'status': 'resolved'
    })
    assert 'Error Updating status' in result.readable_output


def test_fetch_incidents_with_invalid_response(client, requests_mock):
    requests_mock.get(f"{BASE_URL}api/v2/reports", json={"reports": []})

    incidents = fetch_incidents(client, first_fetch=True, last_run="", first_fetch_interval=1)
    assert len(incidents) == 0


def test_get_report_pdf_command_missing_id(client):
    result = get_report_pdf_command(client, {})
    assert result.readable_output == "Report ID not provided."


def test_client_initialization():
    """Test Client initialization with various parameter combinations"""
    # Test with minimum required parameters
    client1 = Client(client_id="test_id", client_secret="test_secret")
    assert client1.client_id == "test_id"
    assert client1.client_secret == "test_secret"
    assert client1.token is None

    # Test with all parameters
    client2 = Client(
        client_id="test_id",
        client_secret="test_secret",
        auth_token="existing_token",
        token_time="2024-02-19T12:00:00Z"
    )
    assert client2.token == "existing_token"
    assert client2.token_time == "2024-02-19T12:00:00Z"


def test_fetch_token_success(requests_mock):
    """Test successful token fetch"""
    client = Client(client_id="test_id", client_secret="test_secret")
    mock_response = {"access_token": "new_token"}
    requests_mock.post("https://auth.cybelangel.com/oauth/token", json=mock_response)

    client.fetch_token()
    assert client.token == "Bearer new_token"
    assert client.new_token_fetched is True


def test_get_reports_success(client, requests_mock):
    """Test successful retrieval of reports"""
    mock_response = {
        "reports": [
            {"id": "1", "title": "Report 1"},
            {"id": "2", "title": "Report 2"}
        ]
    }
    requests_mock.get(f"{BASE_URL}api/v2/reports", json=mock_response)

    reports = client.get_reports(interval=60)
    assert len(reports) == 2
    assert reports[0]["id"] == "1"
    assert reports[1]["title"] == "Report 2"


def test_get_all_reports_success(client, requests_mock):
    """Test successful retrieval of all reports"""
    mock_response = {
        "reports": [
            {"id": "1", "title": "Old Report"},
            {"id": "2", "title": "Recent Report"}
        ]
    }
    requests_mock.get(f"{BASE_URL}api/v2/reports", json=mock_response)

    reports = client.get_all_reports()
    assert len(reports) == 2
    assert all(isinstance(report, dict) for report in reports)


def test_get_all_reports_error(client, requests_mock):
    """Test error handling in get_all_reports"""
    requests_mock.get(f"{BASE_URL}api/v2/reports", status_code=500)

    reports = client.get_all_reports()
    assert len(reports) == 1
    assert "Error getting reports" in reports[0]["msg"]


def test_fetch_incidents_command_complete(client, requests_mock):
    """Test the complete fetch_incidents command flow"""
    # Mock successful token refresh
    mock_token_response = {"access_token": "new_token"}
    requests_mock.post("https://auth.cybelangel.com/oauth/token", json=mock_token_response)

    # Mock reports response
    mock_reports_response = {
        "reports": [
            {
                "incident_id": "test-1",
                "created_at": "2024-02-19T10:00:00",
                "severity": 3,
                "category": "test",
                "abstract": "Test incident"
            }
        ]
    }
    requests_mock.get(f"{BASE_URL}api/v2/reports", json=mock_reports_response)

    # Test first fetch
    incidents = fetch_incidents(
        client,
        first_fetch=True,
        last_run=None,
        first_fetch_interval=1
    )

    assert len(incidents) == 1
    assert incidents[0]["name"] == "CybelAngel Report - test-1"
    assert incidents[0]["severity"] == 3
    assert incidents[0]["category"] == "test"
