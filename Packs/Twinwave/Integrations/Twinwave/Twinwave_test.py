from unittest.mock import MagicMock

import pytest
import demistomock as demisto

import Twinwave


def test_get_api_url_uses_version_path():
    assert Twinwave.get_api_url("api.twinwave.io") == "https://api.twinwave.io/v1/"
    regional_host = "api.eu1.twinwave.io"
    assert Twinwave.get_api_url(regional_host, version="v2") == f"https://{regional_host}/v2/"


def test_get_api_url_rejects_unsupported_host():
    with pytest.raises(ValueError) as error:
        Twinwave.get_api_url("api.invalid.twinwave.io")

    for host in Twinwave.SUPPORTED_API_HOSTS:
        assert host in str(error.value)


def test_client_initialization():
    client = Twinwave.Client(api_token="test-token", verify=False, proxy=False)

    assert client._base_url == "https://api.twinwave.io/v1/"
    assert client._verify is False
    assert client._headers == {
        "X-API-KEY": "test-token",
        "User-Agent": Twinwave.USER_AGENT,
    }


def test_get_recent_jobs_uses_content_client(mocker):
    client = Twinwave.Client(api_token="test-token", verify=True, proxy=False)
    request = mocker.patch.object(client, "_http_request", return_value={"Jobs": []})

    result = client.get_recent_jobs(num_jobs=20, username="alice", source="ui", state="done")

    assert result == {"Jobs": []}
    request.assert_called_once_with(
        "GET",
        url_suffix="jobs/recent",
        params={"count": 20, "username": "alice", "source": "ui", "state": "done"},
    )


def test_download_job_pdf_uses_binary_response(mocker):
    client = Twinwave.Client(api_token="test-token", verify=True, proxy=False)
    request = mocker.patch.object(client, "_http_request", return_value=b"%PDF-1.7")

    assert client.download_job_pdf("job-123") == b"%PDF-1.7"
    request.assert_called_once_with(
        "GET",
        url_suffix="jobs/job-123/pdfreport",
        resp_type="content",
    )


@pytest.mark.parametrize("response_data", [{"error": "not found"}, {"forensics": []}])
def test_get_task_raw_forensics_allows_not_found(mocker, response_data):
    client = Twinwave.Client(api_token="test-token", verify=True, proxy=False)
    response = MagicMock()
    response.json.return_value = response_data
    request = mocker.patch.object(client, "_http_request", return_value=response)

    assert client.get_task_raw_forensics("job-123", "task-456") == response_data
    request.assert_called_once_with(
        "GET",
        url_suffix="jobs/job-123/tasks/task-456/rawforensics",
        resp_type="response",
        ok_codes=(200, 404),
    )


def test_submit_url_uses_json_body(mocker):
    client = Twinwave.Client(api_token="test-token", verify=True, proxy=False)
    request = mocker.patch.object(client, "_http_request", return_value={"ID": "job-123"})

    result = client.submit_url(
        scan_url="https://example.com",
        engine_list=["engine-a"],
        parameters="{}",
        priority=10,
        profile="default",
    )

    assert result == {"ID": "job-123"}
    request.assert_called_once_with(
        "POST",
        url_suffix="jobs/urls",
        json_data={
            "url": "https://example.com",
            "engines": ["engine-a"],
            "parameters": "{}",
            "priority": 10,
            "profile": "default",
        },
    )


def test_submit_file_uses_multipart_form_data(mocker):
    client = Twinwave.Client(api_token="test-token", verify=True, proxy=False)
    request = mocker.patch.object(client, "_http_request", return_value={"ID": "job-123"})

    result = client.submit_file(
        file_name="sample.exe",
        file_obj=b"file-content",
        engine_list=["engine-a"],
        priority=10,
        profile="default",
    )

    assert result == {"ID": "job-123"}
    request.assert_called_once_with(
        "POST",
        url_suffix="jobs/files",
        data={
            "engines": '["engine-a"]',
            "filename": "sample.exe",
            "priority": 10,
            "profile": "default",
        },
        files={"filedata": b"file-content"},
    )


def test_submit_file_uses_entry_filename_when_override_is_missing(mocker, tmp_path):
    file_path = tmp_path / "sample.exe"
    file_path.write_bytes(b"file-content")
    mocker.patch.object(demisto, "getFilePath", return_value={"path": str(file_path), "name": "sample.exe"})
    client = MagicMock()
    client.submit_file.return_value = {"JobID": "job-123"}

    Twinwave.submit_file(client, {"entry_id": "entry-123", "priority": "10"})

    client.submit_file.assert_called_once_with(
        file_name="sample.exe",
        file_obj=b"file-content",
        engine_list=[],
        priority=10,
        profile=None,
    )


def test_submit_file_uses_filename_override(mocker, tmp_path):
    file_path = tmp_path / "sample.bin"
    file_path.write_bytes(b"file-content")
    mocker.patch.object(demisto, "getFilePath", return_value={"path": str(file_path), "name": "sample.bin"})
    client = MagicMock()
    client.submit_file.return_value = {"JobID": "job-123"}

    Twinwave.submit_file(client, {"entry_id": "entry-123", "filename": "sample.exe", "priority": "10"})

    assert client.submit_file.call_args.kwargs["file_name"] == "sample.exe"


def test_submit_file_rejects_missing_file_entry(mocker):
    mocker.patch.object(demisto, "getFilePath", return_value=None)

    with pytest.raises(Twinwave.DemistoException, match="Failed to find file entry"):
        Twinwave.submit_file(MagicMock(), {"entry_id": "missing-entry", "priority": "10"})


def test_submit_file_wraps_file_lookup_error(mocker):
    mocker.patch.object(demisto, "getFilePath", side_effect=RuntimeError("lookup failed"))

    with pytest.raises(Twinwave.DemistoException, match="lookup failed"):
        Twinwave.submit_file(MagicMock(), {"entry_id": "missing-entry", "priority": "10"})


def test_download_job_pdf_returns_file_result(mocker):
    client = MagicMock()
    client.get_job.return_value = {"State": "done"}
    client.download_job_pdf.return_value = b"%PDF-1.7 report"
    file_result = mocker.patch.object(Twinwave, "fileResult", return_value={"EntryID": "entry-123"})

    result = Twinwave.download_job_pdf(client, {"job_id": "job-123"})

    assert result == {"EntryID": "entry-123"}
    client.get_job.assert_called_once_with(job_id="job-123")
    client.download_job_pdf.assert_called_once_with(job_id="job-123")
    file_result.assert_called_once_with("Twinwave job report job-123.pdf", data=b"%PDF-1.7 report")


def test_download_job_pdf_requires_job_id():
    client = MagicMock()

    with pytest.raises(ValueError, match="job ID is required"):
        Twinwave.download_job_pdf(client, {})

    client.get_job.assert_not_called()
    client.download_job_pdf.assert_not_called()


def test_download_job_pdf_rejects_in_progress_job():
    client = MagicMock()
    client.get_job.return_value = {"State": "InProgress"}

    with pytest.raises(ValueError, match="job is in progress"):
        Twinwave.download_job_pdf(client, {"job_id": "job-123"})

    client.download_job_pdf.assert_not_called()


@pytest.mark.parametrize("pdf_data", [b"", b"not-a-pdf"])
def test_download_job_pdf_rejects_invalid_pdf(pdf_data):
    client = MagicMock()
    client.get_job.return_value = {"State": "done"}
    client.download_job_pdf.return_value = pdf_data

    with pytest.raises(ValueError, match="not a PDF"):
        Twinwave.download_job_pdf(client, {"job_id": "job-123"})
