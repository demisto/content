import json
from pathlib import Path

import pytest
from CapeSandbox import (
    CapeSandboxClient,
    cape_file_submit_command,
    cape_file_view_command,
    cape_machines_list_command,
    cape_task_delete_command,
    cape_task_report_get_command,
    cape_task_screenshot_download_command,
    cape_tasks_list_command,
    cape_url_submit_command,
    test_module,
)


def load_json_test_data(name: str) -> dict:
    here = Path(__file__).parent
    return json.loads((here / "test_data" / name).read_text())


def test_test_module_success():
    """Ensure test-module succeeds when api_token is provided."""
    client = CapeSandboxClient(
        base_url="http://example.com/",
        verify=False,
        proxy=False,
        api_token="token",
    )
    assert test_module(client) == "ok"


def test_cape_task_report_get_json_only_info(mocker):
    """cape-task-report-get should return ONLY the info object to context and render HR."""
    payload = load_json_test_data("report.json")

    client = CapeSandboxClient(
        base_url="http://example.com/",
        verify=False,
        proxy=False,
        api_token="token",
    )

    mocker.patch.object(
        client,
        "get_task_report",
        return_value=payload,
    )

    args = {"task_id": "123"}
    result = cape_task_report_get_command(client, args)

    # Validate outputs are ONLY info
    assert result.outputs == payload["info"]
    # Validate readable_output includes key fields
    ro = result.readable_output or ""
    assert "Task Report 123" in ro
    assert str(payload["info"]["id"]) in ro


def test_cape_task_report_get_zip_download(mocker):
    """cape-task-report-get should return a file entry when zip=true."""
    content = b"PK\x03\x04...zipbytes"
    client = CapeSandboxClient(
        base_url="http://example.com/",
        verify=False,
        proxy=False,
        api_token="token",
    )

    mocker.patch.object(
        client,
        "get_task_report",
        return_value=content,
    )

    args = {"task_id": "456", "format": "json", "zip": "true"}
    result = cape_task_report_get_command(client, args)

    assert isinstance(result, dict)
    assert result.get("File") == "cape_task_456_report_json.zip"
    assert isinstance(result.get("Contents"), bytes | bytearray)


def test_cape_tasks_list_with_task_id(mocker):
    """cape-tasks-list should return a single task when task_id is provided."""
    task = {"data": {"id": 789, "target": "http://example.com", "status": "reported"}}
    client = CapeSandboxClient(
        base_url="http://example.com/",
        verify=False,
        proxy=False,
        api_token="token",
    )

    mocker.patch.object(client, "get_task_view", return_value=task)

    args = {"task_id": "789"}
    result = cape_tasks_list_command(client, args)

    assert result.outputs == task["data"]
    ro = result.readable_output or ""
    assert "Task 789" in ro


def test_cape_tasks_list_pagination_caps_and_offset(mocker):
    """page_size over 50 should be capped to 50 and offset computed from page."""
    client = CapeSandboxClient(
        base_url="http://example.com/",
        verify=False,
        proxy=False,
        api_token="token",
    )

    mocked = mocker.patch.object(client, "list_tasks", return_value={"data": []})

    # page_size=200 should cap to 50; page=3 -> offset=(3-1)*50=100
    args = {"page_size": "200", "page": "3"}
    result = cape_tasks_list_command(client, args)
    assert result.outputs == []
    mocked.assert_called_once_with(limit=50, offset=100)


def test_cape_task_screenshot_download_single(mocker):
    """Download a single screenshot should return a file entry dict."""
    client = CapeSandboxClient(
        base_url="http://example.com/",
        verify=False,
        proxy=False,
        api_token="token",
    )
    content = b"\x89PNG..."
    mocker.patch.object(client, "get_task_screenshot", return_value=content)

    args = {"task_id": "321", "screenshot": "2"}
    result = cape_task_screenshot_download_command(client, args)
    assert isinstance(result, dict)
    assert result.get("File") == "cape_task_321_screenshot_2.png"
    assert isinstance(result.get("Contents"), bytes | bytearray)


def test_cape_machines_list_single_view(mocker):
    """When machine_name provided, return a single machine object in outputs."""
    client = CapeSandboxClient(
        base_url="http://example.com/",
        verify=False,
        proxy=False,
        api_token="token",
    )
    machine = {"machine": {"id": 1, "name": "win10-x64", "status": "idle"}}
    mocker.patch.object(client, "view_machine", return_value=machine)

    args = {"machine_name": "win10-x64"}
    result = cape_machines_list_command(client, args)
    assert result.outputs == machine["machine"]
    ro = result.readable_output or ""
    assert "Machine win10-x64" in ro


def test_cape_task_delete_multiple_ids(mocker):
    """Delete command should call delete_task for each id and return HR lines."""
    client = CapeSandboxClient(
        base_url="http://example.com/",
        verify=False,
        proxy=False,
        api_token="token",
    )
    mocked = mocker.patch.object(client, "delete_task", return_value={"error": False})
    args = {"task_id": ["10", "11"]}
    res = cape_task_delete_command(client, args)
    assert "Task id=10 was deleted successfully" in (res.readable_output or "")
    assert "Task id=11 was deleted successfully" in (res.readable_output or "")
    assert mocked.call_count == 2


def test_cape_file_view_by_task(mocker):
    client = CapeSandboxClient(
        base_url="http://example.com/",
        verify=False,
        proxy=False,
        api_token="token",
    )
    resp = {"data": {"id": 8, "file_type": "exe", "md5": "a" * 32}}
    mocker.patch.object(client, "files_view_by_task", return_value=resp)
    result = cape_file_view_command(client, {"task_id": "8"})
    assert result.outputs == resp["data"]


def test_cape_file_view_by_md5(mocker):
    client = CapeSandboxClient(
        base_url="http://example.com/",
        verify=False,
        proxy=False,
        api_token="token",
    )
    md5 = "5ef783861cd328abceb4964348455763"
    resp = {"data": {"id": 9, "md5": md5}}
    mocker.patch.object(client, "files_view_by_md5", return_value=resp)
    result = cape_file_view_command(client, {"md5": md5})
    assert result.outputs == resp["data"]


def test_cape_file_view_by_sha256(mocker):
    client = CapeSandboxClient(
        base_url="http://example.com/",
        verify=False,
        proxy=False,
        api_token="token",
    )
    sha256 = "4adeb12fa01f0a765123698782a72f68db84fa67e11f19e1019050f1b4c05b18"
    resp = {"data": {"id": 10, "sha256": sha256}}
    mocker.patch.object(client, "files_view_by_sha256", return_value=resp)
    result = cape_file_view_command(client, {"sha256": sha256})
    assert result.outputs == resp["data"]


def test_cape_status_get_hr_only(mocker):
    client = CapeSandboxClient(
        base_url="http://example.com/",
        verify=False,
        proxy=False,
        api_token="token",
    )
    status = {
        "tasks": {"reported": 1, "running": 2, "completed": 3, "pending": 4},
        "hostname": "cape01",
        "machines": {"available": 2, "total": 3},
        "tools": ["cape"],
        "server": {"storage": {"used_by": "ok"}},
    }
    mocker.patch.object(client, "get_status", return_value=status)
    res = cape_status_get_command(client, {})
    assert res.outputs is None or res.outputs == {}
    ro = res.readable_output or ""
    assert "Tasks reported" in ro
    assert "cape01" in ro


def test_cape_task_screenshot_download_all(mocker):
    client = CapeSandboxClient(
        base_url="http://example.com/",
        verify=False,
        proxy=False,
        api_token="token",
    )
    mocker.patch.object(
        client, "list_task_screenshots", return_value={"screenshots": [1, 2]}
    )
    mocker.patch.object(client, "get_task_screenshot", return_value=b"\x89PNG...")
    result = cape_task_screenshot_download_command(client, {"task_id": "900"})
    assert isinstance(result, list)
    assert len(result) == 2
    assert result[0].get("File") == "cape_task_900_screenshot_1.png"


def test_cape_file_submit_polling_reported(mocker):
    """When task_id is provided and status is reported, command should return task view outputs."""
    client = CapeSandboxClient(
        base_url="http://example.com/",
        verify=False,
        proxy=False,
        api_token="token",
    )
    mocker.patch.object(client, "get_task_status", return_value={"data": "reported"})
    mocker.patch.object(client, "get_task_view", return_value={"data": {"id": 111}})
    res = cape_file_submit_command(client, {"task_id": "111"})
    assert res.outputs == {"id": 111}


def test_cape_file_submit_polling_not_ready(mocker):
    client = CapeSandboxClient(
        base_url="http://example.com/",
        verify=False,
        proxy=False,
        api_token="token",
    )
    mocker.patch.object(client, "get_task_status", return_value={"data": "running"})
    res = cape_file_submit_command(client, {"task_id": "112"})
    sc = res.scheduled_command
    assert sc is not None
    assert sc._command == "cape-file-submit"
    args = sc._args
    assert args is not None
    assert args.get("task_id") == "112"


def test_cape_url_submit_polling_paths(mocker):
    client = CapeSandboxClient(
        base_url="http://example.com/",
        verify=False,
        proxy=False,
        api_token="token",
    )
    # reported path
    mocker.patch.object(client, "get_task_status", return_value={"data": "reported"})
    mocker.patch.object(client, "get_task_view", return_value={"data": {"id": 113}})
    res = cape_url_submit_command(client, {"task_id": "113"})
    assert res.outputs == {"id": 113}
    # not ready path
    mocker.patch.object(client, "get_task_status", return_value={"data": "running"})
    res2 = cape_url_submit_command(client, {"task_id": "114"})
    sc2 = res2.scheduled_command
    assert sc2 is not None
    assert sc2._command == "cape-url-submit"
    args2 = sc2._args
    assert args2 is not None
    assert args2.get("task_id") == "114"


def test_auth_username_password_fetch_and_cache(mocker):
    """ensure_token should fetch via username/password and cache the token."""
    client = CapeSandboxClient(
        base_url="http://example.com/",
        verify=False,
        proxy=False,
        username="user",
        password="pass",
    )

    # No cached token initially
    mocker.patch("CapeSandboxClient.get_integration_context", return_value={})
    set_ctx = mocker.patch("CapeSandboxClient.set_integration_context")
    # Token retrieval via POST /api-token-auth/
    mocker.patch.object(
        client, "_http_request", return_value={"token": "fetched-token"}
    )

    token = client.ensure_token()
    assert token == "fetched-token"
    set_ctx.assert_called_once_with({"api_token": "fetched-token"})


def test_auth_uses_cached_token_without_request(mocker):
    client = CapeSandboxClient(
        base_url="http://example.com/",
        verify=False,
        proxy=False,
        username="user",
        password="pass",
    )
    mocker.patch(
        "CapeSandboxClient.get_integration_context",
        return_value={"api_token": "cached-token"},
    )
    # If _http_request is called, test should fail
    mocker.patch.object(
        client,
        "_http_request",
        side_effect=AssertionError("_http_request should not be called"),
    )

    token = client.ensure_token()
    assert token == "cached-token"


def test_auth_headers_use_token_in_requests(mocker):
    client = CapeSandboxClient(
        base_url="http://example.com/",
        verify=False,
        proxy=False,
        username="user",
        password="pass",
    )
    mocker.patch(
        "CapeSandboxClient.get_integration_context",
        return_value={"api_token": "cached-token"},
    )

    captured = {}

    def _capture_headers(**kwargs):
        captured["headers"] = kwargs.get("headers")
        return {"ok": True}

    mocker.patch.object(client, "_http_request", side_effect=_capture_headers)

    # any client call will invoke http_request -> _http_request with auth headers
    client.get_task_status(1)
    headers = captured.get("headers")
    assert isinstance(headers, dict)
    assert headers.get("Authorization") == "Token cached-token"


def test_auth_missing_credentials_raises():
    with pytest.raises(DemistoException):
        CapeSandboxClient(
            base_url="http://example.com/",
            verify=False,
            proxy=False,
        )
