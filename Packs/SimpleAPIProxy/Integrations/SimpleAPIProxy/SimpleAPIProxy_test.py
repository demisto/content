import json

import pytest

import demistomock as demisto

API_PATH = "https://upstream.example.com"
PARAMS = {
    "api_path": API_PATH,
    "api_credential_type": "Bearer Token",
    "api_credentials": {"identifier": "", "password": "UPSTREAM-SECRET"},
    "api_permissions": json.dumps({"Permissions": [{"target": "/api/v1/status", "allowed_methods": ["GET"]}]}),
    "longRunningPort": "8000",
}


@pytest.fixture
def client(mocker):
    mocker.patch.object(demisto, "params", return_value=PARAMS)
    import importlib

    import SimpleAPIProxy
    from fastapi.testclient import TestClient

    importlib.reload(SimpleAPIProxy)
    return TestClient(SimpleAPIProxy.app)


@pytest.mark.parametrize(
    "target, expected",
    [
        ("/api/v1/status", True),
        ("/api/v1/status/123", True),
        ("/api/v1/status?x=1&y=2", True),
        ("/api/v1/status/..data", True),
        ("/api/v1/status/../../../admin/users", False),
        ("/api/v1/status/./../admin", False),
        ("/api/v1/status/%2e%2e/%2e%2e/admin", False),
        ("/api/v1/status/%2E%2E/admin", False),
        ("/api/v1/status/%252e%252e/admin", False),
        ("/api/v1/status/..", False),
        ("/api/v1/status\\..\\admin", False),
        ("/api/v1/status/%5c..%5cadmin", False),
        ("/api/v1/status/\n", False),
        ("//evil.com/api/v1/status", False),
        ("@evil.com/api/v1/status", False),
        ("api/v1/status", False),
        ("", False),
        (None, False),
        (123, False),
    ],
)
def test_is_safe_target(mocker, target, expected):
    """
    Given: A client-supplied target path.
    When: Validating the target before matching it against the allowlist.
    Then: Targets containing (encoded) dot-segments, backslashes, control chars or not being clean absolute paths are rejected.
    """
    mocker.patch.object(demisto, "params", return_value=PARAMS)
    from SimpleAPIProxy import is_safe_target

    assert is_safe_target(target) is expected


@pytest.mark.parametrize(
    "url, api_path, expected",
    [
        ("https://upstream.example.com/api/v1/status", "https://upstream.example.com", True),
        ("https://upstream.example.com/base/api", "https://upstream.example.com/base", True),
        ("https://upstream.example.com.evil.com/api", "https://upstream.example.com", False),
        ("https://upstream.example.com@evil.com/api", "https://upstream.example.com", False),
        ("https://other.example.com/base/api", "https://upstream.example.com/base", False),
        ("http://upstream.example.com/api", "https://upstream.example.com", False),
    ],
)
def test_is_url_within_api_path(mocker, url, api_path, expected):
    """
    Given: A final URL and the configured Target API Base Path.
    When: Verifying the URL before forwarding the request.
    Then: Only URLs on the same scheme, host and base path are allowed.
    """
    mocker.patch.object(demisto, "params", return_value=PARAMS)
    from SimpleAPIProxy import is_url_within_api_path

    assert is_url_within_api_path(url, api_path) is expected


def test_handle_post_allowed_target(client, requests_mock):
    """
    Given: An allowlisted target and method.
    When: Posting a proxy request.
    Then: The request is forwarded to the upstream API with the stored credential.
    """
    upstream = requests_mock.get(f"{API_PATH}/api/v1/status/1", json={"status": "ok"})

    response = client.post("/", json={"target": "/api/v1/status/1", "method": "GET"})

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
    assert upstream.last_request.headers["Authorization"] == "Bearer UPSTREAM-SECRET"


@pytest.mark.parametrize(
    "target",
    [
        "/api/v1/status/../../../admin/users",
        "/api/v1/status/%2e%2e/%2e%2e/admin/users",
        "/api/v1/status/%252e%252e/admin/users",
    ],
)
def test_handle_post_path_traversal_blocked(client, requests_mock, target):
    """
    Given: A target that starts with an allowlisted prefix but contains path traversal segments.
    When: Posting a proxy request.
    Then: The request is rejected and never forwarded to the upstream API.
    """
    restricted = requests_mock.get(f"{API_PATH}/admin/users", json={"RESTRICTED": True})

    response = client.post("/", json={"target": target, "method": "GET"})

    assert response.status_code == 400
    assert response.text == "Invalid target."
    assert not restricted.called
    assert not requests_mock.called


def test_handle_post_target_not_allowlisted(client, requests_mock):
    """
    Given: A target that is not in the allowlist.
    When: Posting a proxy request.
    Then: The request is rejected with "Target not found.".
    """
    response = client.post("/", json={"target": "/admin/users", "method": "GET"})

    assert response.status_code == 400
    assert response.text == "Target not found."
    assert not requests_mock.called


def test_handle_post_method_not_allowed(client, requests_mock):
    """
    Given: An allowlisted target with a method that is not allowed.
    When: Posting a proxy request.
    Then: The request is rejected with "Method not allowed.".
    """
    response = client.post("/", json={"target": "/api/v1/status", "method": "DELETE"})

    assert response.status_code == 400
    assert response.text == "Method not allowed."
    assert not requests_mock.called
