import importlib
import json

import demistomock as demisto
import pytest
from fastapi.testclient import TestClient

API_PATH = "https://api.example.com"
UPSTREAM_TOKEN = "synthetic-backend-token"
PARAMS = {
    "api_credential_type": "Bearer Token",
    "api_path": API_PATH,
    "api_credentials": {"identifier": "", "password": UPSTREAM_TOKEN},
    "api_permissions": json.dumps({"Permissions": [{"target": "/v1/users", "allowed_methods": ["GET"]}]}),
    "longRunningPort": "8000",
}


@pytest.fixture
def proxy_module(mocker):
    """Imports the integration with the test params, since its globals are read from params at import time."""
    mocker.patch.object(demisto, "params", return_value=PARAMS)
    import SimpleAPIProxy

    return importlib.reload(SimpleAPIProxy)


@pytest.fixture
def client(proxy_module):
    return TestClient(proxy_module.app)


@pytest.mark.parametrize(
    "target",
    [
        "/v1/users/../admin",
        "/v1/users/./../admin",
        "/v1/users/%2e%2e/admin",
        "/v1/users/%2E%2E/admin",
        "/v1/users/%252e%252e/admin",
        "/v1/users/..%2fadmin",
        "/v1/users\\..\\admin",
        "/v1/users/..",
    ],
)
def test_handle_post_rejects_dot_segments(client, requests_mock, target):
    """
    Given:
        - A permission allowing GET /v1/users only.
    When:
        - A client sends a target that starts with the allowed prefix but contains (encoded) dot segments.
    Then:
        - The proxy returns 400 and never calls the upstream API with the privileged credential.
    """
    upstream = requests_mock.get(requests_mock.ANY, json={"secret": "admin"})

    response = client.post("/", json={"target": target, "method": "GET"})

    assert response.status_code == 400
    assert not upstream.called


@pytest.mark.parametrize("target", ["@evil.com/v1/users", ".evil.com/v1/users"])
def test_handle_post_rejects_host_change(mocker, client, requests_mock, proxy_module, target):
    """
    Given:
        - A permissive permission regex that matches any target.
    When:
        - A client sends a target that changes the host of the final URL.
    Then:
        - The proxy returns 400 and never sends the upstream credential.
    """
    mocker.patch.object(proxy_module, "API_PERMISSIONS", {"Permissions": [{"target": ".*", "allowed_methods": ["GET"]}]})
    upstream = requests_mock.get(requests_mock.ANY, json={})

    response = client.post("/", json={"target": target, "method": "GET"})

    assert response.status_code == 400
    assert not upstream.called


def test_handle_post_allowed_target(client, requests_mock):
    """
    Given:
        - A permission allowing GET /v1/users.
    When:
        - A client requests GET /v1/users/123.
    Then:
        - The request is forwarded to the upstream API with the configured credential.
    """
    upstream = requests_mock.get(f"{API_PATH}/v1/users/123", json={"id": "123"})

    response = client.post("/", json={"target": "/v1/users/123", "method": "GET"})

    assert response.status_code == 200
    assert response.json() == {"id": "123"}
    assert upstream.last_request.headers["Authorization"] == f"Bearer {UPSTREAM_TOKEN}"


def test_handle_post_disallowed_target(client, requests_mock):
    """
    Given:
        - A permission allowing GET /v1/users.
    When:
        - A client requests GET /v1/admin directly.
    Then:
        - The proxy returns 400 without calling the upstream API.
    """
    upstream = requests_mock.get(requests_mock.ANY, json={})

    response = client.post("/", json={"target": "/v1/admin", "method": "GET"})

    assert response.status_code == 400
    assert not upstream.called


def test_handle_post_missing_target(client):
    """
    Given:
        - A request body without a target.
    When:
        - Posting it to the proxy.
    Then:
        - The proxy returns 400 instead of failing with a server error.
    """
    response = client.post("/", json={"method": "GET"})

    assert response.status_code == 400
