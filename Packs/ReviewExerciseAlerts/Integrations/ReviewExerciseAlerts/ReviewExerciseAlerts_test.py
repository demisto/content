import json

import pytest

from ReviewExerciseAlerts import (
    Client,
    alert_list_command,
    alert_update_command,
    dedupe_alerts,
    parse_since,
)
from ReviewExerciseAlerts import test_module as run_test_module

BASE_URL = "https://api.example.com"


def util_load_json(path: str) -> dict:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


@pytest.fixture
def client(mocker) -> Client:
    mocker.patch(
        "ReviewExerciseAlerts.get_integration_context",
        return_value={"access_token": "token", "expires_at": 4102444800000},
    )
    return Client(base_url=BASE_URL, client_id="id", client_secret="secret", verify=False, proxy=False)


def test_list_alerts_follows_cursor(client, requests_mock):
    """
    Given: Two full pages of alerts linked by a cursor.
    When: Listing 50 alerts.
    Then: Both pages are fetched and all alerts are returned.
    """
    page_1 = util_load_json("test_data/alerts_page_1.json")
    page_2 = util_load_json("test_data/alerts_page_2.json")
    requests_mock.get(f"{BASE_URL}/api/v1/alerts", [{"json": page_1}, {"json": page_2}])

    alerts = client.list_alerts(limit=50)

    assert len(alerts) == 50
    assert alerts[0]["id"] == "A-0001"
    assert alerts[-1]["id"] == "A-0050"


def test_list_alerts_pagination(client, mocker):
    """
    Given: The client returns alerts.
    When: Running review-exercise-alert-list.
    Then: Alerts are returned to the context.
    """
    page_1 = util_load_json("test_data/alerts_page_1.json")
    mocker.patch.object(Client, "list_alerts", return_value=page_1["data"])

    result = alert_list_command(client, {"limit": "10"})

    assert result
    assert result.outputs_prefix == "ReviewExerciseAlerts.Alert"


def test_alert_update_command(client, requests_mock):
    """
    Given: A valid alert ID and status.
    When: Running review-exercise-alert-update.
    Then: The alert is updated and a confirmation is returned.
    """
    requests_mock.post(f"{BASE_URL}/api/v1/alerts/A-0001", json={"id": "A-0001", "status": "closed"})

    result = alert_update_command(client, {"alert_id": "A-0001", "status": "closed"})

    assert result.readable_output == "Alert A-0001 was updated successfully."
    assert requests_mock.last_request.json() == {"status": "closed"}


def test_alert_update_command_invalid_status(client):
    """
    Given: An unsupported status value.
    When: Running review-exercise-alert-update.
    Then: A descriptive error is raised.
    """
    with pytest.raises(Exception, match="Invalid status"):
        alert_update_command(client, {"alert_id": "A-0001", "status": "archived"})


def test_parse_since():
    """
    Given: A relative time expression.
    When: Parsing it.
    Then: An ISO 8601 UTC timestamp is returned.
    """
    assert parse_since(None) is None
    assert parse_since("3 days").endswith("Z")


def test_dedupe_alerts():
    """
    Given: A list of alerts with a duplicate entry.
    When: Deduplicating.
    Then: Only unique alerts remain.
    """
    alerts = util_load_json("test_data/alerts_page_1.json")["data"][:3]

    assert len(dedupe_alerts(alerts + alerts[:1])) == 3


def test_test_module(client, requests_mock):
    """
    Given: A reachable API.
    When: Running test-module.
    Then: "ok" is returned.
    """
    requests_mock.get(f"{BASE_URL}/api/v1/alerts", json=util_load_json("test_data/alerts_page_1.json"))

    assert run_test_module(client) == "ok"
