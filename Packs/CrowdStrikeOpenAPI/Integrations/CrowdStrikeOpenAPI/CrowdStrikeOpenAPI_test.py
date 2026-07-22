import json

import pytest
from CrowdStrikeOpenAPI import Client, query_behaviors_command, update_notificationsv1_command


@pytest.fixture()
def client(requests_mock):
    requests_mock.post(
        "https://api.crowdstrike.com/oauth2/token",
        json={
            "access_token": "access_token",
        },
    )
    return Client(params={})


def util_load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


def test_query_behaviors(client, requests_mock):
    """
    Given:
        - Limit arg set to 1
    When:
        - Running query behaviors command
    Then:
        - Verify request sent as expected
        - Verify command outputs are as expected
    """
    args = {"limit": "1"}
    api_response = util_load_json("./test_data/query_behaviors_response.json")
    requests_mock.get("https://api.crowdstrike.com/incidents/queries/behaviors/v1?limit=1", json=api_response)

    result = query_behaviors_command(client=client, args=args)

    assert result.outputs == api_response


def test_update_notificationsv1(client, requests_mock):
    """
    Given:
        - Notification ID, status, and assigned_to_uuid
    When:
        - Running update notificationsv1 command
    Then:
        - Verify request body is sent as an array (for bulk updates)
        - Verify command outputs are as expected
    """
    args = {
        "domain_updatenotificationrequestv1_id": "test-notification-id",
        "domain_updatenotificationrequestv1_status": "in-progress",
        "domain_updatenotificationrequestv1_assigned_to_uuid": "test-uuid",
    }
    api_response = util_load_json("./test_data/update_notificationsv1_response.json")

    # Mock the PATCH request
    mock_patch = requests_mock.patch("https://api.crowdstrike.com/recon/entities/notifications/v1", json=api_response)

    result = update_notificationsv1_command(client=client, args=args)

    # Verify the request body is an array (for bulk updates)
    assert mock_patch.called
    request_body = mock_patch.last_request.json()
    assert isinstance(request_body, list), "Request body should be an array for bulk updates"
    assert len(request_body) == 1
    assert request_body[0]["id"] == "test-notification-id"
    assert request_body[0]["status"] == "in-progress"
    assert request_body[0]["assigned_to_uuid"] == "test-uuid"

    # Verify command outputs
    assert result.outputs == api_response
