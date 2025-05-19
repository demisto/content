import pytest

from CommonServerPython import DemistoException

from TaegisXDRv2 import (
    Client,
    execute_playbook_command,
    fetch_alerts_command,
    fetch_assets_command,
    create_comment_command,
    fetch_comment_command,
    fetch_comments_command,
    update_comment_command,
    fetch_endpoint_command,
    fetch_incidents,
    fetch_investigation_command,
    fetch_investigation_alerts_command,
    fetch_users_command,
    fetch_playbook_execution_command,
    isolate_asset_command,
    create_investigation_command,
    update_investigation_command,
    archive_investigation_command,
    unarchive_investigation_command,
    update_alert_status_command,
    add_evidence_to_investigation_command,
    create_sharelink_command,
    test_module as connectivity_test,
)

from test_data.data import *  # nopycln: import


""" UTILITY FUNCTIONS """


def mock_client(requests_mock, mock_response):
    base_url = "https://api.ctpx.secureworks.com"

    requests_mock.post(f"{base_url}/graphql", json=mock_response)
    requests_mock.get(f"{base_url}/assets/version", json=mock_response)
    client = Client(
        client_id="TestID",
        client_secret="TestSecret",
        base_url=base_url,
    )
    return client


""" TESTS """


def test_execute_playbook(requests_mock):
    """Tests taegis-execute-playbook command function"""
    client = mock_client(requests_mock, EXECUTE_PLAYBOOK_RESPONSE)
    args = {
        "id": TAEGIS_PLAYBOOK_INSTANCE_ID,
        "inputs": {
            "MyInput": "MyValue",
        },
    }

    response = execute_playbook_command(client=client, env=TAEGIS_ENVIRONMENT, args=args)
    assert response.outputs["id"] == TAEGIS_PLAYBOOK_EXECUTION_ID

    with pytest.raises(ValueError, match="Cannot execute playbook, missing playbook_id"):
        assert execute_playbook_command(client=client, env=TAEGIS_ENVIRONMENT, args={})

    client = mock_client(requests_mock, EXECUTE_PLAYBOOK_BAD_RESPONSE)
    with pytest.raises(ValueError, match="Failed to execute playbook: must be defined"):
        assert execute_playbook_command(client=client, env=TAEGIS_ENVIRONMENT, args=args)


def test_fetch_alerts(requests_mock):
    client = mock_client(requests_mock, FETCH_ALERTS_RESPONSE)
    args = {
        "limit": 1,
        "offset": 0,
        "cql_query": "from alert severity >= 0.6 and status='OPEN'",
    }

    # Test with no IDs set
    response = fetch_alerts_command(client=client, env=TAEGIS_ENVIRONMENT, args=args)
    assert response.outputs[0] == TAEGIS_ALERT
    assert len(response.outputs) == len([TAEGIS_ALERT])


def test_fetch_alerts_by_id(requests_mock):
    """Tests taegis-fetch-alert command function"""
    client = mock_client(requests_mock, FETCH_ALERTS_BY_ID_RESPONSE)

    # Test with IDs set (list)
    args = {"ids": ["alert://priv:crowdstrike:11772:1666247222095:4e41ec02-ca53-5ff7-95cc-eda434221ba6"]}
    response = fetch_alerts_command(client=client, env=TAEGIS_ENVIRONMENT, args=args)
    assert response.outputs[0] == TAEGIS_ALERT
    assert len(response.outputs) == len([TAEGIS_ALERT])

    # Test with IDs set (comma separated list)
    args = {"ids": "alert://priv:crowdstrike:11772:1666247222095:4e41ec02-ca53-5ff7-95cc-eda434221ba6"}
    response = fetch_alerts_command(client=client, env=TAEGIS_ENVIRONMENT, args=args)
    assert response.outputs[0] == TAEGIS_ALERT
    assert len(response.outputs) == len([TAEGIS_ALERT])


def test_fetch_assets(requests_mock):
    """Tests taegis-fetch-assets command function"""

    client = mock_client(requests_mock, FETCH_ASSETS_RESPONSE)
    args = {
        "page": 0,
        "page_size": 1,
    }

    response = fetch_assets_command(client=client, env=TAEGIS_ENVIRONMENT, args=args)
    assert response.outputs == [TAEGIS_ASSET]

    # Test allowed search fields
    args = {"host_id": TAEGIS_ASSET["hostId"]}
    response = fetch_assets_command(client=client, env=TAEGIS_ENVIRONMENT, args=args)
    assert response.outputs[0] == TAEGIS_ASSET
    assert len(response.outputs) == len([TAEGIS_ASSET])

    # Asset Query Failure
    client = mock_client(requests_mock, FETCH_ASSETS_BAD_RESPONSE)
    with pytest.raises(ValueError, match="Failed to fetch assets:"):
        assert fetch_assets_command(client=client, env=TAEGIS_ENVIRONMENT, args=args)


def test_create_comment(requests_mock):
    """Tests taegis-create-comment command function"""
    client = mock_client(requests_mock, CREATE_COMMENT_RESPONSE)

    # comment not set
    with pytest.raises(ValueError, match="Cannot create comment, comment cannot be empty"):
        assert create_comment_command(client=client, env=TAEGIS_ENVIRONMENT, args={})

    # id not set
    with pytest.raises(ValueError, match="Cannot create comment, id cannot be empty"):
        assert create_comment_command(client=client, env=TAEGIS_ENVIRONMENT, args={"comment": "Test comment"})

    args = {
        "comment": "Test Comment",
        "id": "12345-12345-12345",
        "fields": "id",
    }

    # Successful fetch - Comment created
    response = create_comment_command(client=client, env=TAEGIS_ENVIRONMENT, args=args)
    assert response.outputs == CREATE_COMMENT_RESPONSE["data"]["addCommentToInvestigation"]

    # Comment creation failed
    client = mock_client(requests_mock, CREATE_UPDATE_COMMENT_BAD_RESPONSE)
    with pytest.raises(ValueError, match="Failed to create comment:"):
        assert create_comment_command(client=client, env=TAEGIS_ENVIRONMENT, args=args)


def test_fetch_comment_by_id(requests_mock):
    """Tests taegis-fetch-comment command function"""
    client = mock_client(requests_mock, FETCH_COMMENT_RESPONSE)

    # comment_id not set
    with pytest.raises(ValueError, match="Cannot fetch comment, missing comment_id"):
        assert fetch_comment_command(client=client, env=TAEGIS_ENVIRONMENT, args={})

    args = {"id": "ff9ca818-4749-4ccb-883a-2ccc6f6c9e0f"}

    # Successful fetch - Comment found
    response = fetch_comment_command(client=client, env=TAEGIS_ENVIRONMENT, args=args)
    assert response.outputs == FETCH_COMMENT_RESPONSE["data"]["comment"]

    # Comment not found
    client = mock_client(requests_mock, {})
    with pytest.raises(ValueError, match="Could not locate comment by provided ID"):
        assert fetch_comment_command(client=client, env=TAEGIS_ENVIRONMENT, args=args)


def test_fetch_comments(requests_mock):
    """Tests taegis-fetch-comments command function"""
    client = mock_client(requests_mock, FETCH_COMMENTS_RESPONSE)

    # comment_id not set
    with pytest.raises(ValueError, match="Cannot fetch comments, missing id"):
        assert fetch_comments_command(client=client, env=TAEGIS_ENVIRONMENT, args={})

    args = {
        "id": "c2e09554-833e-41a1-bc9d-8160aec0d70d",
    }

    # Successful fetch
    response = fetch_comments_command(client=client, env=TAEGIS_ENVIRONMENT, args=args)
    assert response.outputs == FETCH_COMMENTS_RESPONSE["data"]["commentsV2"]["comments"]

    # Comment not found, bad response
    client = mock_client(requests_mock, FETCH_COMMENTS_BAD_RESPONSE)
    response = fetch_comments_command(client=client, env=TAEGIS_ENVIRONMENT, args=args)
    assert response.outputs == []


def test_update_comment(requests_mock):
    """Tests taegis-update-comment command function"""
    client = mock_client(requests_mock, UPDATE_COMMENT_RESPONSE)

    # comment not set
    with pytest.raises(ValueError, match="Cannot update comment, comment id cannot be empty"):
        assert update_comment_command(client=client, env=TAEGIS_ENVIRONMENT, args={})

    # comment_id not set
    with pytest.raises(ValueError, match="Cannot update comment, comment cannot be empty"):
        assert update_comment_command(client=client, env=TAEGIS_ENVIRONMENT, args={"id": "test"})

    args = {
        "comment": FETCH_COMMENT_RESPONSE["data"]["comment"]["comment"],
        "id": FETCH_COMMENT_RESPONSE["data"]["comment"]["id"],
    }

    #  # Successful fetch - Comment created
    response = update_comment_command(client=client, env=TAEGIS_ENVIRONMENT, args=args)
    assert response.outputs == UPDATE_COMMENT_RESPONSE["data"]["updateInvestigationComment"]

    # Comment creation failed
    client = mock_client(requests_mock, CREATE_UPDATE_COMMENT_BAD_RESPONSE)
    with pytest.raises(ValueError, match="Failed to locate/update comment:"):
        assert update_comment_command(client=client, env=TAEGIS_ENVIRONMENT, args=args)


def test_fetch_endpoint(requests_mock):
    """Tests taegis-fetch-endpoint command function"""
    client = mock_client(requests_mock, FETCH_ENDPOINT_RESPONSE)

    # comment_id not set
    with pytest.raises(ValueError, match="Cannot fetch endpoint information, missing id"):
        assert fetch_endpoint_command(client=client, env=TAEGIS_ENVIRONMENT, args={})

    args = {"id": "110d1fd3a23c95c0120d0d10451cb001"}

    # Successful fetch - Endpoint found
    response = fetch_endpoint_command(client=client, env=TAEGIS_ENVIRONMENT, args=args)
    assert response.outputs == FETCH_ENDPOINT_RESPONSE["data"]["assetEndpointInfo"]

    # Endpoint not found
    client = mock_client(requests_mock, FETCH_ENDPOINT_BAD_RESPONSE)
    with pytest.raises(ValueError, match="Failed to fetch endpoint information"):
        assert fetch_endpoint_command(client=client, env=TAEGIS_ENVIRONMENT, args=args)


def test_connectivity(requests_mock):
    response = {"revision": "1e9c12c7f3f51d5ecc0da91d1ac8bcb27e3566a7", "timestamp": "2022-01-01T17:02:01Z"}
    client = mock_client(requests_mock, response)
    assert connectivity_test(client=client) == "ok"


def test_fetch_incidents_alerts(requests_mock):
    """Tests taegis-fetch-incidents (alerts) command function"""
    client = mock_client(requests_mock, FETCH_ALERTS_RESPONSE)
    response = fetch_incidents(client=client, env=TAEGIS_ENVIRONMENT, fetch_type="alerts")
    assert response[0]["name"] == FETCH_ALERTS_RESPONSE["data"]["alertsServiceSearch"]["alerts"]["list"][0]["metadata"]["title"]


def test_fetch_incidents_investigations(requests_mock):
    """Tests taegis-fetch-incidents (investigations) command function"""
    client = mock_client(requests_mock, FETCH_INCIDENTS_RESPONSE)
    response = fetch_incidents(client=client, env=TAEGIS_ENVIRONMENT)
    assert response[0]["name"] == FETCH_INCIDENTS_RESPONSE["data"]["investigationsSearch"]["investigations"][0]["description"]

    # Invalid max_fetch
    with pytest.raises(ValueError, match="Max Fetch must be between 1 and 200"):
        assert fetch_incidents(client=client, env=TAEGIS_ENVIRONMENT, max_fetch=0)
    with pytest.raises(ValueError, match="Max Fetch must be between 1 and 200"):
        assert fetch_incidents(client=client, env=TAEGIS_ENVIRONMENT, max_fetch=201)

    # Invalid fetch_type
    with pytest.raises(ValueError, match="Incident Type is invalid"):
        assert fetch_incidents(client=client, env=TAEGIS_ENVIRONMENT, fetch_type="BAD_TYPE")

    # Failure from Taegis API
    client = mock_client(requests_mock, FETCH_INCIDENTS_BAD_RESPONSE)
    error = f"Error when fetching incidents: {FETCH_INCIDENTS_BAD_RESPONSE['errors'][0]['message']}"
    with pytest.raises(DemistoException, match=error):
        assert fetch_incidents(client=client, env=TAEGIS_ENVIRONMENT, max_fetch=200)

    # Unknown error
    client = mock_client(requests_mock, {})
    response = fetch_incidents(client=client, env=TAEGIS_ENVIRONMENT)
    assert len(response) == 0

    # Ignore incidents that have been archived
    FETCH_INCIDENTS_RESPONSE["data"]["investigationsSearch"]["investigations"][0]["archived_at"] = "2022-02-03T13:53:35Z"
    client = mock_client(requests_mock, FETCH_INCIDENTS_RESPONSE)
    response = fetch_incidents(client=client, env=TAEGIS_ENVIRONMENT)
    assert len(response) == 0


def test_fetch_investigation(requests_mock):
    """Tests taegis-fetch-investigation command function

    Test fetching of a single incident
    """
    client = mock_client(requests_mock, FETCH_INVESTIGATION_RESPONSE)
    args = {
        "id": "c2e09554-833e-41a1-bc9d-8160aec0d70d",
        "page": 0,
        "page_sie": 1,
    }

    response = fetch_investigation_command(client=client, env=TAEGIS_ENVIRONMENT, args=args)
    assert response.outputs[0] == TAEGIS_INVESTIGATION
    assert response.outputs[0]["url"] == f"{TAEGIS_URL}/investigations/{args['id']}"

    # Investigation not found
    mock_result = {"errors": [{"message": "record not found"}], "data": {"investigationV2": None}}
    client = mock_client(requests_mock, mock_result)
    response = fetch_investigation_command(client=client, env=TAEGIS_ENVIRONMENT, args=args)
    assert len(response.outputs) == 0

    # Invalid query response
    client = mock_client(requests_mock, {})
    response = fetch_investigation_command(client=client, env=TAEGIS_ENVIRONMENT, args=args)
    assert len(response.outputs) == 0


def test_fetch_investigations(requests_mock):
    """Tests taegis-fetch-investigations command function

    Test fetching of all incidents
    """

    client = mock_client(requests_mock, FETCH_INVESTIGATIONS_RESPONSE)
    args = {
        "page": 0,
        "page_size": 1,
    }

    response = fetch_investigation_command(client=client, env=TAEGIS_ENVIRONMENT, args=args)
    assert response.outputs == [TAEGIS_INVESTIGATION]


def test_fetch_investigation_alerts(requests_mock):
    """Tests taegis-fetch-investigation-alerts command function"""
    client = mock_client(requests_mock, FETCH_INVESTIGATION_ALERTS_RESPONSE)
    args = {
        "id": "c2e09554-833e-41a1-bc9d-8160aec0d70d",
    }

    response = fetch_investigation_alerts_command(client=client, env=TAEGIS_ENVIRONMENT, args=args)
    assert response.outputs[0] == TAEGIS_ALERT
    assert len(response.outputs) == len([TAEGIS_ALERT])

    # No alerts returned
    client = mock_client(requests_mock, {})
    response = fetch_investigation_alerts_command(client=client, env=TAEGIS_ENVIRONMENT, args=args)
    assert len(response.outputs) == 0

    # Investigation ID not provided
    with pytest.raises(ValueError, match="Cannot fetch investigation, missing investigation_id"):
        assert fetch_investigation_alerts_command(client=client, env=TAEGIS_ENVIRONMENT, args={})


def test_fetch_playbook_execution(requests_mock):
    """Tests taegis-fetch-playbook-execution command function"""
    client = mock_client(requests_mock, FETCH_PLAYBOOK_EXECUTION_RESPONSE)
    args = {
        "id": TAEGIS_PLAYBOOK_EXECUTION_ID,
    }

    response = fetch_playbook_execution_command(client=client, env=TAEGIS_ENVIRONMENT, args=args)
    assert response.outputs == TAEGIS_PLAYBOOK_EXECUTION

    client = mock_client(requests_mock, FETCH_PLAYBOOK_EXECUTION_RESPONSE)
    with pytest.raises(ValueError, match="Cannot fetch playbook execution, missing execution id"):
        assert fetch_playbook_execution_command(client=client, env=TAEGIS_ENVIRONMENT, args={})

    client = mock_client(requests_mock, FETCH_PLAYBOOK_EXECUTION_BAD_RESPONSE)
    with pytest.raises(ValueError, match="Failed to fetch playbook execution"):
        assert fetch_playbook_execution_command(client=client, env=TAEGIS_ENVIRONMENT, args=args)


def test_create_investigation(requests_mock):
    """Tests taegis-create-investigation command function"""
    client = mock_client(requests_mock, CREATE_INVESTIGATION_RESPONSE)

    # Invalid assignee_id
    with pytest.raises(ValueError, match="assigneeId MUST be in 'auth0|12345' format or '@secureworks'"):
        assert create_investigation_command(client=client, env=TAEGIS_ENVIRONMENT, args={"assignee_id": "BadID"})

    # Invalid priority
    with pytest.raises(ValueError, match="Priority must be between 1-4"):
        assert create_investigation_command(client=client, env=TAEGIS_ENVIRONMENT, args={"priority": 7})

    # Invalid status
    with pytest.raises(ValueError, match="The provided status, BAD_STATUS, is not valid for updating an investigation"):
        assert create_investigation_command(client=client, env=TAEGIS_ENVIRONMENT, args={"status": "BAD_STATUS"})

    # Invalid type
    with pytest.raises(ValueError, match="The provided type, BAD_TYPE, is not valid for updating an investigation."):
        assert create_investigation_command(client=client, env=TAEGIS_ENVIRONMENT, args={"type": "BAD_TYPE"})

    # Invalid title
    with pytest.raises(ValueError, match="Title must be defined"):
        assert create_investigation_command(client=client, env=TAEGIS_ENVIRONMENT, args={})

    # Successul Creation
    response = create_investigation_command(client=client, env=TAEGIS_ENVIRONMENT, args={"title": "Test Title"})
    assert response.outputs["id"] == CREATE_INVESTIGATION_RESPONSE["data"]["createInvestigationV2"]["id"]

    # Investigation creation failed
    client = mock_client(requests_mock, FETCH_INCIDENTS_BAD_RESPONSE)
    with pytest.raises(ValueError, match="Failed to create investigation:"):
        assert create_investigation_command(client=client, env=TAEGIS_ENVIRONMENT, args={"title": "Test Title"})


def test_update_investigation(requests_mock):
    """Tests taegis-update-investigation command function"""
    client = mock_client(requests_mock, UPDATE_INVESTIGATION_RESPONSE)
    args = {}

    # id not set
    with pytest.raises(ValueError, match="Cannot fetch investigation without id defined"):
        assert update_investigation_command(client=client, env=TAEGIS_ENVIRONMENT, args=args)

    args["id"] = UPDATE_INVESTIGATION_RESPONSE["data"]["updateInvestigationV2"]["id"]

    # Invalid investigation status
    args["status"] = "BadStatus"
    bad_status = r"The provided status, BadStatus, is not valid for updating an investigation. Supported Status Values:.*"
    with pytest.raises(ValueError, match=bad_status):
        assert update_investigation_command(client=client, env=TAEGIS_ENVIRONMENT, args=args)

    args["status"] = "ACTIVE"

    # Invalid assigneeId Format
    args["assigneeId"] = "BadAssigneeIDFormat"
    with pytest.raises(ValueError, match="assigneeId MUST be in 'auth0|12345' format or '@secureworks'"):
        assert update_investigation_command(client=client, env=TAEGIS_ENVIRONMENT, args=args)

    args["assigneeId"] = "@secureworks"

    # Invalid priority
    args["priority"] = 10
    with pytest.raises(ValueError, match="Priority must be between 1-4"):
        assert update_investigation_command(client=client, env=TAEGIS_ENVIRONMENT, args=args)

    args["priority"] = 1

    # Invalid type
    args["type"] = "BAD_TYPE"
    with pytest.raises(ValueError, match="The provided type, BAD_TYPE, is not valid for updating an investigation."):
        assert update_investigation_command(client=client, env=TAEGIS_ENVIRONMENT, args=args)

    # No valid update fields set
    args = {"id": UPDATE_INVESTIGATION_RESPONSE["data"]["updateInvestigationV2"]["id"]}
    with pytest.raises(ValueError, match="No valid investigation fields provided. Supported Update Fields"):
        assert update_investigation_command(client=client, env=TAEGIS_ENVIRONMENT, args=args)

    # Tags defined
    args["tags"] = "test_tag01"
    response = update_investigation_command(client=client, env=TAEGIS_ENVIRONMENT, args=args)
    assert response.outputs["id"] == args["id"]

    # Successful Update
    args = {
        "id": UPDATE_INVESTIGATION_RESPONSE["data"]["updateInvestigationV2"]["id"],
        "title": "Test Investigation Updated",
        "priority": 2,
        "status": "ACTIVE",
    }
    response = update_investigation_command(client=client, env=TAEGIS_ENVIRONMENT, args=args)
    assert response.outputs["id"] == args["id"]

    # Investigation update failure
    client = mock_client(requests_mock, FETCH_COMMENTS_BAD_RESPONSE)
    with pytest.raises(ValueError, match="Failed to locate/update investigation"):
        assert update_investigation_command(client=client, env=TAEGIS_ENVIRONMENT, args=args)


def test_archive_investigation(requests_mock):
    """Tests taegis-archive-investigation command function"""
    client = mock_client(requests_mock, INVESTIGATION_ARCHIVE_RESPONSE)

    # Test Archiving
    args = {"id": TAEGIS_INVESTIGATION["id"]}
    response = archive_investigation_command(client=client, env=TAEGIS_ENVIRONMENT, args=args)
    assert response.outputs["id"] == args["id"]
    assert response.raw_response["data"]["archiveInvestigation"]

    # investigation id not set
    with pytest.raises(ValueError, match="Cannot archive investigation, missing investigation id"):
        assert archive_investigation_command(client=client, env=TAEGIS_ENVIRONMENT, args={})

    # Investigation archive not found
    client = mock_client(requests_mock, INVESTIGATION_ARCHIVE_ALREADY_COMPLETE)
    with pytest.raises(ValueError, match="Could not locate investigation with id:.*"):
        assert archive_investigation_command(client=client, env=TAEGIS_ENVIRONMENT, args=args)


def test_unarchive_investigation(requests_mock):
    """Tests taegis-unarchive-investigation command function"""
    client = mock_client(requests_mock, INVESTIGATION_UNARCHIVE_RESPONSE)

    # Test Unarchiving
    args = {"id": TAEGIS_INVESTIGATION["id"]}
    response = unarchive_investigation_command(client=client, env=TAEGIS_ENVIRONMENT, args=args)
    assert response.outputs["id"] == args["id"]
    assert response.raw_response["data"]["unArchiveInvestigation"]

    # investigation id not set
    with pytest.raises(ValueError, match="Cannot unarchive investigation, missing investigation id"):
        assert unarchive_investigation_command(client=client, env=TAEGIS_ENVIRONMENT, args={})

    # Investigation is not archived
    client = mock_client(requests_mock, INVESTIGATION_ARCHIVE_ALREADY_COMPLETE)
    response = unarchive_investigation_command(client=client, env=TAEGIS_ENVIRONMENT, args=args)
    assert response.outputs["id"] == args["id"]
    assert response.outputs["status"] == "Investigation is not currently archived"

    # Could not find investigation by investigation id
    args = {"id": "InvalidInvestigationId"}
    client = mock_client(requests_mock, INVESTIGATION_NOT_ARCHIVED_RESPONSE)
    with pytest.raises(ValueError, match="Could not locate investigation with id:.*"):
        assert unarchive_investigation_command(client=client, env=TAEGIS_ENVIRONMENT, args=args)


def test_isolate_asset(requests_mock):
    """Tests taegis-isolate-asset command function"""
    client = mock_client(requests_mock, ISOLATE_ASSET_RESPONSE)

    # asset id not set
    with pytest.raises(ValueError, match="Cannot isolate asset, missing id"):
        assert isolate_asset_command(client=client, env=TAEGIS_ENVIRONMENT, args={})
    args = {"id": TAEGIS_ASSET["id"]}

    # reason not set
    with pytest.raises(ValueError, match="Cannot isolate asset, missing reason"):
        assert isolate_asset_command(client=client, env=TAEGIS_ENVIRONMENT, args=args)
    args["reason"] = "My isolation reason"

    # Successful isolation
    response = isolate_asset_command(client=client, env=TAEGIS_ENVIRONMENT, args=args)
    assert response.outputs == ISOLATE_ASSET_RESPONSE["data"]["isolateAsset"]

    # Endpoint not found
    client = mock_client(requests_mock, ISOLATE_ASSET_BAD_RESPONSE)
    with pytest.raises(ValueError, match="Failed to isolate asset"):
        assert isolate_asset_command(client=client, env=TAEGIS_ENVIRONMENT, args=args)


def test_fetch_users(requests_mock):
    client = mock_client(requests_mock, FETCH_USERS_RESPONSE)
    args = {
        "limit": 1,
        "page_size": 0,
    }

    response = fetch_users_command(client=client, env=TAEGIS_ENVIRONMENT, args=args)
    assert response.outputs[0] == TAEGIS_USER
    assert len(response.outputs) == len([TAEGIS_USER])

    client = mock_client(requests_mock, FETCH_USERS_BAD_RESPONSE)
    with pytest.raises(ValueError, match="Failed to fetch user information:"):
        assert fetch_users_command(client=client, env=TAEGIS_ENVIRONMENT, args=args)

    # Test user search by email
    client = mock_client(requests_mock, FETCH_USERS_RESPONSE)
    args["email"] = TAEGIS_USER["email"]
    response = fetch_users_command(client=client, env=TAEGIS_ENVIRONMENT, args=args)
    assert response.outputs[0] == TAEGIS_USER
    assert len(response.outputs) == len([TAEGIS_USER])

    # Test user search by auth0 user id
    client = mock_client(requests_mock, FETCH_USER_RESPONSE)
    args["id"] = TAEGIS_USER["user_id"]
    args.pop("email")
    response = fetch_users_command(client=client, env=TAEGIS_ENVIRONMENT, args=args)
    assert response.outputs[0] == TAEGIS_USER
    assert len(response.outputs) == len([TAEGIS_USER])

    # Invalid id Format
    args["id"] = "BadAssigneeIDFormat"
    invalid_fields = r"id MUST be in 'auth0|12345' format"
    with pytest.raises(ValueError, match=invalid_fields):
        assert fetch_users_command(client=client, env=TAEGIS_ENVIRONMENT, args=args)


def test_update_alert_status(requests_mock):
    """Tests taegis-update-alert-status command function"""
    client = mock_client(requests_mock, UPDATE_ALERT_STATUS_RESPONSE)

    args = {"ids": TAEGIS_ALERT["id"]}

    # alert ids not set
    with pytest.raises(ValueError, match="Alert IDs must be defined"):
        assert update_alert_status_command(client=client, env=TAEGIS_ENVIRONMENT, args={})

    # status not set
    with pytest.raises(ValueError, match="Alert status must be defined"):
        assert update_alert_status_command(client=client, env=TAEGIS_ENVIRONMENT, args=args)

    args["status"] = "Bad Status"
    with pytest.raises(ValueError, match="The provided status, Bad Status, is not valid for updating an alert"):
        assert update_alert_status_command(client=client, env=TAEGIS_ENVIRONMENT, args=args)

    # Successful update
    args["status"] = "NOT_ACTIONABLE"
    response = update_alert_status_command(client=client, env=TAEGIS_ENVIRONMENT, args=args)
    assert response.outputs == UPDATE_ALERT_STATUS_RESPONSE["data"]["alertsServiceUpdateResolutionInfo"]

    # Alert not updated
    client = mock_client(requests_mock, UPDATE_ALERT_STATUS_BAD_RESPONSE)
    with pytest.raises(ValueError, match="Failed to locate/update alert"):
        assert update_alert_status_command(client=client, env=TAEGIS_ENVIRONMENT, args=args)


def test_add_evidence_to_investigation(requests_mock):
    """Tests taegis-add-evidence-to-investigation command function"""
    alerts = ["alert://priv:crowdstrike:11772:1666247222095:4e41ec02-ca53-5ff7-95cc-eda434221ba6"]

    client = mock_client(requests_mock, TAEGIS_ADD_EVIDENCE_TO_INVESTIGATION_RESPONSE)
    args = {
        "id": UPDATE_INVESTIGATION_RESPONSE["data"]["updateInvestigationV2"]["id"],
        "alerts": alerts,
    }
    response = add_evidence_to_investigation_command(client=client, env=TAEGIS_ENVIRONMENT, args=args)

    assert response.outputs["investigationId"] == args["id"]

    args = {}

    # investigation_id not set
    with pytest.raises(ValueError, match="Cannot add evidence to investigation, id cannot be empty"):
        assert add_evidence_to_investigation_command(client=client, env=TAEGIS_ENVIRONMENT, args=args)

    args["id"] = UPDATE_INVESTIGATION_RESPONSE["data"]["updateInvestigationV2"]["id"]

    # alerts not set
    with pytest.raises(ValueError, match="Cannot add evidence to investigation. alerts, events, or alert_query must be defined"):
        assert add_evidence_to_investigation_command(client=client, env=TAEGIS_ENVIRONMENT, args=args)

    args["alerts"] = alerts

    # Unknown error
    client = mock_client(requests_mock, {"errors": [{"message": "Unknown Error"}]})
    with pytest.raises(ValueError, match="Failed to create investigation"):
        assert add_evidence_to_investigation_command(client=client, env=TAEGIS_ENVIRONMENT, args=args)


def test_create_sharelink(requests_mock):
    """Tests taegis-create-sharelink function"""

    client = mock_client(requests_mock, CREATE_SHARELINK_RESPONSE)

    args = {"tenant_id": "123456"}

    # id not set
    with pytest.raises(ValueError, match="Cannot create ShareLink, id cannot be empty"):
        assert create_sharelink_command(client=client, env=TAEGIS_ENVIRONMENT, args=args)

    # type not set
    args["id"] = UPDATE_INVESTIGATION_RESPONSE["data"]["updateInvestigationV2"]["id"]
    with pytest.raises(ValueError, match="Cannot create ShareLink, type cannot be empty"):
        assert create_sharelink_command(client=client, env=TAEGIS_ENVIRONMENT, args=args)

    # Unknown type
    args["type"] = "BAD_TYPE"
    with pytest.raises(ValueError, match="The provided ShareLink type, BAD_TYPE, is not valid for creating a ShareLink."):
        assert create_sharelink_command(client=client, env=TAEGIS_ENVIRONMENT, args=args)

    # Successful Creation
    args["type"] = "investigationId"
    response = create_sharelink_command(client=client, env=TAEGIS_ENVIRONMENT, args=args)
    assert response.outputs["id"] == CREATE_SHARELINK_RESPONSE["data"]["createShareLink"]["id"]

    # Unknown error
    client = mock_client(requests_mock, {"errors": [{"message": "Unknown Error"}]})
    with pytest.raises(ValueError, match="Failed to create ShareLink"):
        assert create_sharelink_command(client=client, env=TAEGIS_ENVIRONMENT, args=args)
