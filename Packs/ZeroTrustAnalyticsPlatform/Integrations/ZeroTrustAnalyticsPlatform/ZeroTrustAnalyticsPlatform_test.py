import json
from datetime import datetime

from ZeroTrustAnalyticsPlatform import (
    Client,
    fetch_incidents,
    get_mapping_fields,
    get_remote_data,
    get_modified_remote_data,
    update_remote_system,
    ztap_get_alert_entries,
)

from test_data.api_data import (
    alert_data,
    escalation_path_data,
    event_data,
    comment_data,
    log_data,
    organization_data,
    group_data,
    user_data,
)
from test_data.xsoar_data import (
    alert_response,
    alert_response_remote,
    comment_entries,
    log_entries,
)

TEST_MIRROR_DIRECTION = "Both"
TEST_INTEGRATION_INSTANCE = "dummy_instance"
TEST_ESCALATE_ORG = "dummy_org"
TEST_ESCALATE_GROUP = "Default"
TEST_COMMENT_TAG = "comment_tag"
TEST_ESCALATE_TAG = "escalate_tag"
TEST_INPUT_TAG = "input_tag"


def get_test_client():
    client = Client("some_mock_url", verify_certificate=False)
    client.comment_tag = TEST_COMMENT_TAG
    client.escalate_tag = TEST_ESCALATE_TAG
    client.input_tag = TEST_INPUT_TAG
    client.reopen_group = TEST_ESCALATE_GROUP
    return client


def test_fetch_incidents(mocker):
    client = get_test_client()

    mocker.patch.object(client, "get_alerts", return_value=alert_data())
    mocker.patch.object(
        client, "get_escalation_path", return_value=escalation_path_data()
    )
    mocker.patch.object(client, "get_events", return_value=event_data())
    mocker.patch.object(client, "get_active_user", return_value=user_data())

    last_run = {
        "last_run": "2021-01-01T00:00:00Z",
        "existing_ids": [],
    }
    max_fetch = 100
    first_fetch_timestamp = "7 days"
    response, new_last_run = fetch_incidents(
        client,
        last_run,
        first_fetch_timestamp,
        max_fetch,
        TEST_MIRROR_DIRECTION,
        TEST_INTEGRATION_INSTANCE,
    )

    mock_response_0 = json.dumps(alert_response()[0])
    mock_response_1 = json.dumps(alert_response()[1])

    assert response[0]["rawJSON"] == mock_response_0
    assert response[1]["rawJSON"] == mock_response_1
    assert new_last_run["last_run"] == "2021-05-11T20:11:31Z"
    assert new_last_run["existing_ids"] == ["1", "2"]


def test_fetch_incidents_already_escalated(mocker):
    client = get_test_client()

    old_escalation_path = (
        {
            "time": "2020-05-01T00:00:00Z",
            "group": "Default (dummy_org)",
            "group_id": "1",
            "type": "Group",
        },
        {
            "time": datetime.now().isoformat() + "Z",
            "group": "Default (dummy_org)",
            "group_id": "1",
            "type": "Group",
        },
    )

    mocker.patch.object(client, "get_alerts", return_value=alert_data())
    mocker.patch.object(client, "get_escalation_path", return_value=old_escalation_path)
    mocker.patch.object(client, "get_events", return_value=event_data())
    mocker.patch.object(client, "get_active_user", return_value=user_data())

    last_run = {
        "last_run": "2021-01-01T00:00:00Z",
        "existing_ids": [],
    }
    max_fetch = 100
    first_fetch_timestamp = "7 days"
    response, new_last_run = fetch_incidents(
        client,
        last_run,
        first_fetch_timestamp,
        max_fetch,
        TEST_MIRROR_DIRECTION,
        TEST_INTEGRATION_INSTANCE,
    )

    assert len(response) == 0
    assert new_last_run["last_run"] == "2021-05-11T20:11:31Z"
    assert new_last_run["existing_ids"] == []


def test_fetch_incidents_first_fetch(mocker):
    client = get_test_client()

    recent_escalation_path = (
        {
            "time": datetime.now().isoformat() + "Z",
            "group": "Default (dummy_org)",
            "group_id": "1",
            "type": "Group",
        },
    )

    mocker.patch.object(client, "get_alerts", return_value=alert_data())
    mocker.patch.object(
        client, "get_escalation_path", return_value=recent_escalation_path
    )
    mocker.patch.object(client, "get_events", return_value=event_data())
    mocker.patch.object(client, "get_active_user", return_value=user_data())

    last_run = {}
    max_fetch = 100
    first_fetch_timestamp = "7 days"
    response, new_last_run = fetch_incidents(
        client,
        last_run,
        first_fetch_timestamp,
        max_fetch,
        TEST_MIRROR_DIRECTION,
        TEST_INTEGRATION_INSTANCE,
    )

    mock_response_0 = json.dumps(alert_response()[0])
    mock_response_1 = json.dumps(alert_response()[1])

    assert response[0]["rawJSON"] == mock_response_0
    assert response[1]["rawJSON"] == mock_response_1
    assert new_last_run["existing_ids"] == ["1", "2"]


def test_fetch_incidents_existing_ids(mocker):
    client = get_test_client()

    mocker.patch.object(client, "get_alerts", return_value=alert_data())
    mocker.patch.object(
        client, "get_escalation_path", return_value=escalation_path_data()
    )
    mocker.patch.object(client, "get_events", return_value=event_data())
    mocker.patch.object(client, "get_active_user", return_value=user_data())

    last_run = {
        "last_run": "2021-05-11T20:11:31Z",
        "existing_ids": ["1", "2"],
    }
    max_fetch = 100
    first_fetch_timestamp = "7 days"
    response, new_last_run = fetch_incidents(
        client,
        last_run,
        first_fetch_timestamp,
        max_fetch,
        TEST_MIRROR_DIRECTION,
        TEST_INTEGRATION_INSTANCE,
    )

    assert len(response) == 0
    assert new_last_run["last_run"] == "2021-05-11T20:11:31Z"
    assert new_last_run["existing_ids"] == ["1", "2"]


def test_get_mapping_fields():
    response = get_mapping_fields()
    fields = response.scheme_types_mappings[0].fields
    assert "status" in fields


def test_get_remote_data(mocker):
    client = get_test_client()

    mocker.patch.object(client, "get_alert", return_value=alert_data()[0])
    mocker.patch.object(client, "get_events", return_value=event_data())
    mocker.patch.object(client, "get_comments", return_value=comment_data())
    mocker.patch.object(client, "get_logs", return_value=log_data())
    mocker.patch.object(client, "get_active_user", return_value=user_data())

    args = {
        "id": "1",
        "lastUpdate": "2021-01-01T00:00:00Z",
    }
    investigation = {}
    response = get_remote_data(client, investigation, args)

    alert_json = json.dumps(response.mirrored_object)
    mock_response = json.dumps(alert_response_remote())
    entries_json = json.dumps(response.entries)
    entry_response = json.dumps(comment_entries() + log_entries())

    assert alert_json == mock_response
    assert entries_json == entry_response


def test_get_remote_data_no_new_events(mocker):
    client = get_test_client()

    mocker.patch.object(client, "get_alert", return_value=alert_data()[0])
    mocker.patch.object(client, "get_comments", return_value=[])
    mocker.patch.object(client, "get_logs", return_value=[])
    mocker.patch.object(client, "get_active_user", return_value=user_data())

    args = {
        "id": "1",
        "lastUpdate": "2022-01-01T00:00:00Z",
    }
    investigation = {}
    response = get_remote_data(client, investigation, args)

    assert "xsoar_trigger_events" not in response.mirrored_object


def test_get_remote_data_closed_incident(mocker):
    client = get_test_client()

    closed_alert = {
        "datetime_created": "2021-05-11T20:11:31Z",
        "datetime_firstevent": "2021-05-11T20:11:30Z",
        "datetime_closed": "2021-05-11T21:00:00Z",
        "datetime_events_added": "2021-05-11T20:11:31Z",
        "id": 1,
        "status": "closed",
        "review_outcome": "resolved",
    }
    mocker.patch.object(client, "get_alert", return_value=closed_alert)
    mocker.patch.object(client, "get_events", return_value=[])
    mocker.patch.object(client, "get_comments", return_value=[])
    mocker.patch.object(client, "get_logs", return_value=[])
    mocker.patch.object(client, "get_active_user", return_value=user_data())

    client.close_incident = True
    args = {
        "id": "1",
        "lastUpdate": "2021-01-01T00:00:00Z",
    }
    investigation = {
        "lastOpen": "2021-05-01T00:00:00Z",
    }
    response = get_remote_data(client, investigation, args)

    assert len(response.entries) == 1
    assert response.entries[-1]["Contents"]["dbotIncidentClose"]

    # Reopened after close time
    investigation = {
        "lastOpen": "2021-05-12T00:00:00Z",
    }
    response = get_remote_data(client, investigation, args)

    assert len(response.entries) == 0


def test_get_remote_data_reopen_incident(mocker):
    client = get_test_client()

    reopened_alert = {
        "datetime_created": "2021-05-11T20:11:31Z",
        "datetime_firstevent": "2021-05-11T20:11:30Z",
        "datetime_closed": "2021-05-11T21:00:00Z",
        "datetime_events_added": "2021-05-11T20:11:31Z",
        "datetime_org_assigned": "2021-05-11T22:00:00Z",
        "id": 1,
        "status": "assigned",
    }
    mocker.patch.object(client, "get_alert", return_value=reopened_alert)
    mocker.patch.object(client, "get_comments", return_value=[])
    mocker.patch.object(client, "get_logs", return_value=[])
    mocker.patch.object(client, "get_active_user", return_value=user_data())

    client.reopen_incident = True
    args = {
        "id": "1",
        "lastUpdate": "2021-05-11T23:00:00Z",
    }
    investigation = {
        "closed": "2021-05-01T00:00:00Z",
    }
    response = get_remote_data(client, investigation, args)

    assert len(response.entries) == 1
    assert response.entries[-1]["Contents"]["dbotIncidentReopen"]

    # Closed after reopen time
    investigation = {
        "closed": "2021-05-12T00:00:00Z",
    }
    response = get_remote_data(client, investigation, args)

    assert len(response.entries) == 0


def test_get_modified_remote_data(mocker):
    client = get_test_client()

    mocker.patch.object(client, "get_all_alerts", return_value=alert_data())

    args = {
        "lastUpdate": "2021-01-01T00:00:00Z",
    }
    response = get_modified_remote_data(client, args)

    assert response.modified_incident_ids == ["1", "2"]


def test_update_remote_system(mocker):
    client = get_test_client()
    mocker.patch.object(client, "get_alert", return_value=alert_data()[0])
    mocker.patch.object(client, "get_logs", return_value=[])
    mocker.patch.object(client, "upload_comment")
    mocker.patch.object(client, "get_active_user", return_value=user_data())

    client.close_incident = True
    args = {
        "remoteId": "1",
        "status": 1,
        "entries": [
            {
                "user": "test user",
                "contents": "test contents",
                "tags": TEST_COMMENT_TAG,
            }
        ],
        "incidentChanged": False,
    }
    investigation = {}
    response = update_remote_system(client, investigation, args)

    client.upload_comment.assert_called()

    assert response == "1"


def test_update_remote_system_escalate(mocker):
    client = get_test_client()
    mocker.patch.object(client, "get_alert", return_value=alert_data()[0])
    mocker.patch.object(client, "get_logs", return_value=[])
    mocker.patch.object(client, "reassign_alert_to_org")
    mocker.patch.object(client, "get_organizations", return_value=organization_data())
    mocker.patch.object(client, "get_active_user", return_value=user_data())

    client.close_incident = True
    args = {
        "remoteId": "1",
        "status": 1,
        "entries": [
            {
                "user": "test user",
                "contents": "test contents",
                "tags": TEST_ESCALATE_TAG,
            }
        ],
        "incidentChanged": False,
    }
    investigation = {}
    response = update_remote_system(client, investigation, args)

    client.reassign_alert_to_org.assert_called()

    assert response == "1"


def test_update_remote_system_closed(mocker):
    client = get_test_client()
    mocker.patch.object(client, "get_alert", return_value=alert_data()[0])
    mocker.patch.object(client, "get_logs", return_value=[])
    mocker.patch.object(client, "close_alert")
    mocker.patch.object(client, "get_active_user", return_value=user_data())

    client.close_incident = True
    args = {
        "remoteId": "1",
        "status": 2,
        "data": {
            "closeNotes": "Closed as duplicate.",
            "closeReason": "duplicate",
        },
        "delta": {},
        "incidentChanged": True,
    }
    investigation = {"closed": "2021-05-12T00:00:00Z"}
    response = update_remote_system(client, investigation, args)

    client.close_alert.assert_called()

    assert response == "1"


def test_update_remote_system_reopen(mocker):
    client = get_test_client()
    client.reopen_incident = True

    closed_alert = {
        "datetime_created": "2021-05-11T20:11:31Z",
        "datetime_firstevent": "2021-05-11T20:11:30Z",
        "datetime_closed": "2021-05-11T21:00:00Z",
        "datetime_events_added": "2021-05-11T20:11:31Z",
        "id": 1,
        "status": "closed",
    }
    mocker.patch.object(client, "get_alert", return_value=closed_alert)
    mocker.patch.object(client, "get_logs", return_value=[])
    mocker.patch.object(client, "reopen_alert")
    mocker.patch.object(client, "get_groups", return_value=group_data())
    mocker.patch.object(client, "get_active_user", return_value=user_data())

    args = {
        "remoteId": "1",
        "status": 1,
        "data": {},
        "delta": {},
        "incidentChanged": True,
    }
    investigation = {"lastOpen": "2021-05-12T00:00:00Z"}
    response = update_remote_system(client, investigation, args)

    client.reopen_alert.assert_called()

    assert response == "1"


def test_ztap_get_alert_entries(mocker):
    client = get_test_client()

    mocker.patch.object(client, "get_alert", return_value=alert_data())
    mocker.patch.object(client, "get_comments", return_value=comment_data())
    mocker.patch.object(client, "get_logs", return_value=log_data())
    mocker.patch.object(client, "get_active_user", return_value=user_data())

    args = {
        "id": "1",
    }
    response = ztap_get_alert_entries(client, args)

    entries_json = json.dumps(response)
    entry_response = json.dumps(comment_entries() + log_entries())

    assert entries_json == entry_response
