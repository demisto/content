"""Base Integration for Cortex XSOAR - Unit Tests file

Pytest Unit Tests: all funcion names must start with "test_"

More details: https://xsoar.pan.dev/docs/integrations/unit-testing

MAKE SURE YOU REVIEW/REPLACE ALL THE COMMENTS MARKED AS "TODO"

You must add at least a Unit Test function for every XSOAR command
you are implementing with your integration
"""

import json
import io
from typing import Dict

from KnowBe4KMSAT import Client, UserEventClient

KMSAT_BASE_URL = "https://us.api.knowbe4.com"

USER_EVENT_BASE_URL = "https://api.events.knowbe4.com"
REPORTING_BASE_URL = "https://us.api.knowbe4.com/v1"


def util_load_json(path):
    with io.open(path, mode="r", encoding="utf-8") as f:
        return json.loads(f.read())


def test_account_info(requests_mock):
    """
    Given
            no params
    When
            Calling https://us.api.knowbe4.com/v1/account
    Then
            Make sure the data contains account information
    """
    mock_response_data = util_load_json("test_data/account_response.json")
    from KnowBe4KMSAT import kmsat_account_info_list_command

    requests_mock.get(
        f"{REPORTING_BASE_URL}/account", json=mock_response_data, status_code=200
    )

    client = Client(
        REPORTING_BASE_URL,
        verify=False,
        proxy=False,
        headers={
            "Authorization": "Bearer abc123xyz",
            "Content-Type": "application/json",
        },
    )
    args: dict = {}
    result = kmsat_account_info_list_command(client, args)

    assert requests_mock.last_request.headers['X-KB4-Integration'] == "Cortex XSOAR KMSAT"
    assert result.outputs_prefix == "KMSAT.AccountInfo"
    assert result.outputs_key_field == "name"
    assert result.outputs == mock_response_data


def test_account_risk_score_history(requests_mock):
    """
    Given
            no params
    When
            Calling https://us.api.knowbe4.com/v1/account/risk_score_history
    Then
            Make sure the data contains account risk history information
    """
    mock_response_data = util_load_json(
        "test_data/account_risk_score_history_response.json"
    )
    from KnowBe4KMSAT import kmsat_account_risk_score_history_list_command

    requests_mock.get(
        f"{REPORTING_BASE_URL}/account/risk_score_history",
        json=mock_response_data,
        status_code=200,
    )

    client = Client(
        REPORTING_BASE_URL,
        verify=False,
        proxy=False,
        headers={
            "Authorization": "Bearer abc123xyz",
            "Content-Type": "application/json",
        },
    )
    args: dict = {}
    result = kmsat_account_risk_score_history_list_command(client, args)
    assert result.outputs_prefix == "KMSAT.AccountRiskScoreHistory"
    assert result.outputs_key_field == ""
    assert result.outputs == mock_response_data


def test_account_groups_risk_score_history(requests_mock):
    """
    Given
            A group ID argument
    When
            Calling https://us.api.knowbe4.com/v1/groups/1/risk_score_history
    Then
            Make sure the data contains id with expected values
    """
    mock_response_data = util_load_json(
        "test_data/groups_risk_score_history_response.json"
    )
    from KnowBe4KMSAT import kmsat_groups_risk_score_history_list_command

    requests_mock.get(
        f"{REPORTING_BASE_URL}/groups/1/risk_score_history",
        json=mock_response_data,
        status_code=200,
    )

    client = Client(
        REPORTING_BASE_URL,
        verify=False,
        proxy=False,
        headers={
            "Authorization": "Bearer abc123xyz",
            "Content-Type": "application/json",
        },
    )
    args: dict = {"group_id": 1}
    result = kmsat_groups_risk_score_history_list_command(client, args)
    assert result.outputs_prefix == "KMSAT.GroupsRiskScoreHistory"
    assert result.outputs_key_field == "id"
    assert result.outputs == mock_response_data


def test_groups_members_list(requests_mock):
    """
    Given
            A group ID argument
    When
            Calling https://us.api.knowbe4.com/v1/groups/1/members
    Then
            Make sure the data contains id with expected values
    """
    mock_response_data = util_load_json(
        "test_data/groups_risk_score_history_response.json"
    )
    from KnowBe4KMSAT import kmsat_groups_members_list_command

    requests_mock.get(
        f"{REPORTING_BASE_URL}/groups/1/members",
        json=mock_response_data,
        status_code=200,
    )

    client = Client(
        REPORTING_BASE_URL,
        verify=False,
        proxy=False,
        headers={
            "Authorization": "Bearer abc123xyz",
            "Content-Type": "application/json",
        },
    )
    args: dict = {"group_id": 1}
    result = kmsat_groups_members_list_command(client, args)
    assert result.outputs_prefix == "KMSAT.GroupsMembers"
    assert result.outputs_key_field == "id"
    assert result.outputs == mock_response_data


def test_users_risk_score_history_list(requests_mock):
    """
    Given
            A user ID
    When
            Calling https://us.api.knowbe4.com/v1/users/1/risk_score_history
    Then
            Make sure the data returned for user
    """
    mock_response_data = util_load_json(
        "test_data/user_risk_score_history_response.json"
    )
    from KnowBe4KMSAT import kmsat_users_risk_score_history_list_command

    requests_mock.get(
        f"{REPORTING_BASE_URL}/users/1/risk_score_history",
        json=mock_response_data,
        status_code=200,
    )

    client = Client(
        REPORTING_BASE_URL,
        verify=False,
        proxy=False,
        headers={
            "Authorization": "Bearer abc123xyz",
            "Content-Type": "application/json",
        },
    )
    args: dict = {"user_id": 1}
    result = kmsat_users_risk_score_history_list_command(client, args)
    assert result.outputs_prefix == "KMSAT.UsersRiskScoreHistory"
    assert result.outputs_key_field == ""
    assert result.outputs == mock_response_data


def test_phishing_security_tests_list(requests_mock):
    """
    Given
            no params
    When
            Calling https://us.api.knowbe4.com/v1/phishing/security_tests
    Then
            Make sure the data contains campaign_id with expected values
    """
    mock_response_data = util_load_json(
        "test_data/groups_risk_score_history_response.json"
    )
    from KnowBe4KMSAT import kmsat_phishing_security_tests_list_command

    requests_mock.get(
        f"{REPORTING_BASE_URL}/phishing/security_tests",
        json=mock_response_data,
        status_code=200,
    )

    client = Client(
        REPORTING_BASE_URL,
        verify=False,
        proxy=False,
        headers={
            "Authorization": "Bearer abc123xyz",
            "Content-Type": "application/json",
        },
    )
    args: Dict = {}
    result = kmsat_phishing_security_tests_list_command(client, args)
    assert result.outputs_prefix == "KMSAT.PhishingSecurity"
    assert result.outputs_key_field == "campaign_id"
    assert result.outputs == mock_response_data


def test_phishing_security_tests_recipients_list(requests_mock):
    """
    Given
            A phishing security test ID
    When
            Calling https://us.api.knowbe4.com/v1/phishing/security_tests/1/recipients
    Then
            Make sure the data contains recipient_id with expected values
    """
    mock_response_data = util_load_json(
        "test_data/phishing_security_tests_recipients_response.json"
    )
    from KnowBe4KMSAT import kmsat_phishing_security_tests_recipients_list_command

    requests_mock.get(
        f"{REPORTING_BASE_URL}/phishing/security_tests/1/recipients",
        json=mock_response_data,
        status_code=200,
    )

    client = Client(
        REPORTING_BASE_URL,
        verify=False,
        proxy=False,
        headers={
            "Authorization": "Bearer abc123xyz",
            "Content-Type": "application/json",
        },
    )
    args: dict = {"pst_id": 1}
    result = kmsat_phishing_security_tests_recipients_list_command(client, args)
    assert result.outputs_prefix == "KMSAT.PhishingSecurityPST"
    assert result.outputs_key_field == "recipient_id"
    assert result.outputs == mock_response_data


def test_phishing_security_tests_failed_recipients_list(requests_mock):
    """
    Given
            A phishing security test ID
    When
            Calling https://us.api.knowbe4.com/v1/phishing/campaigns/1/security_tests
    Then
            Make sure the data contains recipient_id with expected values
    """
    mock_response_data = util_load_json(
        "test_data/phishing_security_tests_failed_recipients_response.json"
    )
    from KnowBe4KMSAT import kmsat_phishing_security_tests_failed_recipients_list_command

    requests_mock.get(
        f"{REPORTING_BASE_URL}/phishing/security_tests/1/recipients",
        json=mock_response_data,
        status_code=200,
    )

    client = Client(
        REPORTING_BASE_URL,
        verify=False,
        proxy=False,
        headers={
            "Authorization": "Bearer abc123xyz",
            "Content-Type": "application/json",
        },
    )
    args: dict = {"pst_id": 1}
    result = kmsat_phishing_security_tests_failed_recipients_list_command(client, args)
    valid_response = {
        "data": mock_response_data,
        "meta": {
            "filtered_items_in_page": 1,
            "items_total": 1,
            "paging_end": True
        }
    }

    assert result.outputs_prefix == "KMSAT.PhishingSecurityPST"
    assert result.outputs_key_field == "recipient_id"
    assert result.outputs == valid_response


def test_phishing_campaigns_security_tests_list(requests_mock):
    """
    Given
            A campaign ID
    When
            Calling https://us.api.knowbe4.com/v1/phishing/campaigns/1/security_tests
    Then
            Make sure the data is returned for the campaign
    """
    mock_response_data = util_load_json(
        "test_data/phishing_security_tests_failed_recipients_response.json"
    )
    from KnowBe4KMSAT import kmsat_phishing_campaign_security_tests_list_command

    requests_mock.get(
        f"{REPORTING_BASE_URL}/phishing/campaigns/1/security_tests",
        json=mock_response_data,
        status_code=200,
    )

    client = Client(
        REPORTING_BASE_URL,
        verify=False,
        proxy=False,
        headers={
            "Authorization": "Bearer abc123xyz",
            "Content-Type": "application/json",
        },
    )
    args: dict = {"campaign_id": 1}
    result = kmsat_phishing_campaign_security_tests_list_command(client, args)
    assert result.outputs_prefix == "KMSAT.CampaignPST"
    assert result.outputs_key_field == ""
    assert result.outputs == mock_response_data


def test_training_campaigns_list(requests_mock):
    """
    Given
            no params
    When
            Calling https://us.api.knowbe4.com/v1/training/campaigns
    Then
            Make sure the data contains campaign_id with expected values
    """
    mock_response_data = util_load_json(
        "test_data/training_campaigns_response.json"
    )
    from KnowBe4KMSAT import kmsat_training_campaigns_list_command

    requests_mock.get(
        f"{REPORTING_BASE_URL}/training/campaigns",
        json=mock_response_data,
        status_code=200,
    )

    client = Client(
        REPORTING_BASE_URL,
        verify=False,
        proxy=False,
        headers={
            "Authorization": "Bearer abc123xyz",
            "Content-Type": "application/json",
        },
    )
    args: dict = {}
    result = kmsat_training_campaigns_list_command(client, args)
    assert result.outputs_prefix == "KMSAT.TrainingCampaigns"
    assert result.outputs_key_field == "campaign_id"
    assert result.outputs == mock_response_data


def test_training_enrollments_list(requests_mock):
    """
    Given
            no params
    When
            Calling https://us.api.knowbe4.com/v1/training/enrollments
    Then
            Make sure the data contains enrollment_id with expected values
    """
    mock_response_data = util_load_json(
        "test_data/training_enrollments_response.json"
    )
    from KnowBe4KMSAT import kmsat_training_enrollments_list_command

    requests_mock.get(
        f"{REPORTING_BASE_URL}/training/enrollments",
        json=mock_response_data,
        status_code=200,
    )

    client = Client(
        REPORTING_BASE_URL,
        verify=False,
        proxy=False,
        headers={
            "Authorization": "Bearer abc123xyz",
            "Content-Type": "application/json",
        },
    )
    args: dict = {}
    result = kmsat_training_enrollments_list_command(client, args)
    valid_response = {
        "data": mock_response_data,
        "meta": {
            "filtered_items_in_page": 0,
            "items_total": 4,
            "paging_end": True
        }
    }
    assert result.outputs_prefix == "KMSAT.TrainingEnrollments"
    assert result.outputs_key_field == "enrollment_id"
    assert result.outputs == valid_response


def test_status_training_enrollments_list(requests_mock):
    """
    Given
            A status
            Calling https://us.api.knowbe4.com/v1/training/enrollments
    Then
            Make sure the data contains enrollment_id with expected values
    """
    mock_response_data = util_load_json(
        "test_data/training_enrollments_response.json"
    )
    from KnowBe4KMSAT import kmsat_training_enrollments_list_command

    requests_mock.get(
        f"{REPORTING_BASE_URL}/training/enrollments",
        json=mock_response_data,
        status_code=200,
    )

    client = Client(
        REPORTING_BASE_URL,
        verify=False,
        proxy=False,
        headers={
            "Authorization": "Bearer abc123xyz",
            "Content-Type": "application/json",
        },
    )
    expectedStatus: str = "Passed"
    args: dict = {"status": expectedStatus}
    result = kmsat_training_enrollments_list_command(client, args)

    assert result.outputs_prefix == "KMSAT.TrainingEnrollments"
    assert result.outputs_key_field == "enrollment_id"
    assert len(result.outputs["data"]) == 2
    assert len(mock_response_data) > 2
    for enrollment in result.outputs["data"]:
        assert enrollment["status"] == expectedStatus
    responseMeta = result.outputs["meta"]
    assert responseMeta["filtered_items_in_page"] == 2
    assert responseMeta["items_total"] == len(mock_response_data)
    assert responseMeta["paging_end"]


def test_get_user_event_types(requests_mock):
    """
    Given
            no params
    When
            Calling https://api.events.knowbe4.com/event_types
    Then
            Make sure the data array contains event_types with expected values
    """

    mock_response_data = util_load_json("test_data/user_event_types_response.json")
    from KnowBe4KMSAT import kmsat_user_event_types_list_command

    requests_mock.get(
        f"{USER_EVENT_BASE_URL}/event_types", json=mock_response_data, status_code=200
    )

    userEventClient = UserEventClient(
        USER_EVENT_BASE_URL,
        verify=False,
        proxy=False,
        headers={
            "Authorization": "Bearer abc123xyz",
            "Content-Type": "application/json",
        },
    )

    args: dict = {}
    result = kmsat_user_event_types_list_command(userEventClient, args)
    assert result.outputs_prefix == "KMSAT.UserEventTypes"
    assert result.outputs_key_field == "id"
    assert result.outputs == mock_response_data["data"]


def test_get_user_events(requests_mock):
    """
    Given
            no params
    When
            Calling https://api.events.knowbe4.com/events
    Then
            Make sure the data array contains user events
    """

    mock_response_data = util_load_json("test_data/user_events_response.json")
    from KnowBe4KMSAT import kmsat_user_events_list_command

    requests_mock.get(
        f"{USER_EVENT_BASE_URL}/events", json=mock_response_data, status_code=200
    )

    userEventClient = UserEventClient(
        USER_EVENT_BASE_URL,
        verify=False,
        proxy=False,
        headers={
            "Authorization": "Bearer abc123xyz",
            "Content-Type": "application/json",
        },
    )

    args: dict = {}
    result = kmsat_user_events_list_command(userEventClient, args)

    assert requests_mock.last_request.headers['X-KB4-Integration'] == "Cortex XSOAR KMSAT"
    assert result.outputs_prefix == "KMSAT.UserEvents"
    assert result.outputs_key_field == "id"
    assert result.outputs == mock_response_data["data"]


def test_get_user_event(requests_mock):
    """
    Given
            an event ID
    When
            Calling https://api.events.knowbe4.com/events/{id}
    Then
            Make sure the data contains the user event
    """

    eventId: str = "513f46ac-c3d7-4682-ad0d-0c149c0728a2"

    mock_response_data = util_load_json("test_data/user_event_response.json")
    from KnowBe4KMSAT import kmsat_user_event_list_command

    requests_mock.get(
        f"{USER_EVENT_BASE_URL}/events/{eventId}", json=mock_response_data, status_code=200
    )

    userEventClient = UserEventClient(
        USER_EVENT_BASE_URL,
        verify=False,
        proxy=False,
        headers={
            "Authorization": "Bearer abc123xyz",
            "Content-Type": "application/json",
        },
    )

    args: dict = {"id": eventId}
    result = kmsat_user_event_list_command(userEventClient, args)

    assert requests_mock.last_request.headers['X-KB4-Integration'] == "Cortex XSOAR KMSAT"
    assert result.outputs_prefix == "KMSAT.UserEvent"
    assert result.outputs_key_field == "id"
    assert result.outputs == mock_response_data["data"]


def test_delete_user_event(requests_mock):
    """
    Given
            an Event ID
    When
            Calling https://api.events.knowbe4.com/events/{id}
    Then
            Make sure the data array contains user events
    """
    eventId: str = "123-456-789"
    from KnowBe4KMSAT import kmsat_user_event_delete_command

    requests_mock.delete(f"{USER_EVENT_BASE_URL}/events/{eventId}", status_code=204)

    userEventClient = UserEventClient(
        USER_EVENT_BASE_URL,
        verify=False,
        proxy=False,
        headers={
            "Authorization": "Bearer abc123xyz",
            "Content-Type": "application/json",
        },
    )

    args: dict = {"id": eventId}
    result = kmsat_user_event_delete_command(userEventClient, args)

    assert result.readable_output == f"Successfully deleted event: {eventId}"


def test_get_user_event_status(requests_mock):
    """
    Given
            an Event ID
    When
            Calling https://api.events.knowbe4.com/statuses/{id}
    Then
            Make sure the data contains the user events
    """

    eventId: str = "abcdefgh-843c-4fc8-bb2f-decf89876f7b"

    mock_response_data = util_load_json("test_data/user_event_status_response.json")
    from KnowBe4KMSAT import kmsat_user_event_status_list_command

    requests_mock.get(
        f"{USER_EVENT_BASE_URL}/statuses/{eventId}", json=mock_response_data, status_code=200
    )

    userEventClient = UserEventClient(
        USER_EVENT_BASE_URL,
        verify=False,
        proxy=False,
        headers={
            "Authorization": "Bearer abc123xyz",
            "Content-Type": "application/json",
        },
    )

    args: dict = {"id": eventId}
    result = kmsat_user_event_status_list_command(userEventClient, args)

    assert requests_mock.last_request.headers['X-KB4-Integration'] == "Cortex XSOAR KMSAT"
    assert result.outputs_prefix == "KMSAT.UserEventStatus"
    assert result.outputs_key_field == "id"
    assert result.outputs == mock_response_data["data"]


def test_get_user_event_statuses(requests_mock):
    """
    Given
            no params
    When
            Calling https://api.events.knowbe4.com/statuses
    Then
            Make sure the data contains the list of user event requests
    """

    mock_response_data = util_load_json("test_data/user_event_statuses_response.json")
    from KnowBe4KMSAT import kmsat_user_event_statuses_list_command

    requests_mock.get(
        f"{USER_EVENT_BASE_URL}/statuses", json=mock_response_data, status_code=200
    )

    userEventClient = UserEventClient(
        USER_EVENT_BASE_URL,
        verify=False,
        proxy=False,
        headers={
            "Authorization": "Bearer abc123xyz",
            "Content-Type": "application/json",
        },
    )

    args: dict = {}
    result = kmsat_user_event_statuses_list_command(userEventClient, args)

    assert requests_mock.last_request.headers['X-KB4-Integration'] == "Cortex XSOAR KMSAT"
    assert result.outputs_prefix == "KMSAT.UserEventStatuses"
    assert result.outputs_key_field == "id"
    assert result.outputs == mock_response_data["data"]


def test_get_pagination():
    """
    Given
            A page number and the number of results per page.
    When
            Calling get_pagination()
    Then
            Make sure the data returns with page and per_page
    """
    from KnowBe4KMSAT import get_pagination
    args = {"page": 1, "per_page": 10}
    assert get_pagination(args) == args
