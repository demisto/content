from collections.abc import Callable
import pytest
from pytest_mock import MockerFixture
import demistomock as demisto
from PerformActionOnCampaignIncidents import (
    ACTION_ON_CAMPAIGN_FIELD_NAME,
    FIELDS_TO_DISPLAY,
    SELECT_CAMPAIGN_INCIDENTS_FIELD_NAME,
    SELECT_CAMPAIGN_LOWER_INCIDENTS_FIELD_NAME,
    NO_CAMPAIGN_INCIDENTS_MSG,
    main,
    _set_involved_incidents_count,
    _set_part_of_campaign_field,
    _link_or_unlink_between_incidents,
    _set_incidents_to_campaign,
    _get_context,
    _get_incident,
    extract_domain,
    extract_single_or_list,
    _get_email_fields,
    _get_recipients,
    _extract_incident_fields,
    _parse_incident_context_to_valid_incident_campaign_context,
    perform_add_to_campaign,
    perform_remove_from_campaign,
    _set_removed_from_campaigns_field,
    ACTIONS
)
NUM_OF_INCIDENTS = 5
INCIDENT_IDS = [str(i) for i in range(NUM_OF_INCIDENTS)]
CUSTOM_FIELDS = {
    ACTION_ON_CAMPAIGN_FIELD_NAME: "Close",
    SELECT_CAMPAIGN_INCIDENTS_FIELD_NAME: INCIDENT_IDS,
}
MOCKED_INCIDENT = {"id": "100", "CustomFields": CUSTOM_FIELDS}
MOCKED_CAMPAIGN_INCIDENT = {
    "id": "id",
    "name": "name",
    "similarity": None,
    "emailfrom": "emailfrom@domain.com",
    "recipients": [
        "test1@example.com",
        "test2@example.com",
        "test3@example.com",
    ],
    "severity": "severity",
    "status": "status",
    "occurred": "occurred",
    "emailfromdomain": "domain.com",
    "recipientsdomain": ["example.com", "example.com", "example.com"],
}


def prepare(mocker: MockerFixture) -> None:
    mocker.patch.object(demisto, "incidents", return_value=[MOCKED_INCIDENT])
    mocker.patch.object(demisto, "executeCommand")
    mocker.patch(
        "PerformActionOnCampaignIncidents.get_campaign_incident_ids",
        return_value=INCIDENT_IDS,
    )
    mocker.patch.object(demisto, "results")
    mocker.patch.object(demisto, "callingContext", return_value="admin")


@pytest.mark.parametrize("action", ["close", "reopen", "take ownership"])
def test_perform_action_happy_path(mocker: MockerFixture, action: str) -> None:
    """
    Given -
        Perform action button was clicked and there is Selected incident ids

    When -
        Run the perform_action script

    Then -
        Validate the correct message is returned

    """
    prepare(mocker)
    CUSTOM_FIELDS[ACTION_ON_CAMPAIGN_FIELD_NAME] = action
    test_selected_ids = ["All", INCIDENT_IDS]
    for selected_ids in test_selected_ids:
        CUSTOM_FIELDS[SELECT_CAMPAIGN_INCIDENTS_FIELD_NAME] = selected_ids
        # run
        main()

        # validate
        res = demisto.results.call_args[0][0]
        assert "The following incidents was successfully" in res
        assert ",".join(INCIDENT_IDS) in res


def test_no_incidents_in_context(mocker: MockerFixture) -> None:
    """
    Given - there is no email campaign in context

    When - user click on perform action button

    Then - validate the return message about there is no campaign in context

    """

    prepare(mocker)
    CUSTOM_FIELDS[SELECT_CAMPAIGN_INCIDENTS_FIELD_NAME] = []
    CUSTOM_FIELDS[SELECT_CAMPAIGN_LOWER_INCIDENTS_FIELD_NAME] = []

    # run
    main()

    # validate
    assert demisto.results.call_args[0][0] == NO_CAMPAIGN_INCIDENTS_MSG


@pytest.mark.parametrize(
    "execute_command, args, error_message",
    [
        pytest.param(
            _set_involved_incidents_count,
            {"campaign_id": "test_id", "count": 3},
            "Error occurred while trying to set the involvedIncidentsCount field on the campaign incident test_id: Error message",
            id="set involved incidents count",
        ),
        pytest.param(
            _set_part_of_campaign_field,
            {"incident_id": "test_id", "campaign_id": "test_id"},
            "Error occurred while trying to set the partofcampaign field on the incident: Error message",
            id="set part of campaign filed",
        ),
        pytest.param(
            _link_or_unlink_between_incidents,
            {"incident_id": "test_id", "linked_incident_id": [13], "action": "link"},
            "Error occurred while trying to link between incident test_id and linked incidents [13]: Error message",
            id="link or unlink between incidents",
        ),
        pytest.param(
            _set_incidents_to_campaign,
            {"campaign_id": "test_id", "incidents_context": {}, "append": True},
            "Error occurred while trying to set incidents to campaign with ID test_id. Error: Error message",
            id="set incidents to campaign",
        ),
        pytest.param(
            _get_context,
            {"incident_id": "test_id"},
            "Error occurred while trying to get context for incident with ID test_id. Error: Error message",
            id="get context",
        ),
        pytest.param(
            _get_incident,
            {"incident_id": "test_id"},
            "Error occurred while trying to get incident with ID test_id. Error: Error message",
            id="get incident",
        ),
    ],
)
def test_error_in_execute_command(
    mocker: MockerFixture, execute_command: Callable, args: dict, error_message: str
) -> None:
    """
    Given -
        isError is return true to indicate there is error

    When -
        Run the main of PerformActionOnCampaignIncidents

    Then -
        Validate return_error was called
    """
    prepare(mocker)
    mocker.patch("PerformActionOnCampaignIncidents.isError", return_value=True)
    mocker.patch(
        "PerformActionOnCampaignIncidents.get_error", return_value="Error message"
    )

    # run
    try:
        execute_command(**args)
        pytest.fail("SystemExit should occurred as the return_error was called")
    except SystemExit:
        # validate
        res = demisto.results.call_args[0][0]
        assert res["Contents"] == error_message


@pytest.mark.parametrize(
    "email, expected_domain",
    [
        pytest.param("test@example.com", "example.com", id="valid email"),
        pytest.param(None, None, id="None"),
        pytest.param("test", None, id="invalid email"),
    ],
)
def test_extract_domain_with_email(
    email: str | None, expected_domain: str | None
) -> None:
    """Test extracting domain from email address.

    Given:
        - An email address or None value as input

    When:
        - Calling extract_domain() with the email

    Then:
        - Return the domain part of the email if it's a valid address,
          or None if input is empty/invalid
    """
    assert extract_domain(email) == expected_domain


@pytest.mark.parametrize(
    "input, expected_output",
    [
        pytest.param(["test"], "test", id="single item list"),
        pytest.param([[1]], [1], id="single item nested list"),
        pytest.param(["test1", "test2"], ["test1", "test2"], id="list items"),
        pytest.param(None, None, id="None"),
        pytest.param("test", "test", id="string"),
        pytest.param({"test": "test"}, {"test": "test"}, id="dict"),
    ],
)
def test_extract_single_or_list_single_item(
    input: list | None, expected_output: str | list | None
) -> None:
    """Test extracting a single item from input list or keeping input as is if not list.

    Given:
        - An input value that is either a list with a single item, a single value directly,
          or None

    When:
        - Calling extract_single_or_list() with the input

    Then:
        - Return the single item if input is a list with only one item
        - Return the input as is if it's a single value or None
    """
    assert extract_single_or_list(input) == expected_output


@pytest.mark.parametrize(
    "incident_context, return_value",
    [
        pytest.param(
            {
                "Contents": {
                    "data": {
                        "CustomFields": {
                            "emailto": ["test1@example.com"],
                            "emailcc": ["test2@example.com"],
                            "emailbcc": ["test3@example.com"],
                        }
                    }
                }
            },
            ["test1@example.com", "test2@example.com", "test3@example.com"],
            id="email-fields-populated",
        ),
        pytest.param(
            {
                "Contents": {
                    "data": {
                        "CustomFields": {
                            "emailto": None,
                            "emailcc": ["test2@example.com"],
                            "emailbcc": ["test3@example.com"],
                        }
                    }
                }
            },
            [[], "test2@example.com", "test3@example.com"],
            id="empty-emailto-field",
        ),
    ],
)
def test_get_email_fields_with_data(
    mocker: MockerFixture, incident_context, return_value
) -> None:
    """Tests getting email fields from incident context.

    Given:
        - An incident context with email fields populated

    When:
        - Calling _get_email_fields

    Then:
        - It should return a dict with the email fields mapped to their values
    """
    mocker.patch.object(demisto, "dt", side_effect=return_value)

    result = _get_email_fields(incident_context)

    assert result == {
        "CustomFields.emailto": return_value[0],
        "CustomFields.emailcc": return_value[1],
        "CustomFields.emailbcc": return_value[2],
    }


@pytest.mark.parametrize(
    "emails, expected_recipients",
    [
        pytest.param(
            {
                "CustomFields.emailto": ["test1@demisto.com", "test2@demisto.com"],
                "CustomFields.emailcc": ["test3@demisto.com", "test4@demisto.com"],
                "CustomFields.emailbcc": [],
            },
            [
                "test1@demisto.com",
                "test2@demisto.com",
                "test3@demisto.com",
                "test4@demisto.com",
            ],
            id="multiple emails",
        ),
        pytest.param(
            {
                "CustomFields.emailto": ["test@demisto.com"],
                "CustomFields.emailcc": [],
                "CustomFields.emailbcc": [],
            },
            ["test@demisto.com"],
            id="single email",
        ),
        pytest.param(
            {
                "CustomFields.emailto": [],
                "CustomFields.emailcc": [],
                "CustomFields.emailbcc": [],
            },
            [],
            id="empty list",
        ),
    ],
)
def test_get_recipients(emails: dict, expected_recipients: list) -> None:
    """Tests getting recipients from email fields.

    Given:
        - A dict containing emailto, emailcc and emailbcc fields

    When:
        - Calling _get_recipients() with the email fields

    Then:
        - It should return a list containing all email addresses across the fields
    """
    assert _get_recipients(emails) == expected_recipients


@pytest.mark.parametrize(
    "incident_context, return_value, recipients, expected",
    [
        (
            {
                "CustomFields.emailfrom": "emailfrom@domain.com",
                "occurred": "occurred",
                "name": "name",
                "status": "status",
                "id": "id",
                "severity": "severity",
            },
            [
                ["emailfrom@domain.com"],
                ["occurred"],
                ["name"],
                ["status"],
                ["id"],
                ["severity"],
            ],
            ["dummy@dummy", "dummy@dummy"],
            {
                "similarity": None,
                "occurred": "occurred",
                "emailfrom": "emailfrom@domain.com",
                "emailfromdomain": "domain.com",
                "name": "name",
                "status": "status",
                "recipients": ["dummy@dummy", "dummy@dummy"],
                "id": "id",
                "severity": "severity",
                "recipientsdomain": ["dummy", "dummy"],
            },
        )
    ],
)
def test_extract_incident_fields(
    mocker: MockerFixture,
    incident_context: dict,
    return_value: list,
    recipients: list,
    expected: dict,
):
    """Tests extracting fields from an incident.

    Given:
        - An incident context dictionary
        - A return value for the dt mock
        - A list of email recipients

    When:
        - Calling _extract_incident_fields() with the incident context and recipients

    Then:
        - It should return a dictionary containing the expected extracted fields
    """
    mocker.patch.object(demisto, "dt", side_effect=return_value)

    result = _extract_incident_fields(incident_context, recipients)

    assert result == expected


@pytest.mark.parametrize(
    "return_value, field_to_display, expected",
    [
        (
            [
                ["test1@example.com"],
                ["test2@example.com"],
                ["test3@example.com"],
                ["emailfrom@domain.com"],
                ["occurred"],
                ["name"],
                ["status"],
                ["id"],
                ["severity"],
            ],
            FIELDS_TO_DISPLAY,
            {
                "id": "id",
                "name": "name",
                "similarity": None,
                "emailfrom": "emailfrom@domain.com",
                "recipients": [
                    "test1@example.com",
                    "test2@example.com",
                    "test3@example.com",
                ],
                "severity": "severity",
                "status": "status",
                "occurred": "occurred",
                "emailfromdomain": "domain.com",
                "recipientsdomain": ["example.com", "example.com", "example.com"],
                "added_manually_to_campaign": True,
            },
        ),
        (
            [
                ["test1@example.com"],
                ["test2@example.com"],
                ["test3@example.com"],
                ["emailfrom@domain.com"],
                ["occurred"],
                ["name"],
                ["status"],
                ["id"],
                ["severity"],
                ["additional_requested_fields"],
            ],
            [
                "id",
                "name",
                "similarity",
                "emailfrom",
                "recipients",
                "severity",
                "status",
                "occurred",
                "additional_requested_fields",
            ],
            {
                "id": "id",
                "name": "name",
                "similarity": None,
                "emailfrom": "emailfrom@domain.com",
                "recipients": [
                    "test1@example.com",
                    "test2@example.com",
                    "test3@example.com",
                ],
                "severity": "severity",
                "status": "status",
                "occurred": "occurred",
                "additional_requested_fields": ["additional_requested_fields"],
                "emailfromdomain": "domain.com",
                "recipientsdomain": ["example.com", "example.com", "example.com"],
                "added_manually_to_campaign": True,
            },
        ),
    ],
)
def test_parse_incident_context_to_valid_incident_campaign_context(
    mocker: MockerFixture, return_value, field_to_display, expected
) -> None:
    """Tests parsing an incident context to a valid campaign incident context.

    Given test cases with:
        - Case 1: Basic valid case with the default field_to_display
        - Case 2: Valid case with additional requested field

    When:
        - Calling _parse_incident_context_to_valid_incident_campaign_context()

    Then:
        - It should return the expected parsed incident context dictionary
    """
    mocker.patch("PerformActionOnCampaignIncidents.isError", return_value=False)
    mocker.patch.object(demisto, "executeCommand", return_value=[{}])
    mocker.patch.object(demisto, "dt", side_effect=return_value)

    result = _parse_incident_context_to_valid_incident_campaign_context(
        "1", field_to_display
    )
    assert result == expected


@pytest.mark.parametrize(
    "ids_to_add, incident_ids, expected",
    [
        pytest.param(
            ["1", "4"],
            [{"id": "1"}, {"id": "2"}, {"id": "3"}],
            {"4"},
            id="add to campaign",
        ),
        pytest.param(
            ["4", "5", "6"],
            [{"id": "1"}, {"id": "2"}],
            {"4", "5", "6"},
            id="add all to campaign",
        ),
    ],
)
def test_perform_add_to_campaign(
    mocker: MockerFixture, ids_to_add: list, incident_ids: dict, expected: set
) -> None:
    """Tests adding incidents to an email campaign.

    Given:
        - ids_to_add: The IDs of incidents to add to the campaign
        - incident_ids: The existing incidents in the campaign context
        - expected: The expected new incident IDs that should be added

    When:
        - Calling perform_add_to_campaign()

    Then:
        - The returned string should contain the expected new incident IDs
    """
    involved_incidents_count = [1]
    mocker.patch("PerformActionOnCampaignIncidents.isError", return_value=False)
    mocker.patch("PerformActionOnCampaignIncidents._set_removed_from_campaigns_field")
    mocker.patch.object(demisto, "incidents", return_value=[MOCKED_INCIDENT])
    mocker.patch.object(demisto, "executeCommand", return_value=[{}])
    mocker.patch.object(
        demisto,
        "dt",
        side_effect=[incident_ids, FIELDS_TO_DISPLAY, involved_incidents_count],
    )
    mocker.patch(
        "PerformActionOnCampaignIncidents._parse_incident_context_to_valid_incident_campaign_context",
        return_value=MOCKED_CAMPAIGN_INCIDENT,
    )
    res = perform_add_to_campaign(ids_to_add, "add to campaign")
    for i in expected:
        assert i in res


@pytest.mark.parametrize(
    "ids_to_add, incident_ids, expected",
    [
        pytest.param(
            ["1", "2"],
            [{"id": "1"}, {"id": "2"}],
            "No new incidents to add to campaign.",
            id="No new incidents to add to campaign.",
        )
    ],
)
def test_perform_add_to_campaign_no_incidents_to_add(
    mocker: MockerFixture, ids_to_add: list, incident_ids: dict, expected: str
) -> None:
    """Tests adding incidents to an email campaign.

    Given:
        - ids_to_add: The IDs of incidents to add to the campaign
        - incident_ids: The existing incidents in the campaign context
        - expected: The expected new incident IDs that should be added

    When:
        - Calling perform_add_to_campaign() with ids_to_add that exist in campaign incident

    Then:
        - The returned string should contain the expected new incident IDs
    """
    involved_incidents_count = [1]
    mocker.patch("PerformActionOnCampaignIncidents.isError", return_value=False)
    mocker.patch.object(demisto, "incidents", return_value=[MOCKED_INCIDENT])
    mocker.patch.object(demisto, "executeCommand", return_value=[{}])
    mocker.patch.object(
        demisto,
        "dt",
        side_effect=[incident_ids, FIELDS_TO_DISPLAY, involved_incidents_count],
    )
    mocker.patch(
        "PerformActionOnCampaignIncidents._parse_incident_context_to_valid_incident_campaign_context",
        return_value=MOCKED_CAMPAIGN_INCIDENT,
    )
    res = perform_add_to_campaign(ids_to_add, "add to campaign")
    assert expected == res


@pytest.mark.parametrize(
    "ids_to_remove, incident_ids, expected",
    [
        pytest.param(
            ["1", "2"],
            [{"id": "1"}, {"id": "2"}, {"id": "3"}],
            {"2", "1"},
            id="remove from campaign",
        ),
        pytest.param(
            ["1", "2", "3"],
            [{"id": "1"}, {"id": "2"}],
            {"1", "2"},
            id="remove all from campaign",
        ),
    ],
)
def test_perform_remove_from_campaign(
    mocker: MockerFixture, ids_to_remove: list, incident_ids: dict, expected: set
) -> None:
    """Tests removing incidents from an email campaign.

    Given:
        - ids_to_remove: The IDs of incidents to remove from the campaign
        - incident_ids: The existing incidents in the campaign context
        - expected: The expected removed incident IDs

    When:
        - Calling perform_remove_from_campaign() with ids_to_remove

    Then:
        - The returned string should contain the expected removed incident IDs
    """
    involved_incidents_count = [1]
    mocker.patch("PerformActionOnCampaignIncidents.isError", return_value=False)
    mocker.patch("PerformActionOnCampaignIncidents._set_removed_from_campaigns_field")
    mocker.patch.object(demisto, "incidents", return_value=[MOCKED_INCIDENT])
    mocker.patch.object(demisto, "executeCommand", return_value=[{}])
    mocker.patch.object(
        demisto, "dt", side_effect=[incident_ids, involved_incidents_count]
    )
    res = perform_remove_from_campaign(ids_to_remove, "add to campaign")
    for i in expected:
        assert i in res


@pytest.mark.parametrize(
    "ids_to_remove, incident_ids, expected",
    [
        pytest.param(
            ["4", "5"],
            [{"id": "1"}, {"id": "2"}, {"id": "3"}],
            "No incidents to remove from the campaign.",
            id="No incidents to remove from the campaign",
        )
    ],
)
def test_perform_remove_from_campaign_no_incidents_to_remove(
    mocker: MockerFixture, ids_to_remove: list, incident_ids: dict, expected: str
) -> None:
    """Tests removing incidents from an email campaign when there are no incidents to remove.

    Given:
        - ids_to_remove: The IDs of incidents to remove from the campaign
        - incident_ids: The existing incidents in the campaign context

    When:
        - Calling perform_remove_from_campaign() with ids_to_remove that do not exist in campaign incident

    Then:
        - The returned string should indicate there are no incidents to remove
    """
    involved_incidents_count = [1]
    mocker.patch("PerformActionOnCampaignIncidents.isError", return_value=False)
    mocker.patch.object(demisto, "incidents", return_value=[MOCKED_INCIDENT])
    mocker.patch.object(demisto, "executeCommand", return_value=[{}])
    mocker.patch.object(
        demisto, "dt", side_effect=[incident_ids, involved_incidents_count]
    )
    res = perform_remove_from_campaign(ids_to_remove, "add to campaign")
    assert expected == res


@pytest.mark.parametrize(
    "campaign_ids_removed, action, expected_campaign_ids_removed",
    [
        (["campaign1", "campaign2"], ACTIONS.ADD, ["campaign1", "campaign2", "campaign_id"]),
        (None, ACTIONS.ADD, ["campaign_id"]),
        ([], ACTIONS.ADD, ["campaign_id"]),
        (None, ACTIONS.REMOVE, []),
        ([], ACTIONS.REMOVE, []),
        (["campaign1", "campaign_id"], ACTIONS.REMOVE, ["campaign1"]),
        (["campaign1", "campaign2", "campaign_id"], ACTIONS.ADD, ["campaign1", "campaign2", "campaign_id"]),
        (["campaign1"], ACTIONS.REMOVE, ["campaign1"])
    ]
)
def test_set_removed_from_campaigns_field(
    mocker, campaign_ids_removed, action, expected_campaign_ids_removed
):
    mocker.patch("PerformActionOnCampaignIncidents._get_incident", return_value={})
    mocker.patch("PerformActionOnCampaignIncidents._get_data_from_incident", return_value=campaign_ids_removed)
    mock_execute_command = mocker.patch("PerformActionOnCampaignIncidents.demisto.executeCommand")
    mocker.patch("PerformActionOnCampaignIncidents.isError", return_value=False)

    _set_removed_from_campaigns_field("incident_id", "campaign_id", action)

    mock_execute_command.assert_called_once_with(
        "setIncident", {"id": "incident_id", "removedfromcampaigns": expected_campaign_ids_removed}
    )
