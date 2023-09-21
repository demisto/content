from PATHelpdeskAdvanced import convert_response_dates, paginate, Field
import pytest
from datetime import datetime, timezone
from PATHelpdeskAdvanced import (
    DATETIME_FORMAT,
    DemistoException,
    parse_filter_conditions,
)


@pytest.mark.parametrize(
    "kwargs, expected_start, expected_limit",
    [
        ({"limit": 10}, 0, 10),
        ({"page": 2, "page_size": 20, "limit": 30}, 40, 20),
    ],
)
def test_paginate(kwargs, expected_start, expected_limit):
    """
    Given the keyword arguments `kwargs`, `expected_start`, and `expected_limit`.
    When the `paginate` function is called with the provided keyword arguments.
    Then the result of the pagination should have the expected values.
    """
    result = paginate(**kwargs)
    assert result.start == expected_start
    assert result.limit == expected_limit


@pytest.mark.parametrize(
    "demisto_name, expected_demisto_name, expected_hda_name",
    [
        ("incident_id", "incident_id", "IncidentID"),
        ("unread_email_html", "unread_email_html", "UnReadEmailHTML"),
        ("task", "task", "Task"),
        ("unread", "unread", "UnRead"),
        ("user_id_html", "user_id_html", "UserIDHTML"),
    ],
)
def test_field(demisto_name, expected_demisto_name, expected_hda_name):
    """
    Given a Demisto name, when initializing an instance of MyClass,
    then the demisto_name attribute should be set to the given Demisto name,
    and the hda_name attribute should be set to the expected HDA name.

    Args:
        demisto_name (str): The Demisto name.
        expected_demisto_name (str): The expected value of the demisto_name attribute.
        expected_hda_name (str): The expected value of the hda_name attribute.

    Returns:
        None
    """
    field = Field(demisto_name)
    assert field.demisto_name == expected_demisto_name
    assert field.hda_name == expected_hda_name


def test_converts_date_fields():
    """
    Given a response dict with date fields
    When convert_response_dates is called
    Then date fields are converted to datetime, and others are untouched
    """
    EPOCH_2023_INT = 1693573200000
    EPOCH_2022_INT = 1641042000000

    STR_2023 = (
        datetime.fromtimestamp(EPOCH_2023_INT / 1000, tz=timezone.utc)
    ).strftime(DATETIME_FORMAT)
    STR_2022 = (
        datetime.fromtimestamp(EPOCH_2022_INT / 1000, tz=timezone.utc)
    ).strftime(DATETIME_FORMAT)

    raw = {
        "Date1": f"/Date({EPOCH_2023_INT})/",
        "Date2": [f"/Date({EPOCH_2023_INT})/", f"/Date({EPOCH_2022_INT})/", "🕒"],
        "other": [EPOCH_2023_INT, STR_2023],
    }

    result = convert_response_dates(raw)

    assert result["Date1"] == STR_2023
    assert result["Date2"] == [STR_2023, STR_2022, "🕒"]
    assert result["other"] == raw["other"]


@pytest.fixture
def mocked_client(mocker):
    """Given a mocked Client instance"""
    return mocker.Mock()


def test_create_ticket_success(mocked_client):
    from PATHelpdeskAdvanced import create_ticket_command

    """
    Given a client instance and arguments for creating a ticket
    When create_ticket_command is called with the client and args
    Then it should return a CommandResults instance with the expected outputs
    """
    args = {"subject": "Test ticket", "problem": "Something went wrong"}
    mocked_client.create_ticket.return_value = {
        "id": 123,
        "data": {
            "ObjectDescription": "Test ticket",
            "ObjectEntity": "ticket",
            "Solution": "Fixed the issue",
            "TicketClassificationId": 1,
            "IsNew": True,
            "ExpirationDate": "/Date(1609459200000)/",
            "FirstUpdateUserId": 1,
            "OwnerUserId": 2,
            "Date": "/Date(1609459200000)/",
            "AssignedUserId": 2,
        },
    }

    result = create_ticket_command(mocked_client, args)
    assert result.outputs == {
        "id": 123,
        "data": {
            "ObjectDescription": "Test ticket",
            "ObjectEntity": "ticket",
            "Solution": "Fixed the issue",
            "TicketClassificationId": 1,
            "IsNew": True,
            "ExpirationDate": "2021-01-01T00:00:00Z",
            "FirstUpdateUserId": 1,
            "OwnerUserId": 2,
            "Date": "2021-01-01T00:00:00Z",
            "AssignedUserId": 2,
        },
    }
    assert result.raw_response == mocked_client.create_ticket.return_value
    assert result.readable_output == (
        "### Ticket Created\n|Object Description|Object Entity|Solution|Is New|Expiration Date|Date|\n"
        "|---|---|---|---|---|---|\n| "
        "Test ticket | ticket | Fixed the issue | true | 2021-01-01T00:00:00Z | 2021-01-01T00:00:00Z |\n"
    )


def test_list_tickets_success(mocked_client):
    """
    Given a client instance
    When list_tickets_command is called
    Then it should return CommandResults with expected outputs
    """
    from PATHelpdeskAdvanced import list_tickets_command

    data = [
        {
            "ExpirationDate": "/Date(1111111111111)/",
            "Subject": "Support Request",
            "Solution": "Solution text redacted",
            "LocationID": "XXX",
            "Solicits": None,
            "Date": "/Date(1111111111111)/",
            "FirstUpdateUserID": "AA",
            "BilledTokens": 0.0,
            "ServiceID": "XXX",
            "TicketTypeID": "XX",
            "Problem": "Problem description redacted",
            "SiteUnRead": None,
            "ClosureDate": "/Date(1111111111111)/",
            "ContactID": "XXX",
            "SupplierID": None,
            "CustomerContractID": None,
            "EstimatedTaskStartDate": None,
            "OwnerUserID": "AA",
            "Score": 0,
            "LastExpirationDate": "/Date(1111111111111)/",
            "KnownIssue": False,
            "MailBoxID": "XXX",
            "NextExpirationID": "XXX",
            "TicketClassificationID": "XXX",
            "CalendarID": None,
            "UrgencyID": "XX",
            "TaskEffort": None,
            "ProblemHTML": "Problem description redacted",
            "AccountID": "XXX",
            "NextExpirationDate": "/Date(1111111111111)/",
            "AssetID": "XXX",
            "ID": "10000002C",
            "SolutionHTML": "Solution text redacted",
            "EstimatedTaskDuration": 0,
            "LanguageID": 5,
        },
        {
            "ExpirationDate": "/Date(1111111111111)/",
            "Subject": "On-site Support",
            "Solution": "Ticket correctly created through template.",
            "LocationID": "XXX",
            "Solicits": None,
            "Date": "/Date(1111111111111)/",
            "FirstUpdateUserID": "AA",
            "BilledTokens": 0.0,
            "ServiceID": "XXX",
            "TicketTypeID": "XX",
            "Problem": "Problem description redacted",
            "SiteUnRead": 0,
            "ClosureDate": "/Date(1111111111111)/",
            "ContactID": "XXX",
            "SupplierID": None,
            "CustomerContractID": None,
            "EstimatedTaskStartDate": None,
            "OwnerUserID": "XXX",
            "Score": 0,
            "LastExpirationDate": "/Date(1111111111111)/",
            "KnownIssue": False,
            "MailBoxID": "XXX",
            "NextExpirationID": None,
            "TicketClassificationID": "XXX",
            "CalendarID": None,
            "UrgencyID": None,
            "TaskEffort": None,
            "ProblemHTML": "Problem description redacted",
            "AccountID": "XXX",
            "NextExpirationDate": "/Date(1111111111111)/",
            "AssetID": None,
            "ID": "10000003C",
            "SolutionHTML": "Solution text redacted",
            "EstimatedTaskDuration": 0,
        },
    ]
    mocked_client.list_tickets.return_value = {"data": data}

    result = list_tickets_command(mocked_client, {})

    assert result.outputs == [
        {
            "ExpirationDate": "2005-03-18T01:58:31Z",
            "Subject": "Support Request",
            "Solution": "Solution text redacted",
            "LocationID": "XXX",
            "Solicits": None,
            "Date": "2005-03-18T01:58:31Z",
            "FirstUpdateUserID": "AA",
            "BilledTokens": 0.0,
            "ServiceID": "XXX",
            "TicketTypeID": "XX",
            "Problem": "Problem description redacted",
            "SiteUnRead": None,
            "ClosureDate": "2005-03-18T01:58:31Z",
            "ContactID": "XXX",
            "SupplierID": None,
            "CustomerContractID": None,
            "EstimatedTaskStartDate": None,
            "OwnerUserID": "AA",
            "Score": 0,
            "LastExpirationDate": "2005-03-18T01:58:31Z",
            "KnownIssue": False,
            "MailBoxID": "XXX",
            "NextExpirationID": "XXX",
            "TicketClassificationID": "XXX",
            "CalendarID": None,
            "UrgencyID": "XX",
            "TaskEffort": None,
            "ProblemHTML": "Problem description redacted",
            "AccountID": "XXX",
            "NextExpirationDate": "2005-03-18T01:58:31Z",
            "AssetID": "XXX",
            "ID": "10000002C",
            "SolutionHTML": "Solution text redacted",
            "EstimatedTaskDuration": 0,
            "LanguageID": 5,
        },
        {
            "ExpirationDate": "2005-03-18T01:58:31Z",
            "Subject": "On-site Support",
            "Solution": "Ticket correctly created through template.",
            "LocationID": "XXX",
            "Solicits": None,
            "Date": "2005-03-18T01:58:31Z",
            "FirstUpdateUserID": "AA",
            "BilledTokens": 0.0,
            "ServiceID": "XXX",
            "TicketTypeID": "XX",
            "Problem": "Problem description redacted",
            "SiteUnRead": 0,
            "ClosureDate": "2005-03-18T01:58:31Z",
            "ContactID": "XXX",
            "SupplierID": None,
            "CustomerContractID": None,
            "EstimatedTaskStartDate": None,
            "OwnerUserID": "XXX",
            "Score": 0,
            "LastExpirationDate": "2005-03-18T01:58:31Z",
            "KnownIssue": False,
            "MailBoxID": "XXX",
            "NextExpirationID": None,
            "TicketClassificationID": "XXX",
            "CalendarID": None,
            "UrgencyID": None,
            "TaskEffort": None,
            "ProblemHTML": "Problem description redacted",
            "AccountID": "XXX",
            "NextExpirationDate": "2005-03-18T01:58:31Z",
            "AssetID": None,
            "ID": "10000003C",
            "SolutionHTML": "Solution text redacted",
            "EstimatedTaskDuration": 0,
        },
    ]
    assert result.outputs_prefix == "HelpdeskAdvanced.Ticket"
    assert result.outputs_key_field == "ID"
    assert result.raw_response == mocked_client.list_tickets.return_value
    assert result.readable_output == (
        "### Tickets\n"
        "|Subject|Solution|Date|Service ID|Problem|Contact ID|Owner User ID|Account ID|\n"
        "|---|---|---|---|---|---|---|---|\n| Support Request | Solution text redacted | 2005-03-18T01:58:31Z"
        " | XXX | Problem description redacted | XXX | AA | XXX |\n| On-site Support | Ticket correctly created through template."
        " | 2005-03-18T01:58:31Z | XXX | Problem description redacted | XXX | XXX | XXX |\n"
    )


def test_parse_filter_conditions_valid():
    """
    Given a list of valid filter condition strings
    When parse_filter_conditions is called with the list
    Then it should return a list of parsed condition dicts
    """
    conditions = ['"id" eq "123"', '"name" lt "john"', '"nullvalue" ne null']
    expected = [
        {"property": "id", "op": "eq", "value": "123"},
        {"property": "name", "op": "lt", "value": "john"},
        {"property": "nullvalue", "op": "ne", "value": None},
    ]

    assert parse_filter_conditions(conditions) == expected


def test_parse_filter_conditions_invalid():
    """
    Given an invalid filter condition string
    When parse_filter_conditions is called with a list containing the invalid string
    Then it should raise a DemistoException
    """

    with pytest.raises(DemistoException):
        parse_filter_conditions(('"id" eq 123',))
