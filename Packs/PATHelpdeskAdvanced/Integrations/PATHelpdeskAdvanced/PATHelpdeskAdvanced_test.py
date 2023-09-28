import freezegun
import pytest
from datetime import datetime, timezone

from PATHelpdeskAdvanced import (
    DATETIME_FORMAT,
    DemistoException,
    Filter,
    Field,
    convert_response_dates,
    paginate,
    json,
    demisto,
    Client,
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


class TestCommands:
    @classmethod
    def test_create_ticket(cls, mocked_client):
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

    @classmethod
    def test_list_tickets(cls, mocked_client):
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
        assert result.readable_output == "\n".join(
            (
                "### Tickets",
                "|Ticket ID|Subject|Solution|Date|Service ID|Problem|Contact ID|Owner User ID|Account ID|",
                "|---|---|---|---|---|---|---|---|---|",
                "| 10000002C | Support Request | Solution text redacted | 2005-03-18T01:58:31Z | XXX | Problem description redacted | XXX | AA | XXX |",
                "| 10000003C | On-site Support | Ticket correctly created through template. | 2005-03-18T01:58:31Z | XXX | Problem description redacted | XXX | XXX | XXX |",
                "",
            )
        )


class TestFilter:
    def test_filter_parse(self):
        """
        Tests parsing a list of filter condition strings into Filter objects.

        Given A list of filter condition strings
        When Filter.parse_list() is called on the conditions
        Then The expected Filter objects are returned
        """

        assert Filter.parse_list(
            (
                '"id" eq "123"',
                '"name" lt "john"',
                '"nullvalue" ne null',
                '"notanullvalue" ne "none"',  # quotes make it a string, not null
            )
        ) == [
            Filter(key="id", operator="eq", value="123"),
            Filter(key="name", operator="lt", value="john"),
            Filter(key="nullvalue", operator="ne", value=None),
            Filter(key="notanullvalue", operator="ne", value="none"),
        ]

    def test_dumps(self):
        """
        Tests dumping a list of Filter objects to a JSON string.

        Given:
            A list of Filter objects with different key, operator and value.

        When:
            Filter.dumps_list() is called on the list of Filter objects.

        Then:
            The JSON string returned should match the expected format.
        """

        assert Filter.dumps_list(
            (
                Filter(key="id", operator="eq", value="123"),
                Filter(key="name", operator="lt", value="john"),
                Filter(key="nullvalue", operator="ne", value=None),
                Filter(key="notanullvalue", operator="ne", value="none"),
            )
        ) == json.dumps(
            [
                {"property": "id", "op": "eq", "value": "123"},
                {"property": "name", "op": "lt", "value": "john"},
                {"property": "nullvalue", "op": "ne", "value": None},
                {"property": "notanullvalue", "op": "ne", "value": "none"},
            ]
        )

    def test_parse_invalid(self):
        """
        Given an invalid filter condition string
        When parse_filter_conditions is called with a list containing the invalid string
        Then it should raise a DemistoException
        """

        with pytest.raises(DemistoException):
            Filter.parse_list('"id" eq 123')  # missing quotes around value


class TestClient:
    base_url = "https://example.com"

    def dummy_client() -> Client:
        return Client(
            base_url=TestClient.base_url,
            username="test",
            password="test",
            verify=False,
            proxy=False,
        )

    @classmethod
    def logged_in_client(cls, requests_mock):
        cls.mock_login_response(requests_mock)
        return cls.dummy_client()

    @staticmethod
    def mock_login_response(requests_mock):
        requests_mock.post(
            "https://example.com/Authentication/LoginEx?username=test&password=test",
            json={
                "refreshToken": "refresh_token",
                "requestToken": "request_token",
                "expiresIn": 3300,
                "success": True,
            },
        )

    @classmethod
    def test_client_login(cls, mocker, requests_mock) -> None:
        """
        Given an expired refresh token in integration context
        When _reuse_or_create_token is called
        Then it should log in using username/password to get a new token
        """
        # Mock expired token
        cls.mock_login_response()

        mocker.patch.object(
            demisto,
            "getIntegrationContext",
            return_value={},
        )
        client = TestClient.dummy_client()
        assert client.refresh_token == "refresh_token"

    @classmethod
    def test_expired_token(cls, mocker, requests_mock) -> None:
        """
        Given an expired refresh token in integration context
        When _reuse_or_create_token is called
        Then it should log in using username/password to get a new token
        """
        # Mock expired token
        requests_mock.post(
            "https://example.com/Authentication/LoginEx?username=test&password=test",
            json={
                "refreshToken": "new_refresh_token",
                "requestToken": "new_request_token",
                "expiresIn": 3300,
                "success": True,
            },
        )

        mocker.patch.object(
            demisto,
            "getIntegrationContext",
            return_value={},
        )
        client = TestClient.dummy_client()
        assert client.refresh_token == "new_refresh_token"

    @classmethod
    @freezegun.freeze_time("2023-01-01 12:00:00")
    def test_reuse_valid_token(cls, mocker, requests_mock):
        """
        Given a valid refresh token in integration context
        When _reuse_or_create_token is called
        Then it should reuse the existing valid token
        """

        # Mock valid token
        mocker.patch.object(
            demisto,
            "getIntegrationContext",
            return_value={
                "refresh_token": "previous_refresh_token",
                "expires_in": 3600,
                "token_expiry_utc": datetime(2023, 1, 1, 12, 30).isoformat(),
            },
        )
        requests_mock.post(
            "https://example.com/Authentication/RefreshToken?token=previous_refresh_token",
            json={
                "refreshToken": "new_refresh_token",
                "requestToken": "new_request_token",
                "expiresIn": 3300,
                "success": True,
            },
        )
        client = TestClient.dummy_client()

        # Assert valid token reused
        assert client.refresh_token == "new_refresh_token"
        assert client.request_token == "new_request_token"

    @classmethod
    def test_add_ticket_attachment(cls, mocker, requests_mock):
        from PATHelpdeskAdvanced import Path

        client = cls.logged_in_client(requests_mock)
        mocker.patch.object(demisto, "getFilePath", return_value={"path": "test.txt"})
        mocker.patch.object(Path, "open", return_value="mock file contents")
        mocked_request = requests_mock.post(
            "https://example.com/Ticket/UploadNewAttachment", json={"success": True}
        )
        result = client.add_ticket_attachment(["1"], ticket_id="ticket_id")

        assert mocked_request.called_once
        assert (
            'name="TicketAttachment_1"; filename="TicketAttachment_1"\\r\\n\\r\\nmock file contents'
            in str(mocked_request.request_history[0]._request.body)
        )
