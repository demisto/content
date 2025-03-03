from pathlib import Path
from urllib.parse import unquote
import freezegun
import pytest
from datetime import datetime, timezone

from PATHelpdeskAdvanced import (
    DATETIME_FORMAT,
    DemistoException,
    Filter,
    Field,
    PaginateArgs,
    convert_response_dates,
    list_groups_command,
    list_ticket_attachments_command,
    list_users_command,
    paginate,
    json,
    demisto,
    Client,
    pat_table_to_markdown,
)


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

    STR_2023 = (datetime.fromtimestamp(EPOCH_2023_INT / 1000, tz=timezone.utc)).strftime(DATETIME_FORMAT)  # noqa: UP017
    STR_2022 = (datetime.fromtimestamp(EPOCH_2022_INT / 1000, tz=timezone.utc)).strftime(DATETIME_FORMAT)  # noqa: UP017

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
    def test_get_ticket_history(cls, mocked_client):
        from PATHelpdeskAdvanced import get_ticket_history_command

        """
        Given a client instance and arguments for getting a ticket's history
        When get_ticket_history is called with the client and args
        Then it should return a CommandResults instance with the expected outputs
        """
        TICKET_ID = "dummy_ticket_id"
        history = [
            {
                "AccountID": "",
                "Attachments": None,
                "AutEmailCounter": 0,
                "ContactID": "",
                "Data": {
                    "Comment": "testing",
                    "From": "Solved",
                    "FromID": "S6",
                    "To": "In Progress",
                    "ToID": "S2",
                },
                "ExternalAction": None,
                "FullName": "John Doe",
                "HistoryID": 5665556,
                "OperationDescription": "Status change",
                "OperationTypeID": 20,
                "UpdateDate": "2023-10-04T07:45:35Z",
                "UserID": "S00000C",
                "Username": "username",
            }
        ]
        mocked_client.get_ticket_history.return_value = history

        result = get_ticket_history_command(mocked_client, {"ticket_id": TICKET_ID})
        assert result.outputs_prefix == "HelpdeskAdvanced.TicketHistory"
        assert result.outputs == [value | {"TicketID": TICKET_ID} for value in history]
        assert result.raw_response == history
        assert result.readable_output == (
            "### Ticket History: dummy_ticket_id\n|Aut Email Counter|Data|Full Name|History ID|Operation Description|"
            "Operation Type ID|Update Date|User ID|Username|Ticket ID|\n|---|---|---|---|---|---|---|---|---|---|\n|"
            "  | ***Comment***: testing<br>***From***: Solved<br>***FromID***: S6<br>***To***: In Progress<br>***ToID***:"
            " S2 | John Doe |  | Status change |  | 2023-10-04T07:45:35Z | S00000C | username | dummy_ticket_id |\n"
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
                "| 10000002C | Support Request | Solution text redacted | 2005-03-18T01:58:31Z | XXX |"  # continued next line
                " Problem description redacted | XXX | AA | XXX |",
                "| 10000003C | On-site Support | Ticket correctly created through template."  # continued next line
                " | 2005-03-18T01:58:31Z | XXX | Problem description redacted | XXX | XXX | XXX |",
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

    @staticmethod
    def dummy_client() -> Client:
        return Client(
            base_url=TestClient.base_url,
            username="test",
            password="test",
            verify=False,
            proxy=False,
        )

    @classmethod
    def logged_in_client(cls, requests_mock_object):
        cls.mock_login_response(requests_mock_object)
        return cls.dummy_client()

    @staticmethod
    def mock_login_response(requests_mock_object):
        requests_mock_object.post(
            "https://example.com/Authentication/LoginEx?username=test&password=test",
            json={
                "refreshToken": "refresh_token",
                "requestToken": "request_token",
                "expiresIn": 3300,
                "success": True,
            },
        )
        requests_mock_object.post(
            "https://example.com/Authentication/RefreshToken?token=refresh_token",
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
        cls.mock_login_response(requests_mock)

        mocker.patch.object(
            demisto,
            "getIntegrationContext",
            return_value={},
        )
        client = TestClient.dummy_client()
        assert client.token.refresh_token == "refresh_token"

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
        assert client.token.refresh_token == "new_refresh_token"

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
        assert client.token.refresh_token == "new_refresh_token"
        assert client.token.request_token == "new_request_token"

    @classmethod
    def test_add_ticket_attachment(cls, mocker, requests_mock):
        """
        Given a client
        When calling add_ticket_attachment with two files
        Then make sure they are properly sent in the request

        NOTE: This tests the method, not the _command, as the method has non-trivial logic.
        """
        from PATHelpdeskAdvanced import Path

        client = cls.logged_in_client(requests_mock)
        mocker.patch.object(
            demisto,
            "getFilePath",
            return_value={"path": "test.txt", "name": "test.txt"},
        )
        mocker.patch.object(Path, "open", return_value="mock file contents")
        mocked_request = requests_mock.post(
            "https://example.com/Ticket/UploadNewAttachment", json={"success": True}
        )
        client.add_ticket_attachment(["1", "2"], ticket_id="ticket_id")

        assert mocked_request.called_once
        stringified_request = str(mocked_request.request_history[0]._request.body)
        for i in (1, 2):
            assert (
                f'name="TicketAttachment_{i}"; filename="test.txt"\\r\\n\\r\\nmock file contents'
                in stringified_request
            )

    @classmethod
    def test_list_groups(cls, requests_mock):
        """
        Given   a client and a mocked response
        When    calling the list_groups_command with provided arguments
        Then    test that the request is properly made, and the resuilt is properly returned
        """
        mocked_request = requests_mock.post(
            f"{cls.base_url}/WSC/Projection",
            json={
                "data": [
                    {
                        "Description": "dummy group 1",
                        "ID": "G001",
                        "ObjectTypeID": "65",
                    },
                ],
                "success": True,
            },
        )

        result = list_groups_command(
            client=cls.logged_in_client(requests_mock),
            args={"group_id": "G001", "limit": "1", "page": "3", "page_size": "2"},
        )

        assert mocked_request.called_once
        assert unquote(mocked_request.request_history[0].query) == (
            "entity=usergroup&columnexpressions=['id',+'description',+'objecttypeid']&"
            "columnnames=['id',+'description',+'objecttypeid']&start=6&limit=1&"
            'filter=[{"property":+"id",+"op":+"eq",+"value":+"g001"}]'
        )
        assert result.readable_output == (
            "### PAT HelpDeskAdvanced Groups\n|Group ID|Description|Object Type ID|"
            "\n|---|---|---|\n| G001 | dummy group 1 | 65 |\n"
        )
        assert result.outputs == [
            {"ID": "G001", "Description": "dummy group 1", "ObjectTypeID": "65"}
        ]

    @classmethod
    def test_list_users(cls, requests_mock):
        """
        Given   a client and a mocked response
        When    calling the list_users_command provided arguments
        Then    test that the request is properly made, and the resuilt is properly returned
        """
        mocked_request = requests_mock.post(
            f"{cls.base_url}/WSC/Projection",
            json={
                "data": [
                    {
                        "User.Phone": None,
                        "ID": "U001",
                        "User.FirstName": "HDA",
                        "User.LastName": "Cortex XSOAR",
                        "User.EMail": None,
                    }
                ],
                "success": True,
            },
        )

        result = list_users_command(
            client=cls.logged_in_client(requests_mock),
            args={"user_id": "U001", "limit": "1", "page": "3", "page_size": "2"},
        )

        assert mocked_request.called_once
        assert unquote(mocked_request.request_history[0].query) == (
            "entity=users&columnexpressions=['id',+'user.firstname',+'user.lastname',+'user.email',"
            "+'user.phone',+'user.mobile']&columnnames=['id',+'user.firstname',+'user.lastname',+'user.email',"
            '+\'user.phone\',+\'user.mobile\']&start=6&limit=1&filter=[{"property":+"id",+"op":+"eq",+"value":+"u001"}]'
        )
        assert result.readable_output == (
            "### PAT HelpDeskAdvanced Users\n|Phone|ID|First Name|Last Name|E Mail|"
            "\n|---|---|---|---|---|\n|  | U001 | HDA | Cortex XSOAR |  |\n"
        )
        assert result.outputs == [
            {
                "Phone": None,
                "ID": "U001",
                "FirstName": "HDA",
                "LastName": "Cortex XSOAR",
                "EMail": None,
            }
        ]

    @classmethod
    def test_list_ticket_attachments(cls, requests_mock):
        """
        Given   a client and a mocked response
        When    calling the list_users_command provided arguments
        Then    test that the request is properly made, and the resuilt is properly returned
        """
        mocked_request = requests_mock.post(
            f"{cls.base_url}/WSC/List",
            json={
                "data": [
                    {
                        "ObjectDescription": "Untitled document.pdf",
                        "ObjectEntity": "Attachment",
                        "LastUpdateUserID": "",
                        "IsNew": False,
                        "KBSize": 0.76,
                        "ObjectTypeID": "DEFAULT",
                        "ID": "A12345C",
                        "UniqueID": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaaaaaa",
                        "Note": "",
                        "FileName": "Untitled document.pdf",
                        "FirstUpdate": None,
                        "TicketID": "1234567C",
                        "ContentType": "application/pdf",
                        "OwnerUserID": "",
                        "ParentObject": "Incident",
                        "ParentObjectID": "1234567C",
                        "Site": None,
                        "EmailID": "",
                        "BlobID": "A12345C",
                        "FirstUpdateUserID": "S44444C",
                        "RemoteID": "",
                        "LastUpdate": "2023-08-02T00:00:00Z",
                        "Description": "Untitled document.pdf",
                    }
                ],
                "total": 5,
                "result": {
                    "code": "0",
                    "subcode": None,
                    "parameters": None,
                    "desc": "",
                },
                "success": True,
                "requestToken": "token",
            },
        )

        result = list_ticket_attachments_command(
            client=cls.logged_in_client(requests_mock),
            args={"ticket_id": "A12345C", "limit": "1"},
        )

        assert mocked_request.called_once
        assert unquote(mocked_request.request_history[0].query) == (
            'entity=attachments&start=0&limit=1&filter=[{"property":+"parentobject",+"op":+"eq",+"value":+"ticket"},'
            '+{"property":+"parentobjectid",+"op":+"eq",+"value":+"a12345c"}]'
        )
        assert result.readable_output == (
            "### Attachments of A12345C\n|File Name|Last Update|Description|Object Description|First Update User ID|Object Entity"
            "|Content Type|\n|---|---|---|---|---|---|---|\n| Untitled document.pdf "
            "| 2023-08-02T00:00:00Z | Untitled document.pdf"
            " | Untitled document.pdf | S44444C | Attachment | application/pdf |\n"
        )
        assert result.outputs == [
            {
                "ObjectDescription": "Untitled document.pdf",
                "ObjectEntity": "Attachment",
                "LastUpdateUserID": "",
                "IsNew": False,
                "KBSize": 0.76,
                "ObjectTypeID": "DEFAULT",
                "ID": "A12345C",
                "UniqueID": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaaaaaa",
                "Note": "",
                "FileName": "Untitled document.pdf",
                "FirstUpdate": None,
                "TicketID": "1234567C",
                "ContentType": "application/pdf",
                "OwnerUserID": "",
                "ParentObject": "Incident",
                "ParentObjectID": "1234567C",
                "Site": None,
                "EmailID": "",
                "BlobID": "A12345C",
                "FirstUpdateUserID": "S44444C",
                "RemoteID": "",
                "LastUpdate": "2023-08-02T00:00:00Z",
                "Description": "Untitled document.pdf",
            }
        ]

    @classmethod
    def test_non_json_response(cls, requests_mock):
        client = cls.logged_in_client(requests_mock)
        requests_mock.post(
            "https://example.com/WSC/Projection?entity=UserGroup&columnExpressions=%5B%27ID%27"
            "%2C+%27Description%27%2C+%27ObjectTypeID"
            "%27%5D&columnNames=%5B%27ID%27%2C+%27Description%27%2C+%27ObjectTypeID%27%5D&start=0&limit=1",
            text="surprise",
        )
        with pytest.raises(
            ValueError, match="API returned non-JSON response: surprise"
        ):
            client.list_groups(limit=1)

    @classmethod
    @pytest.mark.parametrize(
        "response_file,expected_error_message",
        (
            pytest.param(
                "response_401.html",
                "Server Error. 401 - Unauthorized: Access is denied due to invalid credentials",
                id="401",
            ),
            pytest.param(
                "response_invalid_request.html",
                "A server error has occurred. Please, contact portal administrator.",
                id="invalid response",
            ),
        ),
    )
    def test_error_response(
        cls, requests_mock, response_file: str, expected_error_message: str
    ):
        """
        Given   a client and an invalid response
        When    calling a method that simulates these responses
        Then    make sure the response is parsed well
        """
        client = cls.logged_in_client(requests_mock)

        requests_mock.post(
            "https://example.com/WSC/Projection?entity=UserGroup&columnExpressions=%5B%27ID%27%2C+%27Description%27%2C+%"
            "27ObjectTypeID%27%5D&columnNames=%5B%27ID%27%2C+%27Description%27%2C+%27ObjectTypeID%27%5D&start=0&limit=1",
            text=Path(f"test_data/{response_file}").read_text(),
        )
        with pytest.raises(DemistoException, match=expected_error_message):
            client.list_groups(limit=1)


class TestPaginate:
    @staticmethod
    def test_paginate_with_limit_only():
        """
        Given limit is provided
        When paginate is called with only limit
        Then it returns start as 0 and provided limit
        """
        assert paginate(limit=10) == PaginateArgs(start=0, limit=10)

    @staticmethod
    def test_paginate_with_page_and_page_size():
        """
        Given limit is provided
        When paginate is called with paging arguments
        Then it returns start as 0 and provided limit
        """
        assert paginate(page=2, page_size=3, limit=3) == PaginateArgs(start=6, limit=3)

    @staticmethod
    def test_paginate_with_invalid_args():
        """
        Given only one of page or page_size is provided
        When paginate is called with invalid args
        Then it raises an appropriate error
        """
        with pytest.raises(ValueError):
            paginate(page=1, limit="None")

        with pytest.raises(KeyError):
            paginate(page_size=10)

    @staticmethod
    def test_paginate_with_non_int_args():
        """
        Given page and page_size are non-integer values
        When paginate is called with non-int args
        Then it raises a DemistoException
        """
        with pytest.raises(ValueError):
            paginate(page="a", page_size="b", limit=3)


class TestPatToMarkdown:
    @staticmethod
    def test_pat_table_to_markdown_with_no_fields():
        """
        Given a title, output dict, and no fields
        When pat_table_to_markdown is called
        Then it returns markdown string of the full output
        """
        title = "Test Title"
        output = {"key1": "value1", "key2": "value2"}
        assert (
            pat_table_to_markdown(title, output, None)
            == "### Test Title\n|Key 1|Key 2|\n|---|---|\n| value1 | value2 |\n"
        )

    @staticmethod
    def test_pat_table_to_markdown_with_fields():
        """
        Given title, output, and specified fields
        When pat_table_to_markdown is called
        Then it returns markdown string of filtered outputs
        """
        title = "Test Title"
        output = {"Field1": "1", "Field2": "2", "Field3": "3"}
        fields = (Field("field1"), Field("field2"))

        assert (
            pat_table_to_markdown(title, output, fields)
            == "### Test Title\n|Field 1|Field 2|\n|---|---|\n| 1 | 2 |\n"
        )

    @staticmethod
    def test_pat_table_to_markdown_with_field_replacements():
        """
        Given title, output dict, fields, and field replacements
        When pat_table_to_markdown is called with field_replacements
        Then it returns markdown string with replaced field names
        """
        title = "Test Title"
        replace_me = Field("replace_me")
        untouched = Field("untouched")
        replaced = Field("replaced")
        output = {replace_me.hda_name: "1", untouched.hda_name: "2"}

        assert (
            pat_table_to_markdown(
                title, output, fields=None, field_replacements={replace_me: replaced}
            )
            == "### Test Title\n|Replaced|Untouched|\n|---|---|\n| 1 | 2 |\n"
        )
