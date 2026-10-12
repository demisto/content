from copy import deepcopy

import CommonServerPython
import DeleteReportedEmail
import pytest
from CommonServerPython import *
from DeleteReportedEmail import *

TEST_DATA = "test_data"
SEARCH_RESPONSE_SUFFIX = "_search_response.json"

EXPECTED_DELETION_ARGS_RESULTS = {
    "gmail": {"user-id": "user_id", "message-id": "message_id", "permanent": False, "using-brand": "brand"},
    "MSGraph": {
        "user_id": "user_id",
        "message_id": "message_id",
        "using-brand": "brand",
    },
    "EWSv2": {"item-ids": "item_id", "delete-type": "soft", "using-brand": "brand", "target-mailbox": "user_id"},
    "EWS365": {"item-ids": "item_id", "delete-type": "soft", "using-brand": "brand", "target-mailbox": "user_id"},
}

ARGS_FUNC = {"EWS365": DeletionArgs.ews, "EWSv2": DeletionArgs.ews, "gmail": DeletionArgs.gmail, "MSGraph": DeletionArgs.msgraph}

SEARCH_FUNC = {
    "gmail": "gmail-search",
    "EWSv2": "ews-search-mailbox",
    "EWS365": "ews-search-mailbox",
    "MSGraph": "msgraph-mail-list-emails",
}

SEARCH_ARGS = {
    "delete-type": "soft",
    "using-brand": "brand",
    "email_subject": "subject",
    "message-id": "message_id",
    "query": "query",
    "target-mailbox": "user_id",
    "user_id": "user_id",
    "odata": "odata",
    "user-id": "user_id",
}

MISSING_EMAIL_ERROR_MSG = "Email not found in mailbox. It may have been manually deleted."

WAS_EMAIL_DELETED_EXPECTED_RESULTS = [
    ([], ("Skipped", MISSING_EMAIL_ERROR_MSG)),
    ([{"message_id": "message-id", "result": "Success"}], ("Success", "")),
]


@pytest.mark.parametrize("integration_name", ["EWS365", "EWSv2", "gmail", "MSGraph"])
def test_get_deletion_args(integration_name):
    """
    Given:
    a dict of search args parsed earlier
    and search results retrieved from the search operation priorly
    When:
    Deleting an email
    Then:
    return the suitable deletion args
    """
    with open(os.path.join(TEST_DATA, f"{integration_name}{SEARCH_RESPONSE_SUFFIX}")) as file:
        search_results = json.load(file)
    assert EXPECTED_DELETION_ARGS_RESULTS[integration_name] == ARGS_FUNC[integration_name](search_results, SEARCH_ARGS)


@pytest.mark.parametrize("integration_name", ["EWS365", "EWSv2", "gmail", "MSGraph"])
def test_delete_email(mocker, integration_name):
    """
    Given:
        Search arguments to use for the search operation
    When:
        Initiating a delete
    Then:
        delete the email
    """
    with open(os.path.join(TEST_DATA, f"{integration_name}{SEARCH_RESPONSE_SUFFIX}")) as file:
        search_results = json.load(file)
    mocker.patch.object(DeleteReportedEmail, "execute_command", return_value=search_results)
    assert (
        delete_email(SEARCH_ARGS, SEARCH_FUNC[integration_name], ARGS_FUNC[integration_name], "func", lambda x: False)
        == "Success"
    )


@pytest.mark.parametrize("delete_email_context, result", WAS_EMAIL_DELETED_EXPECTED_RESULTS)
def test_was_email_already_deleted(mocker, delete_email_context, result):
    """

    Given:
        An email that was not found in the mailbox
    When:
        When deleting an email and checking if it may have been already deleted
    Then:
        Return 'Success' if the email was already deleted priorly, and 'Skipped' otherwise, and the error msg
    """
    search_args = {"message-id": "message-id"}
    mocker.patch.object(demisto, "get", return_value=delete_email_context)
    e = MissingEmailException()
    assert was_email_already_deleted(search_args, str(e)) == result


def test_extract_graph_objects():
    """
    Given:
        Various structures returned by execute_command for MS Graph.
    When:
        Calling _extract_graph_objects helper.
    Then:
        Return a flat list of objects.
    """
    # List of objects
    assert DeleteReportedEmail._extract_graph_objects([{"id": "1"}]) == [{"id": "1"}]
    # OData dict with 'value'
    assert DeleteReportedEmail._extract_graph_objects({"@odata.context": "meta", "value": [{"id": "2"}]}) == [{"id": "2"}]
    # Single dict
    assert DeleteReportedEmail._extract_graph_objects({"id": "3"}) == [{"id": "3"}]
    # None
    assert DeleteReportedEmail._extract_graph_objects(None) == []


class TestMicrosoftGraphSecurityDeleteMail:
    @pytest.fixture(autouse=True)
    def setup(self, mocker):
        self.args = {}
        self.message_id = "<test@message.com>"
        self.using_brand = "Microsoft Graph"
        self.delete_type = "soft"

        mocker.patch.object(DeleteReportedEmail, "check_demisto_version", return_value=None)
        mocker.patch.object(DeleteReportedEmail, "was_email_already_deleted", return_value=("Skipped", ""))
        mocker.patch.object(DeleteReportedEmail, "schedule_next_command", return_value="Scheduled")

    def test_first_run_success(self, mocker):
        """
        Given:
            No case_id or search_id in args.
        When:
            Initiating the first run of the Microsoft Graph Security deletion polling.
        Then:
            It should resolve the case, create a search with the specific KQL query,
            trigger the estimate, return 'In Progress', and populate args.
        """

        def execute_command_mock(cmd, args):
            if cmd == "msg-list-ediscovery-cases":
                return []
            if cmd == "msg-create-ediscovery-case":
                return [{"id": "case-123"}]
            if cmd == "msg-create-ediscovery-search":
                assert args["content_query"] == 'Identifier:"<test@message.com>"'
                return [{"id": "search-456"}]
            if cmd == "msg-run-estimate-statistics":
                return []
            return []

        mocker.patch.object(DeleteReportedEmail, "execute_command", side_effect=execute_command_mock)

        res, scheduled = microsoft_graph_security_delete_mail(self.args, self.message_id, self.using_brand, self.delete_type)

        assert res == "In Progress"
        assert scheduled == "Scheduled"
        assert self.args["case_id"] == "case-123"
        assert self.args["search_id"] == "search-456"

    def test_polling_in_progress(self, mocker):
        """
        Given:
            case_id and search_id in args, and the estimate status is 'running'.
        When:
            Polling for estimate completion.
        Then:
            It should return 'In Progress' and schedule next command.
        """
        self.args = {"case_id": "case-123", "search_id": "search-456"}

        def execute_command_mock(cmd, args):
            if cmd == "msg-get-last-estimate-statistics-operation":
                return [{"status": "running"}]
            return []

        mocker.patch.object(DeleteReportedEmail, "execute_command", side_effect=execute_command_mock)
        res, scheduled = microsoft_graph_security_delete_mail(self.args, self.message_id, self.using_brand, self.delete_type)

        assert res == "In Progress"
        assert scheduled == "Scheduled"

    def test_polling_success(self, mocker):
        """
        Given:
            case_id and search_id in args, and the estimate status is 'succeeded' with >0 items.
        When:
            Polling for estimate completion.
        Then:
            It should execute the purge command, delete the search, and return SUCCESS_MESSAGE.
        """
        self.args = {"case_id": "case-123", "search_id": "search-456"}
        mock_execute = mocker.patch.object(DeleteReportedEmail, "execute_command")

        def execute_command_mock(cmd, args):
            if cmd == "msg-get-last-estimate-statistics-operation":
                return [
                    {
                        "status": "succeeded",
                        "indexedItemCount": 1,
                        "totalItemCount": 0,
                    }
                ]
            return []

        mock_execute.side_effect = execute_command_mock
        res, scheduled = microsoft_graph_security_delete_mail(self.args, self.message_id, self.using_brand, self.delete_type)

        assert res == DeleteReportedEmail.SUCCESS_MESSAGE
        assert scheduled is None
        mock_execute.assert_any_call("msg-purge-ediscovery-data", mocker.ANY)
        mock_execute.assert_any_call("msg-delete-ediscovery-search", mocker.ANY)

    def test_polling_email_missing(self, mocker):
        """
        Given:
            case_id and search_id in args, and the estimate status is 'succeeded' with 0 items.
        When:
            Polling for estimate completion.
        Then:
            It should raise MissingEmailException.
        """
        self.args = {"case_id": "case-123", "search_id": "search-456"}

        def execute_command_mock(cmd, args):
            if cmd == "msg-get-last-estimate-statistics-operation":
                return [
                    {
                        "status": "succeeded",
                        "indexedItemCount": 0,
                        "totalItemCount": 0,
                    }
                ]
            return []

        mocker.patch.object(DeleteReportedEmail, "execute_command", side_effect=execute_command_mock)

        with pytest.raises(MissingEmailException):
            microsoft_graph_security_delete_mail(self.args, self.message_id, self.using_brand, self.delete_type)

    def test_polling_failed(self, mocker):
        self.args = {"case_id": "case-123", "search_id": "search-456"}

        def execute_command_mock(cmd, args):
            if cmd == "msg-get-last-estimate-statistics-operation":
                return [{"status": "failed"}]
            return []

        mocker.patch.object(DeleteReportedEmail, "execute_command", side_effect=execute_command_mock)

        with pytest.raises(DeletionFailed, match="eDiscovery estimate statistics failed"):
            microsoft_graph_security_delete_mail(self.args, self.message_id, self.using_brand, self.delete_type)


GENERAL_SEARCH_ARGS = {
    "delete-type": "emaildeletetype",
    "email_subject": "reportedemailsubject",
    "message-id": "<reportedemail@messageid>",
}

ADDED_SEARCH_ARGS = {
    "Gmail": {"query": 'rfc822msgid:"<reportedemail@messageid>"', "user-id": "reportedemailto"},
    "EWSO365": {"target-mailbox": "reportedemailto"},
    "EWS v2": {"target-mailbox": "reportedemailto"},
    "MicrosoftGraphMail": {
        "user_id": "reportedemailto",
        "odata": "$filter=internetMessageId eq '%3Creportedemail%40messageid%3E'",
    },
    "Microsoft Graph": {"to_user_id": "reportedemailto"},
}


@pytest.mark.parametrize(
    "brand",
    [
        "Gmail",
        "EWSO365",
        "EWS v2",
        "Agari Phishing Defense",
        "MicrosoftGraphMail",
        "Microsoft Graph",
    ],
)
def test_search_args(mocker, brand):
    """

    Given:
        Script args
    When:
        Initiating a delete
    Then:
        Return the suitable search args

    """
    INCIDENT_INFO = {
        "CustomFields": {
            "reportedemailorigin": "Attached",
            "reportedemailmessageid": "<reportedemail@messageid>",
            "reportedemailto": "reportedemailto",
            "emaildeletetype": "emaildeletetype",
            "reportedemailfrom": "reportedemailfrom",
            "reportedemailsubject": "reportedemailsubject",
        }
    }
    mocker.patch.object(DeleteReportedEmail, "delete_from_brand_handler", return_value=brand)
    mocker.patch.object(demisto, "incident", return_value=INCIDENT_INFO)
    GENERAL_SEARCH_ARGS["using-brand"] = brand
    current_search_args = GENERAL_SEARCH_ARGS.copy()
    current_search_args.update(ADDED_SEARCH_ARGS.get(brand, {}))
    assert get_search_args({}) == current_search_args

    # Test 'email_origin' is 'none' exception
    incident_info_copy = deepcopy(INCIDENT_INFO)
    mocker.patch.object(demisto, "incident", return_value=incident_info_copy)
    incident_info_copy["CustomFields"]["reportedemailorigin"] = "None"
    with pytest.raises(ValueError) as e:
        get_search_args({})
    assert "'Reported Email Origin' field could not be found" in str(e.value)

    # Test missing message id exception
    incident_info_copy = deepcopy(INCIDENT_INFO)
    mocker.patch.object(demisto, "incident", return_value=incident_info_copy)
    incident_info_copy["CustomFields"].pop("reportedemailmessageid")
    with pytest.raises(ValueError) as e:
        get_search_args({})
    assert "'Reported Email Message ID' field could not be found" in str(e.value)

    # Test missing user id exception
    incident_info_copy = deepcopy(INCIDENT_INFO)
    mocker.patch.object(demisto, "incident", return_value=incident_info_copy)
    incident_info_copy["CustomFields"].pop("reportedemailto")
    with pytest.raises(ValueError) as e:
        get_search_args({})
    assert "'Reported Email To' field could not be found" in str(e.value)

    # Test multiple recipients
    incident_info_copy = deepcopy(INCIDENT_INFO)
    mocker.patch.object(demisto, "incident", return_value=incident_info_copy)
    incident_info_copy["CustomFields"]["reportedemailto"] = "user1@user.com, user2@user.com"
    with pytest.raises(ValueError) as e:
        get_search_args({})
    assert "Please make sure that there is only one 'Reported Email To' address." in str(e.value)


def test_schedule_next_command(mocker):
    """

    Given:
        Script args
    When:
        Initiating a delete using the Microsoft Graph eDiscovery polling flow
    Then:
        Return a ScheduledCommand object

    """
    mocker.patch.object(CommonServerPython, "is_demisto_version_ge", return_value=True)
    args = {"arg": "arg"}
    assert isinstance(schedule_next_command(args), ScheduledCommand)


class TestMessageIdValidation:
    """Tests for Message-ID format validation in get_search_args."""

    BASE_INCIDENT = {
        "CustomFields": {
            "reportedemailorigin": "Attached",
            "reportedemailmessageid": "",
            "reportedemailto": "user@example.com",
            "emaildeletetype": "soft",
            "reportedemailfrom": "sender@example.com",
            "reportedemailsubject": "Test Subject",
        },
        "sourceBrand": "Gmail",
    }

    def _make_incident(self, message_id: str) -> dict:
        incident = deepcopy(self.BASE_INCIDENT)
        incident["CustomFields"]["reportedemailmessageid"] = message_id
        return incident

    def test_valid_message_id_accepted(self, mocker):
        """Test that a valid Message-ID passes format validation."""
        incident = self._make_incident("<abc@example.com>")
        mocker.patch.object(demisto, "incident", return_value=incident)
        mocker.patch.object(DeleteReportedEmail, "delete_from_brand_handler", return_value="Gmail")
        result = get_search_args({})
        assert result["message-id"] == "<abc@example.com>"

    def test_message_id_with_operator_rejected(self, mocker):
        """Test that a Message-ID with extra operators is rejected by format validation."""
        incident = self._make_incident("<x@y> OR subject:Invoice")
        mocker.patch.object(demisto, "incident", return_value=incident)
        mocker.patch.object(DeleteReportedEmail, "delete_from_brand_handler", return_value="Gmail")
        with pytest.raises(DemistoException, match="Refusing suspicious Message-ID"):
            get_search_args({})

    def test_message_id_without_angle_brackets_rejected(self, mocker):
        """Test that a Message-ID without angle brackets is rejected by format validation."""
        incident = self._make_incident("abc@example.com")
        mocker.patch.object(demisto, "incident", return_value=incident)
        mocker.patch.object(DeleteReportedEmail, "delete_from_brand_handler", return_value="Gmail")
        with pytest.raises(DemistoException, match="Refusing suspicious Message-ID"):
            get_search_args({})

    def test_gmail_query_uses_quoted_format(self, mocker):
        """Test that the Gmail query string uses the quoted rfc822msgid format."""
        message_id = "<test123@example.com>"
        incident = self._make_incident(message_id)
        mocker.patch.object(demisto, "incident", return_value=incident)
        mocker.patch.object(DeleteReportedEmail, "delete_from_brand_handler", return_value="Gmail")
        result = get_search_args({})
        assert result["query"] == f'rfc822msgid:"{message_id}"'

    def test_odata_filter_escapes_single_quotes(self, mocker):
        """Test that single quotes in Message-ID are escaped in the OData filter."""
        message_id = "<it's@example.com>"
        incident = self._make_incident(message_id)
        mocker.patch.object(demisto, "incident", return_value=incident)
        mocker.patch.object(DeleteReportedEmail, "delete_from_brand_handler", return_value="MicrosoftGraphMail")
        result = get_search_args({})
        odata = result["odata"]
        escaped_id = "%3Cit%27%27s%40example.com%3E"
        assert f"'{escaped_id}'" in odata


def test_delete_email_refuses_multiple_search_results(mocker):
    """
    Given:
        A search command that returns multiple results (list with >1 element).
    When:
        delete_email is called.
    Then:
        A DemistoException is raised refusing the delete to avoid ambiguity.
    """
    multi_results = [{"id": "1"}, {"id": "2"}]
    mocker.patch.object(DeleteReportedEmail, "execute_command", return_value=multi_results)

    with pytest.raises(DemistoException, match="expected exactly 1. Refusing delete to avoid ambiguity"):
        delete_email(
            search_args={"message-id": "<test@example.com>"},
            search_function="some-search-command",
            delete_args_function=lambda sr, sa: {},
            delete_function="some-delete-command",
        )


class TestExtractMessageId:
    """Tests for the extract_message_id helper function."""

    def test_gmail_returns_message_id_from_headers(self):
        """
        Given:
            A Gmail search result with the RFC Message-ID in payload.headers.
        When:
            extract_message_id is called with search_function="gmail-search".
        Then:
            The RFC Message-ID is extracted from the headers and returned.
        """
        result = [
            {
                "id": "internal_id",
                "payload": {
                    "headers": [
                        {"name": "Subject", "value": "Test"},
                        {"name": "Message-ID", "value": "<abc@example.com>"},
                    ],
                    "body": {"size": 0},
                },
            }
        ]
        assert extract_message_id(result, "gmail-search") == "<abc@example.com>"

    def test_gmail_missing_payload_headers_returns_none(self):
        """
        Given:
            A Gmail search result without payload.headers.
        When:
            extract_message_id is called with search_function="gmail-search".
        Then:
            None is returned because the headers are missing.
        """
        result = [{"id": "internal_id", "historyId": "123"}]
        assert extract_message_id(result, "gmail-search") is None

    def test_ews_returns_message_id(self):
        """
        Given:
            An EWS search result with a "messageId" field.
        When:
            extract_message_id is called with search_function="ews-search-mailbox".
        Then:
            The RFC Message-ID from "messageId" is returned.
        """
        result = [{"itemId": "item_1", "messageId": "<abc@example.com>"}]
        assert extract_message_id(result, "ews-search-mailbox") == "<abc@example.com>"

    def test_ews_missing_message_id_returns_none(self):
        """
        Given:
            An EWS search result without a "messageId" field.
        When:
            extract_message_id is called with search_function="ews-search-mailbox".
        Then:
            None is returned.
        """
        result = [{"itemId": "item_1"}]
        assert extract_message_id(result, "ews-search-mailbox") is None

    def test_msgraph_returns_internet_message_id(self):
        """
        Given:
            An MSGraph search result with a nested "value" array containing "internetMessageId".
        When:
            extract_message_id is called with search_function="msgraph-mail-list-emails".
        Then:
            The RFC Message-ID from "internetMessageId" is returned.
        """
        result = [{"@odata.context": "", "value": [{"id": "internal", "internetMessageId": "<xyz@example.com>"}]}]
        assert extract_message_id(result, "msgraph-mail-list-emails") == "<xyz@example.com>"

    def test_msgraph_empty_value_returns_none(self):
        """
        Given:
            An MSGraph search result with an empty "value" array.
        When:
            extract_message_id is called with search_function="msgraph-mail-list-emails".
        Then:
            None is returned.
        """
        result = [{"@odata.context": "", "value": []}]
        assert extract_message_id(result, "msgraph-mail-list-emails") is None

    def test_msgraph_missing_value_key_returns_none(self):
        """
        Given:
            An MSGraph search result without a "value" key.
        When:
            extract_message_id is called with search_function="msgraph-mail-list-emails".
        Then:
            None is returned.
        """
        result = [{"@odata.context": ""}]
        assert extract_message_id(result, "msgraph-mail-list-emails") is None

    def test_unknown_search_function_returns_none(self):
        """
        Given:
            A search result and an unrecognized search function name.
        When:
            extract_message_id is called.
        Then:
            None is returned (default case).
        """
        result = [{"id": "some_id"}]
        assert extract_message_id(result, "unknown-search") is None

    def test_empty_list_returns_none(self):
        """
        Given:
            An empty search result list.
        When:
            extract_message_id is called.
        Then:
            None is returned.
        """
        assert extract_message_id([], "ews-search-mailbox") is None

    def test_non_dict_first_element_returns_none(self):
        """
        Given:
            A search result whose first element is not a dict.
        When:
            extract_message_id is called.
        Then:
            None is returned.
        """
        assert extract_message_id(["not_a_dict"], "ews-search-mailbox") is None

    def test_with_real_test_data(self):
        """
        Given:
            Real test data files for each integration.
        When:
            extract_message_id is called with the correct search function.
        Then:
            The expected message ID is returned for all integrations.
        """
        expected = {
            "gmail-search": "<message_id>",
            "ews-search-mailbox": "message_id",
            "msgraph-mail-list-emails": "message_id",
        }
        for integration_name, search_func in SEARCH_FUNC.items():
            with open(os.path.join(TEST_DATA, f"{integration_name}{SEARCH_RESPONSE_SUFFIX}")) as file:
                search_results = json.load(file)
            result = extract_message_id(search_results, search_func)
            assert result == expected[search_func], f"{integration_name}: expected {expected[search_func]!r}, got {result!r}"


def test_delete_email_refuses_mismatched_message_id(mocker):
    """
    Given:
        An EWS search result whose messageId does not match the expected message-id.
    When:
        delete_email is called with search_function="ews-search-mailbox".
    Then:
        A DemistoException is raised indicating the mismatch.
    """
    mismatched_result = [{"itemId": "item_1", "messageId": "<wrong@example.com>"}]
    mocker.patch.object(DeleteReportedEmail, "execute_command", return_value=mismatched_result)

    with pytest.raises(DemistoException, match="Search returned message .* but expected"):
        delete_email(
            search_args={"message-id": "<expected@example.com>"},
            search_function="ews-search-mailbox",
            delete_args_function=DeletionArgs.ews,
            delete_function="ews-delete-items",
        )
