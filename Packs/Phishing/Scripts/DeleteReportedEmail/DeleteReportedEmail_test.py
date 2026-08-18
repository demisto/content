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
    search_args = {"message_id": "message-id"}
    mocker.patch.object(demisto, "get", return_value=delete_email_context)
    e = MissingEmailException()
    assert was_email_already_deleted(search_args, str(e)) == result


def test_was_email_found_security_and_compliance():
    """

    Given:
        Search results from security and compliance
    When:
        When deleting an email and checking if it was found in the search operation done priorly
    Then:
        Return true if the email was found, and false otherwise
    """
    success_results_dict = [
        {"SuccessResults": "{Location: sr-test01@demistodev.onmicrosoft.com, Item count: 1, Total size: 55543}"}
    ]
    success_results_dict_not_found = [
        {"SuccessResults": "{Location: sr-test01@demistodev.onmicrosoft.com, Item count: 0, Total size: 55543}"}
    ]

    assert was_email_found_security_and_compliance(success_results_dict)
    assert not was_email_found_security_and_compliance(success_results_dict_not_found)


def execute_command_search_and_compliance_not_deleted_yet(command, args):
    if command == "o365-sc-get-search" and args:  # noqa: RET503
        return [{"Status": "Completed"}]
    elif command == "o365-sc-list-search-action":
        return []
    elif command == "o365-sc-new-search-action":
        return None
    elif command == "o365-sc-get-search-action":
        return {"Status": "Starting"}


def execute_command_search_and_compliance_deleted_successfully(command, args):
    if command == "o365-sc-get-search" and args:  # noqa: RET503
        return [{"Status": "Completed"}]
    elif command == "o365-sc-list-search-action":
        return [{"Name": "search_name_Purge"}]
    elif command == "o365-sc-new-search-action":
        return None
    elif command == "o365-sc-get-search-action":
        return {"Status": "Completed"}


class TestSecurityAndCompliance:
    @pytest.fixture(autouse=True)
    def setup(self, mocker):
        self.search_args = {
            "delete_type": "delete-type",
            "using_brand": "brand",
            "email_subject": "subject",
            "to_user_id": "user_id",
            "from_user_id": "from_user_id",
            "message_id": "message_id",
        }
        self.args = {}
        import DeleteReportedEmail

        mocker.patch.object(DeleteReportedEmail, "check_demisto_version", return_value=None)
        mocker.patch.object(DeleteReportedEmail, "schedule_next_command", return_value="")
        mocker.patch.object(DeleteReportedEmail, "was_email_found_security_and_compliance", return_value=True)

    def test_first_call(self, mocker):
        """
        Given:
            Search arguments to use for the search operation
        When:
            Initiating a delete via security and compliance
        Then:
            Return that the status is in progress
        """

        mocker.patch.object(
            demisto,
            "executeCommand",
            return_value=[
                {"Contents": {"Status": "Starting"}, "Type": "entry"},
                {"Contents": {"Status": "Starting"}, "Type": "entry"},
            ],
        )
        result = security_and_compliance_delete_mail(self.args, **self.search_args)[0]
        assert result == "In Progress"

    def test_polled_call_create_deletion(self, mocker):
        """
        Given:
            Search arguments to use for the search operation, including the search_name
        When:
            Initiating a delete via security and compliance
        Then:
            Return that the status is in progress
        """
        mocker.patch.object(
            DeleteReportedEmail, "execute_command", side_effect=execute_command_search_and_compliance_not_deleted_yet
        )
        self.args["search_name"] = "search_name"
        result = security_and_compliance_delete_mail(self.args, **self.search_args)[0]
        assert result == "In Progress"

    def test_polled_call_deletion_success(self, mocker):
        """
        Given:
            Search arguments to use for the search operation, including the search_name
        When:
            Initiating a delete via security and compliance
        Then:
            Return Success
        """
        mocker.patch.object(
            DeleteReportedEmail, "execute_command", side_effect=execute_command_search_and_compliance_deleted_successfully
        )
        self.args["search_name"] = "search_name"
        result = security_and_compliance_delete_mail(self.args, **self.search_args)[0]
        assert result == "Success"


# ─── Microsoft Graph Security eDiscovery delete flow helpers ──────────────────


def _msg_estimate_status(status: str, indexed: int = 1, total: int = 1):
    """Build an execute_command side-effect for the Microsoft Graph Security flow.

    The returned callable simulates the eDiscovery command chain up to (and
    including) the estimate-statistics polling step. ``status`` controls the
    reported estimate status, and ``indexed``/``total`` control the item counts.
    """

    def _side_effect(command, args):
        if command == "msg-list-ediscovery-cases":
            return [{"DisplayName": MSG_EDISCOVERY_CASE_NAME, "CaseId": "existing_case_id"}]
        elif command == "msg-create-ediscovery-case":
            return {"CaseId": "new_case_id"}
        elif command == "msg-create-ediscovery-search":
            return {"SearchId": "search_id"}
        elif command == "msg-run-estimate-statistics":
            return {}
        elif command == "msg-get-last-estimate-statistics-operation":
            return {"Status": status, "IndexedItemsCount": indexed, "TotalItemsCount": total}
        return {}

    return _side_effect


def _msg_full_flow(estimate_status="succeeded", purge_status="succeeded", indexed=1, total=1):
    """Build an execute_command side-effect covering the full eDiscovery flow.

    Simulates case resolution, search creation, estimate polling, purge start,
    and purge-operation polling. The captured purge args are stored on the
    returned callable via the ``purge_args`` attribute for inspection.
    """

    captured: dict = {}

    def _side_effect(command, args):
        if command == "msg-list-ediscovery-cases":
            return [{"DisplayName": MSG_EDISCOVERY_CASE_NAME, "CaseId": "existing_case_id"}]
        elif command == "msg-create-ediscovery-case":
            return {"CaseId": "new_case_id"}
        elif command == "msg-create-ediscovery-search":
            return {"SearchId": "search_id"}
        elif command == "msg-run-estimate-statistics":
            return {}
        elif command == "msg-get-last-estimate-statistics-operation":
            return {"Status": estimate_status, "IndexedItemsCount": indexed, "TotalItemsCount": total}
        elif command == "msg-purge-ediscovery-data":
            captured["purge_args"] = args
            return {"Purge": {"OperationID": "purge_op_id"}}
        elif command == "msg-list-case-operation":
            return {"Status": purge_status}
        elif command == "msg-delete-ediscovery-search":
            captured["cleanup_called"] = True
            return {}
        return {}

    _side_effect.captured = captured  # type: ignore[attr-defined]
    return _side_effect


class TestMicrosoftGraphSecurity:
    @pytest.fixture(autouse=True)
    def setup(self, mocker):
        self.kwargs = {
            "to_user_id": "user_id",
            "user_id": "user_id",
            "content_query": 'Identifier:"<reportedemail@messageid>"',
            "case_name": MSG_EDISCOVERY_CASE_NAME,
            "using_brand": "MicrosoftGraphSecurity",
            "delete_type": "soft",
            "message_id": "<reportedemail@messageid>",
        }
        self.args: dict = {}
        mocker.patch.object(DeleteReportedEmail, "check_demisto_version", return_value=None)
        mocker.patch.object(DeleteReportedEmail, "schedule_next_command", return_value="scheduled")
        # By default the email was not previously deleted.
        mocker.patch.object(demisto, "get", return_value=None)

    def test_search_args_kql_uses_identifier_query(self, mocker):
        """
        Given:
            An incident whose brand resolves to MicrosoftGraphSecurity.
        When:
            get_search_args builds the search arguments.
        Then:
            The content_query is the KQL Identifier query (NOT from:+subject:),
            and both to_user_id and user_id are set to the recipient mailbox.
        """
        incident_info = {
            "CustomFields": {
                "reportedemailorigin": "Attached",
                "reportedemailmessageid": "<reportedemail@messageid>",
                "reportedemailto": "recipient@example.com",
                "emaildeletetype": "soft",
                "reportedemailfrom": "sender@example.com",
                "reportedemailsubject": "Test Subject",
            }
        }
        mocker.patch.object(demisto, "incident", return_value=incident_info)
        mocker.patch.object(DeleteReportedEmail, "delete_from_brand_handler", return_value="MicrosoftGraphSecurity")
        result = get_search_args({})
        assert result["content_query"] == 'Identifier:"<reportedemail@messageid>"'
        assert "from:" not in result["content_query"]
        assert "subject:" not in result["content_query"]
        assert result["to_user_id"] == "recipient@example.com"
        assert result["user_id"] == "recipient@example.com"
        assert result["case_name"] == MSG_EDISCOVERY_CASE_NAME

    def test_first_call_persists_state_and_returns_in_progress(self, mocker):
        """
        Given:
            A first invocation with no case_id in args and a still-running estimate.
        When:
            microsoft_graph_security_delete_mail is called.
        Then:
            case_id and search_id are persisted into args and the status is "In Progress".
        """
        mocker.patch.object(
            DeleteReportedEmail, "execute_command", side_effect=_msg_estimate_status("notStarted")
        )
        result, scheduled = microsoft_graph_security_delete_mail(self.args, **self.kwargs)
        assert result == "In Progress"
        assert scheduled == "scheduled"
        assert self.args["case_id"] == "existing_case_id"
        assert self.args["search_id"] == "search_id"

    def test_estimate_still_running_returns_in_progress(self, mocker):
        """
        Given:
            An estimate-statistics operation that has not reached a terminal status.
        When:
            microsoft_graph_security_delete_mail polls the estimate.
        Then:
            The status is "In Progress" and no purge is started.
        """
        mocker.patch.object(DeleteReportedEmail, "execute_command", side_effect=_msg_estimate_status("running"))
        result = microsoft_graph_security_delete_mail(self.args, **self.kwargs)[0]
        assert result == "In Progress"
        assert "purge_operation_id" not in self.args

    def test_estimate_complete_no_items_raises_missing_email(self, mocker):
        """
        Given:
            A completed estimate reporting zero indexed and zero total items.
        When:
            microsoft_graph_security_delete_mail evaluates the estimate.
        Then:
            A MissingEmailException is raised.
        """
        mocker.patch.object(
            DeleteReportedEmail, "execute_command", side_effect=_msg_estimate_status("succeeded", indexed=0, total=0)
        )
        with pytest.raises(MissingEmailException):
            microsoft_graph_security_delete_mail(self.args, **self.kwargs)

    def test_purge_in_progress_returns_in_progress(self, mocker):
        """
        Given:
            The estimate succeeded with items and the purge operation is not yet terminal.
        When:
            microsoft_graph_security_delete_mail polls the purge operation.
        Then:
            The status is "In Progress" and the purge_operation_id is persisted.
        """
        side_effect = _msg_full_flow(estimate_status="succeeded", purge_status="running")
        mocker.patch.object(DeleteReportedEmail, "execute_command", side_effect=side_effect)
        result = microsoft_graph_security_delete_mail(self.args, **self.kwargs)[0]
        assert result == "In Progress"
        assert self.args["purge_operation_id"] == "purge_op_id"

    def test_full_success_calls_cleanup_and_returns_success(self, mocker):
        """
        Given:
            The estimate succeeded with items and the purge operation succeeded.
        When:
            microsoft_graph_security_delete_mail completes the flow.
        Then:
            The search cleanup command is invoked and the status is "Success".
        """
        side_effect = _msg_full_flow(estimate_status="succeeded", purge_status="succeeded")
        mocker.patch.object(DeleteReportedEmail, "execute_command", side_effect=side_effect)
        result, scheduled = microsoft_graph_security_delete_mail(self.args, **self.kwargs)
        assert result == "Success"
        assert scheduled is None
        assert side_effect.captured.get("cleanup_called") is True

    @pytest.mark.parametrize(
        "delete_type, expected_purge_type",
        [("hard", "permanentlyDelete"), ("soft", "recoverable")],
    )
    def test_delete_type_mapping(self, mocker, delete_type, expected_purge_type):
        """
        Given:
            A delete_type of "hard" or "soft".
        When:
            microsoft_graph_security_delete_mail starts the purge.
        Then:
            The corresponding purge_type is passed to msg-purge-ediscovery-data
            ("hard"->"permanentlyDelete", "soft"->"recoverable").
        """
        side_effect = _msg_full_flow(estimate_status="succeeded", purge_status="succeeded")
        mocker.patch.object(DeleteReportedEmail, "execute_command", side_effect=side_effect)
        kwargs = {**self.kwargs, "delete_type": delete_type}
        microsoft_graph_security_delete_mail(self.args, **kwargs)
        assert side_effect.captured["purge_args"]["purge_type"] == expected_purge_type

    def test_already_deleted_guard_returns_success_without_api_calls(self, mocker):
        """
        Given:
            Context indicating this message_id was already deleted successfully.
        When:
            microsoft_graph_security_delete_mail is called.
        Then:
            "Success" is returned early and no eDiscovery API calls are made.
        """
        mocker.patch.object(
            demisto,
            "get",
            return_value=[{"message_id": "<reportedemail@messageid>", "result": "Success"}],
        )
        execute_mock = mocker.patch.object(DeleteReportedEmail, "execute_command")
        result, scheduled = microsoft_graph_security_delete_mail(self.args, **self.kwargs)
        assert result == "Success"
        assert scheduled is None
        execute_mock.assert_not_called()


class TestMsgResolveEdiscoveryCase:
    def test_returns_existing_case_id_when_display_name_matches(self, mocker):
        """
        Given:
            An existing eDiscovery case whose DisplayName matches the requested name.
        When:
            msg_resolve_ediscovery_case is called.
        Then:
            The existing CaseId is returned and no case is created.
        """

        def _side_effect(command, args):
            if command == "msg-list-ediscovery-cases":
                return [
                    {"DisplayName": "Other Case", "CaseId": "other_id"},
                    {"DisplayName": MSG_EDISCOVERY_CASE_NAME, "CaseId": "matching_id"},
                ]
            raise AssertionError(f"Unexpected command called: {command}")

        mocker.patch.object(DeleteReportedEmail, "execute_command", side_effect=_side_effect)
        assert msg_resolve_ediscovery_case(MSG_EDISCOVERY_CASE_NAME, "MicrosoftGraphSecurity") == "matching_id"

    def test_creates_new_case_when_not_found(self, mocker):
        """
        Given:
            No existing eDiscovery case matches the requested display name.
        When:
            msg_resolve_ediscovery_case is called.
        Then:
            A new case is created and its CaseId is returned.
        """

        def _side_effect(command, args):
            if command == "msg-list-ediscovery-cases":
                return [{"DisplayName": "Unrelated", "CaseId": "unrelated_id"}]
            elif command == "msg-create-ediscovery-case":
                return {"CaseId": "created_id"}
            raise AssertionError(f"Unexpected command called: {command}")

        mocker.patch.object(DeleteReportedEmail, "execute_command", side_effect=_side_effect)
        assert msg_resolve_ediscovery_case(MSG_EDISCOVERY_CASE_NAME, "MicrosoftGraphSecurity") == "created_id"


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
    "SecurityAndCompliance": {"to_user_id": "reportedemailto", "from_user_id": "reportedemailfrom"},
    "SecurityAndComplianceV2": {"to_user_id": "reportedemailto", "from_user_id": "reportedemailfrom"},
    "MicrosoftGraphSecurity": {
        "to_user_id": "reportedemailto",
        "user_id": "reportedemailto",
        "content_query": 'Identifier:"<reportedemail@messageid>"',
        "case_name": MSG_EDISCOVERY_CASE_NAME,
    },
}


@pytest.mark.parametrize(
    "brand",
    [
        "Gmail",
        "EWSO365",
        "EWS v2",
        "Agari Phishing Defense",
        "MicrosoftGraphMail",
        "SecurityAndCompliance",
        "SecurityAndComplianceV2",
        "MicrosoftGraphSecurity",
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
        Initiating a delete using security and compliance
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
