"""
Unit tests for AWS SNS SMS Communication integration.

Covers all 20 functions in the integration:
- Helper functions (generate_reply_code, extract_entitlement, parse_entitlement, clean_ask_task_message)
- Entitlement management (save, find, mark_answered, cleanup, get_active, get_available_codes)
- Commands (send-notification, list-entitlements, inject-reply, test-module)
- SMS reply processing (process_sms_reply, send_feedback_sms)
- AWS client creation (get_aws_client with 4 auth methods)
"""
import copy
import pytest
import json
from datetime import datetime, timedelta
from unittest.mock import MagicMock
from AWSSNSSMSCommunication import (
    generate_reply_code,
    generate_sequential_codes,
    extract_entitlement_from_message,
    parse_entitlement_string,
    clean_ask_task_message_and_generate_codes,
    get_active_entitlements_for_phone,
    find_entitlement_by_reply_code,
    save_entitlement,
    mark_entitlement_answered,
    cleanup_expired_entitlements,
    get_available_codes_for_phone,
    send_notification_command,
    list_entitlements_command,
    inject_reply_command,
    test_module_command,
    process_sms_reply,
    send_feedback_sms,
    get_aws_client,
    DEFAULT_REPLY_CODE,
    DEFAULT_SUCCESS_MESSAGE,
    DEFAULT_FAILURE_MESSAGE,
    DATE_FORMAT,
    REPLY_CODE_MODE_RANDOM,
    REPLY_CODE_MODE_SEQUENTIAL,
)


# ===== Shared constants =====

SAMPLE_GUID = "550e8400-e29b-41d4-a716-446655440000"
# Task IDs in XSOAR are numeric; the clean_ask_task_message regex char class
# [a-fA-F0-9\-@|] only matches hex-range chars, digits, -, @, |.
SAMPLE_ENTITLEMENT_ID = f"{SAMPLE_GUID}@123|45"
SAMPLE_PHONE = "+12345678900"


# ===== Shared fixtures =====

@pytest.fixture(autouse=True)
def mock_demisto(mocker):
    """Mock all demisto functions used throughout the integration."""
    mocker.patch("AWSSNSSMSCommunication.demisto.debug")
    mocker.patch("AWSSNSSMSCommunication.demisto.info")
    mocker.patch("AWSSNSSMSCommunication.demisto.error")
    mocker.patch("AWSSNSSMSCommunication.demisto.updateModuleHealth")
    mocker.patch("AWSSNSSMSCommunication.demisto.handleEntitlementForUser")


@pytest.fixture
def integration_context(mocker):
    """Provide a mutable integration context dict with get/set mocks.

    The production code does:
        ctx = get_integration_context_with_sync()   # returns our dict
        ctx["entitlements"].append(...)              # mutates it
        set_integration_context_with_sync(ctx)       # passes same ref back

    So set_ctx receives the *same* object that get_ctx returned.
    We deep-copy before clearing to preserve the mutations.
    """
    ctx = {"entitlements": []}

    def get_ctx():
        return ctx

    def set_ctx(new_ctx):
        snapshot = copy.deepcopy(new_ctx)
        ctx.clear()
        ctx.update(snapshot)

    mocker.patch(
        "AWSSNSSMSCommunication.get_integration_context_with_sync",
        side_effect=get_ctx,
    )
    mocker.patch(
        "AWSSNSSMSCommunication.set_integration_context_with_sync",
        side_effect=set_ctx,
    )
    return ctx


@pytest.fixture
def mock_sns_client(mocker):
    """Mock SNS boto3 client."""
    client = mocker.Mock()
    client.publish.return_value = {"MessageId": "msg-id-123"}
    return client


@pytest.fixture
def mock_sqs_client(mocker):
    """Mock SQS boto3 client."""
    client = mocker.Mock()
    client.get_queue_attributes.return_value = {
        "ResponseMetadata": {"HTTPStatusCode": 200},
        "Attributes": {"QueueArn": "arn:aws:sqs:us-east-1:123456789:test-queue"},
    }
    client.receive_message.return_value = {"Messages": []}
    client.delete_message.return_value = {}
    return client


@pytest.fixture
def mock_params():
    """Standard integration parameters."""
    return {
        "credentials": {"identifier": "AKIATEST", "password": "secret123"},
        "defaultRegion": "us-east-1",
        "sqsQueueUrl": "https://sqs.us-east-1.amazonaws.com/123456789/test-queue",
        "successFeedbackEnabled": True,
        "failureFeedbackEnabled": True,
        "successMessage": DEFAULT_SUCCESS_MESSAGE,
        "failureMessage": DEFAULT_FAILURE_MESSAGE,
    }


def _make_entitlement(
    entitlement_id=SAMPLE_ENTITLEMENT_ID,
    phone=SAMPLE_PHONE,
    codes_to_options=None,
    answered=False,
    created=None,
):
    """Helper to build an entitlement dict."""
    if codes_to_options is None:
        codes_to_options = {"1234": "Yes", "5678": "No"}
    return {
        "entitlement_id": entitlement_id,
        "phone_number": phone,
        "codes_to_options": codes_to_options,
        "message": "Test question\nYes (1234) or No (5678)",
        "created": created or datetime.utcnow().strftime(DATE_FORMAT),
        "answered": answered,
    }


# ===== 1. TestHelperFunctions =====

class TestHelperFunctions:
    """Tests for pure helper / parsing functions."""

    def test_generate_reply_code_format(self):
        """Reply code must be exactly 4 digits."""
        code = generate_reply_code()
        assert len(code) == 4
        assert code.isdigit()

    def test_generate_reply_code_uniqueness(self):
        """Multiple generated codes should not all be the same (statistical)."""
        codes = {generate_reply_code() for _ in range(50)}
        assert len(codes) > 1

    def test_generate_sequential_codes_basic(self):
        """Sequential codes start from 1 when no existing codes."""
        codes = generate_sequential_codes(3, set())
        assert codes == ["1", "2", "3"]

    def test_generate_sequential_codes_skips_existing(self):
        """Sequential codes skip numbers already in use."""
        codes = generate_sequential_codes(2, {"1", "2"})
        assert codes == ["3", "4"]

    def test_generate_sequential_codes_gaps(self):
        """Sequential codes fill gaps in existing codes."""
        codes = generate_sequential_codes(2, {"2", "4"})
        assert codes == ["1", "3"]

    def test_extract_entitlement_with_task(self):
        """Extract GUID@incident|task from SMSAskUser format."""
        msg = f"Approve? - Reply Yes or No: {SAMPLE_GUID}@123|45"
        ent, remaining = extract_entitlement_from_message(msg)
        assert ent == f"{SAMPLE_GUID}@123|45"
        assert SAMPLE_GUID not in remaining

    def test_extract_entitlement_without_task(self):
        """Extract GUID@incident (no task) from SMSAskUser format."""
        msg = f"Approve? - Reply Yes or No: {SAMPLE_GUID}@456"
        ent, remaining = extract_entitlement_from_message(msg)
        assert ent == f"{SAMPLE_GUID}@456"
        assert "|" not in ent

    def test_extract_entitlement_no_match(self):
        """Plain message without entitlement returns (None, original)."""
        msg = "Hello world, no GUID here"
        ent, remaining = extract_entitlement_from_message(msg)
        assert ent is None
        assert remaining == msg

    def test_parse_entitlement_with_task(self):
        """Full parsing of GUID@incident|task."""
        parsed = parse_entitlement_string(f"{SAMPLE_GUID}@123|45")
        assert parsed["guid"] == SAMPLE_GUID
        assert parsed["incident_id"] == "123"
        assert parsed["task_id"] == "45"

    def test_parse_entitlement_without_task(self):
        """Parsing GUID@incident (no task_id)."""
        parsed = parse_entitlement_string(f"{SAMPLE_GUID}@999")
        assert parsed["guid"] == SAMPLE_GUID
        assert parsed["incident_id"] == "999"
        assert parsed["task_id"] == ""

    def test_parse_entitlement_invalid(self):
        """Missing @ separator returns empty dict."""
        parsed = parse_entitlement_string("not-an-entitlement")
        assert parsed == {}


# ===== 2. TestCleanAskTaskMessage =====

class TestCleanAskTaskMessage:
    """Tests for clean_ask_task_message_and_generate_codes()."""

    def test_two_options(self):
        """Standard SMSAskUser format with 2 options generates codes."""
        msg = f"Approve incident? - Reply Yes or No: {SAMPLE_GUID}@123|45"
        cleaned, codes = clean_ask_task_message_and_generate_codes(msg, set())

        assert "Approve incident?" in cleaned
        assert len(codes) == 2
        assert set(codes.values()) == {"Yes", "No"}
        for code in codes:
            assert len(code) == 4 and code.isdigit()

    def test_three_options(self):
        """SMSAskUser format with 3 options."""
        msg = f"Action? - Reply Approve or Deny or Escalate: {SAMPLE_GUID}@1|4"
        cleaned, codes = clean_ask_task_message_and_generate_codes(msg, set())

        assert len(codes) == 3
        assert set(codes.values()) == {"Approve", "Deny", "Escalate"}

    def test_four_options(self):
        """SMSAskUser format with 4 options."""
        msg = f"Priority? - Reply Low or Medium or High or Critical: {SAMPLE_GUID}@1|4"
        cleaned, codes = clean_ask_task_message_and_generate_codes(msg, set())

        assert len(codes) == 4
        assert set(codes.values()) == {"Low", "Medium", "High", "Critical"}

    def test_non_sms_ask_format(self):
        """Non-SMSAskUser message returns original text and empty dict."""
        msg = "Just a plain SMS message"
        cleaned, codes = clean_ask_task_message_and_generate_codes(msg, set())

        assert cleaned == msg
        assert codes == {}

    def test_existing_codes_avoided(self):
        """Generated codes should not collide with existing_codes set."""
        existing = {f"{i:04d}" for i in range(9990)}
        msg = f"Q? - Reply A or B: {SAMPLE_GUID}@1|4"

        cleaned, codes = clean_ask_task_message_and_generate_codes(msg, existing)

        assert len(codes) == 2
        for code in codes:
            assert code not in existing

    def test_multiline_question(self):
        """Question text containing newlines should still match (re.DOTALL)."""
        msg = f"Line1\nLine2\nLine3 - Reply Yes or No: {SAMPLE_GUID}@1|4"
        cleaned, codes = clean_ask_task_message_and_generate_codes(msg, set())

        assert len(codes) == 2
        assert "Line1" in cleaned
        assert "Line3" in cleaned

    def test_sequential_mode_two_options(self):
        """Sequential mode generates codes 1, 2 for first question."""
        msg = f"Approve? - Reply Yes or No: {SAMPLE_GUID}@123|45"
        cleaned, codes = clean_ask_task_message_and_generate_codes(
            msg, set(), reply_code_mode=REPLY_CODE_MODE_SEQUENTIAL
        )

        assert len(codes) == 2
        assert set(codes.keys()) == {"1", "2"}
        assert codes["1"] == "Yes"
        assert codes["2"] == "No"
        assert "Yes (1)" in cleaned
        assert "No (2)" in cleaned

    def test_sequential_mode_skips_existing(self):
        """Sequential mode continues numbering past existing codes."""
        msg = f"Another question? - Reply Yes or No: {SAMPLE_GUID}@123|45"
        cleaned, codes = clean_ask_task_message_and_generate_codes(
            msg, {"1", "2"}, reply_code_mode=REPLY_CODE_MODE_SEQUENTIAL
        )

        assert len(codes) == 2
        assert set(codes.keys()) == {"3", "4"}
        assert codes["3"] == "Yes"
        assert codes["4"] == "No"

    def test_sequential_mode_three_options(self):
        """Sequential mode with 3 options."""
        msg = f"Action? - Reply Approve or Deny or Escalate: {SAMPLE_GUID}@1|4"
        cleaned, codes = clean_ask_task_message_and_generate_codes(
            msg, set(), reply_code_mode=REPLY_CODE_MODE_SEQUENTIAL
        )

        assert len(codes) == 3
        assert codes == {"1": "Approve", "2": "Deny", "3": "Escalate"}


# ===== 3. TestEntitlementManagement =====

class TestEntitlementManagement:
    """Tests for entitlement CRUD operations."""

    def test_save_new_entitlement(self, integration_context):
        """Save a new entitlement with codes_to_options dict."""
        codes = {"1234": "Yes", "5678": "No"}
        result = save_entitlement(SAMPLE_ENTITLEMENT_ID, SAMPLE_PHONE, codes, "msg")

        assert result == codes
        assert len(integration_context["entitlements"]) == 1
        ent = integration_context["entitlements"][0]
        assert ent["entitlement_id"] == SAMPLE_ENTITLEMENT_ID
        assert ent["phone_number"] == SAMPLE_PHONE
        assert ent["codes_to_options"] == codes
        assert ent["answered"] is False

    def test_save_duplicate_returns_existing(self, integration_context):
        """Saving same entitlement_id twice returns existing codes."""
        codes_first = {"1111": "A", "2222": "B"}
        codes_second = {"3333": "C", "4444": "D"}

        save_entitlement(SAMPLE_ENTITLEMENT_ID, SAMPLE_PHONE, codes_first, "msg")
        result = save_entitlement(SAMPLE_ENTITLEMENT_ID, SAMPLE_PHONE, codes_second, "msg2")

        assert result == codes_first
        assert len(integration_context["entitlements"]) == 1

    def test_get_active_entitlements_filters(self, integration_context):
        """Filters by phone number and answered=False."""
        integration_context["entitlements"] = [
            _make_entitlement(entitlement_id="ent1", phone=SAMPLE_PHONE, answered=False),
            _make_entitlement(entitlement_id="ent2", phone=SAMPLE_PHONE, answered=True),
            _make_entitlement(entitlement_id="ent3", phone="+19999999999", answered=False),
        ]

        active = get_active_entitlements_for_phone(SAMPLE_PHONE)

        assert len(active) == 1
        assert active[0]["entitlement_id"] == "ent1"

    def test_find_by_reply_code_found(self, integration_context):
        """Returns (entitlement, chosen_option) tuple when code matches."""
        integration_context["entitlements"] = [
            _make_entitlement(codes_to_options={"1234": "Yes", "5678": "No"}),
        ]

        ent, chosen = find_entitlement_by_reply_code(SAMPLE_PHONE, "5678")

        assert ent is not None
        assert ent["entitlement_id"] == SAMPLE_ENTITLEMENT_ID
        assert chosen == "No"

    def test_find_by_reply_code_not_found(self, integration_context):
        """Returns (None, None) when code doesn't match any entitlement."""
        integration_context["entitlements"] = [
            _make_entitlement(codes_to_options={"1234": "Yes", "5678": "No"}),
        ]

        ent, chosen = find_entitlement_by_reply_code(SAMPLE_PHONE, "9999")

        assert ent is None
        assert chosen is None

    def test_mark_answered(self, integration_context):
        """Sets answered=True and populates answered_at timestamp."""
        integration_context["entitlements"] = [_make_entitlement()]

        mark_entitlement_answered(SAMPLE_ENTITLEMENT_ID)

        ent = integration_context["entitlements"][0]
        assert ent["answered"] is True
        assert "answered_at" in ent

    def test_cleanup_expired(self, integration_context):
        """Removes entitlements older than TTL, keeps fresh ones."""
        now = datetime.utcnow()
        integration_context["entitlements"] = [
            _make_entitlement(
                entitlement_id="old",
                created=(now - timedelta(hours=25)).strftime(DATE_FORMAT),
            ),
            _make_entitlement(
                entitlement_id="fresh",
                created=now.strftime(DATE_FORMAT),
            ),
        ]

        cleanup_expired_entitlements(ttl_hours=24)

        assert len(integration_context["entitlements"]) == 1
        assert integration_context["entitlements"][0]["entitlement_id"] == "fresh"

    def test_get_available_codes(self, integration_context):
        """Returns all (code, option) tuples from active entitlements."""
        integration_context["entitlements"] = [
            _make_entitlement(
                entitlement_id="ent1",
                codes_to_options={"1111": "A", "2222": "B"},
                answered=False,
            ),
            _make_entitlement(
                entitlement_id="ent2",
                codes_to_options={"3333": "C"},
                answered=False,
            ),
            _make_entitlement(
                entitlement_id="ent3",
                codes_to_options={"4444": "D"},
                answered=True,
            ),
        ]

        codes = get_available_codes_for_phone(SAMPLE_PHONE)

        code_values = {c for c, _ in codes}
        assert code_values == {"1111", "2222", "3333"}


# ===== 4. TestSendNotificationCommand =====

class TestSendNotificationCommand:
    """Tests for the send-notification command."""

    def test_simple_message_no_entitlement(self, mocker, mock_sns_client, mock_params):
        """Plain SMS without entitlement just publishes and returns MessageId."""
        mocker.patch("AWSSNSSMSCommunication.get_aws_client", return_value=mock_sns_client)

        result = send_notification_command(
            {"to": SAMPLE_PHONE, "message": "Hello"}, mock_params
        )

        assert result.outputs["MessageId"] == "msg-id-123"
        assert result.outputs["PhoneNumber"] == SAMPLE_PHONE
        assert "Entitlement" not in result.outputs
        mock_sns_client.publish.assert_called_once_with(
            PhoneNumber=SAMPLE_PHONE, Message="Hello"
        )

    def test_with_sms_ask_entitlement(
        self, mocker, mock_sns_client, mock_params, integration_context
    ):
        """Full entitlement flow: extract, generate codes, save, send formatted."""
        mocker.patch("AWSSNSSMSCommunication.get_aws_client", return_value=mock_sns_client)

        msg = f"Approve? - Reply Yes or No: {SAMPLE_GUID}@123|45"
        result = send_notification_command(
            {"to": SAMPLE_PHONE, "message": msg}, mock_params
        )

        assert result.outputs["Entitlement"] == f"{SAMPLE_GUID}@123|45"
        assert isinstance(result.outputs["CodesToOptions"], dict)
        assert len(result.outputs["CodesToOptions"]) == 2
        assert set(result.outputs["CodesToOptions"].values()) == {"Yes", "No"}
        assert len(integration_context["entitlements"]) == 1

    def test_missing_args_raises(self, mock_params):
        """ValueError raised when 'to' or 'message' missing."""
        with pytest.raises(ValueError, match="Both 'to' and 'message'"):
            send_notification_command({"to": SAMPLE_PHONE}, mock_params)

        with pytest.raises(ValueError, match="Both 'to' and 'message'"):
            send_notification_command({"message": "hi"}, mock_params)

    def test_with_sequential_mode(
        self, mocker, mock_sns_client, mock_params, integration_context
    ):
        """Sequential mode generates simple 1, 2 codes instead of 4-digit random."""
        mocker.patch("AWSSNSSMSCommunication.get_aws_client", return_value=mock_sns_client)
        mock_params["replyCodeMode"] = "sequential"

        msg = f"Approve? - Reply Yes or No: {SAMPLE_GUID}@123|45"
        result = send_notification_command(
            {"to": SAMPLE_PHONE, "message": msg}, mock_params
        )

        codes = result.outputs["CodesToOptions"]
        assert codes == {"1": "Yes", "2": "No"}
        # Verify the sent message contains sequential codes
        sent_message = mock_sns_client.publish.call_args[1]["Message"]
        assert "Yes (1)" in sent_message
        assert "No (2)" in sent_message

    def test_fallback_when_no_options(
        self, mocker, mock_sns_client, mock_params, integration_context
    ):
        """When entitlement found but no options parsed, falls back to DEFAULT_REPLY_CODE."""
        mocker.patch("AWSSNSSMSCommunication.get_aws_client", return_value=mock_sns_client)

        # Has entitlement but not in "Reply X or Y:" format
        msg = f"Some text {SAMPLE_GUID}@123|45 more text"
        result = send_notification_command(
            {"to": SAMPLE_PHONE, "message": msg}, mock_params
        )

        assert result.outputs["CodesToOptions"] == {DEFAULT_REPLY_CODE: "response"}


# ===== 5. TestListEntitlementsCommand =====

class TestListEntitlementsCommand:
    """Tests for aws-sns-sms-list-entitlements command."""

    def test_list_all_active(self, mocker, integration_context, mock_params):
        """Returns unanswered entitlements."""
        mocker.patch("AWSSNSSMSCommunication.argToBoolean", side_effect=lambda x: bool(x))

        integration_context["entitlements"] = [
            _make_entitlement(entitlement_id="ent1", answered=False),
            _make_entitlement(entitlement_id="ent2", answered=True),
        ]

        result = list_entitlements_command({}, mock_params)

        assert len(result.outputs) == 1
        assert result.outputs[0]["EntitlementID"] == "ent1"

    def test_list_filtered_by_phone(self, mocker, integration_context, mock_params):
        """Filters by phone_number argument."""
        mocker.patch("AWSSNSSMSCommunication.argToBoolean", side_effect=lambda x: bool(x))

        integration_context["entitlements"] = [
            _make_entitlement(entitlement_id="ent1", phone=SAMPLE_PHONE),
            _make_entitlement(entitlement_id="ent2", phone="+19999999999"),
        ]

        result = list_entitlements_command(
            {"phone_number": SAMPLE_PHONE}, mock_params
        )

        assert len(result.outputs) == 1
        assert result.outputs[0]["PhoneNumber"] == SAMPLE_PHONE

    def test_list_empty(self, mocker, integration_context, mock_params):
        """No entitlements returns appropriate message."""
        mocker.patch("AWSSNSSMSCommunication.argToBoolean", side_effect=lambda x: bool(x))

        result = list_entitlements_command({}, mock_params)

        assert "No entitlements found" in result.readable_output


# ===== 6. TestInjectReplyCommand =====

class TestInjectReplyCommand:
    """Tests for aws-sns-sms-inject-reply debug command."""

    def test_successful_injection(self, mocker, integration_context, mock_params):
        """Finds entitlement, calls handleEntitlementForUser, marks answered."""
        integration_context["entitlements"] = [
            _make_entitlement(codes_to_options={"1234": "Yes", "5678": "No"}),
        ]

        result = inject_reply_command(
            {"phone_number": SAMPLE_PHONE, "reply_code": "1234"}, mock_params
        )

        assert result.outputs["Success"] is True
        assert result.outputs["ChosenOption"] == "Yes"
        import AWSSNSSMSCommunication

        AWSSNSSMSCommunication.demisto.handleEntitlementForUser.assert_called_once_with(
            "123", SAMPLE_GUID, SAMPLE_PHONE, "Yes", "45"
        )
        assert integration_context["entitlements"][0]["answered"] is True

    def test_invalid_code_format(self, integration_context, mock_params):
        """Non-numeric code returns error output."""
        result = inject_reply_command(
            {"phone_number": SAMPLE_PHONE, "reply_code": "abc"}, mock_params
        )

        assert result.outputs["Success"] is False
        assert "Invalid reply code format" in result.outputs["Error"]

    def test_sequential_code_injection(self, mocker, integration_context, mock_params):
        """Sequential mode single-digit codes work with inject-reply."""
        integration_context["entitlements"] = [
            _make_entitlement(codes_to_options={"1": "Yes", "2": "No"}),
        ]

        result = inject_reply_command(
            {"phone_number": SAMPLE_PHONE, "reply_code": "1"}, mock_params
        )

        assert result.outputs["Success"] is True
        assert result.outputs["ChosenOption"] == "Yes"

    def test_no_matching_entitlement(self, integration_context, mock_params):
        """Valid code format but no matching entitlement returns error with active codes."""
        integration_context["entitlements"] = [
            _make_entitlement(codes_to_options={"1234": "Yes"}),
        ]

        result = inject_reply_command(
            {"phone_number": SAMPLE_PHONE, "reply_code": "9999"}, mock_params
        )

        assert result.outputs["Success"] is False
        assert "No matching entitlement" in result.outputs["Error"]
        assert len(result.outputs["ActiveEntitlements"]) == 1

    def test_missing_args(self, mock_params):
        """ValueError when phone_number or reply_code missing."""
        with pytest.raises(ValueError, match="Both phone_number and reply_code"):
            inject_reply_command({"phone_number": SAMPLE_PHONE}, mock_params)


# ===== 7. TestProcessSmsReply =====

class TestProcessSmsReply:
    """Tests for process_sms_reply() - core SQS message processing."""

    def _make_sqs_message(self, phone=SAMPLE_PHONE, body_text="1234"):
        """Build an SQS message wrapping an SNS notification."""
        sns_payload = {
            "originationNumber": phone,
            "messageBody": body_text,
        }
        return {
            "MessageId": "sqs-msg-1",
            "Body": json.dumps({
                "Type": "Notification",
                "Message": json.dumps(sns_payload),
            }),
            "ReceiptHandle": "receipt-1",
        }

    def test_valid_reply_success(
        self, mocker, integration_context, mock_sns_client, mock_params
    ):
        """Match code -> handleEntitlementForUser -> mark answered -> send success feedback."""
        mocker.patch("AWSSNSSMSCommunication.get_aws_client", return_value=mock_sns_client)
        integration_context["entitlements"] = [
            _make_entitlement(codes_to_options={"1234": "Yes", "5678": "No"}),
        ]

        process_sms_reply(self._make_sqs_message(body_text="1234"), mock_params)

        import AWSSNSSMSCommunication

        AWSSNSSMSCommunication.demisto.handleEntitlementForUser.assert_called_once_with(
            "123", SAMPLE_GUID, SAMPLE_PHONE, "Yes", "45"
        )
        assert integration_context["entitlements"][0]["answered"] is True
        # Success feedback SMS sent
        mock_sns_client.publish.assert_called_once()
        call_kwargs = mock_sns_client.publish.call_args
        assert call_kwargs[1]["PhoneNumber"] == SAMPLE_PHONE

    def test_valid_reply_no_match(
        self, mocker, integration_context, mock_sns_client, mock_params
    ):
        """Valid 4-digit code but no matching entitlement -> failure feedback."""
        mocker.patch("AWSSNSSMSCommunication.get_aws_client", return_value=mock_sns_client)
        integration_context["entitlements"] = [
            _make_entitlement(codes_to_options={"1234": "Yes"}),
        ]

        process_sms_reply(self._make_sqs_message(body_text="9999"), mock_params)

        import AWSSNSSMSCommunication

        AWSSNSSMSCommunication.demisto.handleEntitlementForUser.assert_not_called()
        mock_sns_client.publish.assert_called_once()

    def test_invalid_code_format(
        self, mocker, integration_context, mock_sns_client, mock_params
    ):
        """Non-numeric text -> failure feedback when active entitlements exist."""
        mocker.patch("AWSSNSSMSCommunication.get_aws_client", return_value=mock_sns_client)
        integration_context["entitlements"] = [
            _make_entitlement(codes_to_options={"1234": "Yes"}),
        ]

        process_sms_reply(self._make_sqs_message(body_text="hello"), mock_params)

        import AWSSNSSMSCommunication

        AWSSNSSMSCommunication.demisto.handleEntitlementForUser.assert_not_called()
        mock_sns_client.publish.assert_called_once()

    def test_sequential_code_reply(
        self, mocker, integration_context, mock_sns_client, mock_params
    ):
        """Single-digit sequential codes are accepted and processed correctly."""
        mocker.patch("AWSSNSSMSCommunication.get_aws_client", return_value=mock_sns_client)
        integration_context["entitlements"] = [
            _make_entitlement(codes_to_options={"1": "Yes", "2": "No"}),
        ]

        process_sms_reply(self._make_sqs_message(body_text="2"), mock_params)

        import AWSSNSSMSCommunication

        AWSSNSSMSCommunication.demisto.handleEntitlementForUser.assert_called_once_with(
            "123", SAMPLE_GUID, SAMPLE_PHONE, "No", "45"
        )
        assert integration_context["entitlements"][0]["answered"] is True

    def test_success_feedback_disabled(
        self, mocker, integration_context, mock_sns_client, mock_params
    ):
        """When successFeedbackEnabled=False, no success SMS sent."""
        mocker.patch("AWSSNSSMSCommunication.get_aws_client", return_value=mock_sns_client)
        mocker.patch(
            "AWSSNSSMSCommunication.argToBoolean",
            side_effect=lambda x: x if isinstance(x, bool) else str(x).lower() == "true",
        )
        mock_params["successFeedbackEnabled"] = False
        integration_context["entitlements"] = [
            _make_entitlement(codes_to_options={"1234": "Yes"}),
        ]

        process_sms_reply(self._make_sqs_message(body_text="1234"), mock_params)

        import AWSSNSSMSCommunication

        AWSSNSSMSCommunication.demisto.handleEntitlementForUser.assert_called_once()
        mock_sns_client.publish.assert_not_called()

    def test_failure_feedback_disabled(
        self, mocker, integration_context, mock_sns_client, mock_params
    ):
        """When failureFeedbackEnabled=False, no failure SMS sent."""
        mocker.patch("AWSSNSSMSCommunication.get_aws_client", return_value=mock_sns_client)
        mocker.patch(
            "AWSSNSSMSCommunication.argToBoolean",
            side_effect=lambda x: x if isinstance(x, bool) else str(x).lower() == "true",
        )
        mock_params["failureFeedbackEnabled"] = False
        integration_context["entitlements"] = [
            _make_entitlement(codes_to_options={"1234": "Yes"}),
        ]

        process_sms_reply(self._make_sqs_message(body_text="9999"), mock_params)

        mock_sns_client.publish.assert_not_called()

    def test_empty_message_skipped(self, mocker, mock_params):
        """Message without phone or text returns early without processing."""
        mocker.patch(
            "AWSSNSSMSCommunication.argToBoolean",
            side_effect=lambda x: x if isinstance(x, bool) else str(x).lower() == "true",
        )
        sqs_msg = {
            "MessageId": "sqs-msg-1",
            "Body": json.dumps({"originationNumber": "", "messageBody": ""}),
        }

        process_sms_reply(sqs_msg, mock_params)

        import AWSSNSSMSCommunication

        AWSSNSSMSCommunication.demisto.handleEntitlementForUser.assert_not_called()


# ===== 8. TestTestModuleCommand =====

class TestTestModuleCommand:
    """Tests for test-module command."""

    def test_module_success(self, mocker, mock_sqs_client, mock_params):
        """SQS get_queue_attributes returns 200 -> 'ok'."""
        mocker.patch("AWSSNSSMSCommunication.get_aws_client", return_value=mock_sqs_client)

        result = test_module_command(mock_params)

        assert result == "ok"
        mock_sqs_client.get_queue_attributes.assert_called_once_with(
            QueueUrl=mock_params["sqsQueueUrl"],
            AttributeNames=["QueueArn"],
        )

    def test_module_no_queue_url(self, mock_params):
        """Missing sqsQueueUrl raises exception."""
        mock_params["sqsQueueUrl"] = ""

        with pytest.raises(Exception, match="SQS Queue URL is required"):
            test_module_command(mock_params)


# ===== 9. TestGetAwsClient =====

class TestGetAwsClient:
    """Tests for get_aws_client() with different auth methods.

    boto3 is imported *inside* get_aws_client(), so we inject a mock boto3
    module into sys.modules before each test. This allows patching even when
    the real boto3 package is not installed.
    """

    @pytest.fixture(autouse=True)
    def _inject_mock_boto3(self, mocker):
        """Inject a mock boto3 module so the local import inside get_aws_client works."""
        import sys
        from unittest.mock import MagicMock

        self._mock_boto3 = MagicMock()
        # Also need a mock botocore.config.Config
        self._mock_botocore = MagicMock()
        self._orig_boto3 = sys.modules.get("boto3")
        self._orig_botocore = sys.modules.get("botocore")
        self._orig_botocore_config = sys.modules.get("botocore.config")
        sys.modules["boto3"] = self._mock_boto3
        sys.modules.setdefault("botocore", self._mock_botocore)
        sys.modules.setdefault("botocore.config", self._mock_botocore.config)
        yield
        # Restore originals
        if self._orig_boto3 is not None:
            sys.modules["boto3"] = self._orig_boto3
        else:
            sys.modules.pop("boto3", None)
        if self._orig_botocore is not None:
            sys.modules["botocore"] = self._orig_botocore
        else:
            sys.modules.pop("botocore", None)
        if self._orig_botocore_config is not None:
            sys.modules["botocore.config"] = self._orig_botocore_config
        else:
            sys.modules.pop("botocore.config", None)

    def test_access_key_only(self):
        """Creates client with access key credentials (no role ARN)."""
        mock_client = MagicMock()
        self._mock_boto3.client.return_value = mock_client

        params = {
            "credentials": {"identifier": "AKIA123", "password": "secret"},
            "defaultRegion": "eu-west-1",
            "timeout": "30",
            "retries": "3",
            "insecure": False,
        }

        result = get_aws_client(params, "sns")

        assert result == mock_client
        self._mock_boto3.client.assert_called_once()
        call_args, call_kwargs = self._mock_boto3.client.call_args
        assert call_args[0] == "sns"
        assert call_kwargs["aws_access_key_id"] == "AKIA123"
        assert call_kwargs["aws_secret_access_key"] == "secret"

    def test_role_arn_only(self):
        """Creates STS client, assumes role, creates service client with temp creds."""
        mock_sts = MagicMock()
        mock_sts.assume_role.return_value = {
            "Credentials": {
                "AccessKeyId": "ASIA_TEMP",
                "SecretAccessKey": "temp_secret",
                "SessionToken": "temp_token",
                "Expiration": "2026-01-01T00:00:00Z",
            }
        }
        mock_sqs = MagicMock()
        self._mock_boto3.client.side_effect = [mock_sts, mock_sqs]

        params = {
            "credentials": None,
            "defaultRegion": "us-east-1",
            "roleArn": "arn:aws:iam::123456789:role/TestRole",
            "roleSessionName": "xsoar-session",
            "sessionDuration": "900",
            "timeout": "60",
            "retries": "5",
            "insecure": False,
        }

        result = get_aws_client(params, "sqs")

        assert result == mock_sqs
        mock_sts.assume_role.assert_called_once()
        second_call_kwargs = self._mock_boto3.client.call_args_list[1][1]
        assert second_call_kwargs["aws_access_key_id"] == "ASIA_TEMP"
        assert second_call_kwargs["aws_session_token"] == "temp_token"

    def test_default_credentials(self):
        """No keys, no role -> default credentials (EC2 instance role, env vars)."""
        mock_client = MagicMock()
        self._mock_boto3.client.return_value = mock_client

        params = {
            "credentials": None,
            "defaultRegion": "us-east-1",
            "timeout": "60",
            "retries": "5",
            "insecure": False,
        }

        result = get_aws_client(params, "sns")

        assert result == mock_client
        call_args, call_kwargs = self._mock_boto3.client.call_args
        assert call_args[0] == "sns"
        assert "aws_access_key_id" not in call_kwargs


# ===== 10. TestSendFeedbackSms =====

class TestSendFeedbackSms:
    """Tests for send_feedback_sms helper."""

    def test_sends_sms(self, mocker, mock_sns_client, mock_params):
        """Publishes feedback message via SNS."""
        mocker.patch("AWSSNSSMSCommunication.get_aws_client", return_value=mock_sns_client)

        send_feedback_sms(SAMPLE_PHONE, "Thank you!", mock_params)

        mock_sns_client.publish.assert_called_once_with(
            PhoneNumber=SAMPLE_PHONE, Message="Thank you!"
        )

    def test_handles_publish_error(self, mocker, mock_sns_client, mock_params):
        """Logs error but does not raise on publish failure."""
        mock_sns_client.publish.side_effect = Exception("SNS error")
        mocker.patch("AWSSNSSMSCommunication.get_aws_client", return_value=mock_sns_client)

        send_feedback_sms(SAMPLE_PHONE, "msg", mock_params)

        import AWSSNSSMSCommunication

        AWSSNSSMSCommunication.demisto.error.assert_called()
