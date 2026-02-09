"""
Unit tests for AWS SNS SMS Communication integration
"""
import pytest
import json
from datetime import datetime, timedelta
from AWSSNSSMSCommunication import (
    generate_reply_code,
    extract_entitlement_from_message,
    parse_entitlement_string,
    get_active_entitlements_for_phone,
    find_entitlement_by_reply_code,
    save_entitlement,
    mark_entitlement_answered,
    cleanup_expired_entitlements,
    DEFAULT_REPLY_CODE,
    DATE_FORMAT
)


class TestHelperFunctions:
    """Test helper functions"""

    def test_generate_reply_code(self):
        """Test reply code generation"""
        code = generate_reply_code()
        assert len(code) == 4
        assert code.isdigit()

    def test_extract_entitlement_from_message(self):
        """Test entitlement extraction from message"""
        message = "Please respond: 550e8400-e29b-41d4-a716-446655440000@123|task1 Yes or No?"
        guid, remaining = extract_entitlement_from_message(message)

        assert guid == "550e8400-e29b-41d4-a716-446655440000"
        assert "Yes or No?" in remaining

    def test_extract_entitlement_no_match(self):
        """Test extraction when no entitlement present"""
        message = "Simple message without entitlement"
        guid, remaining = extract_entitlement_from_message(message)

        assert guid is None
        assert remaining == message

    def test_parse_entitlement_string(self):
        """Test parsing entitlement components"""
        entitlement = "550e8400-e29b-41d4-a716-446655440000@123456|task789"
        parsed = parse_entitlement_string(entitlement)

        assert parsed["guid"] == "550e8400-e29b-41d4-a716-446655440000"
        assert parsed["incident_id"] == "123456"
        assert parsed["task_id"] == "task789"

    def test_parse_entitlement_no_task(self):
        """Test parsing entitlement without task ID"""
        entitlement = "550e8400-e29b-41d4-a716-446655440000@123456"
        parsed = parse_entitlement_string(entitlement)

        assert parsed["guid"] == "550e8400-e29b-41d4-a716-446655440000"
        assert parsed["incident_id"] == "123456"
        assert parsed["task_id"] == ""


class TestEntitlementManagement:
    """Test entitlement management functions"""

    @pytest.fixture(autouse=True)
    def setup_and_teardown(self, mocker):
        """Setup and teardown for each test"""
        # Mock integration context
        self.mock_context = {"entitlements": []}
        mocker.patch("AWSSNSSMSCommunication.get_integration_context_with_sync", return_value=self.mock_context)
        mocker.patch("AWSSNSSMSCommunication.set_integration_context_with_sync")
        yield
        # Cleanup
        self.mock_context = {"entitlements": []}

    def test_save_entitlement(self, mocker):
        """Test saving a new entitlement"""
        mocker.patch("AWSSNSSMSCommunication.get_integration_context_with_sync", return_value=self.mock_context)

        entitlement_id = "550e8400-e29b-41d4-a716-446655440000@123"
        phone = "+12345678900"
        code = "1234"
        message = "Test message"

        reply_code = save_entitlement(entitlement_id, phone, code, message)

        assert reply_code == code
        assert len(self.mock_context["entitlements"]) == 1
        assert self.mock_context["entitlements"][0]["entitlement_id"] == entitlement_id
        assert self.mock_context["entitlements"][0]["phone_number"] == phone
        assert self.mock_context["entitlements"][0]["answered"] is False

    def test_get_active_entitlements_for_phone(self, mocker):
        """Test retrieving active entitlements for a phone number"""
        phone = "+12345678900"
        self.mock_context["entitlements"] = [
            {
                "entitlement_id": "ent1",
                "phone_number": phone,
                "reply_code": "1111",
                "answered": False,
                "created": datetime.utcnow().strftime(DATE_FORMAT)
            },
            {
                "entitlement_id": "ent2",
                "phone_number": phone,
                "reply_code": "2222",
                "answered": True,  # Already answered
                "created": datetime.utcnow().strftime(DATE_FORMAT)
            },
            {
                "entitlement_id": "ent3",
                "phone_number": "+19999999999",  # Different phone
                "reply_code": "3333",
                "answered": False,
                "created": datetime.utcnow().strftime(DATE_FORMAT)
            }
        ]

        mocker.patch("AWSSNSSMSCommunication.get_integration_context_with_sync", return_value=self.mock_context)

        active = get_active_entitlements_for_phone(phone)

        assert len(active) == 1
        assert active[0]["entitlement_id"] == "ent1"

    def test_find_entitlement_by_reply_code(self, mocker):
        """Test finding entitlement by reply code"""
        phone = "+12345678900"
        self.mock_context["entitlements"] = [
            {
                "entitlement_id": "ent1",
                "phone_number": phone,
                "reply_code": "1234",
                "answered": False,
                "created": datetime.utcnow().strftime(DATE_FORMAT)
            }
        ]

        mocker.patch("AWSSNSSMSCommunication.get_integration_context_with_sync", return_value=self.mock_context)

        found = find_entitlement_by_reply_code(phone, "1234")

        assert found is not None
        assert found["entitlement_id"] == "ent1"

    def test_mark_entitlement_answered(self, mocker):
        """Test marking entitlement as answered"""
        self.mock_context["entitlements"] = [
            {
                "entitlement_id": "ent1",
                "phone_number": "+12345678900",
                "reply_code": "1234",
                "answered": False,
                "created": datetime.utcnow().strftime(DATE_FORMAT)
            }
        ]

        mocker.patch("AWSSNSSMSCommunication.get_integration_context_with_sync", return_value=self.mock_context)

        mark_entitlement_answered("ent1")

        assert self.mock_context["entitlements"][0]["answered"] is True
        assert "answered_at" in self.mock_context["entitlements"][0]

    def test_cleanup_expired_entitlements(self, mocker):
        """Test cleanup of expired entitlements"""
        now = datetime.utcnow()
        old_time = (now - timedelta(hours=25)).strftime(DATE_FORMAT)
        new_time = now.strftime(DATE_FORMAT)

        self.mock_context["entitlements"] = [
            {
                "entitlement_id": "ent1",
                "phone_number": "+12345678900",
                "reply_code": "1111",
                "answered": False,
                "created": old_time  # 25 hours old - should be removed
            },
            {
                "entitlement_id": "ent2",
                "phone_number": "+12345678900",
                "reply_code": "2222",
                "answered": False,
                "created": new_time  # Fresh - should be kept
            }
        ]

        mocker.patch("AWSSNSSMSCommunication.get_integration_context_with_sync", return_value=self.mock_context)

        cleanup_expired_entitlements(ttl_hours=24)

        assert len(self.mock_context["entitlements"]) == 1
        assert self.mock_context["entitlements"][0]["entitlement_id"] == "ent2"


class TestCommands:
    """Test command functions"""

    @pytest.fixture
    def mock_sns_client(self, mocker):
        """Mock SNS client"""
        client = mocker.Mock()
        client.publish.return_value = {"MessageId": "test-message-id-123"}
        return client

    @pytest.fixture
    def mock_params(self):
        """Mock integration parameters"""
        return {
            "credentials": {
                "identifier": "test_key",
                "password": "test_secret"
            },
            "defaultRegion": "us-east-1",
            "sqsQueueUrl": "https://sqs.us-east-1.amazonaws.com/123456789/test-queue"
        }

    def test_send_notification_simple_message(self, mocker, mock_sns_client, mock_params):
        """Test sending simple message without entitlement"""
        from AWSSNSSMSCommunication import send_notification_command

        mocker.patch("AWSSNSSMSCommunication.get_aws_client", return_value=mock_sns_client)

        args = {
            "to": "+12345678900",
            "message": "Simple test message"
        }

        result = send_notification_command(args, mock_params)

        assert "MessageId" in result.outputs
        assert result.outputs["MessageId"] == "test-message-id-123"
        mock_sns_client.publish.assert_called_once()

    def test_send_notification_with_entitlement_no_active(self, mocker, mock_sns_client, mock_params):
        """Test sending message with entitlement when no other entitlements active"""
        from AWSSNSSMSCommunication import send_notification_command

        mocker.patch("AWSSNSSMSCommunication.get_aws_client", return_value=mock_sns_client)
        mocker.patch("AWSSNSSMSCommunication.get_active_entitlements_for_phone", return_value=[])
        mocker.patch("AWSSNSSMSCommunication.save_entitlement", return_value=DEFAULT_REPLY_CODE)

        args = {
            "to": "+12345678900",
            "message": "550e8400-e29b-41d4-a716-446655440000@123 Do you approve? Yes/No"
        }

        result = send_notification_command(args, mock_params)

        assert result.outputs["ReplyCode"] == DEFAULT_REPLY_CODE
        assert "Entitlement" in result.outputs

    def test_send_notification_with_entitlement_multiple_active(self, mocker, mock_sns_client, mock_params):
        """Test sending message with entitlement when other entitlements are active"""
        from AWSSNSSMSCommunication import send_notification_command

        mocker.patch("AWSSNSSMSCommunication.get_aws_client", return_value=mock_sns_client)
        mocker.patch("AWSSNSSMSCommunication.get_active_entitlements_for_phone", return_value=[
            {"reply_code": "1111"}, {"reply_code": "2222"}
        ])
        mocker.patch("AWSSNSSMSCommunication.save_entitlement", return_value="3333")

        args = {
            "to": "+12345678900",
            "message": "550e8400-e29b-41d4-a716-446655440000@123 Do you approve? Yes/No"
        }

        result = send_notification_command(args, mock_params)

        # Should have generated a unique code
        assert result.outputs["ReplyCode"] != DEFAULT_REPLY_CODE
        assert result.outputs["ReplyCode"] == "3333"
