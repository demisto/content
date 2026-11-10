import pytest
from datetime import datetime, UTC

from pytest_mock import MockerFixture
import demistomock as demisto
from CortexAssistantApiModule import (
    BackendErrorCode,
    BackendErrorType,
    BackendResponse,
    AssistantStatus,
    AssistantMessageType,
    AssistantActionIds,
    AssistantMessages,
    AssistantMessagingHandler,
    IGNORED_MESSAGE_IDS,
)


# ============================================================================
# Mock Handler for Testing
# ============================================================================


class MockMessagingHandler(AssistantMessagingHandler):
    """Mock implementation for testing platform-agnostic logic."""

    def __init__(self):
        super().__init__()
        self.sent_messages = []
        self.updated_messages = []
        self.deleted_messages = []
        self.posted_responses = []

    async def send_message_async(self, channel_id: str, message: str, thread_id: str = "",
                                  blocks: list | None = None, attachments: list | None = None,
                                  ephemeral: bool = False, user_id: str = ""):
        self.sent_messages.append({"channel_id": channel_id, "message": message, "ephemeral": ephemeral})
        return {"ts": "1234567890.123456"}

    async def update_message(self, channel_id: str, message_id: str, text: str = "", blocks: list | None = None):
        self.updated_messages.append({"channel_id": channel_id, "message_id": message_id, "text": text, "blocks": blocks})

    def delete_message(self, channel_id: str, message_id: str) -> tuple[bool, dict]:
        self.deleted_messages.append({"channel_id": channel_id, "message_id": message_id})
        return True, {"ok": True}

    async def get_user_info(self, user_id: str) -> dict:
        return {"id": user_id, "email": "test@example.com"}

    async def get_thread_last_messages(self, channel_id: str, thread_id: str, limit: int = 20) -> list:
        return []

    def format_user_mention(self, user_id: str) -> str:
        return f"<@{user_id}>"

    def normalize_message_from_user(self, text: str) -> str:
        return text

    def prepare_message_blocks(self, message: str, message_type: str, is_update: bool = False) -> tuple:
        return ([], [])

    def prepare_merged_step_blocks(self, step_contents: list[str]) -> tuple[list, list]:
        return ([{"type": "merged_steps", "contents": step_contents}], [])

    def create_agent_selection_ui(self, agents: list) -> list:
        return [{"type": "section"}] if agents else []

    def create_approval_ui(self) -> list:
        return [{"type": "actions"}]

    def create_feedback_ui(self, message_id: str) -> dict:
        return {"type": "feedback", "message_id": message_id}

    def post_agent_response(self, channel_id: str, thread_id: str, blocks: list,
                                  attachments: list, agent_name: str = "", fallback_text: str = "") -> dict | None:
        self.last_posted_blocks = blocks
        self.posted_responses.append({"blocks": blocks, "attachments": attachments})
        return {"ts": "1234567890.123456"}

    def update_existing_message(self, channel_id: str, thread_id: str, message_id: str,
                                attachments: list) -> bool:
        return True

    def finalize_plan_header(self, channel_id: str, thread_id: str, step_message_id: str):
        pass

    def update_context(self, context_updates: dict):
        pass

    async def show_feedback_modal(self, trigger_id: str, message_id: str, channel_id: str, thread_id: str):
        pass

    async def get_conversation_context_formatted(self, channel_id: str, thread_id: str,
                                                  bot_id: str, current_message_id: str,
                                                  max_context_messages: int = 5) -> str:
        return ""


# ============================================================================
# Test BackendErrorType
# ============================================================================


def test_backend_error_type_values():
    """
    Given:
        BackendErrorType enum.
    When:
        Accessing enum values.
    Then:
        All error types have correct string values.
    """
    assert BackendErrorType.LLM_NOT_ENABLED.value == "llm_not_enabled"
    assert BackendErrorType.USER_NOT_FOUND.value == "user_not_found"
    assert BackendErrorType.PERMISSION_DENIED.value == "permission_denied"
    assert BackendErrorType.CONVERSATION_NOT_FOUND.value == "conversation_not_found"
    assert BackendErrorType.WRONG_USER.value == "wrong_user"
    assert BackendErrorType.UNKNOWN.value == "unknown"


# ============================================================================
# Test BackendResponse
# ============================================================================


def test_backend_response_success():
    """
    Given:
        Success parameters.
    When:
        Creating a BackendResponse.
    Then:
        Response indicates success with no errors.
    """
    response = BackendResponse(success=True)
    assert response.success is True
    assert response.error_type is None
    assert response.error_message is None


def test_backend_response_failure():
    """
    Given:
        Failure parameters with error details.
    When:
        Creating a BackendResponse.
    Then:
        Response contains error type and message.
    """
    response = BackendResponse(
        success=False,
        error_type=BackendErrorType.USER_NOT_FOUND,
        error_message="User does not exist"
    )
    assert response.success is False
    assert response.error_type == BackendErrorType.USER_NOT_FOUND
    assert response.error_message == "User does not exist"


# ============================================================================
# Test AssistantStatus
# ============================================================================


def test_assistant_status_is_awaiting_user_action():
    """
    Given:
        Different status values.
    When:
        Checking if status is awaiting user action.
    Then:
        Returns True only for agent selection and approval statuses.
    """
    assert AssistantStatus.is_awaiting_user_action(AssistantStatus.AWAITING_AGENT_SELECTION.value) is True
    assert AssistantStatus.is_awaiting_user_action(AssistantStatus.AWAITING_SENSITIVE_ACTION_APPROVAL.value) is True
    assert AssistantStatus.is_awaiting_user_action(AssistantStatus.AWAITING_BACKEND_RESPONSE.value) is False
    assert AssistantStatus.is_awaiting_user_action(AssistantStatus.RESPONDING_WITH_PLAN.value) is False


def test_assistant_status_get_timeout():
    """
    Given:
        Different status values.
    When:
        Getting timeout for each status.
    Then:
        Returns correct timeout duration in seconds.
    """
    assert AssistantStatus.get_timeout_for_status(AssistantStatus.AWAITING_BACKEND_RESPONSE.value) == 60
    assert AssistantStatus.get_timeout_for_status(AssistantStatus.RESPONDING_WITH_PLAN.value) == 300
    assert AssistantStatus.get_timeout_for_status(AssistantStatus.AWAITING_AGENT_SELECTION.value) == 604800
    assert AssistantStatus.get_timeout_for_status(AssistantStatus.AWAITING_SENSITIVE_ACTION_APPROVAL.value) == 1209600
    assert AssistantStatus.get_timeout_for_status("invalid") == 0


def test_assistant_status_is_expired():
    """
    Given:
        Status and last_updated timestamp.
    When:
        Checking if conversation is expired.
    Then:
        Returns True if time elapsed exceeds timeout.
    """
    current_time = datetime.now(UTC).timestamp()
    
    # Not expired - updated 30 seconds ago
    last_updated = current_time - 30
    assert AssistantStatus.is_expired(AssistantStatus.AWAITING_BACKEND_RESPONSE.value, last_updated) is False
    
    # Expired - updated 2 minutes ago (timeout is 1 minute)
    last_updated = current_time - 120
    assert AssistantStatus.is_expired(AssistantStatus.AWAITING_BACKEND_RESPONSE.value, last_updated) is True


# ============================================================================
# Test AssistantMessageType
# ============================================================================


def test_assistant_message_type_is_model_type():
    """
    Given:
        Different message types.
    When:
        Checking if message type is a model type.
    Then:
        Returns True for model, clarification, copilot, script, and approval types.
    """
    assert AssistantMessageType.is_model_type(AssistantMessageType.MODEL.value) is True
    assert AssistantMessageType.is_model_type(AssistantMessageType.CLARIFICATION.value) is True
    assert AssistantMessageType.is_model_type(AssistantMessageType.APPROVAL.value) is True
    assert AssistantMessageType.is_model_type(AssistantMessageType.STEP.value) is False
    assert AssistantMessageType.is_model_type(AssistantMessageType.ERROR.value) is False


def test_assistant_message_type_is_step_type():
    """
    Given:
        Different message types.
    When:
        Checking if message type is a step type.
    Then:
        Returns True for step and thought types.
    """
    assert AssistantMessageType.is_step_type(AssistantMessageType.STEP.value) is True
    assert AssistantMessageType.is_step_type(AssistantMessageType.THOUGHT.value) is True
    assert AssistantMessageType.is_step_type(AssistantMessageType.MODEL.value) is False


def test_assistant_message_type_is_approval_type():
    """
    Given:
        Different message types.
    When:
        Checking if message type requires approval.
    Then:
        Returns True only for approval type.
    """
    assert AssistantMessageType.is_approval_type(AssistantMessageType.APPROVAL.value) is True
    assert AssistantMessageType.is_approval_type(AssistantMessageType.MODEL.value) is False


def test_assistant_message_type_is_error_type():
    """
    Given:
        Different message types.
    When:
        Checking if message type is an error.
    Then:
        Returns True only for error type.
    """
    assert AssistantMessageType.is_error_type(AssistantMessageType.ERROR.value) is True
    assert AssistantMessageType.is_error_type(AssistantMessageType.MODEL.value) is False


# ============================================================================
# Test AssistantMessagingHandler
# ============================================================================


def test_cleanup_expired_conversations_empty():
    """
    Given:
        Empty assistant context.
    When:
        Cleaning up expired conversations.
    Then:
        Returns empty dictionary.
    """
    handler = MockMessagingHandler()
    result = handler.delete_expired_conversations({})
    assert result == {}


def test_cleanup_expired_conversations_removes_expired():
    """
    Given:
        Assistant context with expired and active conversations.
    When:
        Cleaning up expired conversations.
    Then:
        Removes only expired conversations.
    """
    handler = MockMessagingHandler()
    current_time = datetime.now(UTC).timestamp()
    
    assistant = {
        "expired": {
            "status": AssistantStatus.AWAITING_BACKEND_RESPONSE.value,
            "last_updated": current_time - 120  # 2 minutes ago (timeout is 1 min)
        },
        "active": {
            "status": AssistantStatus.AWAITING_BACKEND_RESPONSE.value,
            "last_updated": current_time - 30  # 30 seconds ago
        }
    }
    
    result = handler.delete_expired_conversations(assistant)
    assert "expired" not in result
    assert "active" in result


def test_handle_backend_response_success(mocker: MockerFixture):
    """
    Given:
        Successful backend response.
    When:
        Handling backend response.
    Then:
        Returns BackendResponse with success=True.
    """
    mocker.patch.object(demisto, "debug")
    handler = MockMessagingHandler()
    
    response = {"success": True}
    result = handler.handle_backend_response(response, "test_operation")
    
    assert result.success is True
    assert result.error_type is None


@pytest.mark.parametrize("error_code,expected_type", [
    (BackendErrorCode.LLM_NOT_ENABLED, BackendErrorType.LLM_NOT_ENABLED),
    (BackendErrorCode.USER_NOT_FOUND, BackendErrorType.USER_NOT_FOUND),
    (BackendErrorCode.PERMISSION_DENIED, BackendErrorType.PERMISSION_DENIED),
    (BackendErrorCode.CONVERSATION_NOT_FOUND, BackendErrorType.CONVERSATION_NOT_FOUND),
    (BackendErrorCode.WRONG_USER, BackendErrorType.WRONG_USER),
])
def test_handle_backend_response_errors(mocker: MockerFixture, error_code, expected_type):
    """
    Given:
        Backend response with specific error code.
    When:
        Handling backend response.
    Then:
        Returns BackendResponse with correct error type.
    """
    mocker.patch.object(demisto, "debug")
    mocker.patch.object(demisto, "error")
    handler = MockMessagingHandler()
    
    response = {"error_code": error_code, "error": "Test error"}
    result = handler.handle_backend_response(response, "test_operation")
    
    assert result.success is False
    assert result.error_type == expected_type


def test_format_context_messages_empty():
    """
    Given:
        Empty message list.
    When:
        Formatting context messages.
    Then:
        Returns empty string.
    """
    handler = MockMessagingHandler()
    result = handler.format_context_messages([])
    assert result == ""


def test_format_context_messages_multiple():
    """
    Given:
        Multiple context messages.
    When:
        Formatting context messages.
    Then:
        Returns formatted string with context headers and messages in reverse order.
    """
    handler = MockMessagingHandler()
    messages = [
        {"user": "Alice", "text": "Hello"},
        {"user": "Bob", "text": "Hi there"}
    ]
    result = handler.format_context_messages(messages)
    
    assert AssistantMessages.CONTEXT_START in result
    assert AssistantMessages.CONTEXT_END in result
    assert "**Alice**: Hello" in result
    assert "**Bob**: Hi there" in result


@pytest.mark.asyncio
async def test_submit_feedback_positive(mocker: MockerFixture):
    """
    Given:
        Positive feedback parameters.
    When:
        Submitting feedback to backend.
    Then:
        Calls agentixCommands with is_liked=True.
    """
    handler = MockMessagingHandler()
    mocker.patch.object(demisto, "agentixCommands", return_value={"success": True})
    
    result = await handler.submit_feedback(
        message_id="msg123",
        is_positive=True,
        thread_id="thread123",
        channel_id="channel123",
        username="user@example.com"
    )
    
    assert result.success is True
    call_args = demisto.agentixCommands.call_args[0]
    assert call_args[0] == "rateMessage"
    assert call_args[1]["is_liked"] is True


@pytest.mark.asyncio
async def test_handle_reset_session_not_reset_command(mocker: MockerFixture):
    """
    Given:
        Message that is not a reset command.
    When:
        Handling reset session.
    Then:
        Returns False and unchanged assistant context.
    """
    handler = MockMessagingHandler()
    
    is_reset, assistant = await handler.handle_reset_session(
        text="<@BOT123> hello",
        user_id="user123",
        channel_id="channel123",
        thread_id="thread123",
        assistant={},
        assistant_id_key="conv1",
        bot_id="BOT123",
        user_email="user@example.com"
    )
    
    assert is_reset is False


@pytest.mark.asyncio
async def test_handle_reset_session_agent_selection(mocker: MockerFixture):
    """
    Given:
        Reset command during agent selection status.
    When:
        Handling reset session.
    Then:
        Removes conversation from context and sends success message.
    """
    handler = MockMessagingHandler()
    assistant = {
        "conv1": {
            "status": AssistantStatus.AWAITING_AGENT_SELECTION.value,
            "user": "user123"
        }
    }
    
    is_reset, result_assistant = await handler.handle_reset_session(
        text="<@BOT123> !reset",
        user_id="user123",
        channel_id="channel123",
        thread_id="thread123",
        assistant=assistant,
        assistant_id_key="conv1",
        bot_id="BOT123",
        user_email="user@example.com"
    )
    
    assert is_reset is True
    assert "conv1" not in result_assistant
    assert len(handler.sent_messages) == 1
    assert AssistantMessages.RESET_SESSION_SUCCESS in handler.sent_messages[0]["message"]


@pytest.mark.asyncio
async def test_handle_reset_session_processing(mocker: MockerFixture):
    """
    Given:
        Reset command while processing.
    When:
        Handling reset session.
    Then:
        Keeps conversation and sends cannot reset message.
    """
    handler = MockMessagingHandler()
    assistant = {
        "conv1": {
            "status": AssistantStatus.AWAITING_BACKEND_RESPONSE.value,
            "user": "user123"
        }
    }
    
    is_reset, result_assistant = await handler.handle_reset_session(
        text="<@BOT123> !reset",
        user_id="user123",
        channel_id="channel123",
        thread_id="thread123",
        assistant=assistant,
        assistant_id_key="conv1",
        bot_id="BOT123",
        user_email="user@example.com"
    )
    
    assert is_reset is True
    assert "conv1" in result_assistant
    assert AssistantMessages.RESET_SESSION_CANNOT_RESET_PROCESSING in handler.sent_messages[0]["message"]


def test_send_agent_response_invalid_message_type(mocker: MockerFixture):
    """
    Given:
        Invalid response_type in messages list.
    When:
        Sending agent response.
    Then:
        Raises ValueError.
    """
    handler = MockMessagingHandler()

    with pytest.raises(ValueError) as exc_info:
        handler.send_agent_response(
            channel_id="channel123",
            thread_id="thread123",
            messages=[{"content": "Test", "response_type": "invalid_type", "is_final": False}],
            assistant_context={},
            assistant_id_key="conv1",
        )

    assert "Invalid response_type" in str(exc_info.value)


def test_send_agent_response_model_completed(mocker: MockerFixture):
    """
    Given:
        Model message with is_final=True.
    When:
        Sending agent response.
    Then:
        Releases lock by removing conversation from context.
    """
    mocker.patch.object(demisto, "debug")
    mocker.patch.object(demisto, "results")
    handler = MockMessagingHandler()
    assistant = {"conv1": {"status": "awaiting_backend_response"}}

    result = handler.send_agent_response(
        channel_id="channel123",
        thread_id="thread123",
        messages=[{"content": "Answer", "response_type": AssistantMessageType.MODEL.value, "is_final": True}],
        assistant_context=assistant,
        assistant_id_key="conv1",
    )

    assert "conv1" not in result


def test_send_agent_response_approval_type(mocker: MockerFixture):
    """
    Given:
        Approval message type.
    When:
        Sending agent response.
    Then:
        Updates status to awaiting sensitive action approval.
    """
    mocker.patch.object(demisto, "debug")
    mocker.patch.object(demisto, "results")
    handler = MockMessagingHandler()
    assistant = {"conv1": {}}

    result = handler.send_agent_response(
        channel_id="channel123",
        thread_id="thread123",
        messages=[{"content": "Approve?", "response_type": AssistantMessageType.APPROVAL.value, "is_final": False}],
        assistant_context=assistant,
        assistant_id_key="conv1",
    )

    assert result["conv1"]["status"] == AssistantStatus.AWAITING_SENSITIVE_ACTION_APPROVAL.value


def test_send_agent_response_error_releases_lock(mocker: MockerFixture):
    """
    Given:
        Error message type.
    When:
        Sending agent response.
    Then:
        Immediately releases lock.
    """
    mocker.patch.object(demisto, "debug")
    mocker.patch.object(demisto, "results")
    handler = MockMessagingHandler()
    assistant = {"conv1": {"status": "awaiting_backend_response"}}

    result = handler.send_agent_response(
        channel_id="channel123",
        thread_id="thread123",
        messages=[{"content": "Error occurred", "response_type": AssistantMessageType.ERROR.value, "is_final": True}],
        assistant_context=assistant,
        assistant_id_key="conv1",
    )

    assert "conv1" not in result


def test_send_agent_response_error_adds_user_mention(mocker: MockerFixture):
    """
    Given:
    	Error message type with a user_id provided.
    When:
    	Sending agent response.
    Then:
    	Inserts a user mention block at the beginning of the blocks list.
    """
    mocker.patch.object(demisto, "debug")
    mocker.patch.object(demisto, "results")
    handler = MockMessagingHandler()
    assistant = {"conv1": {"status": "awaiting_backend_response"}}

    handler.send_agent_response(
        channel_id="channel123",
        thread_id="thread123",
        messages=[{"content": "Request can't be processed at the moment", "response_type": AssistantMessageType.ERROR.value, "is_final": True}],
        assistant_context=assistant,
        assistant_id_key="conv1",
        user_id="U123",
    )

    assert handler.last_posted_blocks[0] == {
        "type": "section",
        "text": {"type": "mrkdwn", "text": "<@U123>"},
    }


def test_send_agent_response_deletes_thinking_indicator(mocker: MockerFixture):
    """
    Given:
        Assistant context with thinking_message_id.
    When:
        Sending agent response.
    Then:
        Deletes thinking indicator message.
    """
    mocker.patch.object(demisto, "debug")
    mocker.patch.object(demisto, "results")
    handler = MockMessagingHandler()
    assistant = {"conv1": {"thinking_message_id": "1234567890.123456"}}

    handler.send_agent_response(
        channel_id="channel123",
        thread_id="thread123",
        messages=[{"content": "Response", "response_type": AssistantMessageType.MODEL.value, "is_final": True}],
        assistant_context=assistant,
        assistant_id_key="conv1",
    )

    assert len(handler.deleted_messages) == 1
    assert handler.deleted_messages[0]["message_id"] == "1234567890.123456"


def test_send_agent_response_model_adds_user_mention(mocker: MockerFixture):
    """
    Given:
        Model message type with a user_id provided.
    When:
        Sending agent response.
    Then:
        Inserts a user mention block at the beginning of the blocks list.
    """
    mocker.patch.object(demisto, "debug")
    mocker.patch.object(demisto, "results")
    handler = MockMessagingHandler()
    assistant = {"conv1": {"status": "awaiting_backend_response"}}

    handler.send_agent_response(
        channel_id="channel123",
        thread_id="thread123",
        messages=[{"content": "Answer", "response_type": AssistantMessageType.MODEL.value, "is_final": True}],
        assistant_context=assistant,
        assistant_id_key="conv1",
        user_id="U123",
    )

    assert handler.last_posted_blocks[0] == {
        "type": "section",
        "text": {"type": "mrkdwn", "text": "<@U123>"},
    }


def test_send_agent_response_step_no_user_mention(mocker: MockerFixture):
    """
    Given:
        Step message type with a user_id provided.
    When:
        Sending agent response.
    Then:
        Does not insert a user mention block (only model types get mentions).
    """
    mocker.patch.object(demisto, "debug")
    mocker.patch.object(demisto, "results")
    handler = MockMessagingHandler()
    assistant = {"conv1": {"status": "awaiting_backend_response"}}

    handler.send_agent_response(
        channel_id="channel123",
        thread_id="thread123",
        messages=[{"content": "Step 1", "response_type": AssistantMessageType.STEP.value, "is_final": False}],
        assistant_context=assistant,
        assistant_id_key="conv1",
        user_id="U123",
    )

    # Step types use prepare_merged_step_blocks, not prepare_message_blocks
    # The merged_steps block should not contain user mention
    for block in handler.last_posted_blocks:
        assert block.get("text", {}).get("text") != "<@U123>"


def test_group_messages_by_type_consecutive_steps_merged():
    """
    Given:
        Messages list with consecutive step-type messages.
    When:
        Grouping messages by type.
    Then:
        Consecutive step messages are grouped together.
    """
    messages = [
        {"content": "Step 1", "response_type": "step", "is_final": False},
        {"content": "Step 2", "response_type": "thought", "is_final": False},
        {"content": "Final answer", "response_type": "model", "is_final": True},
    ]

    groups = AssistantMessagingHandler._group_messages_by_type(messages)

    assert len(groups) == 2
    assert len(groups[0]) == 2  # step + thought merged
    assert groups[0][0]["response_type"] == "step"
    assert groups[0][1]["response_type"] == "thought"
    assert len(groups[1]) == 1  # model separate
    assert groups[1][0]["response_type"] == "model"


def test_group_messages_by_type_mixed_types_separate():
    """
    Given:
        Messages list with alternating step and non-step types.
    When:
        Grouping messages by type.
    Then:
        Non-step types are kept as individual groups.
    """
    messages = [
        {"content": "Step 1", "response_type": "step", "is_final": False},
        {"content": "Approval needed", "response_type": "approval", "is_final": False},
        {"content": "Step 2", "response_type": "step", "is_final": False},
    ]

    groups = AssistantMessagingHandler._group_messages_by_type(messages)

    assert len(groups) == 3
    assert len(groups[0]) == 1
    assert len(groups[1]) == 1
    assert len(groups[2]) == 1


def test_send_agent_response_merges_consecutive_steps(mocker: MockerFixture):
    """
    Given:
        Messages list with two consecutive step messages followed by a model message.
    When:
        Sending agent response.
    Then:
        Step messages are merged into one post, model is sent separately.
    """
    mocker.patch.object(demisto, "debug")
    mocker.patch.object(demisto, "results")
    handler = MockMessagingHandler()
    handler.posted_calls = []
    original_post = handler.post_agent_response

    def tracking_post(*args, **kwargs):
        result = original_post(*args, **kwargs)
        handler.posted_calls.append({"blocks": args[2] if len(args) > 2 else kwargs.get("blocks", [])})
        return result

    handler.post_agent_response = tracking_post
    assistant = {"conv1": {"status": "awaiting_backend_response"}}

    handler.send_agent_response(
        channel_id="channel123",
        thread_id="thread123",
        messages=[
            {"content": "Retrieving cases", "response_type": "step", "is_final": False},
            {"content": "Processing data", "response_type": "step", "is_final": False},
            {"content": "Here are the results", "response_type": "model", "is_final": True, "message_id": "msg1"},
        ],
        assistant_context=assistant,
        assistant_id_key="conv1",
    )

    # Should have 2 posts: one merged step, one model
    assert len(handler.posted_calls) == 2


def test_send_agent_response_completed_derived_from_is_final(mocker: MockerFixture):
    """
    Given:
        Messages list where last message has is_final=True.
    When:
        Sending agent response.
    Then:
        Completed is derived from last message's is_final and lock is released.
    """
    mocker.patch.object(demisto, "debug")
    mocker.patch.object(demisto, "results")
    handler = MockMessagingHandler()
    assistant = {"conv1": {"status": "awaiting_backend_response"}}

    result = handler.send_agent_response(
        channel_id="channel123",
        thread_id="thread123",
        messages=[
            {"content": "Step 1", "response_type": "step", "is_final": False},
            {"content": "Done", "response_type": "model", "is_final": True},
        ],
        assistant_context=assistant,
        assistant_id_key="conv1",
    )

    assert "conv1" not in result


def test_backend_response_includes_error_code(mocker):
    """
    Given:
        Backend response with error_code.
    When:
        Handling backend response.
    Then:
        BackendResponse includes error_code field.
    """
    mocker.patch.object(demisto, "error")
    handler = MockMessagingHandler()
    
    response = {"error_code": 999, "error": "Unknown error"}
    result = handler.handle_backend_response(response, "test_operation")
    
    assert result.success is False
    assert result.error_code == 999
    assert result.error_type == BackendErrorType.UNKNOWN


def test_send_agent_response_approval_final_has_no_feedback(mocker: MockerFixture):
    """
    Given:
        An approval (sensitive action) message that is also is_final=True.
    When:
        Sending agent response.
    Then:
        No feedback (like/dislike) buttons are attached to the approval message.
    """
    mocker.patch.object(demisto, "debug")
    mocker.patch.object(demisto, "results")
    handler = MockMessagingHandler()
    assistant = {"conv1": {"status": AssistantStatus.AWAITING_BACKEND_RESPONSE.value}}

    handler.send_agent_response(
        channel_id="channel123",
        thread_id="thread123",
        messages=[
            {"content": "Delete all the things?", "response_type": AssistantMessageType.APPROVAL.value,
             "is_final": True, "message_id": "appr-1"},
        ],
        assistant_context=assistant,
        assistant_id_key="conv1",
    )

    assert _feedback_message_ids(handler) == []


@pytest.mark.asyncio
async def test_sensitive_action_approval_appends_decision_indicator(mocker: MockerFixture):
    """
    Given:
    	A successful sensitive action approval whose original message blocks are content → actions.
    When:
    	The approval action is handled.
    Then:
    	The approve/reject actions block is removed and the decision indicator is appended at the end.
    	Approval messages have no feedback buttons.
    """
    mocker.patch.object(demisto, "debug")
    mocker.patch.object(demisto, "agentixCommands", return_value={"success": True})

    handler = MockMessagingHandler()
    assistant = {
        "conv1": {
            "user": "U123",
            "status": AssistantStatus.AWAITING_SENSITIVE_ACTION_APPROVAL.value,
            "last_updated": datetime.now(UTC).timestamp(),
        }
    }

    # Simulate original message blocks: content → actions (approve/reject)
    message = {
        "ts": "msg_ts",
        "blocks": [
            {"type": "section", "text": {"type": "mrkdwn", "text": "Sensitive action details"}},
            {"type": "actions", "elements": [{"type": "button", "text": {"type": "plain_text", "text": "Proceed"}}]},
        ],
    }

    await handler._handle_action_sensitive_action_approval(
        action_id=AssistantActionIds.APPROVAL_YES.value,
        user_id="U123",
        user_email="user@example.com",
        channel_id="C123",
        thread_id="T123",
        message=message,
        message_id="msg_ts",
        assistant=assistant,
        assistant_id_key="conv1",
        locked_user="U123",
    )

    # Verify the update_message was called with the actions block removed and the
    # decision indicator appended: [content, decision_indicator]
    updated = handler.updated_messages[0]
    blocks = updated["blocks"]

    assert len(blocks) == 2
    assert blocks[0]["type"] == "section"  # content
    assert blocks[1]["type"] == "context"  # decision indicator (appended last)
    assert blocks[1]["elements"][0]["text"] == AssistantMessages.DECISION_APPROVED
    # No actions/feedback blocks remain
    assert all(block["type"] != "actions" for block in blocks)


# ============================================================================
# Test ignored message_id filtering and feedback button placement
# ============================================================================


def test_send_agent_response_no_feedback_on_intermediate_batch(mocker: MockerFixture):
    """
    Given:
        A batch of intermediate "thinking" model messages (all is_final=False) followed by a
        step message - i.e. the response is not complete yet.
    When:
        Sending agent response.
    Then:
        No feedback buttons are attached to any message, because feedback is only shown once the
        response is complete.
    """
    mocker.patch.object(demisto, "debug")
    mocker.patch.object(demisto, "results")
    handler = MockMessagingHandler()
    assistant = {"conv1": {"status": AssistantStatus.AWAITING_BACKEND_RESPONSE.value}}

    result = handler.send_agent_response(
        channel_id="C0BU9JDMTC5",
        thread_id="1789559349.493479",
        messages=[
            {"content": "First thinking step", "response_type": AssistantMessageType.MODEL.value,
             "is_final": False, "message_id": "lc_run--1"},
            {"content": "Second thinking step", "response_type": AssistantMessageType.MODEL.value,
             "is_final": False, "message_id": "lc_run--2"},
            {"content": "Plan updated (3 steps)", "response_type": AssistantMessageType.STEP.value,
             "is_final": False, "message_id": "plan_updated"},
        ],
        assistant_context=assistant,
        assistant_id_key="conv1",
    )

    assert _feedback_message_ids(handler) == []
    # Response not complete - conversation lock is kept
    assert "conv1" in result


def _feedback_message_ids(handler: MockMessagingHandler) -> list:
    """Collect the message_ids of all feedback blocks that were posted."""
    ids = []
    for posted in handler.posted_responses:
        for block in posted["blocks"]:
            if block.get("type") == "feedback":
                ids.append(block["message_id"])
    return ids


def test_send_agent_response_ignores_configured_message_ids(mocker: MockerFixture):
    """
    Given:
        Step messages whose message_id is in IGNORED_MESSAGE_IDS (agent_selected, artifact_created).
    When:
        Sending agent response.
    Then:
        Those messages are dropped and never posted to the platform.
    """
    mocker.patch.object(demisto, "debug")
    mocker.patch.object(demisto, "results")
    handler = MockMessagingHandler()

    handler.send_agent_response(
        channel_id="channel123",
        thread_id="thread123",
        messages=[
            {"content": "agent selected", "response_type": AssistantMessageType.STEP.value,
             "is_final": False, "message_id": "agent_selected"},
            {"content": "Created artifact CortexListIssues", "response_type": AssistantMessageType.STEP.value,
             "is_final": False, "message_id": "artifact_created"},
        ],
        assistant_context={},
        assistant_id_key="conv1",
    )

    assert handler.posted_responses == []


def test_send_agent_response_ignored_messages_still_mark_completion(mocker: MockerFixture):
    """
    Given:
        A model message followed by an ignored step message that carries is_final=True.
    When:
        Sending agent response.
    Then:
        The ignored message is not posted, but completion is still derived from it and the lock is released.
    """
    mocker.patch.object(demisto, "debug")
    mocker.patch.object(demisto, "results")
    handler = MockMessagingHandler()
    assistant = {"conv1": {"status": "awaiting_backend_response"}}

    result = handler.send_agent_response(
        channel_id="channel123",
        thread_id="thread123",
        messages=[
            {"content": "The answer", "response_type": AssistantMessageType.MODEL.value,
             "is_final": False, "message_id": "lc_run--abc"},
            {"content": "agent selected", "response_type": AssistantMessageType.STEP.value,
             "is_final": True, "message_id": "agent_selected"},
        ],
        assistant_context=assistant,
        assistant_id_key="conv1",
    )

    posted_ids = _feedback_message_ids(handler)
    assert posted_ids == ["lc_run--abc"]
    assert "conv1" not in result


def test_send_agent_response_feedback_only_on_last_nonempty_model(mocker: MockerFixture):
    """
    Given:
        Multiple model messages where the last one has empty content but is_final=True.
    When:
        Sending agent response.
    Then:
        Feedback buttons are attached only to the last non-empty model message, and the empty
        final message is not posted.
    """
    mocker.patch.object(demisto, "debug")
    mocker.patch.object(demisto, "results")
    handler = MockMessagingHandler()
    assistant = {"conv1": {"status": "awaiting_backend_response"}}

    result = handler.send_agent_response(
        channel_id="channel123",
        thread_id="thread123",
        messages=[
            {"content": "First model msg", "response_type": AssistantMessageType.MODEL.value,
             "is_final": False, "message_id": "lc_run--1"},
            {"content": "Final answer with the table", "response_type": AssistantMessageType.MODEL.value,
             "is_final": False, "message_id": "lc_run--2"},
            {"content": "", "response_type": AssistantMessageType.MODEL.value,
             "is_final": True, "message_id": "model"},
        ],
        assistant_context=assistant,
        assistant_id_key="conv1",
    )

    posted_ids = _feedback_message_ids(handler)
    assert posted_ids == ["lc_run--2"]
    # Empty final message must not be posted (only two model messages sent)
    assert len(handler.posted_responses) == 2
    assert "conv1" not in result


def test_get_feedback_message_id_no_model_messages():
    """
    Given:
        Only step-type messages.
    When:
        Determining the feedback message id.
    Then:
        Returns an empty string since no model message qualifies.
    """
    handler = MockMessagingHandler()
    messages = [
        {"content": "step 1", "response_type": AssistantMessageType.STEP.value, "message_id": "s1"},
        {"content": "step 2", "response_type": AssistantMessageType.STEP.value, "message_id": "s2"},
    ]
    assert handler._get_feedback_message_id(messages) == ""


def test_send_agent_response_ignores_echoed_user_message(mocker: MockerFixture):
    """
    Given:
        A response whose first message is the user's own message echoed back by the backend,
        identified by the source-chat context marker prefix, followed by real model responses
        and an empty final message.
    When:
        Sending agent response.
    Then:
        The echoed user message is not posted, the real answer is, feedback goes on the last
        non-empty model message, and the lock is released.
    """
    mocker.patch.object(demisto, "debug")
    mocker.patch.object(demisto, "results")
    handler = MockMessagingHandler()
    assistant = {"conv1": {"status": AssistantStatus.RESPONDING_WITH_PLAN.value}}

    echoed_user_content = (
        "--- Source chat context ---\n"
        "The following chat session metadata is automatically attached.\n"
        "This chat was initiated from Slack.\n"
        "channel_id: C0BU9JDMTC5\n"
        "thread_id: 1789027287.010439\n"
        "--- End of source chat context ---\n\n Create War Room Entry"
    )

    result = handler.send_agent_response(
        channel_id="C0BU9JDMTC5",
        thread_id="1789027287.010439",
        messages=[
            {"content": echoed_user_content, "response_type": AssistantMessageType.MODEL.value,
             "is_final": False, "message_id": "a6eb4e1f-257b-41a6-903a-16b5356beb13"},
            {"content": "Searching the knowledge base.", "response_type": AssistantMessageType.MODEL.value,
             "is_final": False, "message_id": "lc_run--1"},
            {"content": "Which Case ID would you like to link?", "response_type": AssistantMessageType.MODEL.value,
             "is_final": False, "message_id": "lc_run--final"},
            {"content": "", "response_type": AssistantMessageType.MODEL.value,
             "is_final": True, "message_id": "model"},
        ],
        assistant_context=assistant,
        assistant_id_key="conv1",
    )

    # Only the two real model messages are posted (echo + empty final are dropped)
    assert len(handler.posted_responses) == 2
    assert _feedback_message_ids(handler) == ["lc_run--final"]
    assert "conv1" not in result


def test_is_echoed_user_message_detects_marker():
    """
    Given:
        Messages with and without the source-chat context marker prefix.
    When:
        Checking whether they are echoed user messages.
    Then:
        Only the one starting with the marker is detected as an echo.
    """
    handler = MockMessagingHandler()
    assert handler._is_echoed_user_message(
        {"content": "--- Source chat context ---\nfoo\nCreate War Room Entry"}
    ) is True
    assert handler._is_echoed_user_message(
        {
            "content": (
                "--- Previous chat context ---\n"
                "**Test User**: Create War Room Entry in issue 5 with the details\n"
                "--- End of context ---\n\n**Current message**:"
            )
        }
    ) is True
    assert handler._is_echoed_user_message({"content": "A normal model answer"}) is False
    assert handler._is_echoed_user_message({"content": ""}) is False


def test_send_agent_response_empty_final_message_releases_lock(mocker: MockerFixture):
    """
    Given:
        A sequence of model messages ending with an empty message that has is_final=True
        (the backend's completion signal).
    When:
        Sending agent response.
    Then:
        The lock is released even though the empty final message is never posted, and feedback
        buttons are attached only to the last non-empty model message.
    """
    mocker.patch.object(demisto, "debug")
    mocker.patch.object(demisto, "results")
    handler = MockMessagingHandler()
    assistant = {"conv1": {"status": AssistantStatus.RESPONDING_WITH_PLAN.value}}

    result = handler.send_agent_response(
        channel_id="C0BU9JDMTC5",
        thread_id="1788962266.139879",
        messages=[
            {"content": "Intermediate step", "response_type": AssistantMessageType.MODEL.value,
             "is_final": False, "message_id": "lc_run--1"},
            {"content": "Final answer with the table", "response_type": AssistantMessageType.MODEL.value,
             "is_final": False, "message_id": "lc_run--final"},
            {"content": "", "response_type": AssistantMessageType.MODEL.value,
             "is_final": True, "message_id": "model"},
        ],
        assistant_context=assistant,
        assistant_id_key="conv1",
    )

    assert "conv1" not in result
    assert _feedback_message_ids(handler) == ["lc_run--final"]


def test_send_agent_response_approval_final_keeps_lock(mocker: MockerFixture):
    """
    Given:
        An approval message that is also marked is_final=True.
    When:
        Sending agent response.
    Then:
        The lock is kept and status is set to awaiting sensitive action approval.
    """
    mocker.patch.object(demisto, "debug")
    mocker.patch.object(demisto, "results")
    handler = MockMessagingHandler()
    assistant = {"conv1": {"status": AssistantStatus.AWAITING_BACKEND_RESPONSE.value}}

    result = handler.send_agent_response(
        channel_id="channel123",
        thread_id="thread123",
        messages=[
            {"content": "Approve?", "response_type": AssistantMessageType.APPROVAL.value,
             "is_final": True, "message_id": "appr-1"},
        ],
        assistant_context=assistant,
        assistant_id_key="conv1",
    )

    assert "conv1" in result
    assert result["conv1"]["status"] == AssistantStatus.AWAITING_SENSITIVE_ACTION_APPROVAL.value


def test_ignored_message_ids_contains_expected_values():
    """
    Given:
        The IGNORED_MESSAGE_IDS constant.
    When:
        Inspecting its contents.
    Then:
        It contains the known internal step notification ids.
    """
    assert "agent_selected" in IGNORED_MESSAGE_IDS
    assert "artifact_created" in IGNORED_MESSAGE_IDS
    assert "action_execute_failed" in IGNORED_MESSAGE_IDS
