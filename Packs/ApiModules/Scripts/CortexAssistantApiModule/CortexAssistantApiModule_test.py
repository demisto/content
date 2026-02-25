import pytest
from datetime import datetime, UTC

from pytest_mock import MockerFixture
import demistomock as demisto
from CortexAssistantApiModule import (
    BackendErrorType,
    BackendResponse,
    AssistantStatus,
    AssistantMessageType,
    AssistantActionIds,
    AssistantMessages,
    AssistantMessagingHandler,
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

    async def send_message_async(self, channel_id: str, message: str, thread_id: str = "",
                                  blocks: list | None = None, attachments: list | None = None,
                                  ephemeral: bool = False, user_id: str = ""):
        self.sent_messages.append({"channel_id": channel_id, "message": message, "ephemeral": ephemeral})
        return {"ts": "1234567890.123456"}

    async def update_message(self, channel_id: str, message_ts: str, text: str = "", blocks: list | None = None):
        self.updated_messages.append({"channel_id": channel_id, "message_ts": message_ts, "text": text})

    def delete_message_sync(self, channel_id: str, message_ts: str):
        self.deleted_messages.append({"channel_id": channel_id, "message_ts": message_ts})

    async def get_user_info(self, user_id: str) -> dict:
        return {"id": user_id, "email": "test@example.com"}

    async def get_thread_history(self, channel_id: str, thread_id: str, limit: int = 20) -> list:
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
        return {"type": "actions"}

    def post_agent_response_sync(self, channel_id: str, thread_id: str, blocks: list,
                                  attachments: list, agent_name: str = "") -> dict | None:
        self.last_posted_blocks = blocks
        return {"ts": "1234567890.123456"}

    def update_existing_message(self, channel_id: str, thread_id: str, message_ts: str,
                                attachments: list) -> bool:
        return True

    def finalize_plan_header(self, channel_id: str, thread_id: str, step_message_ts: str):
        pass

    def update_context(self, context_updates: dict):
        pass

    async def open_feedback_modal(self, trigger_id: str, message_id: str, channel_id: str, thread_id: str):
        pass

    async def get_conversation_context_formatted(self, channel_id: str, thread_id: str,
                                                  bot_id: str, current_message_ts: str) -> str:
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
    result = handler.cleanup_expired_conversations({})
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
    
    result = handler.cleanup_expired_conversations(assistant)
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
    (103000, BackendErrorType.LLM_NOT_ENABLED),
    (103102, BackendErrorType.USER_NOT_FOUND),
    (103103, BackendErrorType.PERMISSION_DENIED),
    (103201, BackendErrorType.CONVERSATION_NOT_FOUND),
    (103204, BackendErrorType.WRONG_USER),
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


def test_send_agent_response_deletes_thinking_indicator(mocker: MockerFixture):
    """
    Given:
        Assistant context with thinking_message_ts.
    When:
        Sending agent response.
    Then:
        Deletes thinking indicator message.
    """
    mocker.patch.object(demisto, "debug")
    mocker.patch.object(demisto, "results")
    handler = MockMessagingHandler()
    assistant = {"conv1": {"thinking_message_ts": "1234567890.123456"}}

    handler.send_agent_response(
        channel_id="channel123",
        thread_id="thread123",
        messages=[{"content": "Response", "response_type": AssistantMessageType.MODEL.value, "is_final": True}],
        assistant_context=assistant,
        assistant_id_key="conv1",
    )

    assert len(handler.deleted_messages) == 1
    assert handler.deleted_messages[0]["message_ts"] == "1234567890.123456"


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
    original_post = handler.post_agent_response_sync

    def tracking_post(*args, **kwargs):
        result = original_post(*args, **kwargs)
        handler.posted_calls.append({"blocks": args[2] if len(args) > 2 else kwargs.get("blocks", [])})
        return result

    handler.post_agent_response_sync = tracking_post
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
