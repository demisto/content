from typing import Optional
from enum import Enum
import demistomock as demisto
from CommonServerPython import *


# ============================================================================
# Enums - Status, Message Types, and Action IDs
# ============================================================================


class AssistantStatus(str, Enum):
    """
    Manages the status of Assistant AI interactions.

    Status flow:
    1. AWAITING_BACKEND_RESPONSE: User message sent to backend, waiting for AI response
    2. RESPONDING_WITH_PLAN: Currently responding back with plan steps
    3. AWAITING_AGENT_SELECTION: Sent list of available agents, waiting for user to select
    4. AWAITING_SENSITIVE_ACTION_APPROVAL: Sent sensitive action message, waiting for approval/rejection
    """

    AWAITING_BACKEND_RESPONSE = "awaiting_backend_response"
    RESPONDING_WITH_PLAN = "responding_with_plan"
    AWAITING_AGENT_SELECTION = "awaiting_agent_selection"
    AWAITING_SENSITIVE_ACTION_APPROVAL = "awaiting_sensitive_action_approval"

    @classmethod
    def is_awaiting_user_action(cls, status: str) -> bool:
        """
        Check if the status indicates we're waiting for user action.

        Args:
            status: The status to check

        Returns:
            True if waiting for user action, False otherwise
        """
        return status in {cls.AWAITING_AGENT_SELECTION.value, cls.AWAITING_SENSITIVE_ACTION_APPROVAL.value}

    @classmethod
    def get_timeout_for_status(cls, status: str) -> int:
        """
        Get the timeout duration for a given status.

        Args:
            status: The status to get timeout for

        Returns:
            Timeout duration in seconds, or 0 if status is invalid
        """
        timeouts = {
            cls.AWAITING_BACKEND_RESPONSE.value: 1 * 60,  # 1 minutes
            cls.RESPONDING_WITH_PLAN.value: 5 * 60,  # 5 minutes
            cls.AWAITING_AGENT_SELECTION.value: 7 * 24 * 60 * 60,  # 7 days
            cls.AWAITING_SENSITIVE_ACTION_APPROVAL.value: 14 * 24 * 60 * 60,  # 14 days
        }
        return timeouts.get(status, 0)

    @classmethod
    def is_expired(cls, status: str, last_updated: float) -> bool:
        """
        Check if a conversation has expired based on its status and last update time.

        Args:
            status: The conversation status
            last_updated: Unix timestamp of last update

        Returns:
            True if the conversation has expired, False otherwise
        """
        from datetime import datetime, UTC

        timeout = cls.get_timeout_for_status(status)
        if timeout == 0:
            return False

        current_time = datetime.now(UTC).timestamp()
        time_elapsed = current_time - last_updated

        return time_elapsed > timeout


class AssistantMessageType(str, Enum):
    """
    Message types for Assistant AI responses.

    Type mapping (from backend):
    - step: Step execution (function calls, actions)
    - model: Model/AI response (final text response)
    - error: Error message
    - user: User message
    - thought: AI thinking
    - approval: Approval request for sensitive actions
    - clarification: Clarification request
    - copilot: Copilot response
    - script: Script execution
    """

    # Message types from backend
    STEP = "step"
    MODEL = "model"
    ERROR = "error"
    USER = "user"
    THOUGHT = "thought"
    APPROVAL = "approval"
    CLARIFICATION = "clarification"
    COPILOT = "copilot"
    SCRIPT = "script"

    @classmethod
    def is_model_type(cls, message_type: str) -> bool:
        """Check if a message type is a model/final response type."""
        return message_type in {cls.MODEL.value, cls.CLARIFICATION.value, cls.COPILOT.value, cls.SCRIPT.value, cls.APPROVAL.value}

    @classmethod
    def is_step_type(cls, message_type: str) -> bool:
        """Check if a message type is a step type (step/thought)."""
        return message_type in {cls.STEP.value, cls.THOUGHT.value}

    @classmethod
    def is_approval_type(cls, message_type: str) -> bool:
        """Check if a message type requires approval."""
        return message_type == cls.APPROVAL.value

    @classmethod
    def is_error_type(cls, message_type: str) -> bool:
        """Check if a message type is an error."""
        return message_type == cls.ERROR.value


class AssistantActionIds(str, Enum):
    """
    Action IDs for Assistant interactive elements.
    """

    AGENT_SELECTION = "agent_selection"
    APPROVAL_YES = "yes_btn"
    APPROVAL_NO = "no_btn"
    FEEDBACK = "assistant_feedback"

    # Special constants (not enum values)
    AGENT_SELECTION_VALUE_PREFIX = "assistant-agent-selection-"
    FEEDBACK_MODAL_CALLBACK_ID = "assistant_feedback_modal"
    FEEDBACK_MODAL_QUICK_BLOCK_ID = "quick_feedback_block"
    FEEDBACK_MODAL_TEXT_BLOCK_ID = "feedback_text_block"
    FEEDBACK_MODAL_CHECKBOXES_ACTION_ID = "quick_feedback_checkboxes"
    FEEDBACK_MODAL_TEXT_INPUT_ACTION_ID = "feedback_text_input"


# ============================================================================
# Messages - User-facing text and UI labels
# ============================================================================


class AssistantMessages:
    """
    User-facing messages and UI text for Assistant AI interactions.
    These messages are platform-agnostic and can be used across different integrations.
    """

    # Bot display name (used when replacing bot mentions in messages sent to backend)
    BOT_DISPLAY_NAME = "Cortex Assistant"

    # Commands
    RESET_SESSION_COMMAND = "reset session"

    # Thinking indicator (shown while waiting for AI response)
    THINKING_INDICATOR = ":thought_balloon: Thinking..."

    # Context formatting
    CONTEXT_START = "--- Previous conversation context ---"
    CONTEXT_END = "--- End of context ---"
    CURRENT_MESSAGE_HEADER = "**Current message**:"

    # Messages for when user action is awaited - specific to action type
    AWAITING_AGENT_SELECTION = "Still waiting for you to select an agent from the dropdown above."
    AWAITING_APPROVAL_RESPONSE = "Still waiting for you to approve or reject the sensitive action above."

    ONLY_LOCKED_USER_CAN_RESPOND = (
        "You cannot mention {bot_tag} in this thread. Only {locked_user_tag} can interact with the AI here."
    )

    # Messages for when backend is processing
    ALREADY_PROCESSING = "Already processing a previous message. Please wait."

    # Messages for when plan is being sent
    WAITING_FOR_COMPLETION = "Still waiting for the response to complete."

    # Messages for action errors
    CANNOT_SELECT_AGENT = "You cannot make this selection. Only {locked_user_tag} can choose."
    CANNOT_APPROVE_ACTION = "You cannot respond to this action. Only {locked_user_tag} can approve or reject."

    # Permission error
    NOT_AUTHORIZED = "You are not authorized to interact with the {bot_tag} in this thread."

    # Reset session messages
    RESET_SESSION_SUCCESS = "✅ Session reset successfully."
    RESET_SESSION_FAILED = "❌ Failed to reset session."
    RESET_SESSION_NO_ACTIVE_SESSION = "No active session to reset. You can start a new conversation by mentioning me."
    RESET_SESSION_CANNOT_RESET_AWAITING_SELECTION = (
        "Cannot reset - still waiting for agent selection. No conversation has started yet."
    )
    RESET_SESSION_CANNOT_RESET_PROCESSING = (
        "Cannot reset session while processing a message. Please wait for the response to complete."
    )
    RESET_SESSION_CANNOT_RESET_RESPONDING = "Cannot reset session while responding. Please wait for the response to complete."

    # Agent selection messages
    NO_AGENTS_AVAILABLE = "❌ No agents are currently available for you. Please try again later or contact your administrator."
    AGENT_SELECTION_FAILED = "❌ Failed to start conversation with selected agent. Please try again or select a different agent."

    # Agent selection UI texts
    AGENT_SELECTION_PROMPT = "Please select an agent:"
    AGENT_SELECTION_PLACEHOLDER = "Select an agent"
    AGENT_SELECTION_CONFIRM_TITLE = "Confirm agent selection"
    AGENT_SELECTION_CONFIRM_TEXT = "Are you sure you want to use this agent?"
    AGENT_SELECTION_CONFIRM_BUTTON = "Yes, use this agent"
    AGENT_SELECTION_DENY_BUTTON = "No, let me choose again"

    # Approval UI texts
    APPROVAL_HEADER = "⚠️ Sensitive action detected. Approval required"
    APPROVAL_PROMPT = "*Should I proceed?*"
    APPROVAL_PROCEED_BUTTON = "Proceed"
    APPROVAL_CANCEL_BUTTON = "Cancel"
    APPROVAL_CONFIRM_TITLE = "Are you sure?"
    APPROVAL_CONFIRM_TEXT = "This action will be executed. Do you want to proceed?"
    APPROVAL_CONFIRM_BUTTON = "Yes, proceed"
    APPROVAL_DENY_BUTTON = "No, cancel"

    # Feedback buttons texts
    FEEDBACK_GOOD_BUTTON = "Good response"
    FEEDBACK_BAD_BUTTON = "Bad response"
    FEEDBACK_GOOD_ACCESSIBILITY = "Mark this response as good"
    FEEDBACK_BAD_ACCESSIBILITY = "Mark this response as bad"
    FEEDBACK_THANK_YOU = "Thanks for your feedback!"

    # Feedback modal texts
    FEEDBACK_MODAL_TITLE = "Send feedback"
    FEEDBACK_MODAL_SUBMIT = "Submit"
    FEEDBACK_MODAL_CANCEL = "Cancel"
    FEEDBACK_MODAL_QUICK_LABEL = "Quick Feedback"
    FEEDBACK_MODAL_ADDITIONAL_LABEL = "Anything to add?"
    FEEDBACK_MODAL_ADDITIONAL_PLACEHOLDER = "Enter your feedback here..."

    # Feedback modal checkbox options (text is also used as value)
    FEEDBACK_OPTION_NO_ANSWER = "No answer but I expected you to know that"
    FEEDBACK_OPTION_FACTUALLY_INCORRECT = "Factually incorrect"
    FEEDBACK_OPTION_ANSWERED_ANOTHER = "Answered another question"
    FEEDBACK_OPTION_PARTIALLY_HELPFUL = "Partially helpful"
    FEEDBACK_OPTION_UNHELPFUL = "Unhelpful"

    # Decision indicators
    DECISION_APPROVED = "✅ *Approved*"
    DECISION_CANCELLED = "❌ *Cancelled*"


# ============================================================================
# Base Handler Class
# ============================================================================


class AssistantMessagingHandler:
    """
    Base class for handling Assistant messaging across different platforms.
    This class contains the platform-agnostic logic for handling Assistant interactions.
    Platform-specific implementations (Slack, Teams, etc.) should inherit from this class
    and implement the abstract methods.
    """

    # Integration context key for assistant conversations
    CONTEXT_KEY = "assistant_context"

    def __init__(self):
        """Initialize the messaging handler"""

    # ============================================================================
    # Abstract methods - must be implemented by platform-specific subclasses
    # ============================================================================

    async def send_message_async(
        self,
        channel_id: str,
        message: str,
        thread_id: str = "",
        blocks: Optional[list] = None,
        attachments: Optional[list] = None,
        ephemeral: bool = False,
        user_id: str = "",
    ):
        """
        Send a message to the platform.
        Must be implemented by subclass.

        Args:
            channel_id: The channel/conversation ID
            message: The message text
            thread_id: Optional thread ID
            blocks: Optional platform-specific blocks
            attachments: Optional attachments
            ephemeral: Whether message should be ephemeral (visible only to user_id)
            user_id: User ID for ephemeral messages
        """
        raise NotImplementedError("Subclass must implement send_message_async()")

    async def update_message(
        self,
        channel_id: str,
        message_ts: str,
        text: str = "",
        blocks: Optional[list] = None,
    ):
        """
        Update an existing message.
        Must be implemented by subclass.

        Args:
            channel_id: The channel/conversation ID
            message_ts: The message timestamp/ID
            text: Optional new text
            blocks: Optional new blocks
        """
        raise NotImplementedError("Subclass must implement update_message()")

    def delete_message_sync(
        self,
        channel_id: str,
        message_ts: str,
    ):
        """
        Delete an existing message.
        Must be implemented by subclass.

        Args:
            channel_id: The channel/conversation ID
            message_ts: The message timestamp/ID
        """
        raise NotImplementedError("Subclass must implement delete_message_sync()")

    async def get_user_info(self, user_id: str) -> dict:
        """
        Get user information.
        Must be implemented by subclass.

        Args:
            user_id: The user ID

        Returns:
            User information dictionary
        """
        raise NotImplementedError("Subclass must implement get_user_info()")

    async def get_thread_history(self, channel_id: str, thread_id: str, limit: int = 20) -> list:
        """
        Get conversation history.
        Must be implemented by subclass.

        Args:
            channel_id: The channel ID
            thread_id: The thread ID
            limit: Maximum number of messages to retrieve

        Returns:
            List of messages
        """
        raise NotImplementedError("Subclass must implement get_thread_history()")

    def format_user_mention(self, user_id: str) -> str:
        """
        Format a user mention for the platform.
        Must be implemented by subclass.

        Args:
            user_id: The user ID

        Returns:
            Formatted user mention string
        """
        raise NotImplementedError("Subclass must implement format_user_mention()")

    def normalize_message_from_user(self, text: str) -> str:
        """
        Normalize message text from user for backend processing.
        Must be implemented by subclass.

        Args:
            text: The message text with platform-specific formatting

        Returns:
            Normalized text suitable for backend
        """
        raise NotImplementedError("Subclass must implement normalize_message_from_user()")

    def prepare_message_blocks(self, message: str, message_type: str, is_update: bool = False) -> tuple:
        """
        Prepare platform-specific message blocks.
        Must be implemented by subclass.

        Args:
            message: The message text
            message_type: The message type
            is_update: Whether this is an update to existing message (True) or new message (False)

        Returns:
            Tuple of (blocks, attachments)
        """
        raise NotImplementedError("Subclass must implement prepare_message_blocks()")

    def create_agent_selection_ui(self, agents: list) -> list:
        """
        Create agent selection UI.
        Must be implemented by subclass.

        Args:
            agents: List of available agents

        Returns:
            Platform-specific UI blocks
        """
        raise NotImplementedError("Subclass must implement create_agent_selection_ui()")

    def create_approval_ui(self) -> list:
        """
        Create approval UI for sensitive actions.
        Must be implemented by subclass.

        Returns:
            Platform-specific UI blocks
        """
        raise NotImplementedError("Subclass must implement create_approval_ui()")

    def create_feedback_ui(self, message_id: str) -> dict:
        """
        Create feedback UI.
        Must be implemented by subclass.

        Args:
            message_id: The message ID for tracking

        Returns:
            Platform-specific feedback UI
        """
        raise NotImplementedError("Subclass must implement create_feedback_ui()")

    def post_agent_response_sync(
        self,
        channel_id: str,
        thread_id: str,
        blocks: list,
        attachments: list,
    ) -> Optional[dict]:
        """
        Send a new agent message to the platform.
        Must be implemented by subclass.

        Args:
            channel_id: The channel ID
            thread_id: The thread ID
            blocks: Message blocks
            attachments: Message attachments

        Returns:
            Response dict with 'ts' (message timestamp) if successful, None otherwise
        """
        raise NotImplementedError("Subclass must implement post_agent_response_sync()")

    def update_existing_message(
        self,
        channel_id: str,
        thread_id: str,
        message_ts: str,
        attachments: list,
    ) -> bool:
        """
        Update an existing message.
        Must be implemented by subclass.

        Args:
            channel_id: The channel ID
            thread_id: The thread ID
            message_ts: The message timestamp to update
            attachments: New attachments

        Returns:
            True if successful, False otherwise
        """
        raise NotImplementedError("Subclass must implement update_existing_message()")

    def finalize_plan_header(
        self,
        channel_id: str,
        thread_id: str,
        step_message_ts: str,
    ):
        """
        Finalize the plan header (remove "updating..." indicator).
        Must be implemented by subclass.

        Args:
            channel_id: The channel ID
            thread_id: The thread ID
            step_message_ts: The step message timestamp
        """
        raise NotImplementedError("Subclass must implement finalize_plan_header()")

    def send_or_update_agent_response(
        self,
        channel_id: str,
        thread_id: str,
        message_type: str,
        blocks: list,
        attachments: list,
        assistant: dict,
        assistant_id_key: str,
    ) -> dict:
        """
        Send or update an agent response based on message type.
        Platform-agnostic implementation that uses platform-specific methods.

        Args:
            channel_id: The channel ID
            thread_id: The thread ID
            message_type: The message type
            blocks: Message blocks
            attachments: Message attachments
            assistant: The assistant context
            assistant_id_key: The conversation key

        Returns:
            Updated assistant dictionary
        """
        step_message_ts = assistant.get(assistant_id_key, {}).get("step_message_ts")

        if AssistantMessageType.is_step_type(message_type):
            # For step types, update existing message if it exists, otherwise create new one
            if step_message_ts:
                # Update existing step message
                demisto.debug(f"Updating step message {step_message_ts}")
                success = self.update_existing_message(channel_id, thread_id, step_message_ts, attachments)
                if not success:
                    # Fallback: send as new message
                    demisto.error("Failed to update step message, sending as new message")
                    response = self.post_agent_response_sync(channel_id, thread_id, blocks, attachments)
                    if response and assistant_id_key in assistant:
                        assistant[assistant_id_key]["step_message_ts"] = response.get("ts")
            else:
                # Send new step message and save its timestamp
                response = self.post_agent_response_sync(channel_id, thread_id, blocks, attachments)
                if response and assistant_id_key in assistant:
                    assistant[assistant_id_key]["step_message_ts"] = response.get("ts")
        else:
            # For non-step types (model, approval, error), always send as new message
            self.post_agent_response_sync(channel_id, thread_id, blocks, attachments)

            # Finalize Plan message when sending final response
            if AssistantMessageType.is_model_type(message_type) and assistant_id_key in assistant:
                # Update Plan header to remove "updating..." if step_message_ts exists
                if step_message_ts:
                    self.finalize_plan_header(channel_id, thread_id, step_message_ts)
                # Clear step_message_ts
                assistant[assistant_id_key].pop("step_message_ts", None)

        return assistant

    def update_context(self, context_updates: dict):
        """
        Update the integration context.
        Must be implemented by subclass.

        Args:
            context_updates: Dictionary of updates to apply
        """
        raise NotImplementedError("Subclass must implement update_context()")

    async def open_feedback_modal(
        self,
        trigger_id: str,
        message_id: str,
        channel_id: str,
        thread_id: str,
    ):
        """
        Open a feedback modal for negative feedback collection.
        Must be implemented by subclass.

        Args:
            trigger_id: The trigger ID for opening the modal
            message_id: The message ID for tracking
            channel_id: The channel ID
            thread_id: The thread ID
        """
        raise NotImplementedError("Subclass must implement open_feedback_modal()")

    async def submit_feedback(
        self,
        message_id: str,
        feedback_score: int,
        thread_id: str,
        channel_id: str,
        username: str,
        issues: Optional[list] = None,
        message: str = "",
    ):
        """
        Submit feedback to backend.
        Platform-agnostic implementation.

        Args:
            message_id: The message ID
            feedback_score: 1 for positive, 0 for negative
            thread_id: The thread ID
            channel_id: The channel ID
            username: The username
            issues: Optional list of issues (for negative feedback)
            message: Optional feedback message
        """
        args = {
            "message_id": message_id,
            "feedback_score": feedback_score,
            "thread_id": thread_id,
            "channel_id": channel_id,
            "username": username,
        }
        if issues:
            args["issues"] = issues
        if message:
            args["improvement_suggestion"] = message

        demisto.agentixCommands("rateMessage", args)

    # ============================================================================
    # Platform-agnostic methods - shared logic across all platforms
    # ============================================================================

    def cleanup_expired_conversations(self, assistant: dict) -> dict:
        """
        Cleans up expired conversations from the assistant context.
        Each status has a different timeout duration.

        Args:
            assistant: The assistant context dictionary

        Returns:
            Updated assistant dictionary with expired conversations removed
        """
        if not assistant:
            return assistant

        expired_keys = []

        for assistant_id_key, conversation in assistant.items():
            status = conversation.get("status", "")
            last_updated = conversation.get("last_updated", 0)

            # Check if conversation has expired
            if AssistantStatus.is_expired(status, last_updated):
                expired_keys.append(assistant_id_key)
                demisto.debug(
                    f"Conversation {assistant_id_key} expired (status: {status}, "
                    f"last_updated: {last_updated}, timeout: {AssistantStatus.get_timeout_for_status(status)}s)"
                )

        # Remove expired conversations
        for key in expired_keys:
            del assistant[key]
            demisto.info(f"Cleaned up expired conversation: {key}")

        if expired_keys:
            demisto.info(f"Cleaned up {len(expired_keys)} expired conversations")

        return assistant

    def check_and_cleanup_assistant_conversations(self):
        """
        Checks and cleans up expired Assistant conversations from integration context.
        This should be called periodically (e.g., in long_running_loop).
        Handles loading from context, cleanup, and saving back to context.
        """
        try:
            # Get integration context
            integration_context = get_integration_context(sync=True)
            assistant = integration_context.get(self.CONTEXT_KEY, {})

            # Parse if it's a string
            if isinstance(assistant, str):
                assistant = json.loads(assistant)

            if not assistant:
                return

            # Store original count before cleanup
            original_count = len(assistant)

            # Cleanup expired conversations
            cleaned_assistant = self.cleanup_expired_conversations(assistant)

            # Update context if anything was cleaned
            if len(cleaned_assistant) != original_count:
                demisto.debug(f"Updating context after cleanup: {original_count} -> {len(cleaned_assistant)} conversations")
                set_to_integration_context_with_retries({self.CONTEXT_KEY: cleaned_assistant}, sync=True)
        except Exception as e:
            demisto.error(f"Failed to cleanup expired Assistant conversations: {e}")

    async def handle_reset_session(
        self,
        text: str,
        user_id: str,
        channel_id: str,
        thread_id: str,
        assistant: dict,
        assistant_id_key: str,
        bot_id: str,
        user_email: str,
    ) -> tuple[bool, dict]:
        """
        Handles reset session command.
        Checks if the message is exactly "@BotName reset session" (case-insensitive).

        Args:
            text: The message text
            user_id: The user ID
            channel_id: The channel ID
            thread_id: The thread ID
            assistant: The assistant context dictionary
            assistant_id_key: The unique key for this conversation
            bot_id: The bot user ID
            user_email: The user email address

        Returns:
            Tuple of (is_reset_command, updated_assistant)
        """
        # Check for exact "reset session" command
        # Format: @BotName reset session (with optional whitespace)
        bot_mention = self.format_user_mention(bot_id)
        # Remove the bot mention and check if remaining text is exactly "reset session"
        text_without_mention = text.replace(bot_mention, "").strip()

        if text_without_mention.lower() != AssistantMessages.RESET_SESSION_COMMAND:
            return False, assistant

        # Check status to determine if reset is allowed
        if assistant_id_key in assistant:
            status = assistant[assistant_id_key].get("status", "")

            # For agent selection - release lock locally without calling backend
            if status == AssistantStatus.AWAITING_AGENT_SELECTION.value:
                del assistant[assistant_id_key]
                await self.send_message_async(
                    channel_id,
                    AssistantMessages.RESET_SESSION_SUCCESS,
                    thread_id=thread_id,
                    ephemeral=True,
                    user_id=user_id,
                )
                return True, assistant

            # Cannot reset while processing
            if status == AssistantStatus.AWAITING_BACKEND_RESPONSE.value:
                await self.send_message_async(
                    channel_id,
                    AssistantMessages.RESET_SESSION_CANNOT_RESET_PROCESSING,
                    thread_id=thread_id,
                    ephemeral=True,
                    user_id=user_id,
                )
                return True, assistant

            # Cannot reset while responding
            if status == AssistantStatus.RESPONDING_WITH_PLAN.value:
                await self.send_message_async(
                    channel_id,
                    AssistantMessages.RESET_SESSION_CANNOT_RESET_RESPONDING,
                    thread_id=thread_id,
                    ephemeral=True,
                    user_id=user_id,
                )
                return True, assistant

        # For AWAITING_SENSITIVE_ACTION_APPROVAL or no lock - allow reset
        # Call backend to reset conversation
        response = demisto.agentixCommands(
            "resetConversation",
            {
                "channel_id": channel_id,
                "thread_id": thread_id,
                "username": user_email,
            },
        )

        if isinstance(response, dict) and response.get("success"):
            # Remove from assistant context
            if assistant_id_key in assistant:
                del assistant[assistant_id_key]

            await self.send_message_async(
                channel_id, AssistantMessages.RESET_SESSION_SUCCESS, thread_id=thread_id, ephemeral=True, user_id=user_id
            )
        elif isinstance(response, dict) and "No active session" in str(response.get("error", "")):
            # Backend says no active session
            await self.send_message_async(
                channel_id, AssistantMessages.RESET_SESSION_NO_ACTIVE_SESSION, thread_id=thread_id, ephemeral=True, user_id=user_id
            )
        else:
            demisto.error(f"Failed to reset conversation: {response}")
            await self.send_message_async(
                channel_id, AssistantMessages.RESET_SESSION_FAILED, thread_id=thread_id, ephemeral=True, user_id=user_id
            )

        return True, assistant

    async def handle_modal_submission(
        self,
        message_id: str,
        channel_id: str,
        thread_id: str,
        user_id: str,
        user_email: str,
        issues: list,
        feedback_text: str,
    ):
        """
        Handles modal submissions (e.g., negative feedback).
        Platform-agnostic logic that submits feedback.

        Args:
            message_id: The message ID
            channel_id: The channel ID
            thread_id: The thread ID
            user_id: The user ID
            user_email: The user's email
            issues: List of selected issues
            feedback_text: Additional feedback text
        """
        # Send negative feedback with checkboxes and text to backend
        await self.submit_feedback(
            message_id=message_id,
            feedback_score=0,
            thread_id=thread_id,
            channel_id=channel_id,
            username=user_email,
            issues=issues,
            message=feedback_text,
        )

        # Send confirmation message (ephemeral)
        await self.send_message_async(
            channel_id, AssistantMessages.FEEDBACK_THANK_YOU, thread_id=thread_id, ephemeral=True, user_id=user_id
        )

    async def handle_action(
        self,
        actions: list,
        user_id: str,
        user_email: str,
        channel_id: str,
        thread_id: str,
        message: dict,
        assistant: dict,
        assistant_id_key: str,
        trigger_id: str,
    ) -> dict:
        """
        Handles interactive actions (agent selection, approval, feedback).
        Platform-agnostic logic that uses platform-specific methods.

        Args:
            actions: The list of actions from the payload
            user_id: The user ID
            user_email: The user's email
            channel_id: The channel ID
            thread_id: The thread ID
            message: The message dict from payload
            assistant: The assistant context dictionary
            assistant_id_key: The unique key for this conversation
            trigger_id: The trigger ID for modals

        Returns:
            Updated assistant dictionary
        """
        from datetime import UTC, datetime

        message_ts = message.get("ts", "")

        # Decode the action payload
        action = actions[0]
        action_id = action.get("action_id", "")
        action_value = action.get("value", "")

        # OPTION 1: Feedback Buttons
        if action_id == AssistantActionIds.FEEDBACK.value:
            # Value format: "positive-message_id" or "negative-message_id"
            # message_id can contain hyphens (e.g., UUID), so split only on first hyphen
            parts = action_value.split("-", 1)
            if len(parts) == 2:
                feedback_type, message_id = parts
                is_positive = feedback_type == "positive"
            else:
                demisto.error(f"Invalid feedback value format: {action_value}")
                return assistant

            if is_positive:
                # Positive feedback - send immediately
                await self.submit_feedback(
                    message_id=message_id,
                    feedback_score=1,
                    thread_id=thread_id,
                    channel_id=channel_id,
                    username=user_email,
                )

                # Send confirmation message (ephemeral)
                await self.send_message_async(
                    channel_id, AssistantMessages.FEEDBACK_THANK_YOU, thread_id=thread_id, ephemeral=True, user_id=user_id
                )
            else:
                # Negative feedback - open modal
                if trigger_id:
                    try:
                        await self.open_feedback_modal(trigger_id, message_id, channel_id, thread_id)
                    except Exception as e:
                        demisto.error(f"Failed to open feedback modal: {e}")
                        # Fallback to ephemeral message
                        await self.send_message_async(
                            channel_id, AssistantMessages.FEEDBACK_THANK_YOU, thread_id=thread_id, ephemeral=True, user_id=user_id
                        )

            # Feedback doesn't require active conversation
            return assistant

        # For other actions, check if conversation exists
        if assistant_id_key not in assistant:
            return assistant

        locked_user = assistant[assistant_id_key].get("user", "")

        # OPTION 2: Agent Selection
        if action_id == AssistantActionIds.AGENT_SELECTION.value:
            selected_option = action.get("selected_option", {})
            option_value = selected_option.get("value", "")
            original_message = assistant[assistant_id_key].get("message", "")

            if user_id == locked_user:
                # Correct user selected an agent
                selected_agent_id = option_value.replace(AssistantActionIds.AGENT_SELECTION_VALUE_PREFIX, "")
                selected_agent_name = selected_option.get("text", {}).get("text", "")

                # Send message to backend with selected agent
                response = demisto.agentixCommands(
                    "sendToConversation",
                    {
                        "channel_id": channel_id,
                        "thread_id": thread_id,
                        "message": original_message,
                        "username": user_email,
                        "agent_id": selected_agent_id,
                    },
                )

                # Check if backend call was successful
                if isinstance(response, dict) and response.get("success"):
                    # Update the original message to show selection
                    await self.update_message(channel_id, message_ts, text=f"Selected agent: {selected_agent_name}", blocks=[])

                    # Send thinking indicator
                    thinking_response = await self.send_message_async(
                        channel_id, AssistantMessages.THINKING_INDICATOR, thread_id=thread_id
                    )
                    thinking_ts = thinking_response.get("ts") if thinking_response else None

                    # Update status
                    assistant[assistant_id_key]["status"] = AssistantStatus.AWAITING_BACKEND_RESPONSE.value
                    assistant[assistant_id_key]["selected_agent"] = selected_agent_id
                    assistant[assistant_id_key]["last_updated"] = datetime.now(UTC).timestamp()

                    # Store thinking message timestamp if sent successfully
                    if thinking_ts:
                        assistant[assistant_id_key]["thinking_message_ts"] = thinking_ts
                else:
                    # Backend call failed - show error and keep status as AWAITING_AGENT_SELECTION
                    error_message = response.get("error", "Unknown error") if isinstance(response, dict) else str(response)
                    demisto.error(f"Failed to send agent selection to backend: {error_message}")

                    # Send ephemeral error message to user
                    await self.send_message_async(
                        channel_id, AssistantMessages.AGENT_SELECTION_FAILED, thread_id=thread_id, ephemeral=True, user_id=user_id
                    )
                    # Keep the conversation in AWAITING_AGENT_SELECTION status so user can try again
            else:
                # Wrong user trying to select
                error_msg = AssistantMessages.CANNOT_SELECT_AGENT.format(locked_user_tag=self.format_user_mention(locked_user))
                await self.send_message_async(channel_id, error_msg, thread_id=thread_id, ephemeral=True, user_id=user_id)

        # OPTION 3: Sensitive Action Approval
        elif action_id in [AssistantActionIds.APPROVAL_YES.value, AssistantActionIds.APPROVAL_NO.value]:
            if user_id == locked_user:
                # Correct user responded
                is_approved = action_id == AssistantActionIds.APPROVAL_YES.value

                # Send response to backend
                demisto.agentixCommands(
                    "sendToConversation",
                    {
                        "channel_id": channel_id,
                        "thread_id": thread_id,
                        "message": "Yes" if is_approved else "No",
                        "username": user_email,
                        "is_approved": is_approved,
                    },
                )

                # Update the original message
                decision_indicator = AssistantMessages.DECISION_APPROVED if is_approved else AssistantMessages.DECISION_CANCELLED
                original_blocks = message.get("blocks", [])
                updated_blocks = [block for block in original_blocks if block.get("type") != "actions"]
                updated_blocks.append({"type": "context", "elements": [{"type": "mrkdwn", "text": decision_indicator}]})

                try:
                    await self.update_message(channel_id, message_ts, blocks=updated_blocks)
                except Exception as e:
                    demisto.error(f"Failed to update approval message: {e}")
                    # Fallback
                    await self.update_message(channel_id, message_ts, text=decision_indicator, blocks=[])

                # Update status
                assistant[assistant_id_key]["status"] = AssistantStatus.AWAITING_BACKEND_RESPONSE.value
                assistant[assistant_id_key]["sensitive_action_response"] = "approved" if is_approved else "rejected"
                assistant[assistant_id_key]["last_updated"] = datetime.now(UTC).timestamp()
            else:
                # Wrong user trying to respond
                error_msg = AssistantMessages.CANNOT_APPROVE_ACTION.format(locked_user_tag=self.format_user_mention(locked_user))
                await self.send_message_async(channel_id, error_msg, thread_id=thread_id, ephemeral=True, user_id=user_id)

        return assistant

    def format_context_messages(self, context_messages: list[dict]) -> str:
        """
        Formats a list of context messages into a string.
        Platform-agnostic formatting logic.

        Args:
            context_messages: List of message dicts with 'user' and 'text' keys

        Returns:
            Formatted context string
        """
        if not context_messages:
            return ""

        # Create formatted context string
        context_lines = [AssistantMessages.CONTEXT_START]
        for ctx_msg in reversed(context_messages):  # Show oldest first
            context_lines.append(f"**{ctx_msg['user']}**: {ctx_msg['text']}")
        context_lines.append(AssistantMessages.CONTEXT_END)
        context_lines.append("")  # Empty line before current message

        return "\n".join(context_lines)

    async def get_conversation_context_formatted(
        self, channel_id: str, thread_id: str, bot_id: str, current_message_ts: str
    ) -> str:
        """
        Retrieves and formats conversation context.
        Must be implemented by subclass to handle platform-specific message parsing.

        Args:
            channel_id: The channel ID
            thread_id: The thread ID
            bot_id: The bot user ID
            current_message_ts: The current message timestamp

        Returns:
            Formatted context string
        """
        raise NotImplementedError("Subclass must implement get_conversation_context_formatted()")

    async def handle_bot_mention(
        self,
        text: str,
        user_id: str,
        user_email: str,
        channel_id: str,
        thread_id: str,
        assistant: dict,
        assistant_id_key: str,
        bot_id: str,
        message_ts: str,
    ) -> dict:
        """
        Handles when the bot is mentioned in a message for Assistant AI.
        This is platform-agnostic logic.

        Args:
            text: The message text
            user_id: The user ID
            user_email: The user's email
            channel_id: The channel ID
            thread_id: The thread ID
            assistant: The assistant context dictionary
            assistant_id_key: The unique key for this conversation
            bot_id: The bot user ID
            message_ts: The current message timestamp

        Returns:
            Updated assistant dictionary - to be saved by caller
        """

        # Check for "reset session" command first
        is_reset, assistant = await self.handle_reset_session(text, user_id, channel_id, thread_id, assistant, assistant_id_key, bot_id, user_email)
        if is_reset:
            return assistant

        # Check if there's already an active conversation
        if assistant_id_key in assistant:
            status = assistant[assistant_id_key].get("status", "")
            locked_user = assistant[assistant_id_key].get("user", "")

            # Determine the appropriate message
            message_to_send = None

            if AssistantStatus.is_awaiting_user_action(status):
                # Waiting for user action (agent selection or approval)
                if locked_user == user_id:
                    # Show specific message based on what we're waiting for
                    if status == AssistantStatus.AWAITING_AGENT_SELECTION.value:
                        message_to_send = AssistantMessages.AWAITING_AGENT_SELECTION
                    elif status == AssistantStatus.AWAITING_SENSITIVE_ACTION_APPROVAL.value:
                        message_to_send = AssistantMessages.AWAITING_APPROVAL_RESPONSE
                else:
                    message_to_send = AssistantMessages.ONLY_LOCKED_USER_CAN_RESPOND.format(
                        bot_tag=self.format_user_mention(bot_id), locked_user_tag=self.format_user_mention(locked_user)
                    )

            elif status == AssistantStatus.AWAITING_BACKEND_RESPONSE.value:
                # Already processing a previous message
                message_to_send = AssistantMessages.ALREADY_PROCESSING

            elif status == AssistantStatus.RESPONDING_WITH_PLAN.value:
                # Currently responding with a plan
                if locked_user == user_id:
                    message_to_send = AssistantMessages.WAITING_FOR_COMPLETION
                else:
                    message_to_send = AssistantMessages.ONLY_LOCKED_USER_CAN_RESPOND.format(
                        bot_tag=self.format_user_mention(bot_id), locked_user_tag=self.format_user_mention(locked_user)
                    )

            # Send message if needed
            if message_to_send:
                await self.send_message_async(channel_id, message_to_send, thread_id=thread_id, ephemeral=True, user_id=user_id)
            return assistant

        # Get conversation context (up to 5 previous messages)
        context = await self.get_conversation_context_formatted(channel_id, thread_id, bot_id, message_ts)

        # Replace bot mention with friendly display name for backend
        bot_mention = self.format_user_mention(bot_id)
        text_cleaned = text.replace(bot_mention, AssistantMessages.BOT_DISPLAY_NAME).strip()

        # Normalize message for backend (decode HTML entities, preserve structure)
        text_normalized = self.normalize_message_from_user(text_cleaned)

        # Normalize context as well
        context_normalized = self.normalize_message_from_user(context) if context else ""

        # Prepare message with context
        message_with_context = text_normalized
        if context_normalized:
            message_with_context = f"{context_normalized}\n{AssistantMessages.CURRENT_MESSAGE_HEADER}\n{text_normalized}"

        # Send message to backend using agentixCommands
        demisto.debug(f"Sending user message to backend: channel={channel_id}, thread={thread_id}, user={user_email}")
        response = demisto.agentixCommands(
            "sendToConversation",
            {
                "channel_id": channel_id,
                "thread_id": thread_id,
                "message": message_with_context,
                "username": user_email,
            },
        )

        # Check if response contains agent list (requires user to select an agent)
        if "agents" in response:
            agents_list = response.get("agents", [])
            demisto.debug(f"Backend returned {len(agents_list) if isinstance(agents_list, list) else 0} agents for selection")
            # Check if agents list is empty or UI creation failed
            if agents_list:
                # Backend returned a list of agents - user needs to select one
                # Create agent selection UI
                agent_selection_blocks = self.create_agent_selection_ui(agents_list)

                if agent_selection_blocks:
                    # Send agent selection UI
                    await self.send_message_async(channel_id, "", thread_id, blocks=agent_selection_blocks)

                    # Lock the conversation with agent selection status
                    from datetime import UTC, datetime

                    assistant[assistant_id_key] = {
                        "date": thread_id,
                        "user": user_id,
                        "message": message_with_context,
                        "channel_id": channel_id,
                        "thread_id": thread_id,
                        "status": AssistantStatus.AWAITING_AGENT_SELECTION.value,
                        "last_updated": datetime.now(UTC).timestamp(),
                    }
                    demisto.debug(f"Locked conversation {assistant_id_key} for agent selection")
                else:
                    # Failed to create agent selection UI
                    demisto.error("Failed to create agent selection UI despite having agents")
                    await self.send_message_async(
                        channel_id, AssistantMessages.NO_AGENTS_AVAILABLE, thread_id=thread_id, ephemeral=True, user_id=user_id
                    )
            else:
                # Empty agents list
                demisto.error("Received empty agents list from backend")
                await self.send_message_async(
                    channel_id, AssistantMessages.NO_AGENTS_AVAILABLE, thread_id=thread_id, ephemeral=True, user_id=user_id
                )

        elif isinstance(response, dict) and response.get("success"):
            # Send thinking indicator
            thinking_response = await self.send_message_async(channel_id, AssistantMessages.THINKING_INDICATOR, thread_id=thread_id)
            thinking_ts = thinking_response.get("ts") if thinking_response else None

            # Lock the conversation with initial status
            from datetime import UTC, datetime

            assistant[assistant_id_key] = {
                "date": thread_id,
                "user": user_id,
                "message": text,
                "channel_id": channel_id,
                "thread_id": thread_id,
                "status": AssistantStatus.AWAITING_BACKEND_RESPONSE.value,
                "last_updated": datetime.now(UTC).timestamp(),
            }

            # Store thinking message timestamp if sent successfully
            if thinking_ts:
                assistant[assistant_id_key]["thinking_message_ts"] = thinking_ts
            
            demisto.debug(f"Locked conversation {assistant_id_key}, awaiting backend response")

        elif "User not authorized for this thread" in str(response):
            demisto.debug(f"User {user_email} not authorized for thread {thread_id}")
            error_msg = AssistantMessages.NOT_AUTHORIZED.format(bot_tag=self.format_user_mention(bot_id))
            await self.send_message_async(channel_id, error_msg, thread_id=thread_id, ephemeral=True, user_id=user_id)
        else:
            # Permission error or other issue - don't lock
            demisto.error(f"Backend sendToConversation failed: {response}")

        return assistant

    def send_agent_response(
        self,
        channel_id: str,
        thread_id: str,
        message: str,
        message_type: str,
        message_id: str = "",
        completed: bool = False,
        assistant_context: dict | None = None,
        assistant_id_key: str = "",
    ) -> dict:
        """
        Sends an agent response and updates the Assistant status accordingly.
        This is platform-agnostic logic that uses platform-specific methods.

        Args:
            channel_id: The channel ID
            thread_id: The thread ID
            message: The message text
            message_type: The message type (from AssistantMessageType)
            message_id: Optional message ID for feedback tracking
            completed: Whether this is the final response
            assistant_context: The assistant context dictionary
            assistant_id_key: The unique key for this conversation

        Returns:
            Updated assistant dictionary

        Raises:
            ValueError: If message_type is not valid
        """
        # Validate message_type
        try:
            AssistantMessageType(message_type)
        except ValueError:
            error_msg = (
                f"Invalid message_type: '{message_type}'. "
                f"Must be one of: {', '.join([t.value for t in AssistantMessageType])}"
            )
            demisto.error(error_msg)
            raise ValueError(error_msg)

        if not assistant_context:
            assistant_context = {}

        demisto.debug(f"Sending agent response: type={message_type}, completed={completed}, conversation={assistant_id_key}")

        # Replace escaped characters with actual characters
        message = message.replace("\\n", "\n")
        message = message.replace('\\"', '"')
        message = message.replace("\\'", "'")

        # Check if this is an update (step_message_ts exists in assistant)
        is_update = (
            assistant_context.get(assistant_id_key, {}).get("step_message_ts") is not None
            if AssistantMessageType.is_step_type(message_type)
            else False
        )

        # Prepare blocks and attachments using platform-specific method
        blocks, attachments = self.prepare_message_blocks(message, message_type, is_update)
        if not blocks:
            blocks = []

        # Variables for status update
        new_status = None
        should_release_lock = False

        # Handle different message types
        if AssistantMessageType.is_model_type(message_type):
            # MODEL TYPES - Final responses
            should_release_lock = completed
            # Add feedback buttons for final responses
            if message_id:
                blocks.append(self.create_feedback_ui(message_id))

        elif AssistantMessageType.is_approval_type(message_type):
            # APPROVAL - Sensitive action requiring approval
            blocks.extend(self.create_approval_ui())
            new_status = AssistantStatus.AWAITING_SENSITIVE_ACTION_APPROVAL.value

        elif AssistantMessageType.is_step_type(message_type):
            # STEP TYPES - Plan steps
            new_status = AssistantStatus.RESPONDING_WITH_PLAN.value

        elif AssistantMessageType.is_error_type(message_type):
            # ERROR - release lock immediately
            should_release_lock = True

        # Delete thinking indicator if it exists (before sending first response)
        if assistant_id_key in assistant_context:
            thinking_ts = assistant_context[assistant_id_key].get("thinking_message_ts")
            if thinking_ts:
                try:
                    self.delete_message_sync(channel_id, thinking_ts)
                except Exception as e:
                    demisto.error(f"Failed to delete thinking indicator: {e}")
                # Remove thinking_message_ts from context
                assistant_context[assistant_id_key].pop("thinking_message_ts", None)

        # Send or update message using platform-specific method
        assistant_context = self.send_or_update_agent_response(
            channel_id, thread_id, message_type, blocks, attachments, assistant_context, assistant_id_key
        )

        # Update context based on message type
        if assistant_id_key in assistant_context:
            if should_release_lock:
                # Release the lock
                del assistant_context[assistant_id_key]
                self.update_context({self.CONTEXT_KEY: assistant_context})
            elif new_status:
                # Update status
                from datetime import UTC, datetime

                assistant_context[assistant_id_key]["status"] = new_status
                assistant_context[assistant_id_key]["last_updated"] = datetime.now(UTC).timestamp()
                self.update_context({self.CONTEXT_KEY: assistant_context})

        demisto.results("Agent response sent successfully.")
        return assistant_context
