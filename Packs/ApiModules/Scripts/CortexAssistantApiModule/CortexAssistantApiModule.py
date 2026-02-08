from typing import Optional
import demistomock as demisto
from CommonServerPython import *


class AgentixStatus:
    """
    Manages the status of Agentix AI Assistant interactions.

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

    # All valid statuses
    VALID_STATUSES = {
        AWAITING_BACKEND_RESPONSE,
        RESPONDING_WITH_PLAN,
        AWAITING_AGENT_SELECTION,
        AWAITING_SENSITIVE_ACTION_APPROVAL,
    }
    
    # Timeout durations (in seconds) for automatic cleanup
    # These determine how long a conversation can stay in each status before being automatically cleaned up
    TIMEOUT_AWAITING_BACKEND_RESPONSE = 120  # 2 minutes
    TIMEOUT_RESPONDING_WITH_PLAN = 120  # 2 minutes
    TIMEOUT_AWAITING_AGENT_SELECTION = 604800  # 7 days
    TIMEOUT_AWAITING_SENSITIVE_ACTION_APPROVAL = 1209600  # 14 days
    
    # Map status to timeout duration
    STATUS_TIMEOUTS = {
        AWAITING_BACKEND_RESPONSE: TIMEOUT_AWAITING_BACKEND_RESPONSE,
        RESPONDING_WITH_PLAN: TIMEOUT_RESPONDING_WITH_PLAN,
        AWAITING_AGENT_SELECTION: TIMEOUT_AWAITING_AGENT_SELECTION,
        AWAITING_SENSITIVE_ACTION_APPROVAL: TIMEOUT_AWAITING_SENSITIVE_ACTION_APPROVAL,
    }

    @classmethod
    def is_valid(cls, status: str) -> bool:
        """
        Check if a status is valid.

        Args:
            status: The status to validate

        Returns:
            True if the status is valid, False otherwise
        """
        return status in cls.VALID_STATUSES

    @classmethod
    def is_awaiting_user_action(cls, status: str) -> bool:
        """
        Check if the status indicates we're waiting for user action.

        Args:
            status: The status to check

        Returns:
            True if waiting for user action, False otherwise
        """
        return status in {cls.AWAITING_AGENT_SELECTION, cls.AWAITING_SENSITIVE_ACTION_APPROVAL}
    
    @classmethod
    def get_timeout_for_status(cls, status: str) -> int:
        """
        Get the timeout duration for a given status.
        
        Args:
            status: The status to get timeout for
            
        Returns:
            Timeout duration in seconds, or 0 if status is invalid
        """
        return cls.STATUS_TIMEOUTS.get(status, 0)
    
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


class AgentixMessageType:
    """
    Message types for Agentix AI Assistant responses.

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

    Our grouping:
    - MODEL_TYPES: model, clarification, copilot, script (all treated as final responses)
    - STEP_TYPES: step, thought (shown with subtle styling)
    - APPROVAL_TYPES: approval (requires user approval)
    - ERROR_TYPES: error (shown with error styling)
    """

    # Message types from backend
    STEP = "step"  # Step execution
    MODEL = "model"  # Model/AI response
    ERROR = "error"  # Error message
    USER = "user"  # User message
    THOUGHT = "thought"  # AI thinking
    APPROVAL = "approval"  # Approval request
    CLARIFICATION = "clarification"  # Clarification request
    COPILOT = "copilot"  # Copilot response
    SCRIPT = "script"  # Script execution

    # All valid message types
    VALID_TYPES = {STEP, MODEL, ERROR, USER, THOUGHT, APPROVAL, CLARIFICATION, COPILOT, SCRIPT}

    # Types that are treated as final model responses (with feedback buttons)
    MODEL_TYPES = {MODEL, CLARIFICATION, COPILOT, SCRIPT, APPROVAL}

    # Types that are considered "step" types (shown with subtle styling)
    STEP_TYPES = {STEP, THOUGHT}

    # Types that require approval
    APPROVAL_TYPES = {APPROVAL}

    # Error types
    ERROR_TYPES = {ERROR}

    @classmethod
    def is_valid(cls, message_type: str) -> bool:
        """
        Check if a message type is valid.

        Args:
            message_type: The message type to validate

        Returns:
            True if the message type is valid, False otherwise
        """
        return message_type in cls.VALID_TYPES

    @classmethod
    def is_model_type(cls, message_type: str) -> bool:
        """
        Check if a message type is a model/final response type.

        Args:
            message_type: The message type to check

        Returns:
            True if it's a model type, False otherwise
        """
        return message_type in cls.MODEL_TYPES

    @classmethod
    def is_step_type(cls, message_type: str) -> bool:
        """
        Check if a message type is a step type (step/thought).

        Args:
            message_type: The message type to check

        Returns:
            True if it's a step type, False otherwise
        """
        return message_type in cls.STEP_TYPES

    @classmethod
    def is_approval_type(cls, message_type: str) -> bool:
        """
        Check if a message type requires approval.

        Args:
            message_type: The message type to check

        Returns:
            True if it requires approval, False otherwise
        """
        return message_type in cls.APPROVAL_TYPES

    @classmethod
    def is_error_type(cls, message_type: str) -> bool:
        """
        Check if a message type is an error.

        Args:
            message_type: The message type to check

        Returns:
            True if it's an error type, False otherwise
        """
        return message_type in cls.ERROR_TYPES


class AgentixMessages:
    """
    User-facing messages and UI text for Agentix AI Assistant interactions.
    These messages are platform-agnostic and can be used across different integrations.
    """
    
    # Bot display name (used when replacing bot mentions in messages sent to backend)
    BOT_DISPLAY_NAME = "Cortex Assistant"
    
    # Commands
    RESET_SESSION_COMMAND = "reset session"

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
    RESET_SESSION_CANNOT_RESET_AWAITING_SELECTION = "Cannot reset - still waiting for agent selection. No conversation has started yet."
    RESET_SESSION_CANNOT_RESET_PROCESSING = "Cannot reset session while processing a message. Please wait for the response to complete."
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


class AgentixActionIds:
    """
    Action IDs for Agentix interactive elements.
    Centralized constants for easy maintenance.
    """
    
    # Interactive action IDs
    AGENT_SELECTION = "agent_selection"
    APPROVAL_YES = "yes_btn"
    APPROVAL_NO = "no_btn"
    FEEDBACK = "agentix_feedback"
    
    # Agent selection value prefix
    AGENT_SELECTION_VALUE_PREFIX = "agentix-agent-selection-"
    
    # Modal callback IDs
    FEEDBACK_MODAL_CALLBACK_ID = "agentix_feedback_modal"
    
    # Feedback modal block IDs
    FEEDBACK_MODAL_QUICK_BLOCK_ID = "quick_feedback_block"
    FEEDBACK_MODAL_TEXT_BLOCK_ID = "feedback_text_block"
    
    # Feedback modal action IDs
    FEEDBACK_MODAL_CHECKBOXES_ACTION_ID = "quick_feedback_checkboxes"
    FEEDBACK_MODAL_TEXT_INPUT_ACTION_ID = "feedback_text_input"
    
    # All valid action IDs
    VALID_ACTION_IDS = {AGENT_SELECTION, APPROVAL_YES, APPROVAL_NO, FEEDBACK}
    
    @classmethod
    def is_valid(cls, action_id: str) -> bool:
        """
        Check if an action ID is valid.
        
        Args:
            action_id: The action ID to validate
            
        Returns:
            True if the action ID is valid, False otherwise
        """
        return action_id in cls.VALID_ACTION_IDS


class AgentixMessagingHandler:
    """
    Base class for handling Agentix messaging across different platforms.
    This class contains the platform-agnostic logic for handling Agentix interactions.
    Platform-specific implementations (Slack, Teams, etc.) should inherit from this class
    and implement the abstract methods.
    """
    
    def __init__(self):
        """Initialize the messaging handler"""
    
    # ============================================================================
    # Abstract methods - must be implemented by platform-specific subclasses
    # ============================================================================
    
    async def send_message(
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
        raise NotImplementedError("Subclass must implement send_message()")
    
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
    
    async def get_conversation_history(
        self,
        channel_id: str,
        thread_ts: str,
        limit: int = 20
    ) -> list:
        """
        Get conversation history.
        Must be implemented by subclass.
        
        Args:
            channel_id: The channel ID
            thread_ts: The thread timestamp
            limit: Maximum number of messages to retrieve
            
        Returns:
            List of messages
        """
        raise NotImplementedError("Subclass must implement get_conversation_history()")
    
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
    
    def send_new_message(
        self,
        channel_id: str,
        thread_id: str,
        blocks: list,
        attachments: list,
    ) -> Optional[dict]:
        """
        Send a new message to the platform.
        Must be implemented by subclass.
        
        Args:
            channel_id: The channel ID
            thread_id: The thread ID
            blocks: Message blocks
            attachments: Message attachments
            
        Returns:
            Response dict with 'ts' (message timestamp) if successful, None otherwise
        """
        raise NotImplementedError("Subclass must implement send_new_message()")
    
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
    
    def send_or_update_message(
        self,
        channel_id: str,
        thread_id: str,
        message_type: str,
        blocks: list,
        attachments: list,
        agentix: dict,
        agentix_id_key: str,
    ) -> dict:
        """
        Send or update a message based on message type.
        Platform-agnostic implementation that uses platform-specific methods.
        
        Args:
            channel_id: The channel ID
            thread_id: The thread ID
            message_type: The message type
            blocks: Message blocks
            attachments: Message attachments
            agentix: The agentix context
            agentix_id_key: The conversation key
            
        Returns:
            Updated agentix dictionary
        """
        step_message_ts = agentix.get(agentix_id_key, {}).get("step_message_ts")
        
        if AgentixMessageType.is_step_type(message_type):
            # For step types, update existing message if it exists, otherwise create new one
            if step_message_ts:
                # Update existing step message
                demisto.debug(f"Updating existing step message {step_message_ts} with new content")
                success = self.update_existing_message(channel_id, thread_id, step_message_ts, attachments)
                if not success:
                    # Fallback: send as new message
                    demisto.error("Failed to update step message, sending as new message")
                    response = self.send_new_message(channel_id, thread_id, blocks, attachments)
                    if response and agentix_id_key in agentix:
                        agentix[agentix_id_key]["step_message_ts"] = response.get("ts")
            else:
                # Send new step message and save its timestamp
                response = self.send_new_message(channel_id, thread_id, blocks, attachments)
                if response and agentix_id_key in agentix:
                    agentix[agentix_id_key]["step_message_ts"] = response.get("ts")
                    demisto.debug(f"Saved step message timestamp: {response.get('ts')}")
        else:
            # For non-step types (model, approval, error), always send as new message
            self.send_new_message(channel_id, thread_id, blocks, attachments)
            
            # Finalize Plan message when sending final response
            if AgentixMessageType.is_model_type(message_type) and agentix_id_key in agentix:
                # Update Plan header to remove "updating..." if step_message_ts exists
                if step_message_ts:
                    self.finalize_plan_header(channel_id, thread_id, step_message_ts)
                # Clear step_message_ts
                agentix[agentix_id_key].pop("step_message_ts", None)
        
        return agentix
    
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
        thread_ts: str,
    ):
        """
        Open a feedback modal for negative feedback collection.
        Must be implemented by subclass.
        
        Args:
            trigger_id: The trigger ID for opening the modal
            message_id: The message ID for tracking
            channel_id: The channel ID
            thread_ts: The thread timestamp
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
        
        demisto.agentixCommands("rateConversation", args)
    
    # ============================================================================
    # Platform-agnostic methods - shared logic across all platforms
    # ============================================================================
    
    def cleanup_expired_conversations(self, agentix: dict) -> dict:
        """
        Cleans up expired conversations from the agentix context.
        Each status has a different timeout duration:
        - AWAITING_BACKEND_RESPONSE: 2 minutes
        - RESPONDING_WITH_PLAN: 2 minutes
        - AWAITING_AGENT_SELECTION: 7 days
        - AWAITING_SENSITIVE_ACTION_APPROVAL: 14 days
        
        Args:
            agentix: The agentix context dictionary
            
        Returns:
            Updated agentix dictionary with expired conversations removed
        """
        if not agentix:
            return agentix
        
        expired_keys = []
        
        for agentix_id_key, conversation in agentix.items():
            status = conversation.get("status", "")
            last_updated = conversation.get("last_updated", 0)
            
            # Check if conversation has expired
            if AgentixStatus.is_expired(status, last_updated):
                expired_keys.append(agentix_id_key)
                demisto.debug(
                    f"Conversation {agentix_id_key} expired (status: {status}, "
                    f"last_updated: {last_updated}, timeout: {AgentixStatus.get_timeout_for_status(status)}s)"
                )
        
        # Remove expired conversations
        for key in expired_keys:
            del agentix[key]
            demisto.info(f"Cleaned up expired conversation: {key}")
        
        if expired_keys:
            demisto.info(f"Cleaned up {len(expired_keys)} expired conversations")
        
        return agentix
    
    def check_and_cleanup_agentix_conversations(self):
        """
        Checks and cleans up expired Agentix conversations from integration context.
        This should be called periodically (e.g., in long_running_loop).
        Handles loading from context, cleanup, and saving back to context.
        """
        try:
            # Get integration context
            integration_context = get_integration_context(sync=True)
            agentix = integration_context.get("agentix", {})
            
            # Parse if it's a string
            if isinstance(agentix, str):
                agentix = json.loads(agentix)
            
            if not agentix:
                return
            
            # Store original count before cleanup
            original_count = len(agentix)
            
            # Cleanup expired conversations
            cleaned_agentix = self.cleanup_expired_conversations(agentix)
            
            # Update context if anything was cleaned
            if len(cleaned_agentix) != original_count:
                demisto.debug(f"Updating context after cleanup: {original_count} -> {len(cleaned_agentix)} conversations")
                set_to_integration_context_with_retries(
                    {"agentix": cleaned_agentix},
                    sync=True
                )
        except Exception as e:
            demisto.error(f"Failed to cleanup expired Agentix conversations: {e}")
    
    async def handle_reset_session(
        self,
        text: str,
        user_id: str,
        channel_id: str,
        thread_ts: str,
        agentix: dict,
        agentix_id_key: str,
        bot_id: str,
    ) -> tuple[bool, dict]:
        """
        Handles reset session command.
        Checks if the message is exactly "@BotName reset session" (case-insensitive).
        
        Args:
            text: The message text
            user_id: The user ID
            channel_id: The channel ID
            thread_ts: The thread timestamp
            agentix: The agentix context dictionary
            agentix_id_key: The unique key for this conversation
            bot_id: The bot user ID
            
        Returns:
            Tuple of (is_reset_command, updated_agentix)
        """
        # Check for exact "reset session" command
        # Format: @BotName reset session (with optional whitespace)
        bot_mention = self.format_user_mention(bot_id)
        # Remove the bot mention and check if remaining text is exactly "reset session"
        text_without_mention = text.replace(bot_mention, "").strip()
        
        if text_without_mention.lower() != AgentixMessages.RESET_SESSION_COMMAND:
            return False, agentix
        
        demisto.debug(f"Reset session command detected for {agentix_id_key}")
        
        # Check status to determine if reset is allowed
        if agentix_id_key in agentix:
            status = agentix[agentix_id_key].get("status", "")
            
            # Cannot reset while waiting for agent selection (no conversation started yet)
            if status == AgentixStatus.AWAITING_AGENT_SELECTION:
                await self.send_message(
                    channel_id,
                    AgentixMessages.RESET_SESSION_CANNOT_RESET_AWAITING_SELECTION,
                    thread_id=thread_ts,
                    ephemeral=True,
                    user_id=user_id
                )
                return True, agentix
            
            # Cannot reset while processing
            if status == AgentixStatus.AWAITING_BACKEND_RESPONSE:
                await self.send_message(
                    channel_id,
                    AgentixMessages.RESET_SESSION_CANNOT_RESET_PROCESSING,
                    thread_id=thread_ts,
                    ephemeral=True,
                    user_id=user_id
                )
                return True, agentix
            
            # Cannot reset while responding
            if status == AgentixStatus.RESPONDING_WITH_PLAN:
                await self.send_message(
                    channel_id,
                    AgentixMessages.RESET_SESSION_CANNOT_RESET_RESPONDING,
                    thread_id=thread_ts,
                    ephemeral=True,
                    user_id=user_id
                )
                return True, agentix
        
        # For AWAITING_SENSITIVE_ACTION_APPROVAL or no lock - allow reset
        # Call backend to reset conversation
        response = demisto.agentixCommands(
            "resetConversation",
            {
                "channel_id": channel_id,
                "thread_id": thread_ts,
            }
        )
        
        if isinstance(response, dict) and response.get("success"):
            demisto.debug(f"Successfully reset conversation {agentix_id_key}")
            # Remove from agentix context
            if agentix_id_key in agentix:
                del agentix[agentix_id_key]
            
            await self.send_message(
                channel_id,
                AgentixMessages.RESET_SESSION_SUCCESS,
                thread_id=thread_ts,
                ephemeral=True,
                user_id=user_id
            )
        elif isinstance(response, dict) and "No active session" in str(response.get("error", "")):
            # Backend says no active session
            await self.send_message(
                channel_id,
                AgentixMessages.RESET_SESSION_NO_ACTIVE_SESSION,
                thread_id=thread_ts,
                ephemeral=True,
                user_id=user_id
            )
        else:
            demisto.error(f"Failed to reset conversation: {response}")
            await self.send_message(
                channel_id,
                AgentixMessages.RESET_SESSION_FAILED,
                thread_id=thread_ts,
                ephemeral=True,
                user_id=user_id
            )
        
        return True, agentix
    
    async def handle_modal_submission(
        self,
        message_id: str,
        channel_id: str,
        thread_ts: str,
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
            thread_ts: The thread timestamp
            user_id: The user ID
            user_email: The user's email
            issues: List of selected issues
            feedback_text: Additional feedback text
        """
        # Send negative feedback with checkboxes and text to backend
        await self.submit_feedback(
            message_id=message_id,
            feedback_score=0,
            thread_id=thread_ts,
            channel_id=channel_id,
            username=user_email,
            issues=issues,
            message=feedback_text,
        )

        # Send confirmation message (ephemeral)
        await self.send_message(
            channel_id,
            AgentixMessages.FEEDBACK_THANK_YOU,
            thread_id=thread_ts,
            ephemeral=True,
            user_id=user_id
        )
        demisto.debug(f"Submitted negative feedback for message {message_id}: issues={issues}, text={feedback_text}")
    
    async def handle_action(
        self,
        actions: list,
        user_id: str,
        user_email: str,
        channel_id: str,
        thread_ts: str,
        message: dict,
        agentix: dict,
        agentix_id_key: str,
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
            thread_ts: The thread timestamp
            message: The message dict from payload
            agentix: The agentix context dictionary
            agentix_id_key: The unique key for this conversation
            trigger_id: The trigger ID for modals
            
        Returns:
            Updated agentix dictionary
        """
        from datetime import UTC, datetime
        
        message_ts = message.get("ts", "")
        demisto.debug(f"Processing interactive response for user {user_id}")

        # Decode the action payload
        action = actions[0]
        action_id = action.get("action_id", "")
        action_value = action.get("value", "")

        # OPTION 1: Feedback Buttons
        if action_id == AgentixActionIds.FEEDBACK:
            demisto.debug(f"User provided feedback: action_id={action_id}, value={action_value}")
            
            # Value format: "positive-message_id" or "negative-message_id"
            parts = action_value.split("-")
            if len(parts) == 2:
                feedback_type, message_id = parts
                is_positive = feedback_type == "positive"
            else:
                demisto.error(f"Invalid feedback value format: {action_value}")
                return agentix
            
            if is_positive:
                # Positive feedback - send immediately
                await self.submit_feedback(
                    message_id=message_id,
                    feedback_score=1,
                    thread_id=thread_ts,
                    channel_id=channel_id,
                    username=user_email,
                )
                
                # Send confirmation message (ephemeral)
                await self.send_message(
                    channel_id,
                    AgentixMessages.FEEDBACK_THANK_YOU,
                    thread_id=thread_ts,
                    ephemeral=True,
                    user_id=user_id
                )
            else:
                # Negative feedback - open modal
                if trigger_id:
                    try:
                        await self.open_feedback_modal(trigger_id, message_id, channel_id, thread_ts)
                    except Exception as e:
                        demisto.error(f"Failed to open feedback modal: {e}")
                        # Fallback to ephemeral message
                        await self.send_message(
                            channel_id,
                            AgentixMessages.FEEDBACK_THANK_YOU,
                            thread_id=thread_ts,
                            ephemeral=True,
                            user_id=user_id
                        )
            
            # Feedback doesn't require active conversation
            return agentix
        
        # For other actions, check if conversation exists
        if agentix_id_key not in agentix:
            demisto.debug(f"No active conversation found for {agentix_id_key}")
            return agentix

        locked_user = agentix[agentix_id_key].get("user", "")

        # OPTION 2: Agent Selection
        if action_id == AgentixActionIds.AGENT_SELECTION:
            selected_option = action.get("selected_option", {})
            option_value = selected_option.get("value", "")
            original_message = agentix[agentix_id_key].get("message", "")

            demisto.debug(f"User selected an agent: {option_value}")

            if user_id == locked_user:
                # Correct user selected an agent
                selected_agent_id = option_value.replace(AgentixActionIds.AGENT_SELECTION_VALUE_PREFIX, "")
                selected_agent_name = selected_option.get("text", {}).get("text", "")
                
                # Send message to backend with selected agent
                response = demisto.agentixCommands(
                    "sendToConversation",
                    {
                        "channel_id": channel_id,
                        "thread_id": thread_ts,
                        "message": original_message,
                        "username": user_email,
                        "agent_id": selected_agent_id,
                    }
                )
                
                demisto.debug(f"Agent selection response: {response}")
                
                # Check if backend call was successful
                if isinstance(response, dict) and response.get("success"):
                    # Update the original message to show selection
                    await self.update_message(
                        channel_id,
                        message_ts,
                        text=f"Selected agent: {selected_agent_name}",
                        blocks=[]
                    )

                    # Update status
                    agentix[agentix_id_key]["status"] = AgentixStatus.AWAITING_BACKEND_RESPONSE
                    agentix[agentix_id_key]["selected_agent"] = selected_agent_id
                    agentix[agentix_id_key]["last_updated"] = datetime.now(UTC).timestamp()
                else:
                    # Backend call failed - show error and keep status as AWAITING_AGENT_SELECTION
                    error_message = response.get("error", "Unknown error") if isinstance(response, dict) else str(response)
                    demisto.error(f"Failed to send agent selection to backend: {error_message}")
                    
                    # Send ephemeral error message to user
                    await self.send_message(
                        channel_id,
                        AgentixMessages.AGENT_SELECTION_FAILED,
                        thread_id=thread_ts,
                        ephemeral=True,
                        user_id=user_id
                    )
                    # Keep the conversation in AWAITING_AGENT_SELECTION status so user can try again
            else:
                # Wrong user trying to select
                error_msg = AgentixMessages.CANNOT_SELECT_AGENT.format(
                    locked_user_tag=self.format_user_mention(locked_user)
                )
                await self.send_message(channel_id, error_msg, thread_id=thread_ts, ephemeral=True, user_id=user_id)

        # OPTION 3: Sensitive Action Approval
        elif action_id in [AgentixActionIds.APPROVAL_YES, AgentixActionIds.APPROVAL_NO]:
            demisto.debug(f"User responded to sensitive action: action_id={action_id}")

            if user_id == locked_user:
                # Correct user responded
                is_approved = action_id == AgentixActionIds.APPROVAL_YES

                # Send response to backend
                demisto.agentixCommands(
                    "sendToConversation",
                    {
                        "channel_id": channel_id,
                        "thread_id": thread_ts,
                        "message": "Yes" if is_approved else "No",
                        "username": user_email,
                        "is_approved": is_approved,
                    }
                )

                # Update the original message
                decision_indicator = AgentixMessages.DECISION_APPROVED if is_approved else AgentixMessages.DECISION_CANCELLED
                original_blocks = message.get("blocks", [])
                updated_blocks = [block for block in original_blocks if block.get("type") != "actions"]
                updated_blocks.append({
                    "type": "context",
                    "elements": [{"type": "mrkdwn", "text": decision_indicator}]
                })
                
                try:
                    await self.update_message(channel_id, message_ts, blocks=updated_blocks)
                except Exception as e:
                    demisto.error(f"Failed to update approval message: {e}")
                    # Fallback
                    await self.update_message(channel_id, message_ts, text=decision_indicator, blocks=[])

                # Update status
                agentix[agentix_id_key]["status"] = AgentixStatus.AWAITING_BACKEND_RESPONSE
                agentix[agentix_id_key]["sensitive_action_response"] = "approved" if is_approved else "rejected"
                agentix[agentix_id_key]["last_updated"] = datetime.now(UTC).timestamp()
            else:
                # Wrong user trying to respond
                error_msg = AgentixMessages.CANNOT_APPROVE_ACTION.format(
                    locked_user_tag=self.format_user_mention(locked_user)
                )
                await self.send_message(channel_id, error_msg, thread_id=thread_ts, ephemeral=True, user_id=user_id)
        
        return agentix
    
    async def handle_bot_mention(
        self,
        text: str,
        user_id: str,
        user_email: str,
        channel_id: str,
        thread_ts: str,
        agentix: dict,
        agentix_id_key: str,
        bot_id: str,
        message_ts: str,
    ) -> dict:
        """
        Handles when the bot is mentioned in a message for Agentix AI Assistant.
        This is platform-agnostic logic.

        Args:
            text: The message text
            user_id: The user ID
            user_email: The user's email
            channel_id: The channel ID
            thread_ts: The thread timestamp
            agentix: The agentix context dictionary
            agentix_id_key: The unique key for this conversation
            bot_id: The bot user ID
            message_ts: The current message timestamp
            
        Returns:
            Updated agentix dictionary - to be saved by caller
        """
        
        # Check for "reset session" command first
        is_reset, agentix = await self.handle_reset_session(
            text, user_id, channel_id, thread_ts, agentix, agentix_id_key, bot_id
        )
        if is_reset:
            return agentix

        # Check if there's already an active conversation
        if agentix_id_key in agentix:
            status = agentix[agentix_id_key].get("status", "")
            locked_user = agentix[agentix_id_key].get("user", "")

            # Determine the appropriate message
            message_to_send = None

            if AgentixStatus.is_awaiting_user_action(status):
                # Waiting for user action (agent selection or approval)
                if locked_user == user_id:
                    # Show specific message based on what we're waiting for
                    if status == AgentixStatus.AWAITING_AGENT_SELECTION:
                        message_to_send = AgentixMessages.AWAITING_AGENT_SELECTION
                    elif status == AgentixStatus.AWAITING_SENSITIVE_ACTION_APPROVAL:
                        message_to_send = AgentixMessages.AWAITING_APPROVAL_RESPONSE
                else:
                    message_to_send = AgentixMessages.ONLY_LOCKED_USER_CAN_RESPOND.format(
                        bot_tag=self.format_user_mention(bot_id),
                        locked_user_tag=self.format_user_mention(locked_user)
                    )

            elif status == AgentixStatus.AWAITING_BACKEND_RESPONSE:
                # Already processing a previous message
                message_to_send = AgentixMessages.ALREADY_PROCESSING

            elif status == AgentixStatus.RESPONDING_WITH_PLAN:
                # Currently responding with a plan
                if locked_user == user_id:
                    message_to_send = AgentixMessages.WAITING_FOR_COMPLETION
                else:
                    message_to_send = AgentixMessages.ONLY_LOCKED_USER_CAN_RESPOND.format(
                        bot_tag=self.format_user_mention(bot_id),
                        locked_user_tag=self.format_user_mention(locked_user)
                    )

            # Send message if needed
            if message_to_send:
                await self.send_message(
                    channel_id, message_to_send, thread_id=thread_ts, ephemeral=True, user_id=user_id
                )
            return agentix

        # Get conversation context (up to 5 previous messages)
        context = await self.get_conversation_context_formatted(channel_id, thread_ts, bot_id, message_ts)
        
        # Replace bot mention with friendly display name for backend
        bot_mention = self.format_user_mention(bot_id)
        text_cleaned = text.replace(bot_mention, AgentixMessages.BOT_DISPLAY_NAME).strip()
        
        # Prepare message with context
        message_with_context = text_cleaned
        if context:
            message_with_context = f"{context}\n**Current message**:\n{text_cleaned}"
        
        # Send message to backend using agentixIntegrations
        demisto.debug(f"Sending message to Agentix backend for user {user_email} in channel {channel_id}")
        demisto.debug(f"Message content: {message_with_context}")
        response = demisto.agentixCommands(
            "sendToConversation",
            {
                "channel_id": channel_id,
                "thread_id": thread_ts,
                "message": message_with_context,
                "username": user_email,
            }
        )
        demisto.debug(f"sendToConversation {response=}")

        # Check if response contains agent list (requires user to select an agent)
        if "agents" in response:
            agents_list = response.get("agents", [])
            # TODO: remove
            agents_list = [{"id": "agent_1", "name": "Agent 1"}, {"id": "threat-intel-agent", "name": "Threat Intel"}]
            # Check if agents list is empty or UI creation failed
            if agents_list:
                # Backend returned a list of agents - user needs to select one
                demisto.debug(f"Received agent list with {len(agents_list)} agents")
                
                # Create agent selection UI
                agent_selection_blocks = self.create_agent_selection_ui(agents_list)
                
                if agent_selection_blocks:
                    # Send agent selection UI
                    await self.send_message(channel_id, "", thread_ts, blocks=agent_selection_blocks)
                    
                    # Lock the conversation with agent selection status
                    from datetime import UTC, datetime
                    agentix[agentix_id_key] = {
                        "date": thread_ts,
                        "user": user_id,
                        "message": message_with_context,
                        "channel_id": channel_id,
                        "thread_ts": thread_ts,
                        "status": AgentixStatus.AWAITING_AGENT_SELECTION,
                        "last_updated": datetime.now(UTC).timestamp(),
                    }
                    
                    demisto.debug(
                        f"Created new Agentix conversation {agentix_id_key} with status {AgentixStatus.AWAITING_AGENT_SELECTION}"
                    )
                else:
                    # Failed to create agent selection UI
                    demisto.error("Failed to create agent selection UI despite having agents")
                    await self.send_message(
                        channel_id,
                        AgentixMessages.NO_AGENTS_AVAILABLE,
                        thread_id=thread_ts,
                        ephemeral=True,
                        user_id=user_id
                    )
            else:
                # Empty agents list
                demisto.error("Received empty agents list from backend")
                await self.send_message(
                    channel_id,
                    AgentixMessages.NO_AGENTS_AVAILABLE,
                    thread_id=thread_ts,
                    ephemeral=True,
                    user_id=user_id
                )
        
        elif isinstance(response, dict) and response.get("success"):
            # Lock the conversation with initial status
            from datetime import UTC, datetime
            agentix[agentix_id_key] = {
                "date": thread_ts,
                "user": user_id,
                "message": text,
                "channel_id": channel_id,
                "thread_ts": thread_ts,
                "status": AgentixStatus.AWAITING_BACKEND_RESPONSE,
                "last_updated": datetime.now(UTC).timestamp(),
            }

            demisto.debug(
                f"Created new Agentix conversation {agentix_id_key} with status {AgentixStatus.AWAITING_BACKEND_RESPONSE}"
            )
        elif "User not authorized for this thread" in str(response):
            error_msg = AgentixMessages.NOT_AUTHORIZED.format(bot_tag=self.format_user_mention(bot_id))
            await self.send_message(channel_id, error_msg, thread_id=thread_ts, ephemeral=True, user_id=user_id)
        else:
            # Permission error or other issue - don't lock
            demisto.debug(f"demisto.agentixIntegrations() failed for user {user_email}: {response}")
        
        return agentix
    
    async def get_conversation_context_formatted(
        self,
        channel_id: str,
        thread_ts: str,
        bot_id: str,
        current_message_ts: str
    ) -> str:
        """
        Retrieves and formats conversation context.
        Platform-agnostic logic that uses platform-specific methods.
        
        Args:
            channel_id: The channel ID
            thread_ts: The thread timestamp
            bot_id: The bot user ID
            current_message_ts: The current message timestamp
            
        Returns:
            Formatted context string
        """
        try:
            # Get conversation history using platform-specific method
            messages = await self.get_conversation_history(channel_id, thread_ts, limit=20)
            
            if not messages:
                return ""
            
            # Filter and collect context messages
            context_messages = []
            bot_mention = self.format_user_mention(bot_id)
            
            for msg in reversed(messages):  # Process from oldest to newest
                msg_ts = msg.get("ts", "")
                msg_text = msg.get("text", "")
                msg_user = msg.get("user", "")
                msg_bot_id = msg.get("bot_id", "")
                
                # Skip current message
                if msg_ts == current_message_ts:
                    continue
                
                # Skip bot messages
                if msg_bot_id or msg_user == bot_id:
                    continue
                
                # Stop if we hit a previous bot mention
                if bot_mention in msg_text and msg_ts != current_message_ts:
                    break
                
                # Add to context
                if msg_text and msg_user:
                    # Get user name
                    try:
                        user_info = await self.get_user_info(msg_user)
                        user_name = user_info.get("real_name", user_info.get("name", msg_user))
                    except Exception:
                        user_name = msg_user
                    
                    context_messages.append({
                        "user": user_name,
                        "text": msg_text,
                        "ts": msg_ts
                    })
                
                # Limit to 5 messages
                if len(context_messages) >= 5:
                    break
            
            # Format context messages
            if not context_messages:
                return ""
            
            # Create formatted context string
            context_lines = ["--- Previous conversation context ---"]
            for ctx_msg in reversed(context_messages):  # Show oldest first
                context_lines.append(f"**{ctx_msg['user']}**: {ctx_msg['text']}")
            context_lines.append("--- End of context ---")
            context_lines.append("")  # Empty line before current message
            
            return "\n".join(context_lines)
            
        except Exception as e:
            demisto.error(f"Failed to get conversation context: {e}")
            return ""
    
    def send_agent_response(
        self,
        channel_id: str,
        thread_id: str,
        message: str,
        message_type: str,
        message_id: str = "",
        completed: bool = False,
        agentix: dict | None = None,
        agentix_id_key: str = "",
    ) -> dict:
        """
        Sends an agent response and updates the Agentix status accordingly.
        This is platform-agnostic logic that uses platform-specific methods.
        
        Args:
            channel_id: The channel ID
            thread_id: The thread ID
            message: The message text
            message_type: The message type (from AgentixMessageType)
            message_id: Optional message ID for feedback tracking
            completed: Whether this is the final response
            agentix: The agentix context dictionary
            agentix_id_key: The unique key for this conversation
            
        Returns:
            Updated agentix dictionary
            
        Raises:
            ValueError: If message_type is not valid
        """
        # Validate message_type
        if not AgentixMessageType.is_valid(message_type):
            error_msg = (
                f"Invalid message_type: '{message_type}'. "
                f"Must be one of: {', '.join(sorted(AgentixMessageType.VALID_TYPES))}"
            )
            demisto.error(error_msg)
            raise ValueError(error_msg)
        
        if not agentix:
            agentix = {}

        # Replace escaped characters with actual characters
        message = message.replace("\\n", "\n")
        message = message.replace('\\"', '"')
        message = message.replace("\\'", "'")
        
        # Check if this is an update (step_message_ts exists in agentix)
        is_update = agentix.get(agentix_id_key, {}).get("step_message_ts") is not None if AgentixMessageType.is_step_type(message_type) else False
        
        # Prepare blocks and attachments using platform-specific method
        blocks, attachments = self.prepare_message_blocks(message, message_type, is_update)
        if not blocks:
            blocks = []
        
        # Variables for status update
        new_status = None
        should_release_lock = False
        
        # Handle different message types
        if AgentixMessageType.is_model_type(message_type):
            # MODEL TYPES - Final responses
            should_release_lock = completed
            # Add feedback buttons for final responses
            if message_id:
                blocks.append(self.create_feedback_ui(message_id))
        
        elif AgentixMessageType.is_approval_type(message_type):
            # APPROVAL - Sensitive action requiring approval
            blocks.extend(self.create_approval_ui())
            new_status = AgentixStatus.AWAITING_SENSITIVE_ACTION_APPROVAL
        
        elif AgentixMessageType.is_step_type(message_type):
            # STEP TYPES - Plan steps
            new_status = AgentixStatus.RESPONDING_WITH_PLAN
        
        elif AgentixMessageType.is_error_type(message_type):
            # ERROR - release lock immediately
            should_release_lock = True
        
        # Send or update message using platform-specific method
        agentix = self.send_or_update_message(channel_id, thread_id, message_type, blocks, attachments, agentix, agentix_id_key)
        
        # Update context based on message type
        if agentix_id_key in agentix:
            if should_release_lock:
                # Release the lock
                del agentix[agentix_id_key]
                self.update_context({"agentix": agentix})
                demisto.debug(f"Released lock for {agentix_id_key}")
            elif new_status:
                # Update status
                from datetime import UTC, datetime
                agentix[agentix_id_key]["status"] = new_status
                agentix[agentix_id_key]["last_updated"] = datetime.now(UTC).timestamp()
                self.update_context({"agentix": agentix})
                demisto.debug(f"Updated status for {agentix_id_key} to {new_status}")
        
        demisto.results("Agent response sent successfully.")
        return agentix
