"""Integration for Google Gemini AI Assistant.

This integration provides AI-powered analysis and chat capabilities for XSOAR users.
Supports both Google AI Studio (API key) and Vertex AI (service account) authentication.
"""

from google.auth.transport.requests import Request
from google.oauth2 import service_account
from uuid import uuid4
from typing import Any
import json
import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa


""" CONSTANTS """
DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"  # ISO8601
SUPPORTED_MODELS = [
    # Stable text models
    "gemini-2.5-flash",
    "gemini-2.5-pro",
    "gemini-3.1-flash-lite",
    "gemini-3.5-flash-lite",
    "gemini-3.5-flash",
    "gemini-3.6-flash",
    "gemini-3.7-flash",
    "gemini-3.8-flash",
]
AUTH_TYPE_AI_STUDIO = "AI Studio API Key"
AUTH_TYPE_VERTEX_AI = "Vertex AI Service Account"
VERTEX_AI_BASE_URL = "https://aiplatform.googleapis.com"
GOOGLE_AUTH_SCOPE = "https://www.googleapis.com/auth/cloud-platform"

AUTH_TYPE_AI_STUDIO = "AI Studio API Key"
AUTH_TYPE_VERTEX_AI = "Vertex AI Service Account"
VERTEX_AI_BASE_URL = "https://aiplatform.googleapis.com"
GOOGLE_AUTH_SCOPE = "https://www.googleapis.com/auth/cloud-platform"


def arg_to_float(value: Any) -> float | None:
    """Converts an argument to a float, returning None for empty/missing values.

    Unlike arg_to_number (which always truncates to int), this preserves decimal precision,
    which is required for parameters such as temperature and top_p.

    :param value: The value to convert.
    :return: The float value, or None if empty/missing.
    """
    if value is None:
        return None
    value = str(value).strip()
    if not value:
        return None
    try:
        return float(value)
    except ValueError:
        raise ValueError(f'"{value}" is not a valid number')


class Client(BaseClient):
    """Client to interact with the Google Gemini API.

    Supports both AI Studio (API key) and Vertex AI (service account) authentication.
    It inherits from BaseClient which handles proxy, SSL verification, etc.
    """

    def __init__(
        self,
        base_url: str,
        verify: bool,
        proxy: bool,
        auth_type: str,
        model: str = "gemini-2.5-flash",
        max_tokens: int = 1024,
        temperature: float | None = None,
        top_p: float | None = None,
        top_k: int | None = None,
        api_key: str | None = None,
        service_account_json: str | None = None,
        project_id: str | None = None,
        location: str = "global",
    ):
        """Initialize Client class.

        :param base_url: The base URL of the API.
        :param verify: Whether to verify SSL certificate.
        :param proxy: Whether to use system proxy settings.
        :param auth_type: Authentication type - AI Studio API Key or Vertex AI Service Account.
        :param model: The default Gemini model to use for requests.
        :param max_tokens: Default maximum tokens for responses.
        :param temperature: Default temperature for response generation.
        :param top_p: Default top-p value for response generation.
        :param top_k: Default top-k value for response generation.
        :param api_key: API key for AI Studio authentication.
        :param service_account_json: Service account JSON key for Vertex AI authentication.
        :param project_id: Google Cloud project ID for Vertex AI.
        :param location: Google Cloud location for Vertex AI (default: global).
        """
        super().__init__(base_url=base_url, verify=verify, proxy=proxy)
        self.auth_type = auth_type
        self.model = model
        self.max_tokens = max_tokens
        self.temperature = temperature
        self.top_p = top_p
        self.top_k = top_k

        if auth_type == AUTH_TYPE_AI_STUDIO:
            self.api_key = api_key
            self._headers = {
                "Content-Type": "application/json",
                "Accept": "application/json",
                "x-goog-api-key": self.api_key,
            }
        else:
            try:
                self.service_account_info: dict[str, Any] = json.loads(service_account_json) if service_account_json else {}
            except json.JSONDecodeError as e:
                raise ValueError(f"Invalid Service Account JSON provided: {e}")
            self.project_id = project_id
            self.location = location or "global"
            self._credentials = service_account.Credentials.from_service_account_info(
                self.service_account_info,
                scopes=[GOOGLE_AUTH_SCOPE],
            )
            self._headers = {
                "Content-Type": "application/json",
                "Accept": "application/json",
            }

    def _get_access_token(self) -> str:
        """Get a valid access token for Vertex AI using google-auth credentials.

        Refreshes the token automatically when expired.

        :return: Valid OAuth2 access token string.
        """
        if not self._credentials.valid:
            demisto.debug("Refreshing Vertex AI access token")
            self._credentials.refresh(Request())
        return self._credentials.token

    def _get_request_headers(self) -> dict[str, str] | None:
        """Get the appropriate request headers based on auth type.

        For AI Studio, returns None to use the default self._headers (with API key).
        For Vertex AI, returns headers with a fresh Bearer token.

        :return: Headers dict for Vertex AI, or None for AI Studio.
        """
        if self.auth_type == AUTH_TYPE_AI_STUDIO:
            return None
        access_token = self._get_access_token()
        return {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Authorization": f"Bearer {access_token}",
        }

    def _get_url_suffix(self, model: str, action: str = "generateContent") -> str:
        """Get the appropriate URL suffix based on auth type, model, and action.

        :param model: The model name to use.
        :param action: The API action to call (e.g. generateContent, countTokens).
        :return: URL suffix string for the given action's endpoint.
        """
        if self.auth_type == AUTH_TYPE_AI_STUDIO:
            return f"/v1beta/models/{model}:{action}"
        return f"/v1/projects/{self.project_id}/locations/{self.location}/publishers/google/models/{model}:{action}"

    @staticmethod
    def build_contents(prompt: str, history: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
        """Build the Gemini 'contents' list from a prompt and optional conversation history.

        :param prompt: The user's prompt/question.
        :param history: Optional conversation history in Gemini format.
        :return: List of content entries, history followed by the current prompt.
        """
        contents = list(history) if history else []
        contents.append({"role": "user", "parts": [{"text": prompt}]})
        return contents

    def count_tokens(self, contents: list[dict[str, Any]], model: str | None = None) -> int:
        """Count the number of input tokens a set of contents would consume.

        :param contents: Conversation contents in Gemini format (history + prompt).
        :param model: The Gemini model to use (defaults to instance default).
        :return: The total token count reported by the API.
        """
        selected_model = model or self.model
        response = self._http_request(
            method="POST",
            url_suffix=self._get_url_suffix(selected_model, action="countTokens"),
            json_data={"contents": contents},
            headers=self._get_request_headers(),
        )
        return response.get("totalTokens", 0)

    def generate_content(
        self,
        contents: list[dict[str, Any]],
        model: str | None = None,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> dict[str, Any]:
        """Send prebuilt contents to the Gemini generateContent endpoint.

        :param contents: Conversation contents in Gemini format (history + prompt).
        :param model: The Gemini model to use (defaults to instance default).
        :param temperature: Per-call temperature override (defaults to instance default).
        :param max_tokens: Per-call maximum output token override (defaults to instance default).
        :return: Dictionary containing the API response.
        """
        selected_model = model or self.model
        selected_temperature = temperature if temperature is not None else self.temperature
        selected_max_tokens = max_tokens if max_tokens is not None else self.max_tokens

        # Build generation config using instance defaults
        generation_config = assign_params(
            maxOutputTokens=selected_max_tokens, temperature=selected_temperature, topP=self.top_p, topK=self.top_k
        )

        request_body = {"contents": contents, "generationConfig": generation_config}

        return self._http_request(
            method="POST",
            url_suffix=self._get_url_suffix(selected_model),
            json_data=request_body,
            headers=self._get_request_headers(),
        )

    def send_chat_message(
        self,
        prompt: str,
        model: str | None = None,
        history: list[dict[str, Any]] | None = None,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> dict[str, Any]:
        """Send a chat message to the Gemini API with optional conversation history.

        Conversation history format:
        [
            {
                "role": "user",
                "parts": [{"text": "Previous user message"}]
            },
            {
                "role": "model",
                "parts": [{"text": "Previous AI response"}]
            }
        ]
        :param prompt: The user's prompt/question.
        :param model: The Gemini model to use (defaults to instance default).
        :param history: Optional conversation history in Gemini format.
        :param temperature: Per-call temperature override (defaults to instance default).
        :param max_tokens: Per-call maximum output token override (defaults to instance default).
        :return: Dictionary containing the API response.
        """
        contents = self.build_contents(prompt, history)
        return self.generate_content(contents, model, temperature, max_tokens)


def _truncate_to_token_budget(
    client: Client,
    contents: list[dict[str, Any]],
    model: str | None,
    max_input_tokens: int,
    max_iterations: int = 20,
) -> tuple[list[dict[str, Any]], int, bool]:
    """Shrink contents to fit within a token budget, dropping oldest history first, then trimming the prompt.

    :param client: Google Gemini API client, used to recount tokens after each truncation step.
    :param contents: Conversation contents in Gemini format (history + current prompt as the last entry).
    :param model: The Gemini model to use for token counting.
    :param max_input_tokens: The maximum number of input tokens allowed.
    :param max_iterations: Safety cap on prompt-trimming iterations.
    :return: Tuple of (possibly truncated contents, final token count, whether truncation occurred).
    """
    truncated = False

    # Drop oldest history entries first, always keeping the current prompt (the last entry).
    while len(contents) > 1:
        token_count = client.count_tokens(contents, model)
        if token_count <= max_input_tokens:
            return contents, token_count, truncated
        contents.pop(0)
        truncated = True

    # Only the prompt remains; if it alone still exceeds the budget, trim its text proportionally.
    token_count = client.count_tokens(contents, model)
    iterations = 0
    while token_count > max_input_tokens and iterations < max_iterations:
        text = contents[-1]["parts"][0]["text"]
        if len(text) <= 1:
            break
        new_len = max(1, int(len(text) * (max_input_tokens / token_count) * 0.9))
        contents[-1]["parts"][0]["text"] = text[:new_len]
        token_count = client.count_tokens(contents, model)
        truncated = True
        iterations += 1

    return contents, token_count, truncated


def test_module(client: Client):
    """Tests API connectivity and authentication.

    Uses a simple chat message to verify that the API is reachable and the provided token is valid.

    :param client: Google Gemini API client.
    :return: 'ok' if successful, or an error message string.
    """
    try:
        client.send_chat_message("Hello, please respond with 'OK' to test connectivity.")
        return "ok"
    except DemistoException as e:
        err_msg = e.message
        try:
            err_msg = demisto.get(e.res.json(), "error.message", err_msg)
        except Exception:
            pass
        return_error(f"An unexpected error occurred during connectivity test: {err_msg}")


def google_gemini_send_message_command(client: Client, args: dict[str, Any]):
    """Command function to send a chat message to the Google Gemini API with optional conversation history.

    :param client: Google Gemini API client.
    :param args: Dictionary of command arguments (prompt, model, history, save_conversation, temperature,
        max_tokens, max_input_tokens, truncate).
    :return: CommandResults object(s) with outputs and readable representation.
    """
    prompt = str(args.get("prompt", ""))
    model = args.get("model", None)
    history_arg = args.get("history", [])
    save_conversation = argToBoolean(args.get("save_conversation", False))
    temperature = arg_to_float(args.get("temperature"))
    if temperature is None:
        temperature = 0.5
    max_tokens = arg_to_number(args.get("max_tokens"))
    if max_tokens is None:
        max_tokens = client.max_tokens
    max_input_tokens = arg_to_number(args.get("max_input_tokens"))
    truncate = argToBoolean(args.get("truncate", False))

    if not prompt:
        raise ValueError("The 'prompt' argument is required.")

    history = []
    if history_arg:
        try:
            if isinstance(history_arg, str):
                history = json.loads(history_arg)
            elif isinstance(history_arg, list):
                history = history_arg
        except json.JSONDecodeError:
            raise ValueError("History must be valid JSON array of conversation objects.")

    conversation_id = None
    outputs_key_field = "prompt"
    if save_conversation:
        context = demisto.context()
        existing_history = None

        if google_gemini_context := demisto.get(context, "GoogleGemini.Chat"):
            if isinstance(google_gemini_context, dict) and "History" in google_gemini_context:
                existing_history = google_gemini_context["History"]
                conversation_id = google_gemini_context["ConversationId"]

            elif isinstance(google_gemini_context, list):
                for item in reversed(google_gemini_context):
                    if isinstance(item, dict) and "History" in item:
                        existing_history = item["History"]
                        conversation_id = item["ConversationId"]
                        break

        # trying to take the last 2 entries
        if existing_history and isinstance(existing_history, list):
            if len(existing_history) >= 2:
                history = existing_history[-2:]
            else:
                history = existing_history

    contents = client.build_contents(prompt, history)
    truncated = False

    if max_input_tokens:
        input_token_count = client.count_tokens(contents, model)
        if input_token_count > max_input_tokens:
            if not truncate:
                raise DemistoException(
                    f"Input token count ({input_token_count}) exceeds max_input_tokens ({max_input_tokens}). "
                    "Set truncate=true to automatically shorten the history and prompt to fit the budget."
                )
            contents, input_token_count, truncated = _truncate_to_token_budget(client, contents, model, max_input_tokens)

    response = client.generate_content(contents, model, temperature, max_tokens)

    content = ""
    finish_reason = ""
    if (candidates := response.get("candidates")) and len(candidates) > 0:
        parts = demisto.get(candidates[0], "content.parts")
        if parts and isinstance(parts, list) and len(parts) > 0 and isinstance(parts[0], dict):
            content = parts[0].get("text")  # type: ignore[assignment]
        else:
            finish_reason = demisto.get(candidates[0], "finishReason")

    if not content:
        content = "No response generated."
        if finish_reason:
            return_warning(f"The model finished before completing the full response, due to {finish_reason}")

    usage_metadata = response.get("usageMetadata", {})
    outputs = {
        "Prompt": prompt,
        "Response": content,
        "Model": model or client.model,
        "Temperature": temperature,
        "MaxTokens": max_tokens,
        "InputTokenCount": usage_metadata.get("promptTokenCount"),
        "OutputTokenCount": usage_metadata.get("candidatesTokenCount"),
        "TotalTokenCount": usage_metadata.get("totalTokenCount"),
        "Truncated": truncated,
    }
    if save_conversation:
        current_conversation = history.copy() if history else []
        current_conversation.append({"role": "user", "parts": [{"text": prompt}]})

        if content and content != "No response generated.":
            current_conversation.append({"role": "model", "parts": [{"text": content}]})

        outputs["History"] = current_conversation
        outputs["ConversationId"] = conversation_id or str(uuid4())
        outputs_key_field = "ConversationId"

    return CommandResults(
        outputs_prefix="GoogleGemini.Chat",
        outputs_key_field=outputs_key_field,
        outputs=outputs,
        raw_response=response,
        readable_output=content,
    )


def main():
    """Main execution function for the integration.

    Parses integration parameters and command arguments, initializes the client,
    and calls the appropriate command function.
    """
    params = demisto.params()
    auth_type = params.get("auth_type", AUTH_TYPE_AI_STUDIO)
    verify_certificate = not argToBoolean(params.get("insecure", False))
    proxy = argToBoolean(params.get("proxy", False))
    model = params.get("model", ["gemini-2.5-flash"])  # use multi select to enable adding custom val
    max_tokens = arg_to_number(params.get("max_tokens", 1024)) or 1024

    # Handle optional parameters - use defaults if empty or not provided.
    # arg_to_number always truncates to int, so temperature/top_p (decimal values) are parsed with float() instead.
    temperature = arg_to_float(params.get("temperature", ""))
    top_p = arg_to_float(params.get("top_p", ""))
    top_k = arg_to_number(params.get("top_k", "").strip())

    # Auth-specific parameters
    api_key: str | None = None
    service_account_json: str | None = None
    project_id: str | None = None
    location: str = "global"

    if auth_type == AUTH_TYPE_VERTEX_AI:
        base_url = params.get("url", VERTEX_AI_BASE_URL)
        # Auto-switch from AI Studio default URL to Vertex AI URL
        if base_url == "https://generativelanguage.googleapis.com":
            base_url = VERTEX_AI_BASE_URL
        service_account_json = params.get("service_account_key", {}).get("password")
        project_id = params.get("project_id")
        location = params.get("location", "global") or "global"
        if not service_account_json:
            return_error("Service Account Key JSON is required for Vertex AI authentication.")
            return
        if not project_id:
            return_error("Project ID is required for Vertex AI authentication.")
            return
    else:
        base_url = params.get("url", "https://generativelanguage.googleapis.com")
        api_key = params.get("api_key", {}).get("password")
        if not api_key:
            return_error("API key is not configured. Please configure it in the instance settings.")
            return

    command = demisto.command()
    demisto.debug(f"Command being called is {command}")

    try:
        if len(model) > 1:
            raise DemistoException("Please select one model only.")
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            proxy=proxy,
            auth_type=auth_type,
            model=model[0],
            max_tokens=max_tokens,
            temperature=temperature,
            top_p=top_p,
            top_k=top_k,
            api_key=api_key,
            service_account_json=service_account_json,
            project_id=project_id,
            location=location,
        )
        args = demisto.args()

        if command == "test-module":
            result = test_module(client)
        elif command == "google-gemini-send-message":
            result = google_gemini_send_message_command(client, args)
        else:
            raise NotImplementedError(f"Command {command} is not implemented")

        return_results(result)

    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
