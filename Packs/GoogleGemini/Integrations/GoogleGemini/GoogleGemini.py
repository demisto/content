"""Integration for Google Gemini AI Assistant.

This integration provides AI-powered analysis and chat capabilities for XSOAR users.
"""

from typing import Any
import json

import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa


DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"  # ISO8601
SUPPORTED_MODELS = [
    # Current stable Gemini models
    "gemini-2.0-flash",
    "gemini-2.0-flash-lite",
    "gemini-1.5-flash",
    "gemini-1.5-flash-8b",
    "gemini-1.5-pro",
    # Preview models
    "gemini-2.5-flash-preview-05-20",
    "gemini-2.5-pro-preview-05-06",
    "gemini-2.0-flash-preview-image-generation",
    # Native audio models
    "gemini-2.5-flash-preview-native-audio-dialog",
    "gemini-2.5-flash-exp-native-audio-thinking-dialog",
    # Embedding and specialized models
    "text-embedding-004",
    "models/aqa",
]


class Client(BaseClient):
    """Client to interact with the Google Gemini API.

    Handles HTTP requests to the Gemini service for AI-powered analysis.
    It inherits from BaseClient which handles proxy, SSL verification, etc.
    """

    def __init__(self, base_url: str, verify: bool, proxy: bool, api_key: str, model: str = "gemini-2.5-flash-preview-05-20"):
        """Initialize Client class.

        :param base_url: The base URL of the Gemini API.
        :param verify: Whether to verify SSL certificate.
        :param proxy: Whether to use system proxy settings.
        :param api_key: The API key for authentication.
        :param model: The default Gemini model to use for requests.
        """
        super().__init__(base_url=base_url, verify=verify, proxy=proxy)
        self.api_key = api_key
        self.model = model
        self._headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "x-goog-api-key": self.api_key,
        }

    def send_chat_message(
        self,
        prompt: str,
        model: str | None = None,
        max_tokens: int = 10000,
        temperature: float = 0.7,
        history: list[dict[str, Any]] | None = None,
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
        :param max_tokens: Maximum tokens in the response.
        :param temperature: Temperature for response generation (0.0 to 1.0).
        :param history: Optional conversation history in Gemini format.
        :return: Dictionary containing the API response.
        """
        selected_model = model or self.model
        contents = []

        if history:
            contents.extend(history)

        # Add current user prompt
        contents.append({"role": "user", "parts": [{"text": prompt}]})

        request_body = {"contents": contents, "generationConfig": {"maxOutputTokens": max_tokens, "temperature": temperature}}

        return self._http_request(
            method="POST", url_suffix=f"/v1beta/models/{selected_model}:generateContent", json_data=request_body, ok_codes=(200,)
        )


def test_module(client: Client) -> str:
    """Tests API connectivity and authentication.

    Uses a simple chat message to verify that the API is reachable and the provided token is valid.

    :param client: Google Gemini API client.
    :return: 'ok' if successful, or an error message string.
    """
    try:
        response = client.send_chat_message("Hello, please respond with 'OK' to test connectivity.", max_tokens=10)
        if response.get("error"):
            raise Exception(response.get("error"))
        return "ok"
    except Exception as e:
        return f"An unexpected error occurred during connectivity test: {str(e)}"


def googlegemini_chat_command(client: Client, args: dict[str, Any]):
    """Command function to send a chat message to the Google Gemini API with optional conversation history.

    :param client: Google Gemini API client.
    :param args: Dictionary of command arguments (prompt, model, max_tokens, temperature, history).
    :return: CommandResults object with outputs and readable representation.
    """
    prompt = str(args.get("prompt", ""))
    model = args.get("model", None)
    max_tokens = arg_to_number(args.get("max_tokens", 10000)) or 10000
    temperature = float(args.get("temperature", 0.7))
    history_arg = args.get("history", [])

    if not prompt:
        raise ValueError("The 'prompt' argument is required.")

    if model and model not in SUPPORTED_MODELS:
        warning_message = (
            f"Warning: Model '{model}' is not in the list of officially supported models by this integration version. "
            f"Attempting to use it, but it may not work as expected or could be deprecated. "
            f"Known models at the time of this integration version are: {', '.join(SUPPORTED_MODELS)}"
        )
        return_warning(warning_message)  # Posts to War Room and continues

    history = []
    if history_arg:
        try:
            if isinstance(history_arg, str):
                history = json.loads(history_arg)
            elif isinstance(history_arg, list):
                history = history_arg
        except json.JSONDecodeError:
            raise ValueError("History must be valid JSON array of conversation objects.")

    response = client.send_chat_message(prompt, model, max_tokens, temperature, history)

    if response.get("error"):
        raise Exception(f"API Error: {response.get('error')}")

    content = ""
    if (candidates := response.get("candidates")) and len(candidates) > 0:
        candidate = candidates[0]
        if (
            (content_part := candidate.get("content"))
            and (parts := content_part.get("parts"))
            and len(parts) > 0
            and (text := parts[0].get("text"))
        ):
            content = text

    if not content:
        content = "No response generated."

    return CommandResults(
        outputs_prefix="GoogleGemini.Chat",
        outputs_key_field="",
        outputs={"prompt": prompt, "response": content, "model": model or client.model, "temperature": temperature},
        raw_response=response,
        readable_output=content,
    )


def main():
    """Main execution function for the integration.

    Parses integration parameters and command arguments, initializes the client,
    and calls the appropriate command function.
    """
    params = demisto.params()
    base_url = params["url"]
    verify_certificate = not argToBoolean(params.get("insecure", False))
    proxy = argToBoolean(params.get("proxy", False))
    api_key = params.get("api_key")
    model = params.get("model", "gemini-2.5-flash-preview-05-20")

    if not api_key:
        return_error("API key is not configured. Please configure it in the instance settings.")
        return

    command = demisto.command()
    demisto.debug(f"Command being called is {command}")

    try:
        client = Client(base_url=base_url, verify=verify_certificate, proxy=proxy, api_key=api_key, model=model)
        args = demisto.args()

        if command == "test-module":
            result = test_module(client)
        elif command == "googlegemini-chat":
            result = googlegemini_chat_command(client, args)
        else:
            raise NotImplementedError(f"Command {command} is not implemented")

        return_results(result)

    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
