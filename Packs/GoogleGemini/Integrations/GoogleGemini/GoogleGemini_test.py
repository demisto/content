"""Unit tests for GoogleGemini module"""

import json
import pytest
import GoogleGemini
import demistomock as demisto
from CommonServerPython import DemistoException, CommandResults


def util_load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


@pytest.fixture
def client_fixture(mocker):
    """
    Fixture for the Client object.
    Mocks the BaseClient._http_request method.
    """
    client = GoogleGemini.Client(
        base_url="https://generativelanguage.googleapis.com",
        verify=True,
        proxy=False,
        api_key="test_api_key",
        model="gemini-2.0-flash",
    )
    mocker.patch.object(client, "_http_request")
    return client


# Mock responses
MOCK_SUCCESSFUL_CHAT_RESPONSE = {
    "candidates": [{"content": {"parts": [{"text": "Hello! This is a test response from Gemini."}]}}]
}

MOCK_ERROR_RESPONSE = {"error": {"code": 400, "message": "Invalid request parameters", "status": "INVALID_ARGUMENT"}}

MOCK_EMPTY_RESPONSE = {"candidates": []}

MOCK_NO_TEXT_RESPONSE = {"candidates": [{"content": {"parts": []}}]}


def test_client_init():
    """Test Client initialization with all parameters"""
    client = GoogleGemini.Client(
        base_url="https://test.com", verify=False, proxy=True, api_key="test_key", model="gemini-1.5-pro"
    )

    assert client.api_key == "test_key"
    assert client.model == "gemini-1.5-pro"
    assert client._headers["x-goog-api-key"] == "test_key"
    assert client._headers["Content-Type"] == "application/json"
    assert client._headers["Accept"] == "application/json"


def test_client_init_default_model():
    """Test Client initialization with default model"""
    client = GoogleGemini.Client(base_url="https://test.com", verify=True, proxy=False, api_key="test_key")

    assert client.model == "gemini-2.5-flash-preview-05-20"


def test_send_chat_message_success(client_fixture):
    """Test successful chat message sending"""
    client_fixture._http_request.return_value = MOCK_SUCCESSFUL_CHAT_RESPONSE

    result = client_fixture.send_chat_message(
        prompt="Hello, how are you?", model="gemini-2.0-flash", max_tokens=500, temperature=0.5
    )

    assert result == MOCK_SUCCESSFUL_CHAT_RESPONSE
    client_fixture._http_request.assert_called_once_with(
        method="POST",
        url_suffix="/v1beta/models/gemini-2.0-flash:generateContent",
        json_data={
            "contents": [{"role": "user", "parts": [{"text": "Hello, how are you?"}]}],
            "generationConfig": {"maxOutputTokens": 500, "temperature": 0.5},
        },
        ok_codes=(200,),
    )


def test_send_chat_message_with_history(client_fixture):
    """Test chat message sending with conversation history"""
    client_fixture._http_request.return_value = MOCK_SUCCESSFUL_CHAT_RESPONSE

    history = [
        {"role": "user", "parts": [{"text": "What is the capital of France?"}]},
        {"role": "model", "parts": [{"text": "The capital of France is Paris."}]},
    ]

    result = client_fixture.send_chat_message(prompt="What about Italy?", history=history)

    expected_contents = history + [{"role": "user", "parts": [{"text": "What about Italy?"}]}]

    assert result == MOCK_SUCCESSFUL_CHAT_RESPONSE
    client_fixture._http_request.assert_called_once()
    call_args = client_fixture._http_request.call_args[1]["json_data"]
    assert call_args["contents"] == expected_contents


def test_send_chat_message_default_model(client_fixture):
    """Test chat message sending with default model"""
    client_fixture._http_request.return_value = MOCK_SUCCESSFUL_CHAT_RESPONSE

    client_fixture.send_chat_message("Test prompt")

    client_fixture._http_request.assert_called_once()
    url_suffix = client_fixture._http_request.call_args[1]["url_suffix"]
    assert f"/v1beta/models/{client_fixture.model}:generateContent" in url_suffix


def test_test_module_success(client_fixture):
    """Test test_module function with successful response"""
    client_fixture._http_request.return_value = MOCK_SUCCESSFUL_CHAT_RESPONSE

    result = GoogleGemini.test_module(client_fixture)

    assert result == "ok"
    client_fixture._http_request.assert_called_once()


def test_test_module_exception(client_fixture):
    """Test test_module function with exception"""
    client_fixture._http_request.side_effect = DemistoException("Connection failed")

    result = GoogleGemini.test_module(client_fixture)

    assert "An unexpected error occurred during connectivity test: Connection failed" in result


def test_test_module_api_error_in_response(client_fixture):
    """Test test_module function with API returning an error object in the response."""
    mock_api_error_response = {"error": {"code": 400, "message": "Invalid API key", "status": "UNAUTHENTICATED"}}
    client_fixture._http_request.return_value = mock_api_error_response

    result = GoogleGemini.test_module(client_fixture)

    assert (
        "An unexpected error occurred during connectivity test: "
        + "{'code': 400, 'message': 'Invalid API key', 'status': 'UNAUTHENTICATED'}"
        in result
    )
    client_fixture._http_request.assert_called_once()


def test_googlegemini_chat_command_success(client_fixture):
    """Test googlegemini_chat_command with successful response"""
    client_fixture._http_request.return_value = MOCK_SUCCESSFUL_CHAT_RESPONSE
    args = {"prompt": "What is AI?", "model": "gemini-2.0-flash", "max_tokens": 1000, "temperature": 0.8}

    result = GoogleGemini.googlegemini_chat_command(client_fixture, args)

    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == "GoogleGemini.Chat"
    assert result.outputs is not None
    assert isinstance(result.outputs, dict)
    assert result.outputs["prompt"] == "What is AI?"
    assert result.outputs["response"] == "Hello! This is a test response from Gemini."
    assert result.outputs["model"] == "gemini-2.0-flash"
    assert result.outputs["temperature"] == 0.8
    assert result.readable_output == "Hello! This is a test response from Gemini."


def test_googlegemini_chat_command_missing_prompt(client_fixture):
    """Test googlegemini_chat_command with missing prompt"""
    args = {"model": "gemini-2.0-flash"}

    with pytest.raises(ValueError) as e:
        GoogleGemini.googlegemini_chat_command(client_fixture, args)
    assert "The 'prompt' argument is required." in str(e.value)


def test_googlegemini_chat_command_unsupported_model(client_fixture, mocker):
    """Test googlegemini_chat_command with an unsupported model issues a warning and proceeds."""
    # Mock return_warning which is used in the GoogleGemini module
    mock_return_warning = mocker.patch.object(GoogleGemini, "return_warning")
    client_fixture._http_request.return_value = MOCK_SUCCESSFUL_CHAT_RESPONSE

    unsupported_model_name = "very-experimental-model-v9000"
    args = {"prompt": "Test prompt for unsupported model", "model": unsupported_model_name}

    result = GoogleGemini.googlegemini_chat_command(client_fixture, args)

    # Assert that return_warning was called
    mock_return_warning.assert_called_once()
    warning_call_args = mock_return_warning.call_args[0][0]  # First argument of the first call
    assert f"Warning: Model '{unsupported_model_name}' is not in the list of officially supported models" in warning_call_args
    assert "Attempting to use it" in warning_call_args

    # Assert that the command proceeded and tried to call the API
    client_fixture._http_request.assert_called_once()
    api_call_url_suffix = client_fixture._http_request.call_args[1]["url_suffix"]
    assert f"/v1beta/models/{unsupported_model_name}:generateContent" in api_call_url_suffix

    # Assert that a CommandResults object is returned
    assert isinstance(result, CommandResults)
    assert result.outputs is not None
    assert isinstance(result.outputs, dict)
    assert result.outputs["prompt"] == "Test prompt for unsupported model"
    assert result.outputs["response"] == "Hello! This is a test response from Gemini."  # From MOCK_SUCCESSFUL_CHAT_RESPONSE


def test_googlegemini_chat_command_with_history_string(client_fixture):
    """Test googlegemini_chat_command with history as JSON string"""
    client_fixture._http_request.return_value = MOCK_SUCCESSFUL_CHAT_RESPONSE

    history = [
        {"role": "user", "parts": [{"text": "Previous question"}]},
        {"role": "model", "parts": [{"text": "Previous answer"}]},
    ]

    args = {"prompt": "Follow-up question", "history": json.dumps(history)}

    result = GoogleGemini.googlegemini_chat_command(client_fixture, args)

    assert isinstance(result, CommandResults)
    assert result.outputs is not None
    assert isinstance(result.outputs, dict)
    assert result.outputs["prompt"] == "Follow-up question"


def test_googlegemini_chat_command_with_history_list(client_fixture):
    """Test googlegemini_chat_command with history as list"""
    client_fixture._http_request.return_value = MOCK_SUCCESSFUL_CHAT_RESPONSE

    history = [{"role": "user", "parts": [{"text": "Previous question"}]}]

    args = {"prompt": "Follow-up question", "history": history}

    result = GoogleGemini.googlegemini_chat_command(client_fixture, args)

    assert isinstance(result, CommandResults)
    assert result.outputs is not None
    assert isinstance(result.outputs, dict)
    assert result.outputs["prompt"] == "Follow-up question"


def test_googlegemini_chat_command_invalid_history(client_fixture):
    """Test googlegemini_chat_command with invalid history JSON"""
    args = {"prompt": "Test prompt", "history": "invalid json"}

    with pytest.raises(ValueError) as e:
        GoogleGemini.googlegemini_chat_command(client_fixture, args)
    assert "History must be valid JSON array of conversation objects." in str(e.value)


def test_googlegemini_chat_command_api_error(client_fixture):
    """Test googlegemini_chat_command with API error"""
    client_fixture._http_request.return_value = MOCK_ERROR_RESPONSE
    args = {"prompt": "Test prompt"}

    with pytest.raises(Exception) as e:
        GoogleGemini.googlegemini_chat_command(client_fixture, args)
    assert "API Error:" in str(e.value)


def test_googlegemini_chat_command_no_response_content(client_fixture):
    """Test googlegemini_chat_command with empty response"""
    client_fixture._http_request.return_value = MOCK_EMPTY_RESPONSE
    args = {"prompt": "Test prompt"}

    result = GoogleGemini.googlegemini_chat_command(client_fixture, args)

    assert result.outputs is not None
    assert isinstance(result.outputs, dict)
    assert result.outputs["response"] == "No response generated."
    assert result.readable_output == "No response generated."


def test_googlegemini_chat_command_no_text_in_response(client_fixture):
    """Test googlegemini_chat_command with response that has no text"""
    client_fixture._http_request.return_value = MOCK_NO_TEXT_RESPONSE
    args = {"prompt": "Test prompt"}

    result = GoogleGemini.googlegemini_chat_command(client_fixture, args)

    assert result.outputs is not None
    assert isinstance(result.outputs, dict)
    assert result.outputs["response"] == "No response generated."
    assert result.readable_output == "No response generated."


def test_googlegemini_chat_command_default_values(client_fixture):
    """Test googlegemini_chat_command with default parameter values"""
    client_fixture._http_request.return_value = MOCK_SUCCESSFUL_CHAT_RESPONSE
    args = {"prompt": "Test prompt"}

    result = GoogleGemini.googlegemini_chat_command(client_fixture, args)

    assert result.outputs is not None
    assert isinstance(result.outputs, dict)
    assert result.outputs["model"] == client_fixture.model
    assert result.outputs["temperature"] == 0.7

    # Check that default values were used in the API call
    call_args = client_fixture._http_request.call_args[1]["json_data"]
    assert call_args["generationConfig"]["maxOutputTokens"] == 10000
    assert call_args["generationConfig"]["temperature"] == 0.7


# Parametrized test for different missing parts in chat response
@pytest.mark.parametrize(
    "mock_response_variation, description",
    [
        ({"candidates": [{"role": "model"}]}, "candidate has no content field"),
        ({"candidates": [{"content": None, "role": "model"}]}, "candidate content is None"),
        ({"candidates": [{"content": {"role": "model"}}]}, "content has no parts field"),
        ({"candidates": [{"content": {"parts": None, "role": "model"}}]}, "content parts is None"),
        ({"candidates": [{"content": {"parts": [{}]}}]}, "part has no text field"),
        ({"candidates": [{"content": {"parts": [{"text": None}]}}]}, "part text is None"),
    ],
)
def test_googlegemini_chat_command_varied_empty_responses(client_fixture, mock_response_variation, description):
    """Test googlegemini_chat_command with various malformed/empty responses leading to 'No response generated.'"""
    client_fixture._http_request.return_value = mock_response_variation
    args = {"prompt": f"Test prompt for {description}"}

    result = GoogleGemini.googlegemini_chat_command(client_fixture, args)

    assert isinstance(result, CommandResults)
    assert result.outputs is not None
    assert isinstance(result.outputs, dict)
    assert result.outputs["response"] == "No response generated.", f"Failed for: {description}"
    assert result.readable_output == "No response generated.", f"Failed for: {description}"


@pytest.fixture
def demisto_mocker_fixture(mocker):
    """Mocks demisto related objects used in main function of the integration."""
    mocker.patch.object(GoogleGemini, "demisto", demisto)
    mocker.patch.object(
        demisto,
        "params",
        return_value={
            "url": "https://generativelanguage.googleapis.com",
            "api_key": "test_api_key",
            "model": "gemini-2.0-flash",
            "insecure": False,
            "proxy": False,
        },
    )
    mocker.patch.object(demisto, "args", return_value={})
    mocker.patch.object(demisto, "command", return_value="test-module")
    mocker.patch.object(GoogleGemini, "return_results")
    mocker.patch.object(GoogleGemini, "return_error")
    return demisto  # Return demisto so it can be modified in tests


def test_main_test_module(demisto_mocker_fixture, mocker):
    """Test main function routing to test-module"""
    mock_test_module_func = mocker.patch.object(GoogleGemini, "test_module", return_value="ok")

    GoogleGemini.main()

    mock_test_module_func.assert_called_once()
    GoogleGemini.return_results.assert_called_once_with("ok")


def test_main_default_model_when_not_in_params(demisto_mocker_fixture, mocker):
    """Test that Client is initialized with default model if 'model' is not in params."""
    # Get the mocked demisto object and modify its params
    mocked_demisto = demisto_mocker_fixture
    params_without_model = {
        "url": "https://generativelanguage.googleapis.com",
        "api_key": "test_api_key",
        # 'model' key is omitted
        "insecure": False,
        "proxy": False,
    }
    mocker.patch.object(mocked_demisto, "params", return_value=params_without_model)
    mocker.patch.object(mocked_demisto, "command", return_value="test-module")  # Ensure a valid command

    # Mock Client to intercept its initialization
    mock_client_init = mocker.patch.object(GoogleGemini.Client, "__init__", return_value=None)  # Prevent actual init
    mocker.patch.object(GoogleGemini, "test_module", return_value="ok")  # Mock the command behavior

    GoogleGemini.main()

    # Assert Client was called with the default model
    mock_client_init.assert_called_once()
    called_args, called_kwargs = mock_client_init.call_args
    assert called_kwargs.get("model") == "gemini-2.5-flash-preview-05-20"


def test_main_googlegemini_chat(demisto_mocker_fixture, mocker):
    """Test main function routing to googlegemini-chat"""
    demisto.command.return_value = "googlegemini-chat"
    demisto.args.return_value = {"prompt": "Test prompt"}

    mock_command_result = CommandResults(outputs={"test": "result"})
    mock_command_func = mocker.patch.object(GoogleGemini, "googlegemini_chat_command", return_value=mock_command_result)

    GoogleGemini.main()

    mock_command_func.assert_called_once()
    GoogleGemini.return_results.assert_called_once_with(mock_command_result)


def test_main_not_implemented_command(demisto_mocker_fixture, mocker):
    """Test main function with not implemented command"""
    demisto.command.return_value = "unknown-command"

    GoogleGemini.main()

    GoogleGemini.return_error.assert_called_once()
    args, _ = GoogleGemini.return_error.call_args
    assert "Command unknown-command is not implemented" in args[0]
    assert "Failed to execute unknown-command command" in args[0]


def test_main_missing_api_key(mocker):
    """Test main function when API key is missing"""
    mocker.patch.object(GoogleGemini, "demisto", demisto)
    mocker.patch.object(
        demisto,
        "params",
        return_value={
            "url": "https://generativelanguage.googleapis.com"
            # Missing api_key
        },
    )
    mocker.patch.object(demisto, "command", return_value="test-module")
    mock_return_error = mocker.patch.object(GoogleGemini, "return_error")

    GoogleGemini.main()

    mock_return_error.assert_called_once_with("API key is not configured. Please configure it in the instance settings.")


def test_main_exception_handling(demisto_mocker_fixture, mocker):
    """Test main function exception handling"""
    demisto.command.return_value = "googlegemini-chat"
    demisto.args.return_value = {"prompt": "Test prompt"}

    # Mock an exception in the command
    mocker.patch.object(GoogleGemini, "googlegemini_chat_command", side_effect=Exception("Test error"))

    GoogleGemini.main()

    GoogleGemini.return_error.assert_called_once()
    args, _ = GoogleGemini.return_error.call_args
    assert "Failed to execute googlegemini-chat command" in args[0]
    assert "Test error" in args[0]


def test_supported_models_list():
    """Test that SUPPORTED_MODELS contains expected models"""
    assert "gemini-2.0-flash" in GoogleGemini.SUPPORTED_MODELS
    assert "gemini-1.5-pro" in GoogleGemini.SUPPORTED_MODELS
    assert "gemini-1.5-flash" in GoogleGemini.SUPPORTED_MODELS
    assert len(GoogleGemini.SUPPORTED_MODELS) > 10  # Should have multiple models


def test_googlegemini_chat_command_max_tokens_conversion(client_fixture):
    """Test googlegemini_chat_command properly converts max_tokens argument"""
    client_fixture._http_request.return_value = MOCK_SUCCESSFUL_CHAT_RESPONSE

    # Test with string that can be converted to number
    args = {"prompt": "Test prompt", "max_tokens": "5000"}

    GoogleGemini.googlegemini_chat_command(client_fixture, args)

    call_args = client_fixture._http_request.call_args[1]["json_data"]
    assert call_args["generationConfig"]["maxOutputTokens"] == 5000
