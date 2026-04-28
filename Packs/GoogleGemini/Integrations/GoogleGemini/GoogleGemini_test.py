"""Unit tests for GoogleGemini module"""

import json
import pytest
import GoogleGemini
import demistomock as demisto
from CommonServerPython import DemistoException, CommandResults


def util_load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


MOCK_SERVICE_ACCOUNT_JSON = json.dumps(
    {
        "type": "service_account",
        "project_id": "test-project",
        "private_key_id": "key123",
        "private_key": "-----BEGIN RSA PRIVATE KEY-----\nMIIBogIBAAJBALRiM\n-----END RSA PRIVATE KEY-----\n",
        "client_email": "test@test-project.iam.gserviceaccount.com",
        "client_id": "123456789",
        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
        "token_uri": "https://oauth2.googleapis.com/token",
    }
)


@pytest.fixture
def client_fixture(mocker):
    """
    Fixture for the Client object (AI Studio auth).
    Mocks the BaseClient._http_request method.
    """
    client = GoogleGemini.Client(
        base_url="https://generativelanguage.googleapis.com",
        verify=True,
        proxy=False,
        auth_type=GoogleGemini.AUTH_TYPE_AI_STUDIO,
        api_key="test_api_key",
        model="gemini-2.0-flash",
        max_tokens=1024,
        temperature=0.7,
        top_p=None,
        top_k=None,
    )
    mocker.patch.object(client, "_http_request")
    return client


@pytest.fixture
def vertex_client_fixture(mocker):
    """
    Fixture for the Client object (Vertex AI auth).
    Mocks the google-auth credentials.
    """
    mock_credentials = mocker.MagicMock()
    mock_credentials.valid = True
    mock_credentials.token = "mock_access_token"
    mocker.patch(
        "GoogleGemini.service_account.Credentials.from_service_account_info",
        return_value=mock_credentials,
    )

    client = GoogleGemini.Client(
        base_url="https://aiplatform.googleapis.com",
        verify=True,
        proxy=False,
        auth_type=GoogleGemini.AUTH_TYPE_VERTEX_AI,
        service_account_json=MOCK_SERVICE_ACCOUNT_JSON,
        project_id="test-project",
        location="global",
        model="gemini-2.0-flash",
        max_tokens=1024,
        temperature=0.7,
        top_p=None,
        top_k=None,
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
    """Test Client initialization with all parameters (AI Studio)"""
    client = GoogleGemini.Client(
        base_url="https://test.com",
        verify=False,
        proxy=True,
        auth_type=GoogleGemini.AUTH_TYPE_AI_STUDIO,
        api_key="test_key",
        model="gemini-1.5-pro",
        max_tokens=2048,
        temperature=0.8,
        top_p=0.9,
        top_k=40,
    )

    assert client.api_key == "test_key"
    assert client.model == "gemini-1.5-pro"
    assert client.max_tokens == 2048
    assert client.temperature == 0.8
    assert client.top_p == 0.9
    assert client.top_k == 40
    assert client.auth_type == GoogleGemini.AUTH_TYPE_AI_STUDIO
    assert client._headers["x-goog-api-key"] == "test_key"
    assert client._headers["Content-Type"] == "application/json"
    assert client._headers["Accept"] == "application/json"


def test_client_init_default_model():
    """Test Client initialization with default model and parameters"""
    client = GoogleGemini.Client(
        base_url="https://test.com",
        verify=True,
        proxy=False,
        auth_type=GoogleGemini.AUTH_TYPE_AI_STUDIO,
        api_key="test_key",
    )

    assert client.model == "gemini-2.5-flash-preview-05-20"
    assert client.max_tokens == 1024
    assert client.temperature is None
    assert client.top_p is None
    assert client.top_k is None


def test_client_init_vertex_ai(mocker):
    """Test Client initialization with Vertex AI authentication"""
    mock_credentials = mocker.MagicMock()
    mocker.patch(
        "GoogleGemini.service_account.Credentials.from_service_account_info",
        return_value=mock_credentials,
    )

    client = GoogleGemini.Client(
        base_url="https://aiplatform.googleapis.com",
        verify=True,
        proxy=False,
        auth_type=GoogleGemini.AUTH_TYPE_VERTEX_AI,
        service_account_json=MOCK_SERVICE_ACCOUNT_JSON,
        project_id="test-project",
        location="us-central1",
        model="gemini-2.0-flash",
        max_tokens=2048,
    )

    assert client.auth_type == GoogleGemini.AUTH_TYPE_VERTEX_AI
    assert client.project_id == "test-project"
    assert client.location == "us-central1"
    assert client.service_account_info["client_email"] == "test@test-project.iam.gserviceaccount.com"
    assert client._credentials == mock_credentials
    assert "x-goog-api-key" not in client._headers
    assert client._headers["Content-Type"] == "application/json"


def test_send_chat_message_success(client_fixture):
    """Test successful chat message sending"""
    client_fixture._http_request.return_value = MOCK_SUCCESSFUL_CHAT_RESPONSE

    result = client_fixture.send_chat_message(prompt="Hello, how are you?", model="gemini-2.0-flash")

    assert result == MOCK_SUCCESSFUL_CHAT_RESPONSE
    client_fixture._http_request.assert_called_once_with(
        method="POST",
        url_suffix="/v1beta/models/gemini-2.0-flash:generateContent",
        json_data={
            "contents": [{"role": "user", "parts": [{"text": "Hello, how are you?"}]}],
            "generationConfig": {"maxOutputTokens": 1024, "temperature": 0.7},
        },
        headers=None,
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


def test_test_module_exception(client_fixture, mocker):
    """Test test_module function with exception"""
    client_fixture._http_request.side_effect = DemistoException("Connection failed")
    mock_return_error = mocker.patch.object(GoogleGemini, "return_error")

    GoogleGemini.test_module(client_fixture)

    mock_return_error.assert_called_once_with("An unexpected error occurred during connectivity test: Connection failed")


def test_test_module_api_error(client_fixture, mocker):
    """Test test_module function with API error response"""
    client_fixture._http_request.side_effect = DemistoException(message="{'message': 'Invalid API key'}")
    mock_return_error = mocker.patch.object(GoogleGemini, "return_error")

    GoogleGemini.test_module(client_fixture)

    mock_return_error.assert_called_once_with(
        "An unexpected error occurred during connectivity test: {'message': 'Invalid API key'}"
    )


def test_google_gemini_send_message_command_success(client_fixture):
    """Test google_gemini_send_message_command with successful response"""
    client_fixture._http_request.return_value = MOCK_SUCCESSFUL_CHAT_RESPONSE
    args = {"prompt": "What is AI?", "model": "gemini-2.0-flash"}

    result = GoogleGemini.google_gemini_send_message_command(client_fixture, args)

    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == "GoogleGemini.Chat"
    assert result.outputs_key_field == "prompt"
    assert result.outputs is not None
    assert isinstance(result.outputs, dict)
    assert result.outputs["Prompt"] == "What is AI?"
    assert result.outputs["Response"] == "Hello! This is a test response from Gemini."
    assert result.outputs["Model"] == "gemini-2.0-flash"
    assert result.readable_output == "Hello! This is a test response from Gemini."


def test_google_gemini_send_message_command_missing_prompt(client_fixture):
    """Test google_gemini_send_message_command with missing prompt"""
    args = {"model": "gemini-2.0-flash"}

    with pytest.raises(ValueError) as e:
        GoogleGemini.google_gemini_send_message_command(client_fixture, args)
    assert "The 'prompt' argument is required." in str(e.value)


def test_google_gemini_send_message_command_unsupported_model(client_fixture):
    """Test google_gemini_send_message_command with unsupported model"""
    client_fixture._http_request.return_value = MOCK_SUCCESSFUL_CHAT_RESPONSE
    args = {"prompt": "Test prompt", "model": "unsupported-model"}

    # Should not raise an error, but issue a warning and continue
    result = GoogleGemini.google_gemini_send_message_command(client_fixture, args)

    assert isinstance(result, CommandResults)
    assert result.outputs_key_field == "prompt"
    assert result.outputs is not None
    assert isinstance(result.outputs, dict)
    assert result.outputs["Prompt"] == "Test prompt"
    assert result.outputs["Model"] == "unsupported-model"


def test_google_gemini_send_message_command_with_history_string(client_fixture):
    """Test google_gemini_send_message_command with history as JSON string"""
    client_fixture._http_request.return_value = MOCK_SUCCESSFUL_CHAT_RESPONSE

    history = [
        {"role": "user", "parts": [{"text": "Previous question"}]},
        {"role": "model", "parts": [{"text": "Previous answer"}]},
    ]

    args = {"prompt": "Follow-up question", "history": json.dumps(history)}

    result = GoogleGemini.google_gemini_send_message_command(client_fixture, args)

    assert isinstance(result, CommandResults)
    assert result.outputs_key_field == "prompt"
    assert result.outputs is not None
    assert isinstance(result.outputs, dict)
    assert result.outputs["Prompt"] == "Follow-up question"


def test_google_gemini_send_message_command_with_history_list(client_fixture):
    """Test google_gemini_send_message_command with history as list"""
    client_fixture._http_request.return_value = MOCK_SUCCESSFUL_CHAT_RESPONSE

    history = [{"role": "user", "parts": [{"text": "Previous question"}]}]

    args = {"prompt": "Follow-up question", "history": history}

    result = GoogleGemini.google_gemini_send_message_command(client_fixture, args)

    assert isinstance(result, CommandResults)
    assert result.outputs_key_field == "prompt"
    assert result.outputs is not None
    assert isinstance(result.outputs, dict)
    assert result.outputs["Prompt"] == "Follow-up question"


def test_google_gemini_send_message_command_invalid_history(client_fixture):
    """Test google_gemini_send_message_command with invalid history JSON"""
    args = {"prompt": "Test prompt", "history": "invalid json"}

    with pytest.raises(ValueError) as e:
        GoogleGemini.google_gemini_send_message_command(client_fixture, args)
    assert "History must be valid JSON array of conversation objects." in str(e.value)


def test_google_gemini_send_message_command_api_error(client_fixture):
    """Test google_gemini_send_message_command with API error"""
    # client_fixture._http_request.return_value = MOCK_ERROR_RESPONSE
    client_fixture._http_request.side_effect = DemistoException(message=str(MOCK_ERROR_RESPONSE))
    args = {"prompt": "Test prompt"}

    with pytest.raises(Exception) as e:
        GoogleGemini.google_gemini_send_message_command(client_fixture, args)
    assert "Invalid request parameters" in str(e.value)


def test_google_gemini_send_message_command_no_response_content(client_fixture):
    """Test google_gemini_send_message_command with empty response"""
    client_fixture._http_request.return_value = MOCK_EMPTY_RESPONSE
    args = {"prompt": "Test prompt"}

    result = GoogleGemini.google_gemini_send_message_command(client_fixture, args)

    assert result.outputs_key_field == "prompt"
    assert isinstance(result.outputs, dict)
    assert result.outputs["Response"] == "No response generated."
    assert result.readable_output == "No response generated."


def test_google_gemini_send_message_command_no_text_in_response(client_fixture):
    """Test google_gemini_send_message_command with response that has no text"""
    client_fixture._http_request.return_value = MOCK_NO_TEXT_RESPONSE
    args = {"prompt": "Test prompt"}

    result = GoogleGemini.google_gemini_send_message_command(client_fixture, args)

    assert result.outputs_key_field == "prompt"
    assert isinstance(result.outputs, dict)
    assert result.outputs["Response"] == "No response generated."
    assert result.readable_output == "No response generated."


def test_google_gemini_send_message_command_default_values(client_fixture):
    """Test google_gemini_send_message_command with default parameter values"""
    client_fixture._http_request.return_value = MOCK_SUCCESSFUL_CHAT_RESPONSE
    args = {"prompt": "Test prompt"}

    result = GoogleGemini.google_gemini_send_message_command(client_fixture, args)

    assert result.outputs_key_field == "prompt"
    assert isinstance(result.outputs, dict)
    assert result.outputs["Model"] == client_fixture.model

    # Check that instance default values were used in the API call
    call_args = client_fixture._http_request.call_args[1]["json_data"]
    assert call_args["generationConfig"]["maxOutputTokens"] == 1024
    assert call_args["generationConfig"]["temperature"] == 0.7


def test_google_gemini_send_message_command_save_conversation_false(client_fixture, mocker):
    """Test google_gemini_send_message_command with save_conversation=false"""
    client_fixture._http_request.return_value = MOCK_SUCCESSFUL_CHAT_RESPONSE
    prompt = "Test prompt"
    args = {"prompt": prompt, "save_conversation": "false"}

    result = GoogleGemini.google_gemini_send_message_command(client_fixture, args)

    assert isinstance(result, CommandResults)
    assert isinstance(result.outputs, dict)
    assert result.outputs["Prompt"] == prompt
    assert "Response" in result.outputs
    assert "History" not in result.outputs


def test_google_gemini_send_message_command_save_conversation_true(client_fixture, mocker):
    """Test google_gemini_send_message_command with save_conversation=true"""
    client_fixture._http_request.return_value = MOCK_SUCCESSFUL_CHAT_RESPONSE

    # Mock demisto.context() to return empty context
    mocker.patch.object(GoogleGemini.demisto, "context", return_value={})

    args = {"prompt": "Test prompt", "save_conversation": "true"}

    result = GoogleGemini.google_gemini_send_message_command(client_fixture, args)

    assert isinstance(result, CommandResults)
    assert isinstance(result.outputs, dict)
    assert "Response" in result.outputs
    assert "History" in result.outputs
    assert result.outputs_key_field == "ConversationId"
    assert isinstance(result.outputs["History"], list)
    assert len(result.outputs["History"]) == 2  # user prompt + model response
    assert result.outputs["History"][0]["role"] == "user"
    assert result.outputs["History"][1]["role"] == "model"


def test_google_gemini_send_message_command_save_conversation_with_existing_history_dict(client_fixture, mocker):
    """Test save_conversation with existing history in context as dict"""
    client_fixture._http_request.return_value = MOCK_SUCCESSFUL_CHAT_RESPONSE

    existing_history = [
        {"role": "user", "parts": [{"text": "Previous question"}]},
        {"role": "model", "parts": [{"text": "Previous answer"}]},
    ]
    mocked_context = {"GoogleGemini": {"Chat": {"History": existing_history, "ConversationId": "123abc"}}}
    mocker.patch.object(GoogleGemini.demisto, "context", return_value=mocked_context)

    args = {"prompt": "Follow-up question", "save_conversation": "true"}

    result = GoogleGemini.google_gemini_send_message_command(client_fixture, args)

    assert isinstance(result.outputs, dict)
    assert "History" in result.outputs
    # Should include previous history + new exchange = 4 items total
    assert len(result.outputs["History"]) == 4


def test_google_gemini_send_message_command_save_conversation_with_existing_history_list(client_fixture, mocker):
    """Test save_conversation with existing history in context as list"""
    client_fixture._http_request.return_value = MOCK_SUCCESSFUL_CHAT_RESPONSE

    existing_history = [
        {"role": "user", "parts": [{"text": "Previous question"}]},
        {"role": "model", "parts": [{"text": "Previous answer"}]},
    ]

    mocked_context = {"GoogleGemini": {"Chat": {"History": existing_history, "ConversationId": "123abc"}}}
    mocker.patch.object(GoogleGemini.demisto, "context", return_value=mocked_context)

    args = {"prompt": "Follow-up question", "save_conversation": "true"}

    result = GoogleGemini.google_gemini_send_message_command(client_fixture, args)

    assert isinstance(result.outputs, dict)
    assert "History" in result.outputs
    # Should include previous history + new exchange = 4 items total
    assert len(result.outputs["History"]) == 4


def test_google_gemini_send_message_command_save_conversation_single_existing_item(client_fixture, mocker):
    """Test save_conversation with single item in existing history"""
    client_fixture._http_request.return_value = MOCK_SUCCESSFUL_CHAT_RESPONSE

    existing_history = [{"role": "user", "parts": [{"text": "Previous question"}]}]

    mocked_context = {"GoogleGemini": {"Chat": {"History": existing_history, "ConversationId": "123abc"}}}
    mocker.patch.object(GoogleGemini.demisto, "context", return_value=mocked_context)

    args = {"prompt": "Follow-up question", "save_conversation": "true"}

    result = GoogleGemini.google_gemini_send_message_command(client_fixture, args)

    assert isinstance(result.outputs, dict)
    assert "History" in result.outputs
    # Should include previous single item + new exchange = 3 items total
    assert len(result.outputs["History"]) == 3


def test_google_gemini_send_message_command_save_conversation_no_response_generated(client_fixture, mocker):
    """Test save_conversation when no response is generated"""
    client_fixture._http_request.return_value = MOCK_EMPTY_RESPONSE

    mocker.patch.object(GoogleGemini.demisto, "context", return_value={})

    args = {"prompt": "Test prompt", "save_conversation": "true"}

    result = GoogleGemini.google_gemini_send_message_command(client_fixture, args)

    assert isinstance(result.outputs, dict)
    assert "History" in result.outputs
    # Should only include user prompt, no model response since content was "No response generated."
    assert len(result.outputs["History"]) == 1
    assert result.outputs["History"][0]["role"] == "user"


@pytest.fixture
def demisto_mocker_fixture(mocker):
    """Mocks demisto related objects used in main function of the integration."""
    mocker.patch.object(GoogleGemini, "demisto", demisto)
    mocker.patch.object(
        demisto,
        "params",
        return_value={
            "auth_type": GoogleGemini.AUTH_TYPE_AI_STUDIO,
            "url": "https://generativelanguage.googleapis.com",
            "api_key": {"password": "test_api_key"},  # Fixed: API key as dict with password
            "model": ["gemini-2.0-flash"],
            "model-freetext": "",
            "max_tokens": "1024",
            "temperature": "0.7",
            "top_p": "",
            "top_k": "",
            "insecure": False,
            "proxy": False,
        },
    )
    mocker.patch.object(demisto, "args", return_value={})
    mocker.patch.object(demisto, "command", return_value="test-module")
    mocker.patch.object(GoogleGemini, "return_results")
    mocker.patch.object(GoogleGemini, "return_error")


def test_main_test_module(demisto_mocker_fixture, mocker):
    """Test main function routing to test-module"""
    mock_test_module_func = mocker.patch.object(GoogleGemini, "test_module", return_value="ok")

    GoogleGemini.main()

    mock_test_module_func.assert_called_once()
    GoogleGemini.return_results.assert_called_once_with("ok")


def test_main_google_gemini_send_message(demisto_mocker_fixture, mocker):
    """Test main function routing to google-gemini-send-message"""
    demisto.command.return_value = "google-gemini-send-message"
    demisto.args.return_value = {"prompt": "Test prompt"}

    mock_command_result = CommandResults(outputs={"test": "result"})
    mock_command_func = mocker.patch.object(GoogleGemini, "google_gemini_send_message_command", return_value=mock_command_result)

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
            "auth_type": GoogleGemini.AUTH_TYPE_AI_STUDIO,
            "url": "https://generativelanguage.googleapis.com",
            "model": "gemini-2.0-flash",
            "model-freetext": "",
            "max_tokens": "1024",
            "temperature": "",
            "top_p": "",
            "top_k": "",
            "api_key": {"password": ""},  # Empty API key
        },
    )
    mocker.patch.object(demisto, "command", return_value="test-module")
    mock_return_error = mocker.patch.object(GoogleGemini, "return_error")

    GoogleGemini.main()

    mock_return_error.assert_called_once_with("API key is not configured. Please configure it in the instance settings.")


def test_main_exception_handling(demisto_mocker_fixture, mocker):
    """Test main function exception handling"""
    demisto.command.return_value = "google-gemini-send-message"
    demisto.args.return_value = {"prompt": "Test prompt"}

    # Mock an exception in the command
    mocker.patch.object(GoogleGemini, "google_gemini_send_message_command", side_effect=Exception("Test error"))

    GoogleGemini.main()

    GoogleGemini.return_error.assert_called_once()
    args, _ = GoogleGemini.return_error.call_args
    assert "Failed to execute google-gemini-send-message command" in args[0]
    assert "Test error" in args[0]


def test_main_model_freetext_override(mocker):
    """Test main function when multi values selected fr model"""
    mocker.patch.object(GoogleGemini, "demisto", demisto)
    mock_return_error = mocker.patch.object(GoogleGemini, "return_error")
    mocker.patch.object(
        demisto,
        "params",
        return_value={
            "auth_type": GoogleGemini.AUTH_TYPE_AI_STUDIO,
            "url": "https://generativelanguage.googleapis.com",
            "api_key": {"password": "test_api_key"},
            "model": ["gemini-2.0-flash", "test"],
            "model-freetext": "gemini-1.5-pro",
            "max_tokens": "2048",
            "temperature": "0.8",
            "top_p": "0.9",
            "top_k": "40",
            "insecure": False,
            "proxy": False,
        },
    )

    GoogleGemini.main()

    mock_return_error.assert_called_once()


def test_supported_models_list():
    """Test that SUPPORTED_MODELS contains expected models"""
    assert "gemini-2.0-flash" in GoogleGemini.SUPPORTED_MODELS
    assert "gemini-1.5-pro" in GoogleGemini.SUPPORTED_MODELS
    assert "gemini-1.5-flash" in GoogleGemini.SUPPORTED_MODELS
    assert "gemini-2.5-pro" in GoogleGemini.SUPPORTED_MODELS
    assert "text-embedding-004" in GoogleGemini.SUPPORTED_MODELS
    assert "models/embedding-001" in GoogleGemini.SUPPORTED_MODELS
    assert len(GoogleGemini.SUPPORTED_MODELS) == 11


def test_send_chat_message_with_instance_parameters():
    """Test that send_chat_message uses instance parameters correctly"""
    client = GoogleGemini.Client(
        base_url="https://test.com",
        verify=True,
        proxy=False,
        auth_type=GoogleGemini.AUTH_TYPE_AI_STUDIO,
        api_key="test_key",
        model="gemini-1.5-pro",
        max_tokens=2048,
        temperature=0.8,
        top_p=0.9,
        top_k=40,
    )

    # Mock the HTTP request
    import unittest.mock

    with unittest.mock.patch.object(client, "_http_request") as mock_request:
        mock_request.return_value = MOCK_SUCCESSFUL_CHAT_RESPONSE

        client.send_chat_message("Test prompt")

        # Verify the generation config includes all instance parameters
        call_args = mock_request.call_args[1]["json_data"]
        generation_config = call_args["generationConfig"]
        assert generation_config["maxOutputTokens"] == 2048
        assert generation_config["temperature"] == 0.8
        assert generation_config["topP"] == 0.9
        assert generation_config["topK"] == 40


def test_send_chat_message_with_optional_parameters_none():
    """Test that send_chat_message only includes configured parameters"""
    client = GoogleGemini.Client(
        base_url="https://test.com",
        verify=True,
        proxy=False,
        auth_type=GoogleGemini.AUTH_TYPE_AI_STUDIO,
        api_key="test_key",
        model="gemini-1.5-pro",
        max_tokens=1024,
        temperature=None,
        top_p=None,
        top_k=None,
    )

    # Mock the HTTP request
    import unittest.mock

    with unittest.mock.patch.object(client, "_http_request") as mock_request:
        mock_request.return_value = MOCK_SUCCESSFUL_CHAT_RESPONSE

        client.send_chat_message("Test prompt")

        # Verify the generation config only includes maxOutputTokens
        call_args = mock_request.call_args[1]["json_data"]
        generation_config = call_args["generationConfig"]
        assert generation_config["maxOutputTokens"] == 1024
        assert "temperature" not in generation_config
        assert "topP" not in generation_config
        assert "topK" not in generation_config


def test_malformed_response_no_candidates():
    """Test handling of malformed API response with no candidates key"""
    client = GoogleGemini.Client(
        base_url="https://test.com",
        verify=True,
        proxy=False,
        auth_type=GoogleGemini.AUTH_TYPE_AI_STUDIO,
        api_key="test_key",
    )

    malformed_response = {"usage": {"promptTokens": 5, "totalTokens": 10}}

    import unittest.mock

    with unittest.mock.patch.object(client, "_http_request") as mock_request:
        mock_request.return_value = malformed_response
        result = GoogleGemini.google_gemini_send_message_command(client, {"prompt": "test"})
        assert isinstance(result.outputs, dict)
        assert result.outputs["Response"] == "No response generated."


def test_malformed_response_candidates_not_list():
    """Test handling of malformed API response where candidates is not a list"""
    client = GoogleGemini.Client(
        base_url="https://test.com",
        verify=True,
        proxy=False,
        auth_type=GoogleGemini.AUTH_TYPE_AI_STUDIO,
        api_key="test_key",
    )

    malformed_response = {"candidates": "not a list"}

    import unittest.mock

    with unittest.mock.patch.object(client, "_http_request") as mock_request:
        mock_request.return_value = malformed_response
        result = GoogleGemini.google_gemini_send_message_command(client, {"prompt": "test"})
        assert isinstance(result.outputs, dict)
        assert result.outputs["Response"] == "No response generated."


def test_malformed_response_missing_content():
    """Test handling of malformed API response with missing content"""
    client = GoogleGemini.Client(
        base_url="https://test.com",
        verify=True,
        proxy=False,
        auth_type=GoogleGemini.AUTH_TYPE_AI_STUDIO,
        api_key="test_key",
    )

    malformed_response = {"candidates": [{"finishReason": "STOP"}]}

    import unittest.mock

    with unittest.mock.patch.object(client, "_http_request") as mock_request:
        mock_request.return_value = malformed_response
        result = GoogleGemini.google_gemini_send_message_command(client, {"prompt": "test"})
        assert isinstance(result.outputs, dict)
        assert result.outputs["Response"] == "No response generated."


def test_malformed_response_missing_parts():
    """Test handling of malformed API response with missing parts"""
    client = GoogleGemini.Client(
        base_url="https://test.com",
        verify=True,
        proxy=False,
        auth_type=GoogleGemini.AUTH_TYPE_AI_STUDIO,
        api_key="test_key",
    )

    malformed_response = {"candidates": [{"content": {"role": "model"}}]}

    import unittest.mock

    with unittest.mock.patch.object(client, "_http_request") as mock_request:
        mock_request.return_value = malformed_response
        result = GoogleGemini.google_gemini_send_message_command(client, {"prompt": "test"})
        assert isinstance(result.outputs, dict)
        assert result.outputs["Response"] == "No response generated."


def test_malformed_response_parts_not_list():
    """Test handling of malformed API response where parts is not a list"""
    client = GoogleGemini.Client(
        base_url="https://test.com",
        verify=True,
        proxy=False,
        auth_type=GoogleGemini.AUTH_TYPE_AI_STUDIO,
        api_key="test_key",
    )

    malformed_response = {"candidates": [{"content": {"parts": "not a list"}}]}

    import unittest.mock

    with unittest.mock.patch.object(client, "_http_request") as mock_request:
        mock_request.return_value = malformed_response
        result = GoogleGemini.google_gemini_send_message_command(client, {"prompt": "test"})
        assert isinstance(result.outputs, dict)
        assert result.outputs["Response"] == "No response generated."


def test_malformed_response_missing_text():
    """Test handling of malformed API response with missing text in parts"""
    client = GoogleGemini.Client(
        base_url="https://test.com",
        verify=True,
        proxy=False,
        auth_type=GoogleGemini.AUTH_TYPE_AI_STUDIO,
        api_key="test_key",
    )

    malformed_response = {"candidates": [{"content": {"parts": [{"image": "base64data"}]}}]}

    import unittest.mock

    with unittest.mock.patch.object(client, "_http_request") as mock_request:
        mock_request.return_value = malformed_response
        result = GoogleGemini.google_gemini_send_message_command(client, {"prompt": "test"})
        assert isinstance(result.outputs, dict)
        assert result.outputs["Response"] == "No response generated."


# --- Vertex AI Tests ---


def test_vertex_ai_url_suffix(mocker):
    """Test that Vertex AI URL suffix is constructed correctly"""
    mocker.patch(
        "GoogleGemini.service_account.Credentials.from_service_account_info",
        return_value=mocker.MagicMock(),
    )
    client = GoogleGemini.Client(
        base_url="https://aiplatform.googleapis.com",
        verify=True,
        proxy=False,
        auth_type=GoogleGemini.AUTH_TYPE_VERTEX_AI,
        service_account_json=MOCK_SERVICE_ACCOUNT_JSON,
        project_id="my-project",
        location="us-central1",
    )

    url_suffix = client._get_url_suffix("gemini-2.0-flash")
    assert url_suffix == (
        "/v1/projects/my-project/locations/us-central1" "/publishers/google/models/gemini-2.0-flash:generateContent"
    )


def test_ai_studio_url_suffix():
    """Test that AI Studio URL suffix is constructed correctly"""
    client = GoogleGemini.Client(
        base_url="https://generativelanguage.googleapis.com",
        verify=True,
        proxy=False,
        auth_type=GoogleGemini.AUTH_TYPE_AI_STUDIO,
        api_key="test_key",
    )

    url_suffix = client._get_url_suffix("gemini-2.0-flash")
    assert url_suffix == "/v1beta/models/gemini-2.0-flash:generateContent"


def test_vertex_ai_request_headers(vertex_client_fixture):
    """Test that Vertex AI uses Bearer token headers"""
    headers = vertex_client_fixture._get_request_headers()

    assert headers is not None
    assert headers["Authorization"] == "Bearer mock_access_token"
    assert headers["Content-Type"] == "application/json"


def test_ai_studio_request_headers(client_fixture):
    """Test that AI Studio returns None headers (uses default self._headers)"""
    headers = client_fixture._get_request_headers()
    assert headers is None


def test_vertex_ai_send_message(vertex_client_fixture):
    """Test send_chat_message with Vertex AI auth"""
    vertex_client_fixture._http_request.return_value = MOCK_SUCCESSFUL_CHAT_RESPONSE

    result = vertex_client_fixture.send_chat_message(prompt="Hello", model="gemini-2.0-flash")

    assert result == MOCK_SUCCESSFUL_CHAT_RESPONSE
    vertex_client_fixture._http_request.assert_called_once()
    call_kwargs = vertex_client_fixture._http_request.call_args[1]
    assert (
        "/v1/projects/test-project/locations/global" "/publishers/google/models/gemini-2.0-flash:generateContent"
    ) in call_kwargs["url_suffix"]
    assert call_kwargs["headers"]["Authorization"] == "Bearer mock_access_token"


def test_vertex_ai_send_message_command(vertex_client_fixture):
    """Test google_gemini_send_message_command with Vertex AI client"""
    vertex_client_fixture._http_request.return_value = MOCK_SUCCESSFUL_CHAT_RESPONSE
    args = {"prompt": "What is AI?", "model": "gemini-2.0-flash"}

    result = GoogleGemini.google_gemini_send_message_command(vertex_client_fixture, args)

    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == "GoogleGemini.Chat"
    assert result.outputs is not None
    assert isinstance(result.outputs, dict)
    assert result.outputs["Prompt"] == "What is AI?"
    assert result.outputs["Response"] == "Hello! This is a test response from Gemini."


def test_get_access_token_valid(mocker):
    """Test that valid cached credentials return token without refresh"""
    mock_credentials = mocker.MagicMock()
    mock_credentials.valid = True
    mock_credentials.token = "valid_token"
    mocker.patch(
        "GoogleGemini.service_account.Credentials.from_service_account_info",
        return_value=mock_credentials,
    )

    client = GoogleGemini.Client(
        base_url="https://aiplatform.googleapis.com",
        verify=True,
        proxy=False,
        auth_type=GoogleGemini.AUTH_TYPE_VERTEX_AI,
        service_account_json=MOCK_SERVICE_ACCOUNT_JSON,
        project_id="test-project",
        location="global",
    )

    token = client._get_access_token()
    assert token == "valid_token"
    mock_credentials.refresh.assert_not_called()


def test_get_access_token_expired(mocker):
    """Test that expired credentials trigger a refresh"""
    mock_credentials = mocker.MagicMock()
    mock_credentials.valid = False
    mock_credentials.token = "refreshed_token"
    mocker.patch(
        "GoogleGemini.service_account.Credentials.from_service_account_info",
        return_value=mock_credentials,
    )

    client = GoogleGemini.Client(
        base_url="https://aiplatform.googleapis.com",
        verify=True,
        proxy=False,
        auth_type=GoogleGemini.AUTH_TYPE_VERTEX_AI,
        service_account_json=MOCK_SERVICE_ACCOUNT_JSON,
        project_id="test-project",
        location="global",
    )

    token = client._get_access_token()
    assert token == "refreshed_token"
    mock_credentials.refresh.assert_called_once()


def test_main_vertex_ai_missing_service_account(mocker):
    """Test main function when service account key is missing for Vertex AI"""
    mocker.patch.object(GoogleGemini, "demisto", demisto)
    mocker.patch.object(
        demisto,
        "params",
        return_value={
            "auth_type": GoogleGemini.AUTH_TYPE_VERTEX_AI,
            "url": "https://aiplatform.googleapis.com",
            "model": ["gemini-2.0-flash"],
            "max_tokens": "1024",
            "temperature": "",
            "top_p": "",
            "top_k": "",
            "service_account_key": {"password": ""},
            "project_id": "test-project",
            "location": "global",
        },
    )
    mocker.patch.object(demisto, "command", return_value="test-module")
    mock_return_error = mocker.patch.object(GoogleGemini, "return_error")

    GoogleGemini.main()

    mock_return_error.assert_called_once_with("Service Account Key JSON is required for Vertex AI authentication.")


def test_main_vertex_ai_missing_project_id(mocker):
    """Test main function when project ID is missing for Vertex AI"""
    mocker.patch.object(GoogleGemini, "demisto", demisto)
    mocker.patch.object(
        demisto,
        "params",
        return_value={
            "auth_type": GoogleGemini.AUTH_TYPE_VERTEX_AI,
            "url": "https://aiplatform.googleapis.com",
            "model": ["gemini-2.0-flash"],
            "max_tokens": "1024",
            "temperature": "",
            "top_p": "",
            "top_k": "",
            "service_account_key": {"password": MOCK_SERVICE_ACCOUNT_JSON},
            "project_id": "",
            "location": "global",
        },
    )
    mocker.patch.object(demisto, "command", return_value="test-module")
    mock_return_error = mocker.patch.object(GoogleGemini, "return_error")

    GoogleGemini.main()

    mock_return_error.assert_called_once_with("Project ID is required for Vertex AI authentication.")


def test_main_vertex_ai_auto_switch_url(mocker):
    """Test that Server URL auto-switches from AI Studio default to Vertex AI"""
    mocker.patch.object(GoogleGemini, "demisto", demisto)
    mocker.patch(
        "GoogleGemini.service_account.Credentials.from_service_account_info",
        return_value=mocker.MagicMock(),
    )
    mocker.patch.object(
        demisto,
        "params",
        return_value={
            "auth_type": GoogleGemini.AUTH_TYPE_VERTEX_AI,
            "url": "https://generativelanguage.googleapis.com",  # AI Studio default
            "model": ["gemini-2.0-flash"],
            "max_tokens": "1024",
            "temperature": "",
            "top_p": "",
            "top_k": "",
            "service_account_key": {"password": MOCK_SERVICE_ACCOUNT_JSON},
            "project_id": "test-project",
            "location": "global",
            "insecure": False,
            "proxy": False,
        },
    )
    mocker.patch.object(demisto, "command", return_value="test-module")
    mocker.patch.object(demisto, "args", return_value={})
    mock_test_module = mocker.patch.object(GoogleGemini, "test_module", return_value="ok")
    mocker.patch.object(GoogleGemini, "return_results")

    GoogleGemini.main()

    mock_test_module.assert_called_once()
    client = mock_test_module.call_args[0][0]
    assert client._base_url == "https://aiplatform.googleapis.com"
