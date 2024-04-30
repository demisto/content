import importlib
import io
import pytest
from CommonServerPython import *

OpenAIGPT = importlib.import_module("OpenAIGPT")


class OpenAiClient:
    def get_chat_completions(self):
        pass


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def util_load_text(path: str) -> str:
    with open(path) as f:
        return f.read()


def test_extract_assistant_message():
    """Tests extraction from a valid response with choices and message."""

    from OpenAIGPT import extract_assistant_message

    mock_response = util_load_json('test_data/mock_response.json')

    conversation = []
    extracted_message = extract_assistant_message(response=mock_response, conversation=conversation)

    assert extracted_message == "Hello! How can I assist you today?"
    assert conversation == [{'role': 'assistant', 'content': 'Hello! How can I assist you today?'}]


def test_get_email_parts(mocker):
    """ Tests email parsing and parts extraction. """

    from OpenAIGPT import get_email_parts

    mocker.patch.object(demisto, 'getFilePath', return_value={'path': './test_data/attachment_malicious_url.eml',
                                                              'name': 'attachment_malicious_url.eml'})

    headers, text_body, html_body = get_email_parts(entry_id="0")

    assert headers == util_load_json('./test_data/expected_headers.json')
    assert text_body == 'Body of the text'
    assert html_body.replace('\r\n', '\n') == util_load_text('test_data/expected_html_body.txt')


@pytest.mark.parametrize('args, expected_outputs',
                         [
                             ({
                                 'reset_conversation_history': True,
                                 'message': "Hi There!",
                                 'max_tokens': '100',
                                 'temperature': '0',
                                 'top_p': '1'
                             }, 'TODO - ExpectedOutput1'),
                             ({
                                 'reset_conversation_history': True,
                                 'message': "Hi There!",
                                 'max_tokens': '100',
                             }, 'TODO - ExpectedOutput2'),
                             ({
                                 'reset_conversation_history': True,
                                 'message': "TODO - Message",
                                 'max_tokens': '100',
                                 'temperature': '0',
                                 'top_p': '1'
                             }, 'TODO - ExpectedOutput3')
                         ], ids=['test-send-message-1', 'test-send-message-2', 'test-send-message-3']
                         )
def test_send_message_command(mocker, args, expected_outputs):
    """ """
    from OpenAIGPT import OpenAiClient, send_message_command
    mocker.patch.object(OpenAiClient, '_http_request', return_value=util_load_json('test_data/mock_response.json'))
    mocker.patch.object(demisto, 'context', return_value={'OpenAIGPT.Conversation': [{'role': 'user', 'message': "Hi There!"}, {}]})
    client = OpenAiClient(api_key='DUMMY_API_KEY', model='gpt-4', proxy=False, verify=False)
    res = send_message_command(client=client, args=args)
    pass
