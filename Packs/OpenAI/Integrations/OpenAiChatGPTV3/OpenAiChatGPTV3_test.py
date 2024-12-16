import pytest
from CommonServerPython import *
from OpenAiChatGPTV3 import EmailParts


def util_load_json(path):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


def util_load_text(path: str) -> str:
    with open(path) as f:
        return f.read()


def test_extract_assistant_message():
    """Tests extraction from a valid response with choices and message."""

    from OpenAiChatGPTV3 import extract_assistant_message

    mock_response = util_load_json('test_data/mock_response.json')
    extracted_message = extract_assistant_message(response=mock_response)
    assert extracted_message == "Hello! How can I assist you today?"


@pytest.mark.parametrize('entry_id, should_raise_error', [('VALID_ENTRY_ID', False), ('INVALID_ENTRY_ID', True), ('', True)])
def test_get_email_parts(mocker, entry_id, should_raise_error):
    """ Tests email parsing and parts extraction. """

    from OpenAiChatGPTV3 import get_email_parts

    def mock_file(_entry_id: str):
        if _entry_id == 'VALID_ENTRY_ID':
            return {'path': './test_data/attachment_malicious_url.eml', 'name': 'attachment_malicious_url.eml'}
        elif _entry_id == 'INVALID_ENTRY_ID':
            return {'path': './test_data/dummy_file.txt', 'name': 'dummy_file.txt'}
        return None

    mocker.patch.object(demisto, 'getFilePath', side_effect=mock_file)
    if should_raise_error:
        with pytest.raises(Exception):
            get_email_parts(entry_id=entry_id)
    else:
        headers, text_body, html_body, file_name = get_email_parts(entry_id=entry_id)
        assert headers == util_load_json('test_data/expected_headers.json')
        assert text_body == 'Body of the text'
        assert html_body.replace('\r\n', '\n') == util_load_text('test_data/expected_html_body.txt')


@pytest.mark.parametrize('email_part, args',
                         [(EmailParts.HEADERS, {'entryId': 'XYZ', 'additionalInstructions': 'Identify spoofing.'}),
                          (EmailParts.BODY, {'entryId': '123', 'additionalInstructions': 'Identify data breaches.'})])
def test_check_email_parts(mocker, email_part: str, args: dict):
    """ Tests 'check_email_parts' function. '"""

    from OpenAiChatGPTV3 import OpenAiClient, check_email_part

    mocker.patch.object(OpenAiClient, '_http_request', return_value=util_load_json('test_data/mock_response.json'))
    mocker.patch.object(demisto, 'getFilePath', return_value={'path': './test_data/attachment_malicious_url.eml',
                                                              'name': 'attachment_malicious_url.eml'})

    client = OpenAiClient(url='DUMMY_URL', api_key='DUMMY_API_KEY', model='gpt-4', proxy=False, verify=False)
    check_email_part(email_part, client, args)


@pytest.mark.parametrize('args',
                         [
                             {
                                 'reset_conversation_history': True,
                                 'message': "Hi There!",
                                 'max_tokens': '100',
                                 'temperature': '0',
                                 'top_p': '1'
                             },
                             {
                                 'reset_conversation_history': True,
                                 'message': "Hi There!",
                             },
                             {
                                 'reset_conversation_history': False,
                                 'message': "Hi There!",
                             },
                         ], ids=['test-send-message-with-params', 'test-send-message-no-params', 'test-send-message-no-reset']
                         )
def test_send_message_command(mocker, args):
    """ """
    from OpenAiChatGPTV3 import OpenAiClient, send_message_command
    mocker.patch.object(OpenAiClient, '_http_request', return_value=util_load_json('test_data/mock_response.json'))
    mocker.patch.object(demisto, 'context', return_value={
        'OpenAiChatGPTV3': {'Conversation': [
            {'user': 'Hi There!', 'assistant': 'Hello! How can I assist you today?'}
        ]
        }
    })

    client = OpenAiClient(url='DUMMY_URL', api_key='DUMMY_API_KEY', model='gpt-4', proxy=False, verify=False)
    send_message_command_results, _ = send_message_command(client=client, args=args)


def test_create_soc_email_template_command(mocker):
    from OpenAiChatGPTV3 import OpenAiClient, create_soc_email_template_command
    mocker.patch.object(OpenAiClient, '_http_request', return_value=util_load_json('test_data/mock_response.json'))
    client = OpenAiClient(url='DUMMY_URL', api_key='DUMMY_API_KEY', model='gpt-4', proxy=False, verify=False)
    create_soc_email_template_command(client, args={})
