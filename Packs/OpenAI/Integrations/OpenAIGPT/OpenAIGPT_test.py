import pytest
from CommonServerPython import *
from OpenAIGPT import EmailParts


def util_load_json(path):
    with open(path, encoding='utf-8') as f:
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


@pytest.mark.parametrize('entry_id, should_raise_error', [('VALID_ENTRY_ID', False), ('INVALID_ENTRY_ID', True), ('', True)])
def test_get_email_parts(mocker, entry_id, should_raise_error):
    """ Tests email parsing and parts extraction. """

    from OpenAIGPT import get_email_parts

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

    from OpenAIGPT import OpenAiClient, check_email_part

    mocker.patch.object(OpenAiClient, '_http_request', return_value=util_load_json('test_data/mock_response.json'))
    mocker.patch.object(demisto, 'getFilePath', return_value={'path': './test_data/attachment_malicious_url.eml',
                                                              'name': 'attachment_malicious_url.eml'})

    client = OpenAiClient(api_key='DUMMY_API_KEY', model='gpt-4', proxy=False, verify=False)
    check_email_part(email_part, client, args)


@pytest.mark.parametrize('args, expected_conversation',
                         [
                             ({
                                 'reset_conversation_history': True,
                                 'message': "Hi There!",
                                 'max_tokens': '100',
                                 'temperature': '0',
                                 'top_p': '1'
                             }, [{'content': 'Hi There!', 'role': 'user'},
                                 {'content': 'Hello! How can I assist you today?', 'role': 'assistant'}]),
                             ({
                                 'reset_conversation_history': True,
                                 'message': "Hi There!",
                             }, [{'content': 'Hi There!', 'role': 'user'},
                                 {'content': 'Hello! How can I assist you today?', 'role': 'assistant'}]),
                             ({
                                 'reset_conversation_history': False,
                                 'message': "Hi There!",
                             }, [{'content': 'Hi There!', 'role': 'user'},
                                 {'content': 'Hello! How can I assist you today?', 'role': 'assistant'},
                                 {'content': 'Hi There!', 'role': 'user'},
                                 {'content': 'Hello! How can I assist you today?', 'role': 'assistant'}]),
                         ], ids=['test-send-message-with-params', 'test-send-message-no-params', 'test-send-message-no-reset']
                         )
def test_send_message_command(mocker, args, expected_conversation):
    """ """
    from OpenAIGPT import OpenAiClient, send_message_command
    mocker.patch.object(OpenAiClient, '_http_request', return_value=util_load_json('test_data/mock_response.json'))
    mocker.patch.object(demisto, 'context', return_value={
        'OpenAIGPT': {'Conversation': [
            {'content': 'Hi There!', 'role': 'user'},
            {'content': 'Hello! How can I assist you today?', 'role': 'assistant'}
        ]
        }
    })

    client = OpenAiClient(api_key='DUMMY_API_KEY', model='gpt-4', proxy=False, verify=False)
    res = send_message_command(client=client, args=args)

    assert res.outputs == expected_conversation


def test_create_soc_email_template_command(mocker):
    from OpenAIGPT import OpenAiClient, create_soc_email_template
    mocker.patch.object(OpenAiClient, '_http_request', return_value=util_load_json('test_data/mock_response.json'))
    client = OpenAiClient(api_key='DUMMY_API_KEY', model='gpt-4', proxy=False, verify=False)
    create_soc_email_template(client, args={})
