from unittest.mock import MagicMock, patch
import pytest
from GoogleChat import GoogleChatClient


@pytest.fixture
def google_chat_client(space_id='123', space_key='456'):
    return GoogleChatClient(space_id, space_key)


def test_send_notification_command_called_with(mocker, google_chat_client):
    """
    Given: A mock GoogleChat client.
    When: Running send_notification_command with the required arguments.
    Then: Ensure the http is sent with the desired details.
    """
    from GoogleChat import send_notification_command
    http_request = mocker.patch.object(GoogleChatClient, '_http_request')
    GoogleChatClient._access_token = '456'  # type: ignore
    args = {'message': 'hi', 'to': 'test', 'space_id': '123', 'adaptive_card': '{"button":"yes"}'}
    send_notification_command(google_chat_client, args)
    http_request.assert_called_with('POST',
                                    '/spaces/123/messages',
                                    params={'key': '456'},
                                    json_data={'text': '',
                                               'privateMessageViewer': {'name': 'test'},
                                               'cardsV2': {'button': 'yes'}},
                                    headers={'Authorization': 'Bearer 456', 'Content-Type': 'application/json; charset=UTF-8'},
                                    return_empty_response=True)


def test_send_notification_command_hr(mocker, google_chat_client):
    """
    Given: A mock GoogleChat client.
    When: Running send_notification_command with the required arguments.
    Then: Ensure recieve the desired command_results.
    """
    from GoogleChat import send_notification_command
    http_request = mocker.patch.object(GoogleChatClient, '_http_request')
    http_request.return_value = {
        'name': 'message123',
        'sender': {
            'name': 'user456',
            'displayName': 'John Doe',
            'type': 'USER'
        },
        'space': {
            'displayName': 'Project Chat',
            'name': 'spaces/AAAABBBBCCCC',
            'type': 'ROOM'
        },
        'thread': {
            'name': 'thread789',
            'threadKey': 'abc123'
        }
    }
    GoogleChatClient._access_token = '456'  # type: ignore
    args = {'message': 'hi', 'to': 'test', 'space_id': '123', 'adaptive_card': '{"button":"yes"}'}
    command_results = send_notification_command(google_chat_client, args)
    assert command_results.readable_output == ('### The Message that was sent:\n|Message Name|Sender Name|Sender Display Name|'
                                               'Sender Type|Space Display Name|Space Name|Space Type|Thread Name|Thread Key|\n|'
                                               '---|---|---|---|---|---|---|---|---|\n| message123 | user456 | John Doe | USER |'
                                               ' Project Chat | spaces/AAAABBBBCCCC | ROOM | thread789 | abc123 |\n')
    assert command_results.raw_response == {'name': 'message123',
                                            'sender': {'name': 'user456',
                                                       'displayName': 'John Doe',
                                                       'type': 'USER'},
                                            'space': {'displayName': 'Project Chat',
                                                      'name': 'spaces/AAAABBBBCCCC',
                                                      'type': 'ROOM'},
                                            'thread': {'name': 'thread789', 'threadKey': 'abc123'}}


def test_send_notification_command_card_not_in_format(mocker, google_chat_client):
    """
    Given: A mock GoogleChat client.
    When: Running send_notification_command with the required arguments.
    Then: Raise an error since the adaptive card is not in a valid format.
    """
    from GoogleChat import send_notification_command
    from CommonServerPython import DemistoException
    http_request = mocker.patch.object(GoogleChatClient, '_http_request')
    http_request.return_value = {
        'name': 'message123',
        'sender': {
            'name': 'user456',
            'displayName': 'John Doe',
            'type': 'USER'
        },
        'space': {
            'displayName': 'Project Chat',
            'name': 'spaces/AAAABBBBCCCC',
            'type': 'ROOM'
        },
        'thread': {
            'name': 'thread789',
            'threadKey': 'abc123'
        }
    }
    GoogleChatClient._access_token = '456'  # type: ignore
    args = {'message': 'hi', 'to': 'test', 'space_id': '123', 'adaptive_card': '{}}'}
    with pytest.raises(DemistoException) as e:
        send_notification_command(google_chat_client, args)
    assert e.value.message == 'Could not parse the adaptive card which was uploaded. Error: Extra data: line 1 column 3 (char 2)'


def test_create_access_token_context_exist(google_chat_client):
    """
    Given: A mock GoogleChat client.
    When: Running create_access_token with the required arguments.
    Then: Ensure the access_token in the integration context is retrieved.
    """
    from CommonServerPython import date_to_timestamp
    from datetime import datetime, timedelta, timezone
    service_account_json = ('{'
                            '"type": "service_account",'
                            '"project_id": "test",'
                            '"private_key_id": "123",'
                            '"private_key": "456",'
                            '"client_email": "test@test.com",'
                            '"client_id": "789",'
                            '"auth_uri": "https://accounts.google.com/o/oauth2/auth",'
                            '"token_uri": "https://oauth2.googleapis.com/token",'
                            '"auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",'
                            '"client_x509_cert_url": "https://",'
                            '"universe_domain": "googleapis.com"'
                            '}')

    mock_integration_context = {
        "123.access_token": "asdfghjk",
        # Ensure expiry time is in the future
        "123.expiry_time": date_to_timestamp(datetime.now(timezone.utc) + timedelta(hours=1))
    }

    with patch('GoogleChat.get_integration_context', return_value=mock_integration_context), \
            patch('GoogleChat.date_to_timestamp', side_effect=lambda x: int(x.timestamp())):
        google_chat_client.create_access_token(service_account_json)
        assert hasattr(google_chat_client, '_access_token'), "Attribute _access_token does not exist."
        assert google_chat_client._access_token == "asdfghjk", "The access token was not set correctly."


def test_create_access_token_generate_new_token(google_chat_client):
    """
    Given: A mock GoogleChat client.
    When: Running create_access_token with the required arguments.
    Then: Ensure a new access_token is generated.
    """
    from datetime import datetime, timedelta, timezone
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "access_token": "mocked_access_token",
        "expires_in": 3600
    }
    future_time = datetime.now(timezone.utc) + timedelta(hours=1)
    mock_date_to_timestamp = MagicMock(return_value=int(future_time.timestamp()))
    service_account_json = ('{"type": "service_account","project_id": "test","private_key_id": "123","private_key": "-----BEGIN '
                            'PRIVATE KEY-----11111-----END PRIVATE KEY-----","client_email": "test@test.com","client_id": "789",'
                            '"auth_uri": "https://accounts.google.com/o/oauth2/auth","token_uri": "https://oauth2.googleapis.com'
                            '/token","auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs","client_x509_ce'
                            'rt_url": "https://","universe_domain": "googleapis.com"}')
    with patch('requests.post', return_value=mock_response), \
            patch('GoogleChat.get_integration_context', return_value={}), \
            patch('GoogleChat.set_integration_context', return_value={}), \
            patch('jwt.encode', return_value='mocked_jwt_token') as mock_jwt_encode, \
            patch('GoogleChat.date_to_timestamp', side_effect=mock_date_to_timestamp):
        google_chat_client.create_access_token(service_account_json)
        assert hasattr(google_chat_client, '_access_token'), "Attribute _access_token does not exist."
        assert google_chat_client._access_token == "mocked_access_token", "The access token was not set correctly."
        mock_jwt_encode.assert_called_once()


def test_extract_entitlement():
    """
    When: Running extract_entitlement with the required arguments.
    Then: Ensure guid, incident_id, task_id is correctly extracted.
    """
    from GoogleChat import extract_entitlement
    guid, incident_id, task_id = extract_entitlement('1234567@12|1')
    assert guid == '1234567'
    assert incident_id == '12'
    assert task_id == '1'


def test_extract_entitlement_failed():
    """
    When: Running extract_entitlement with the required arguments.
    Then: Raise an error since the entitlement is not in format.
    """
    from GoogleChat import extract_entitlement
    from CommonServerPython import DemistoException
    with pytest.raises(DemistoException) as e:
        extract_entitlement('123456712|1')
    assert e.value.message == 'Entitlement cannot be parsed- entitlement not in format (entitlementID@incidentID|taskID).'


@pytest.mark.asyncio
async def test_answer_survey():
    """
    When: Running answer_survey with the required arguments.
    Then: Ensure the http is sent with the desired details.
    """
    from GoogleChat import answer_survey

    message = {
        'entitlement': '1234567@12|1',
        'default_reply': 'yes',
        'message_id_hierarchy': 'spaces/12345/messages/098765'
    }

    with patch('GoogleChat.demisto.handleEntitlementForUser') as mock_handle_entitlement, \
            patch('GoogleChat.googleChat_send_chat_reply_async') as mock_send_reply:
        await answer_survey(message)

    mock_handle_entitlement.assert_called_once_with('12', '1234567', '', 'yes', '1')
    mock_send_reply.assert_called_once_with('spaces/12345/messages/098765',
                                            {'updateMask': '*'},
                                            {'text': 'Thank you for your response: yes.'})


@pytest.mark.asyncio
async def test_check_and_handle_entitlement():
    """
    When: Running answer_survey with the required arguments.
    Then: Ensure the correct reply is returned.
    """
    from GoogleChat import check_and_handle_entitlement
    mock_integration_context = {'messages':
                                '[{"message_id_hierarchy": "spaces/12345/messages/09876","entitlement": "1234e5r6@123|1"}]'}
    current_message_id_hierarchy = 'spaces/12345/messages/09876'
    user_name = 'test'
    action_selected = 'yes'
    with patch('GoogleChat.get_integration_context', return_value=mock_integration_context), \
            patch('GoogleChat.set_to_integration_context_with_retries'):
        reply = await check_and_handle_entitlement(user_name, action_selected, current_message_id_hierarchy)
        assert reply == 'Thank you test for your response: yes.'


def test_send_notification_request(mocker, google_chat_client):
    """
    Given: A mock GoogleChat client.
    When: Running send_notification_request with the required arguments.
    Then: Ensure the http is sent with the desired details.
    """
    google_chat_client._access_token = '12345rt6y7u8'
    http_request = mocker.patch.object(GoogleChatClient, '_http_request')
    google_chat_client.send_notification_request('hi', 'test', '12345', '1', '{"button":"123456"}')
    http_request.assert_called_with('POST', '/spaces/12345/messages',
                                    params={'key': '456'},
                                    json_data={'text': 'hi',
                                               'privateMessageViewer': {'name': 'test'},
                                               'thread': {'threadKey': '1'},
                                               'cardsV2': '{"button":"123456"}'},
                                    headers={'Authorization': 'Bearer 12345rt6y7u8',
                                             'Content-Type': 'application/json; charset=UTF-8'},
                                    return_empty_response=True)


def test_send_chat_reply_request(mocker, google_chat_client):
    """
    Given: A mock GoogleChat client.
    When: Running send_chat_reply_request with the required arguments.
    Then: Ensure the http is sent with the desired details.
    """
    google_chat_client._access_token = '12345rt6y7u8'
    params = {
        "updateMask": "*"
    }
    body = {
        "text": 'Thank you for your answer'
    }
    http_request = mocker.patch.object(GoogleChatClient, '_http_request')
    google_chat_client.send_chat_reply_request('/spaces/12345/messages/098765', params, body)
    http_request.assert_called_with('PATCH', url_suffix='/spaces/12345/messages/098765',
                                    params={'updateMask': '*'},
                                    json_data={'text': 'Thank you for your answer'},
                                    headers={'Authorization': 'Bearer 12345rt6y7u8',
                                             'Content-Type': 'application/json; charset=UTF-8'})
