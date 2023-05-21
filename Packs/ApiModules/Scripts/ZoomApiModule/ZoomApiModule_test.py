import pytest
from freezegun import freeze_time
from ZoomApiModule import *


def mock_client_ouath(mocker):
    mocker.patch.object(Zoom_Client, 'get_oauth_token')
    client = Zoom_Client(base_url='https://test.com', account_id="mockaccount",
                         client_id="mockclient", client_secret="mocksecret")
    return client


def test_generate_oauth_token(mocker):
    """
        Given -
           client
        When -
            generating a token
        Then -
            Validate the parameters and the result are as expected
    """
    client = mock_client_ouath(mocker)

    m = mocker.patch.object(client, '_http_request', return_value={'access_token': 'token'})
    res = client.generate_oauth_token()
    assert m.call_args[1]['method'] == 'POST'
    assert m.call_args[1]['full_url'] == 'https://zoom.us/oauth/token'
    assert m.call_args[1]['params'] == {'account_id': 'mockaccount',
                                        'grant_type': 'account_credentials'}
    assert m.call_args[1]['auth'] == ('mockclient', 'mocksecret')

    assert res == 'token'


@pytest.mark.parametrize("result", (" ", "None"))
def test_get_oauth_token__if_not_ctx(mocker, result):
    """
        Given -
           client
        When -
            asking for the latest token's generation_time and the result is None
            or empty
        Then -
            Validate that a new token will be generated.
    """
    import ZoomApiModule
    mocker.patch.object(ZoomApiModule, "get_integration_context",
                        return_value={'token_info': {"generation_time": result,
                                      'oauth_token': "old token"}})
    generate_token_mock = mocker.patch.object(Zoom_Client, "generate_oauth_token")
    Zoom_Client(base_url='https://test.com', account_id="mockaccount",
                client_id="mockclient", client_secret="mocksecret")
    assert generate_token_mock.called


@freeze_time("1988-03-03T11:00:00")
def test_get_oauth_token__while_old_token_still_valid(mocker):
    """
        Given -
           client
        When -
            asking for a token while the previous token is still valid
        Then -
            Validate that a new token will not be generated, and the old token will be returned
            Validate that the old token is the one
            stored in the get_integration_context dict.
    """
    import ZoomApiModule
    mocker.patch.object(ZoomApiModule, "get_integration_context",
                        return_value={'token_info': {"generation_time": "1988-03-03T10:50:00",
                                      'oauth_token': "old token"}})
    generate_token_mock = mocker.patch.object(Zoom_Client, "generate_oauth_token")
    client = Zoom_Client(base_url='https://test.com', account_id="mockaccount",
                         client_id="mockclient", client_secret="mocksecret")
    assert not generate_token_mock.called
    assert client.access_token == "old token"


def test_get_oauth_token___old_token_expired(mocker):
    """
        Given -
           client
        When -
            asking for a token when the previous token was expired
        Then -
            Validate that a func that creates a new token has been called
            Validate that a new token was stored in the get_integration_context dict.
    """
    import ZoomApiModule
    mocker.patch.object(ZoomApiModule, "get_integration_context",
                        return_value={'token_info': {"generation_time": "1988-03-03T10:00:00",
                                      'oauth_token': "old token"}})
    generate_token_mock = mocker.patch.object(Zoom_Client, "generate_oauth_token")
    client = Zoom_Client(base_url='https://test.com', account_id="mockaccount",
                         client_id="mockclient", client_secret="mocksecret")
    assert generate_token_mock.called
    assert client.access_token != "old token"


@pytest.mark.parametrize("return_val", ({'token_info': {}}, {'token_info': {'generation_time': None}}))
def test_get_oauth_token___old_token_is_unreachable(mocker, return_val):
    """
        Given -
           client
        When -
            asking for a token when the previous token is unreachable
        Then -
            Validate that a func that creates a new token has been called
            Validate that a new token was stored in the get_integration_context dict.
    """
    import ZoomApiModule
    mocker.patch.object(ZoomApiModule, "get_integration_context",
                        return_value=return_val)
    generate_token_mock = mocker.patch.object(Zoom_Client, "generate_oauth_token")
    client = Zoom_Client(base_url='https://test.com', account_id="mockaccount",
                         client_id="mockclient", client_secret="mocksecret")
    assert generate_token_mock.called
    assert client.access_token != "old token"


def test_http_request___when_raising_invalid_token_message(mocker):
    """
  Given -
     client
  When -
      asking for a connection when the first try fails, and return an
      'Invalid access token' error message
  Then -
      Validate that a retry to connect with a new token has been done
    """
    import ZoomApiModule
    m = mocker.patch.object(ZoomApiModule.BaseClient, "_http_request",
                            side_effect=DemistoException('Invalid access token'))
    generate_token_mock = mocker.patch.object(Zoom_Client, "generate_oauth_token", return_value="mock")
    mocker.patch.object(ZoomApiModule, "get_integration_context",
                        return_value={'token_info': {"generation_time": "1988-03-03T10:50:00",
                                      'oauth_token': "old token"}})
    try:
        client = Zoom_Client(base_url='https://test.com', account_id="mockaccount",
                             client_id="mockclient", client_secret="mocksecret")

        client.error_handled_http_request('GET', 'https://test.com', params={'bla': 'bla'})
    except Exception:
        pass
    assert m.call_count == 2
    assert generate_token_mock.called


@freeze_time("1988-03-03T11:00:00")
def test_get_jwt_token__encoding_format_check():
    """
        Given -

        When -
            creating a jwt token
        Then -
            Validate that the token is in the right format
    """
    import ZoomApiModule
    encoded_token = ZoomApiModule.get_jwt_token(apiKey="blabla", apiSecret="blabla")
    # 124 is the expected token length based on parameters given
    assert len(encoded_token) == 124
