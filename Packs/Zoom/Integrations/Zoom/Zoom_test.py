from Zoom import Client
from freezegun import freeze_time
import Zoom
import pytest
from CommonServerPython import DemistoException


def mock_client_ouath(mocker):

    mocker.patch.object(Client, 'get_oauth_token')
    client = Client(base_url='https://test.com', account_id="mockaccount",
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
    mocker.patch.object(Zoom, "get_integration_context",
                        return_value={"generation_time": result,
                                      'oauth_token': "old token"})
    generate_token_mock = mocker.patch.object(Client, "generate_oauth_token")
    Client(base_url='https://test.com', account_id="mockaccount",
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
    mocker.patch.object(Zoom, "get_integration_context",
                        return_value={"generation_time": "1988-03-03T10:50:00",
                                      'oauth_token': "old token"})
    generate_token_mock = mocker.patch.object(Client, "generate_oauth_token")
    client = Client(base_url='https://test.com', account_id="mockaccount",
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
    mocker.patch.object(Zoom, "get_integration_context",
                        return_value={"generation_time": "1988-03-03T10:00:00",
                                      'oauth_token': "old token"})
    generate_token_mock = mocker.patch.object(Client, "generate_oauth_token")
    client = Client(base_url='https://test.com', account_id="mockaccount",
                    client_id="mockclient", client_secret="mocksecret")
    assert generate_token_mock.called
    assert client.access_token != "old token"


@pytest.mark.parametrize("return_val", ({}, {'generation_time': None}))
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
    mocker.patch.object(Zoom, "get_integration_context",
                        return_value=return_val)
    generate_token_mock = mocker.patch.object(Client, "generate_oauth_token")
    client = Client(base_url='https://test.com', account_id="mockaccount",
                    client_id="mockclient", client_secret="mocksecret")
    assert generate_token_mock.called
    assert client.access_token != "old token"


# def test_http_request___when_raising_invalid_token_message(mocker):
#     """
#   Given -
#      client
#   When -
#       asking for a connection when the first try fails, and return an
#       'Invalid access token' error messoge
#   Then -
#       Validate that a retry to connect with a new token has been done
# """

#     m = mocker.patch.object(Zoom.BaseClient, "_http_request",
#                             side_effect=DemistoException('Invalid access token'))
#     generate_token_mock = mocker.patch.object(Client, "generate_oauth_token")
#     mocker.patch.object(Zoom, "get_integration_context",
#                         return_value={"generation_time": "1988-03-03T10:50:00",
#                                       'oauth_token': "old token"})
#     try:
#         client = Client(base_url='https://test.com', account_id="mockaccount",
#                         client_id="mockclient", client_secret="mocksecret")
#     except Exception as e:
#         pass
#     assert m.call_count == 2
#     assert generate_token_mock.called
#     assert client.access_token != "old token"
#     # TODO
#     #infinate loop


def test_zoom_user_list__limit(mocker):
    """
        Given -
           client
        When -
            asking for a limit of results
        Then -
            Validate that a func that runs a pagination has been called
    """

    manual_user_list_pagination_mock = mocker.patch.object(Client, "manual_user_list_pagination")
    mocker.patch.object(Client, "user_list_basic_request")
    mocker.patch.object(Client, "generate_oauth_token")
    client = Client(base_url='https://test.com', account_id="mockaccount",
                    client_id="mockclient", client_secret="mocksecret")

    client.zoom_user_list(limit=50)
    assert manual_user_list_pagination_mock.called


def test_zoom_user_list__no_limit(mocker):
    """
        Given -
           client
        When -
            asking for one page results (the default)
        Then -
            Validate that a func that runs a pagination has not been called
            Validate that a func that returns the first page is called
    """
    manual_user_list_pagination_mock = mocker.patch.object(Client, "manual_user_list_pagination")
    user_list_basic_request_mock = mocker.patch.object(Client, "user_list_basic_request")

    mocker.patch.object(Client, "generate_oauth_token")
    client = Client(base_url='https://test.com', account_id="mockaccount",
                    client_id="mockclient", client_secret="mocksecret")

    client.zoom_user_list()
    assert not manual_user_list_pagination_mock.called
    assert user_list_basic_request_mock.called


def test_zoom_user_list__limit_and_page_size(mocker):
    """
        When -
            asking for a limit of results and for a specific page size
        Then -
            Validate that an error message will be returned
    """
    mocker.patch.object(Client, "manual_user_list_pagination", return_value=None)
    mocker.patch.object(Client, "user_list_basic_request", return_value={"next_page_token": "mockmock"})
    mocker.patch.object(Client, "generate_oauth_token")
    client = Client(base_url='https://test.com', account_id="mockaccount",
                    client_id="mockclient", client_secret="mocksecret")
    with pytest.raises(DemistoException) as e:
        client.zoom_user_list(limit=50, user_id="fdghdf")
    assert e.value.message == "Too money arguments. if you choose a limit, don't enter a user_id or page_size"



def test_zoom_user_list__user_id(mocker):
    """
        Given -
           client
        When -
            asking for a specific user
        Then -
            Validate that the API call will be for a specific user
            and the url_suffix has changed to the right value
    """
    # url_suffix = "mockSuffix"
    mocker.patch.object(Client, "manual_user_list_pagination", return_value=None)
    basic_request_mocker = mocker.patch.object(Client, "user_list_basic_request", return_value={"next_page_token": "mockmock"})

    mocker.patch.object(Client, "generate_oauth_token")
    client = Client(base_url='https://test.com', account_id="mockaccount",
                    client_id="mockclient", client_secret="mocksecret")

    client.zoom_user_list(user_id="bla@bla.com")
    assert basic_request_mocker.call_args[0][6] == "users/bla@bla.com"


def test_manual_user_list_pagination__small_limit(mocker):
    """
        Given -
           client
        When -
            limitm > 0 < MAX_RECORDS_PER_PAGE
        Then -
            Validate that the page_size == limit
    """
    mocker.patch.object(Client, "generate_oauth_token")
    basic_request_mocker = mocker.patch.object(Client, "user_list_basic_request", return_value={"next_page_token": "mockmock"})
    client = Client(base_url='https://test.com', account_id="mockaccount",
                    client_id="mockclient", client_secret="mocksecret")
    client.manual_user_list_pagination(next_page_token=None, page_size=1, limit=5,
                                       status="all", role_id=None)
    assert basic_request_mocker.call_args[0][0] == 5
