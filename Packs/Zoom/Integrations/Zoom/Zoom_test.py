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


def test_http_request___when_raising_invalid_token_message(mocker):
    """
  Given -
     client
  When -
      asking for a connection when the first try fails, and return an
      'Invalid access token' error messoge
  Then -
      Validate that a retry to connect with a new token has been done
    """

    m = mocker.patch.object(Zoom.BaseClient, "_http_request",
                            side_effect=DemistoException('Invalid access token'))
    generate_token_mock = mocker.patch.object(Client, "generate_oauth_token", return_value="mock")
    mocker.patch.object(Zoom, "get_integration_context",
                        return_value={"generation_time": "1988-03-03T10:50:00",
                                      'oauth_token': "old token"})
    try:
        client = Client(base_url='https://test.com', account_id="mockaccount",
                        client_id="mockclient", client_secret="mocksecret")
        # a command that uses http_request
        client.zoom_list_users("bla", "bla", 4,
                               "bla")
    except Exception:
        pass
    assert m.call_count == 2
    assert generate_token_mock.called


def test_zoom_list_users_command__limit(mocker):
    """
        Given -
           client
        When -
            asking for a limit of results
        Then -
            Validate that a func that runs a pagination has been called
    """
    manual_list_user_pagination_mock = mocker.patch.object(Zoom, "manual_list_user_pagination")
    mocker.patch.object(Client, "generate_oauth_token")
    client = Client(base_url='https://test.com', account_id="mockaccount",
                    client_id="mockclient", client_secret="mocksecret")
    from Zoom import zoom_list_users_command
    zoom_list_users_command(client=client, limit=50)
    assert manual_list_user_pagination_mock.called


def test_zoom_list_users_command__no_limit(mocker):
    """
        Given -
           client
        When -
            asking for one page results (the default)
        Then -
            Validate that a func that runs a pagination has not been called
            Validate that a func that returns the first page is called
    """
    manual_list_user_pagination_mock = mocker.patch.object(Zoom, "manual_list_user_pagination", return_value=[{"None": None}])
    returned_dict = {'page_count': 1, 'page_number': 1, 'page_size': 30,
                     'total_records': 2, 'next_page_token': '', 'users': [{'id': '1234', 'first_name': 'as', 'last_name': 'bla', 'email': 'example@example.com', 'type': 1, 'pmi': 1234, 'timezone': 'Asia/Jerusalem', 'verified': 1, 'dept': ''}]}
    zoom_list_users_mock = mocker.patch.object(Client, "zoom_list_users", return_value=returned_dict)
    mocker.patch.object(Client, "generate_oauth_token")
    client = Client(base_url='https://test.com', account_id="mockaccount",
                    client_id="mockclient", client_secret="mocksecret")

    from Zoom import zoom_list_users_command
    zoom_list_users_command(client=client, page_size=30, user_id=None, status="active",
                            next_page_token=None, role_id=None, limit=None)
    assert not manual_list_user_pagination_mock.called
    assert zoom_list_users_mock.called


def test_zoom_list_users_command__limit_and_page_size(mocker):
    """
        When -
            asking for a limit of results and for a user_id
        Then -
            Validate that an error message will be returned
    """
    #mocker.patch.object(Client, "manual_user_list_pagination", return_value=None)
    #mocker.patch.object(Client, "user_list_basic_request", return_value={"next_page_token": "mockmock"})
    returned_dict = {'page_count': 1, 'page_number': 1, 'page_size': 30,
                     'total_records': 2, 'next_page_token': '', 'users': [{'id': '1234', 'first_name': 'as', 'last_name': 'bla', 'email': 'example@example.com', 'type': 1, 'pmi': 1234, 'timezone': 'Asia/Jerusalem', 'verified': 1, 'dept': ''}]}
    mocker.patch.object(Client, "zoom_list_users", return_value=returned_dict)
    mocker.patch.object(Client, "generate_oauth_token")
    client = Client(base_url='https://test.com', account_id="mockaccount",
                    client_id="mockclient", client_secret="mocksecret")

    from Zoom import zoom_list_users_command
    with pytest.raises(DemistoException) as e:
        zoom_list_users_command(client=client, page_size=30, user_id="fdghdf", status="active",
                                next_page_token=None, role_id=None, limit=50)

    assert e.value.message == """Too money arguments. if you choose a limit,
                                       don't enter a user_id or page_size or next_page_token"""


def test_zoom_list_users_command__user_id(mocker):
    """
        Given -
           client
        When -
            asking for a specific user
        Then -
            Validate that the API call will be for a specific user
            and the url_suffix has changed to the right value
    """
    returned_dict = {'page_count': 1, 'page_number': 1, 'page_size': 30,
                     'total_records': 2, 'next_page_token': '', 'users': [{'id': '1234', 'first_name': 'as', 'last_name': 'bla', 'email': 'example@example.com', 'type': 1, 'pmi': 1234, 'timezone': 'Asia/Jerusalem', 'verified': 1, 'dept': ''}]}
    zoom_list_users_mocker = mocker.patch.object(Client, "zoom_list_users", return_value=returned_dict)
    mocker.patch.object(Client, "generate_oauth_token")
    client = Client(base_url='https://test.com', account_id="mockaccount",
                    client_id="mockclient", client_secret="mocksecret")

    from Zoom import zoom_list_users_command
    zoom_list_users_command(client=client, page_size=30, user_id="bla@bla.com", status="active",
                            next_page_token=None, role_id=None, limit=None)

    assert zoom_list_users_mocker.call_args[1].get('url_suffix') == "users/bla@bla.com"


def test_manual_list_user_pagination__small_limit(mocker):
    """
        Given -
           client
        When -
            limit > 0 < MAX_RECORDS_PER_PAGE
        Then -
            Validate that the page_size == limit
    """
    mocker.patch.object(Client, "generate_oauth_token")
    returned_dict = {'page_count': 1, 'page_number': 1, 'page_size': 30,
                     'total_records': 2, 'next_page_token': '', 'users': [{'id': '1234', 'first_name': 'as', 'last_name': 'bla', 'email': 'example@example.com', 'type': 1, 'pmi': 1234, 'timezone': 'Asia/Jerusalem', 'verified': 1, 'dept': ''}]}
    zoom_list_users_mocker = mocker.patch.object(Client, "zoom_list_users", return_value=returned_dict)
    client = Client(base_url='https://test.com', account_id="mockaccount",
                    client_id="mockclient", client_secret="mocksecret")
    limit = 5
    from Zoom import manual_list_user_pagination
    manual_list_user_pagination(client=client, next_page_token="None", page_size=1, limit=limit,
                                status="None", role_id="None")
    assert zoom_list_users_mocker.call_args[1].get('page_size') == limit


def test_manual_list_user_pagination__large_limit(mocker):
    """
        Given -
           client
        When -
            limit >  MAX_RECORDS_PER_PAGE
        Then -
            Validate that the page_size at the last call == MAX_RECORDS_PER_PAGE (currently 300) 
    """
    mocker.patch.object(Client, "generate_oauth_token")
    returned_dict = {'page_count': 1, 'page_number': 1, 'page_size': 30,
                     'total_records': 2, 'next_page_token': '', 'users': [{'id': '1234', 'first_name': 'as', 'last_name': 'bla', 'email': 'example@example.com', 'type': 1, 'pmi': 1234, 'timezone': 'Asia/Jerusalem', 'verified': 1, 'dept': ''}]}
    zoom_list_users_mocker = mocker.patch.object(Client, "zoom_list_users", return_value=returned_dict)
    client = Client(base_url='https://test.com', account_id="mockaccount",
                    client_id="mockclient", client_secret="mocksecret")
    limit = 2000
    from Zoom import manual_list_user_pagination
    manual_list_user_pagination(client=client, next_page_token="None", page_size=1, limit=limit,
                                status="None", role_id="None")
    assert zoom_list_users_mocker.call_args[1].get('page_size') == 300


def test_zoom_create_user__basic_user_type(mocker):
    """
       Given -
          client
       When -
           asking for a basic user type
       Then -
           Validate that the right type is sent to the API
    """
    mocker.patch.object(Client, "generate_oauth_token")
    http_request_mocker = mocker.patch.object(Client, "_http_request", return_value=None)
    client = Client(base_url='https://test.com', account_id="mockaccount",
                    client_id="mockclient", client_secret="mocksecret")

    client.zoom_create_user(user_type_num=1, email="mock@moker.com",
                            first_name="John", last_name="Smith")
    assert http_request_mocker.call_args[1].get("json_data").get("user_info").get("type") == 1


def test_zoom_user_create__pro_user_type(mocker):
    """
       Given -
          client
       When -
           asking for a pro user type
       Then -
           Validate that the right type is sent in the http_request
    """
    mocker.patch.object(Client, "generate_oauth_token")
    http_request_mocker = mocker.patch.object(Client, "_http_request", return_value=None)
    client = Client(base_url='https://test.com', account_id="mockaccount",
                    client_id="mockclient", client_secret="mocksecret")

    client.zoom_create_user(user_type_num=2, email="mock@moker.com",
                            first_name="John", last_name="Smith")
    assert http_request_mocker.call_args[1].get("json_data").get("user_info").get("type") == 2


def test_zoom_user_create__Corporate_user_type(mocker):
    """
       Given -
          client
       When -
           asking for a Corporate user type
       Then -
           Validate that the right type is sent in the http_request
    """
    mocker.patch.object(Client, "generate_oauth_token")
    http_request_mocker = mocker.patch.object(Client, "_http_request", return_value=None)
    client = Client(base_url='https://test.com', account_id="mockaccount",
                    client_id="mockclient", client_secret="mocksecret")

    client.zoom_create_user(user_type_num=3, email="mock@moker.com",
                            first_name="John", last_name="Smith")
    assert http_request_mocker.call_args[1].get("json_data").get("user_info").get("type") == 3


def test_zoom__create_meeting_command__instant_meeting(mocker):
    """
       Given -
          client
       When -
           asking for a instant meeting
       Then -
           Validate that the right type is sent in the API
    """
    zoom_create_meeting_mocker = mocker.patch.object(Client, "zoom_create_meeting", return_value={"bla": "bla"})
    mocker.patch.object(Client, "generate_oauth_token")
    client = Client(base_url='https://test.com', account_id="mockaccount",
                    client_id="mockclient", client_secret="mocksecret")

    from Zoom import zoom_create_meeting_command
    zoom_create_meeting_command(client=client,
                                user_id="mock@moker.com",
                                topic="nonsense",
                                type="instant",)
    assert zoom_create_meeting_mocker.call_args[1]["json_data"].get("type") == 1


def test_zoom_meeting_create_command__scheduled_meeting(mocker):
    """
       Given -
          client
       When -
           asking for a scheduled meeting
       Then -
           Validate that the right type is sent in the API
    """
    zoom_create_meeting_mocker = mocker.patch.object(Client, "zoom_create_meeting", return_value={"bla": "bla"})
    mocker.patch.object(Client, "generate_oauth_token")
    client = Client(base_url='https://test.com', account_id="mockaccount",
                    client_id="mockclient", client_secret="mocksecret")

    from Zoom import zoom_create_meeting_command
    zoom_create_meeting_command(client=client,
                                user_id="mock@moker.com",
                                topic="nonsense",
                                type="scheduled")
    assert zoom_create_meeting_mocker.call_args[1]["json_data"].get("type") == 2


def test_zoom_create_meeting_command__too_meny_arguments(mocker):
    """
       Given -
          client
       When -
           asking for a meeting with join_before_host_and_waiting_room
       Then -
           Validate that the right error will return
    """
    mocker.patch.object(Client, "zoom_create_meeting", return_value={"bla": "bla"})
    mocker.patch.object(Client, "generate_oauth_token")
    client = Client(base_url='https://test.com', account_id="mockaccount",
                    client_id="mockclient", client_secret="mocksecret")

    from Zoom import zoom_create_meeting_command
    with pytest.raises(DemistoException) as e:
        zoom_create_meeting_command(client=client,
                                    user_id="mock@moker.com",
                                    topic="nonsense",
                                    type="scheduled",
                                    waiting_room=True, join_before_host=True)
    assert e.value.message == "Collision arguments. join_before_ host argument can be used only if waiting_room is 'False'."


def test_zoom_create_meeting__too_meny_arguments(mocker):
    """
       Given -
          client
       When -
           asking for a meeting with jbh_time ant not join_before_host
       Then -
           Validate that the right error will return
    """
    mocker.patch.object(Client, "zoom_create_meeting", return_value={"bla": "bla"})
    mocker.patch.object(Client, "generate_oauth_token")
    client = Client(base_url='https://test.com', account_id="mockaccount",
                    client_id="mockclient", client_secret="mocksecret")

    from Zoom import zoom_create_meeting_command
    with pytest.raises(DemistoException) as e:
        zoom_create_meeting_command(client=client,
                                    user_id="mock@moker.com",
                                    topic="nonsense",
                                    type="scheduled",
                                    jbh_time=5, join_before_host=False)
    assert e.value.message == "Collision arguments. jbh_time argument can be used only if join_before_host is 'True'."


def test_zoom_create_meeting_command__too_meny_arguments(mocker):
    """
       Given -
          client
       When -
           asking for a meeting with instant type ant start_time
       Then -
           Validate that the right error will return
    """
    mocker.patch.object(Client, "zoom_create_meeting", return_value={"bla": "bla"})
    mocker.patch.object(Client, "generate_oauth_token")
    client = Client(base_url='https://test.com', account_id="mockaccount",
                    client_id="mockclient", client_secret="mocksecret")

    from Zoom import zoom_create_meeting_command
    with pytest.raises(DemistoException) as e:
        zoom_create_meeting_command(client=client,
                                    type="instant", topic="nonsense", user_id="mock@moker.com",
                                    start_time="2022-10-04T15:59:00Z")
    assert e.value.message == "Too money arguments. start_time and timezone are for scheduled meetings only."


def test_zoom_create_meeting_command__too_meny_arguments(mocker):
    """
       Given -
          client
       When -
           asking for a instant meeting with end_times and monthly_week :
       Then -
           Validate that the right error will return
    """
    mocker.patch.object(Client, "zoom_create_meeting", return_value={"bla": "bla"})
    mocker.patch.object(Client, "generate_oauth_token")
    client = Client(base_url='https://test.com', account_id="mockaccount",
                    client_id="mockclient", client_secret="mocksecret")

    from Zoom import zoom_create_meeting_command
    with pytest.raises(DemistoException) as e:
        zoom_create_meeting_command(client=client,
                                    type="instant", recurrence_type=3, topic="nonsense", user_id="mock@moker.com",
                                    end_date_time="2022-10-04T15:59:00Z", monthly_week=2, monthly_week_day=3, end_times=7)
    assert e.value.message == "One or more arguments that were filed are used for recurring meeting with fixed time only"


def test_zoom_create_meeting_command__too_meny_arguments(mocker):
    """
       Given -
          client
       When -
           asking for a recurring meeting with fixed time and recurrence_type = 3,
            with no monthly_week :
       Then -
           Validate that the right error will return
    """
    mocker.patch.object(Client, "zoom_create_meeting", return_value={"bla": "bla"})
    mocker.patch.object(Client, "generate_oauth_token")
    client = Client(base_url='https://test.com', account_id="mockaccount",
                    client_id="mockclient", client_secret="mocksecret")

    from Zoom import zoom_create_meeting_command
    with pytest.raises(DemistoException) as e:
        zoom_create_meeting_command(client=client,
                                    type="recurring meeting with fixed time", recurrence_type=3, topic="nonsense", user_id="mock@moker.com",
                                    end_date_time="2022-10-04T15:59:00Z", monthly_week=2, end_times=7)
    assert e.value.message == "Missing arguments. recurring meeting with fixed time and monthly recurrence_type\n            must have the fallowing arguments: monthly_week and monthly_week_day"


def test_zoom_create_meeting_command__too_meny_arguments(mocker):
    """
       Given -
          client
       When -
           asking for a recurring meeting with fixed time and recurrence_type = 3,
            with no monthly_week :
       Then -
           Validate that the right error will return
    """
    mocker.patch.object(Client, "zoom_create_meeting", return_value={"bla": "bla"})
    mocker.patch.object(Client, "generate_oauth_token")
    client = Client(base_url='https://test.com', account_id="mockaccount",
                    client_id="mockclient", client_secret="mocksecret")

    from Zoom import zoom_create_meeting_command
    with pytest.raises(DemistoException) as e:
        zoom_create_meeting_command(client=client,
                                    type="recurring meeting with fixed time", topic="nonsense", user_id="mock@moker.com")
    assert e.value.message == "Missing arguments. recurring meeting with fixed time is missing this argument: recurrence_type"


def test_meeting_get_command__show_previous_occurrences_is_false(mocker):
    """
       Given -
          client
       When -
           asking to get a meeting, and the previous_occurrences
       Then -
           Validate that the right argument is sent in the API
    """
    returned_dict = {'uuid': 'u=', 'id': 847, 'host_id': 'u', 'host_email': 'example@example.com', 'assistant_id': '', 'topic': 'My Meeting', 'type': 2,
                     'status': 'waiting', 'start_time': '5Z', 'duration': 60, 'timezone': 'lem', 'agenda': '', 'created_at': '48Z', 'start_url': '.2-dio1Se7o'}
    zoom_meeting_get_mocker = mocker.patch.object(Client, "zoom_meeting_get", return_value=returned_dict)
    mocker.patch.object(Client, "generate_oauth_token")
    client = Client(base_url='https://test.com', account_id="mockaccount",
                    client_id="mockclient", client_secret="mocksecret")
    from Zoom import zoom_meeting_get_command
    zoom_meeting_get_command(client=client, meeting_id="1234", show_previous_occurrences=True)
    assert zoom_meeting_get_mocker.call_args[0][2] == True


def test_zoom_meeting_list_command__limit(mocker):
    """
        Given -
           client
        When -
            asking for a limit of results
        Then -
            Validate that a func that runs a pagination has been called
    """

    manual_meeting_list_pagination_mock = mocker.patch.object(Zoom, "manual_meeting_list_pagination")
    mocker.patch.object(Client, "generate_oauth_token")
    client = Client(base_url='https://test.com', account_id="mockaccount",
                    client_id="mockclient", client_secret="mocksecret")
    from Zoom import zoom_meeting_list_command
    zoom_meeting_list_command(client=client, user_id="blabla", limit=50)
    assert manual_meeting_list_pagination_mock.called


def test_zoom_meeting_list_command__no_limit(mocker):
    """
        Given -
           client
        When -
            asking for one page results (the default)
        Then -
            Validate that a func that runs a pagination has not been called
            Validate that a func that returns the first page is called
    """
    manual_meeting_list_pagination_mock = mocker.patch.object(Zoom, "manual_meeting_list_pagination")
    mocker.patch.object(Client, "generate_oauth_token")
    client = Client(base_url='https://test.com', account_id="mockaccount",
                    client_id="mockclient", client_secret="mocksecret")
    returned_dict = {'uuid': 'u=', 'id': 847, 'host_id': 'u', 'host_email': 'example@example.com', 'assistant_id': '', 'topic': 'My Meeting', 'type': 2,
                     'status': 'waiting', 'start_time': '5Z', 'duration': 60, 'timezone': 'lem', 'agenda': '', 'created_at': '48Z', 'start_url': '.2-dio1Se7o'}
    zoom_meeting_list_mock = mocker.patch.object(Client, "zoom_meeting_list", return_value=returned_dict)

    from Zoom import zoom_meeting_list_command
    zoom_meeting_list_command(client=client, user_id="blabla")
    assert not manual_meeting_list_pagination_mock.called
    assert zoom_meeting_list_mock.called


def test_manual_meeting_list_pagination__small_limit(mocker):
    """
        Given -
           client
        When -
            limit > 0 < MAX_RECORDS_PER_PAGE
        Then -
            Validate that the page_size == limit
    """
    mocker.patch.object(Client, "generate_oauth_token")
    returned_dict = {'page_count': 1, 'page_number': 1, 'page_size': 30,
                     'total_records': 2, 'next_page_token': '', 'users': [{'id': '1234', 'first_name': 'as', 'last_name': 'bla', 'email': 'example@example.com', 'type': 1, 'pmi': 1234, 'timezone': 'Asia/Jerusalem', 'verified': 1, 'dept': ''}]}
    zoom_meeting_list_mocker = mocker.patch.object(Client, "zoom_meeting_list", return_value=returned_dict)
    client = Client(base_url='https://test.com', account_id="mockaccount",
                    client_id="mockclient", client_secret="mocksecret")
    limit = 5
    from Zoom import manual_meeting_list_pagination
    manual_meeting_list_pagination(client=client, user_id="bla", next_page_token=None,
                                   page_size=1, limit=limit, type="all")
    assert zoom_meeting_list_mocker.call_args[1].get('page_size') == limit



def test_manual_meeting_list_pagination__large_limit(mocker):
    """
        Given -
           client
        When -
            limit >  MAX_RECORDS_PER_PAGE
        Then -
            Validate that the page_size at the last call == MAX_RECORDS_PER_PAGE (currently 300)
    """
    mocker.patch.object(Client, "generate_oauth_token")
    returned_dict = {'page_count': 1, 'page_number': 1, 'page_size': 30,
                     'total_records': 2, 'next_page_token': '', 'users': [{'id': '1234', 'first_name': 'as', 'last_name': 'bla', 'email': 'example@example.com', 'type': 1, 'pmi': 1234, 'timezone': 'Asia/Jerusalem', 'verified': 1, 'dept': ''}]}
    zoom_meeting_list_mocker = mocker.patch.object(Client, "zoom_meeting_list", return_value=returned_dict)
    client = Client(base_url='https://test.com', account_id="mockaccount",
                    client_id="mockclient", client_secret="mocksecret")
    limit = 2000
    from Zoom import manual_meeting_list_pagination
    manual_meeting_list_pagination(client=client, user_id="bla", next_page_token=None,
                                   page_size=1, limit=limit, type="all")
    assert zoom_meeting_list_mocker.call_args[1].get('page_size') == 300


def test_check_authentication_type_parameters_with_extra_jwt_member(mocker):
    """
        Given -
           client
        When -
            creating a client with an extra authentication type argument
        Then -
            Validate that the error wil raise as excepted
    """
    with pytest.raises(DemistoException) as e:
        Zoom.check_authentication_type_parameters(account_id="mockaccount",
                                                  client_id="mockclient", client_secret="mocksecret",
                                                  api_key="blabla", api_secret="")
    assert e.value.message == """Too many fields were filled.
                                   You should fill the Account ID, Client ID, and Client Secret fields (OAuth),
                                   OR the API Key and API Secret fields (JWT - Deprecated)"""


def test_check_authentication_type_parameters__with_extra_AOuth_member():
    """
        Given -

        When -
            creating a client with an extra authentication type argument
        Then -
            Validate that the error wil raise as excepted
    """
    with pytest.raises(DemistoException) as e:
        Zoom.check_authentication_type_parameters(account_id="",
                                                  client_id="", client_secret="mocksecret",
                                                  api_key="blabla", api_secret="ertert")
    assert e.value.message == """Too many fields were filled.
                                   You should fill the Account ID, Client ID, and Client Secret fields (OAuth),
                                   OR the API Key and API Secret fields (JWT - Deprecated)"""


@freeze_time("1988-03-03T11:00:00")
def test_get_jwt_token__encoding_format_check():
    """
        Given -

        When -
            creating a jwt token
        Then -
            Validate that the token is in the right format 
    """
    encoded_token = Zoom.get_jwt_token(apiKey="blabla", apiSecret="blabla")
    expected = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJibGFibGEiLCJleHAiOjU3MzM4NzgwMH0.8GUkPXA1Dwkj55rGTBqE3chK0IaPiyRTEhCtcOOJjHk'
    assert encoded_token == expected

# i dont like this test:(


def test_zoom_user_list_command__when_user_id(mocker):
    """
        Given -
        a response from a client
        When -
            a user_id argument was passed
        Then -
            Validate that the parsing is as expected
    """
    to_md = {'id': 'C', 'first_name': 'Ye', 'last_name': 'Ro', 'email': 'y@gmail.com', 'type': 1, 'role_name': 'Member', 'pmi': 9, 'use_pmi': False,
             'personal_meeting_url': 'hts://us0', 'timezone': 'Asia/Jerusalem', 'verified': 1, 'dept': '', 'created_at': '2022-12-01T07:40:02Z', 'last_login_time': '2022-12-14T08:14:29Z'}

    mocker.patch.object(Client, "zoom_list_users", return_value=to_md)
    mocker.patch.object(Client, "generate_oauth_token")
    client = Client(base_url='https://test.com', account_id="mockaccount",
                    client_id="mockclient", client_secret="mocksecret")
    from Zoom import zoom_list_users_command
    res = zoom_list_users_command(client, user_id="bla")
    assert len(res.readable_output) == 159

# i dont like this test:(

def test_zoom_meeting_list_command__when_user_id(mocker):
    """
        Given -
        a response from a client
        When -
            a user_id argument was passed
        Then -
            Validate that the parsing is as expected
    """
    to_md = {'id': 'CTJ7hG', 'first_name': 'Ye', 'last_name': 'Ro', 'email': 'y@gmail.com', 'type': 1, 'role_name': 'Member', 'pmi': 98, 'use_pmi': False,
             'personal_meeting_url': 'https://', 'timezone': 'Asia/Jerusalem', 'verified': 1, 'dept': '', 'created_at': '2022-12-01T07:40:02Z', 'last_login_time': '2022-12-14T08:14:29Z'}

    mocker.patch.object(Client, "zoom_meeting_list", return_value=to_md)
    mocker.patch.object(Client, "generate_oauth_token")
    client = Client(base_url='https://test.com', account_id="mockaccount",
                    client_id="mockclient", client_secret="mocksecret")
    from Zoom import zoom_meeting_list_command
    res = zoom_meeting_list_command(client, user_id="bla")
    assert len(res.readable_output) == 133


def test_remove_None_values_from_dict():
    from Zoom import remove_None_values_from_dict
    """
        Given -
        a nested dict
        When -
            some values == None
        Then -
            Validate that the keys with value None are removed
    """
    dict_input = {
        "settings": {
            "allow_multiple_devices": "tuyytu",
            "auto_recording": "dyj",
            "encryption_type": "jy",
            "focus_mode": False,
            "host_video": None,
            "jbh_time": "jdfd",
            "join_before_host": "join_before_host",
            "meeting_authentication": "meeting_authentication",
            "meeting_invitees": "meeting_invitees",
            "waiting_room": False
        },
        "start_time": "start_time",
        "timezone": None,
        "type": "num_type",
        "topic": False
    }
    dict_expected_output = {
        "settings": {
            "allow_multiple_devices": "tuyytu",
            "auto_recording": "dyj",
            "encryption_type": "jy",
            "focus_mode": False,
            "jbh_time": "jdfd",
            "join_before_host": "join_before_host",
            "meeting_authentication": "meeting_authentication",
            "meeting_invitees": "meeting_invitees",
            "waiting_room": False
        },
        "start_time": "start_time",
        "type": "num_type",
        "topic": False
    }

    assert remove_None_values_from_dict(dict_input) == dict_expected_output
