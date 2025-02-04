from fastapi import Request, status
import json
from unittest.mock import patch
from fastapi.security import HTTPBasicCredentials
from Zoom import Client
import Zoom
import pytest
from CommonServerPython import DemistoException, CommandResults
import demistomock as demisto
from freezegun import freeze_time


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
                     'total_records': 2, 'next_page_token': '',
                     'users': [{'id': '1234', 'first_name': 'as',
                                'last_name': 'bla', 'email': 'example@example.com',
                                'type': 1, 'pmi': 1234, 'timezone': 'Asia/Jerusalem', 'verified': 1, 'dept': ''}]}
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
    returned_dict = {'page_count': 1, 'page_number': 1, 'page_size': 30,
                     'total_records': 2, 'next_page_token': '', 'users': [{'id': '1234',
                                                                           'first_name': 'as', 'last_name': 'bla',
                                                                           'email': 'example@example.com', 'type': 1, 'pmi': 1234,
                                                                           'timezone': 'Asia/Jerusalem',
                                                                           'verified': 1, 'dept': ''}]}
    mocker.patch.object(Client, "zoom_list_users", return_value=returned_dict)
    mocker.patch.object(Client, "generate_oauth_token")
    client = Client(base_url='https://test.com', account_id="mockaccount",
                    client_id="mockclient", client_secret="mocksecret")

    from Zoom import zoom_list_users_command
    with pytest.raises(DemistoException) as e:
        zoom_list_users_command(client=client, page_size=30, user_id="fdghdf", status="active",
                                next_page_token=None, role_id=None, limit=50)

    assert e.value.message == """Too many arguments. If you choose a limit,
                                       don't enter a user_id or page_size or next_page_token or page_number."""


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
                     'total_records': 2, 'next_page_token': '',
                     'users': [{'id': '1234', 'first_name': 'as',
                                'last_name': 'bla', 'email': 'example@example.com',
                                'type': 1, 'pmi': 1234, 'timezone': 'Asia/Jerusalem', 'verified': 1, 'dept': ''}]}
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
                     'total_records': 2, 'next_page_token': '',
                     'users': [{'id': '1234', 'first_name': 'as',
                                'last_name': 'bla', 'email': 'example@example.com',
                                'type': 1, 'pmi': 1234, 'timezone': 'Asia/Jerusalem', 'verified': 1, 'dept': ''}]}
    zoom_list_users_mocker = mocker.patch.object(Client, "zoom_list_users", return_value=returned_dict)
    client = Client(base_url='https://test.com', account_id="mockaccount",
                    client_id="mockclient", client_secret="mocksecret")
    limit = 5
    from Zoom import manual_list_user_pagination
    manual_list_user_pagination(client=client, next_page_token="None", limit=limit,
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
                     'total_records': 2, 'next_page_token': '',
                     'users': [{'id': '1234', 'first_name': 'as',
                                'last_name': 'bla', 'email': 'example@example.com',
                                'type': 1, 'pmi': 1234, 'timezone': 'Asia/Jerusalem', 'verified': 1, 'dept': ''}]}
    zoom_list_users_mocker = mocker.patch.object(Client, "zoom_list_users", return_value=returned_dict)
    client = Client(base_url='https://test.com', account_id="mockaccount",
                    client_id="mockclient", client_secret="mocksecret")
    limit = 2000
    from Zoom import manual_list_user_pagination
    manual_list_user_pagination(client=client, next_page_token="None", limit=limit,
                                status="None", role_id="None")
    assert zoom_list_users_mocker.call_args[1].get('page_size') == 300


def test_zoom_create_user_command(mocker):
    client = Client(base_url='https://test.com', account_id="mockaccount",
                    client_id="mockclient", client_secret="mocksecret")

    user_type = 'Basic',
    email = "mock@moker.com",
    first_name = "John",
    last_name = "Smith"

    zoom_create_user_mock = mocker.patch.object(client, "zoom_create_user")
    from Zoom import zoom_create_user_command

    zoom_create_user_command(client, email=email, user_type=user_type, first_name=first_name, last_name=last_name)

    zoom_create_user_mock.assert_called()


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
    http_request_mocker = mocker.patch.object(Client, "error_handled_http_request", return_value=None)
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
           Validate that the right type is sent in the error_handled_http_request
    """
    mocker.patch.object(Client, "generate_oauth_token")
    http_request_mocker = mocker.patch.object(Client, "error_handled_http_request", return_value=None)
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
    http_request_mocker = mocker.patch.object(Client, "error_handled_http_request", return_value=None)
    client = Client(base_url='https://test.com', account_id="mockaccount",
                    client_id="mockclient", client_secret="mocksecret")

    client.zoom_create_user(user_type_num=3, email="mock@moker.com",
                            first_name="John", last_name="Smith")
    assert http_request_mocker.call_args[1].get("json_data").get("user_info").get("type") == 3


def test_zoom_delete_user_command(mocker):
    client = Client(base_url='https://test.com', account_id="mockaccount",
                    client_id="mockclient", client_secret="mocksecret")

    user_id = "user_id"

    zoom_delete_user_mock = mocker.patch.object(client, "zoom_delete_user")
    from Zoom import zoom_delete_user_command

    zoom_delete_user_command(client, user_id=user_id)

    zoom_delete_user_mock.assert_called()


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
                                type="Instant", )
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
                                type="Scheduled")
    assert zoom_create_meeting_mocker.call_args[1]["json_data"].get("type") == 2


def test_zoom_create_meeting_command_too_many_arguments(mocker):
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
                                    type="Scheduled",
                                    waiting_room=True, join_before_host=True)
    assert e.value.message == "Collision arguments. join_before_host argument can be used only if waiting_room is 'False'."


def test_zoom_create_meeting__too_meny_arguments(mocker):
    """
       Given -
          client
       When -
           asking for a meeting with join_before_host_time ant not join_before_host
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
                                    type="Scheduled",
                                    join_before_host_time=5, join_before_host=False)
    assert e.value.message == """Collision arguments.
join_before_host_time argument can be used only if join_before_host is 'True'."""


def test_zoom_create_meeting_command__too_meny_arguments1(mocker):
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
                                    type="Instant", topic="nonsense", user_id="mock@moker.com",
                                    start_time="2022-10-04T15:59:00Z")
    assert e.value.message == "Too many arguments.Use start_time and timezone for scheduled meetings only."


def test_zoom_create_meeting_command__too_many_arguments2(mocker):
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
                                    type="Instant", recurrence_type=3, topic="nonsense", user_id="mock@moker.com",
                                    end_date_time="2022-10-04T15:59:00Z", monthly_week=2, monthly_week_day=3, end_times=7)
    assert e.value.message == "Collision arguments. Choose only one of these two arguments, end_time or end_date_time."


def test_zoom_create_meeting_command__too_meny_arguments3(mocker):
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
                                    type="Recurring meeting with fixed time", recurrence_type="Monthly",
                                    topic="nonsense", user_id="mock@moker.com",
                                    end_date_time="2022-10-04T15:59:00Z", end_times=None)
    assert e.value.message == """Missing arguments. A recurring meeting with a fixed time and monthly recurrence_type
            must have the following arguments: monthly_week and monthly_week_day."""


def test_zoom_create_meeting_command__too_meny_arguments4(mocker):
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
                                    type="Recurring meeting with fixed time", topic="nonsense", user_id="mock@moker.com")
    assert e.value.message == """Missing arguments. A recurring meeting with a fixed
time is missing this argument: recurrence_type."""


def test_zoom_create_meeting_command__too_many_arguments5(mocker):
    """
       Given -
          client
       When -
           asking for a instant meeting with end_times:
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
                                    type="Instant", end_times=7)
    assert e.value.message == 'One or more arguments that were filed\nare used for a recurring meeting with a fixed time only.'


def test_meeting_get_command__show_previous_occurrences_is_false(mocker):
    """
       Given -
          client
       When -
           asking to get a meeting, and the previous_occurrences
       Then -
           Validate that the right argument is sent in the API
    """
    returned_dict = {'uuid': 'u=', 'id': 847, 'host_id': 'u',
                     'host_email': 'example@example.com',
                     'assistant_id': '', 'topic': 'My Meeting', 'type': 2,
                     'status': 'waiting', 'start_time': '5Z',
                     'duration': 60, 'timezone': 'lem', 'agenda': '', 'created_at': '48Z', 'start_url': '.2-dio1Se7o'}
    zoom_meeting_get_mocker = mocker.patch.object(Client, "zoom_meeting_get", return_value=returned_dict)
    mocker.patch.object(Client, "generate_oauth_token")
    client = Client(base_url='https://test.com', account_id="mockaccount",
                    client_id="mockclient", client_secret="mocksecret")
    from Zoom import zoom_meeting_get_command
    zoom_meeting_get_command(client=client, meeting_id="1234", show_previous_occurrences=True)
    assert zoom_meeting_get_mocker.call_args[0][2] is True


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
    returned_dict = {'uuid': 'u=', 'id': 847, 'host_id': 'u',
                     'host_email': 'example@example.com', 'assistant_id': '', 'topic': 'My Meeting', 'type': 2,
                     'status': 'waiting', 'start_time': '5Z',
                     'duration': 60, 'timezone': 'lem', 'agenda': '', 'created_at': '48Z', 'start_url': '.2-dio1Se7o'}
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
                     'total_records': 2, 'next_page_token': '',
                     'users': [{'id': '1234', 'first_name': 'as',
                                'last_name': 'bla', 'email': 'example@example.com',
                                'type': 1, 'pmi': 1234, 'timezone': 'Asia/Jerusalem', 'verified': 1, 'dept': ''}]}
    zoom_meeting_list_mocker = mocker.patch.object(Client, "zoom_meeting_list", return_value=returned_dict)
    client = Client(base_url='https://test.com', account_id="mockaccount",
                    client_id="mockclient", client_secret="mocksecret")
    limit = 5
    from Zoom import manual_meeting_list_pagination
    manual_meeting_list_pagination(client=client, user_id="bla", next_page_token=None,
                                   limit=limit, type="all")
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
                     'total_records': 2, 'next_page_token': '',
                     'users': [{'id': '1234', 'first_name': 'as',
                                'last_name': 'bla', 'email': 'example@example.com',
                                'type': 1, 'pmi': 1234, 'timezone': 'Asia/Jerusalem', 'verified': 1, 'dept': ''}]}
    zoom_meeting_list_mocker = mocker.patch.object(Client, "zoom_meeting_list", return_value=returned_dict)
    client = Client(base_url='https://test.com', account_id="mockaccount",
                    client_id="mockclient", client_secret="mocksecret")
    limit = 2000
    from Zoom import manual_meeting_list_pagination
    manual_meeting_list_pagination(client=client, user_id="bla", next_page_token=None,
                                   limit=limit, type="all")
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
OR the API Key and API Secret fields (JWT - Deprecated)."""


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
OR the API Key and API Secret fields (JWT - Deprecated)."""


def test_zoom_user_list_command__when_user_id(mocker):
    """
        Given -
        a response from a client
        When -
            a user_id argument was passed
        Then -
            Validate that the parsing is as expected
    """
    to_md = {'id': 'C', 'first_name': 'Ye',
             'last_name': 'Ro', 'email': 'y@gmail.com',
             'type': 1, 'role_name': 'Member', 'pmi': 9, 'use_pmi': False,
             'personal_meeting_url': 'hts://us0',
             'timezone': 'Asia/Jerusalem', 'verified': 1,
             'dept': '', 'created_at': '2022-12-01T07:40:02Z',
             'last_login_time': '2022-12-14T08:14:29Z'}

    mocker.patch.object(Client, "zoom_list_users", return_value=to_md)
    mocker.patch.object(Client, "generate_oauth_token")
    client = Client(base_url='https://test.com', account_id="mockaccount",
                    client_id="mockclient", client_secret="mocksecret")
    from Zoom import zoom_list_users_command
    res = zoom_list_users_command(client, user_id="bla")
    assert len(res.readable_output) == 159  # type: ignore[arg-type]


def test_zoom_meeting_list_command__when_user_id(mocker):
    """
        Given -
        a response from a client
        When -
            a user_id argument was passed
        Then -
            Validate that the parsing is as expected
    """
    to_md = {'id': 'CTJ7hG', 'first_name': 'Ye', 'last_name': 'Ro',
             'email': 'y@gmail.com', 'type': 1, 'role_name': 'Member', 'pmi': 98, 'use_pmi': False,
             'personal_meeting_url': 'https://',
             'timezone': 'Asia/Jerusalem', 'verified': 1, 'dept': '',
             'created_at': '2022-12-01T07:40:02Z', 'last_login_time': '2022-12-14T08:14:29Z'}

    mocker.patch.object(Client, "zoom_meeting_list", return_value=to_md)
    mocker.patch.object(Client, "generate_oauth_token")
    client = Client(base_url='https://test.com', account_id="mockaccount",
                    client_id="mockclient", client_secret="mocksecret")
    from Zoom import zoom_meeting_list_command
    res = zoom_meeting_list_command(client, user_id="bla")
    assert len(res.readable_output) == 133  # type: ignore[arg-type]


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


def test_check_start_time_format__wrong_format():
    """Given -
            a time format
        When -
            missing a field
        Then -
            veryfy that the right error wil raise
    """

    from Zoom import check_start_time_format
    with pytest.raises(DemistoException) as e:
        check_start_time_format("2022-13-26T22:22:Z")
    assert e.value.message == "Wrong time format. Use this format: 'yyyy-MM-ddTHH:mm:ssZ' or 'yyyy-MM-ddTHH:mm:ss' "


def test_test_moudle__reciving_errors(mocker):
    mocker.patch.object(Client, "get_oauth_token", return_value=("token", None))
    client = Client(base_url='https://test.com', account_id="mockaccount",
                    client_id="mockclient", client_secret="mocksecret")
    mocker.patch.object(Client, "zoom_list_users", side_effect=DemistoException('Invalid access token'))

    from Zoom import test_module
    assert test_module(client=client) == 'Invalid credentials. Please verify that your credentials are valid.'


def test_test_moudle__reciving_errors1(mocker):
    mocker.patch.object(Client, "get_oauth_token", return_value=("token", None))
    client = Client(base_url='https://test.com', account_id="mockaccount",
                    client_id="mockclient", client_secret="mocksecret")
    mocker.patch.object(Client, "zoom_list_users", side_effect=DemistoException("The Token's Signature resulted invalid"))

    from Zoom import test_module
    assert test_module(client=client) == 'Invalid API Secret. Please verify that your API Secret is valid.'


def test_test_moudle__reciving_errors2(mocker):
    mocker.patch.object(Client, "get_oauth_token", return_value=("token", None))
    client = Client(base_url='https://test.com', account_id="mockaccount",
                    client_id="mockclient", client_secret="mocksecret")
    mocker.patch.object(Client, "zoom_list_users", side_effect=DemistoException("Invalid client_id or client_secret"))

    from Zoom import test_module
    assert test_module(client=client) == 'Invalid Client ID or Client Secret. Please verify that your ID and Secret is valid.'


def test_test_moudle__reciving_errors3(mocker):
    mocker.patch.object(Client, "get_oauth_token", return_value=("token", None))
    client = Client(base_url='https://test.com', account_id="mockaccount",
                    client_id="mockclient", client_secret="mocksecret")
    mocker.patch.object(Client, "zoom_list_users", side_effect=DemistoException("mockerror"))

    from Zoom import test_module
    assert test_module(client=client) == 'Problem reaching Zoom API, check your credentials. Error message: mockerror'


def test_manual_list_user_pagination__next_page_token_None(mocker):
    """
        Given -
           client
        When -
            limit > 0 and next_page_token == None
        Then -
            # Validate that the pagination process will start
    """
    mocker.patch.object(Client, "generate_oauth_token")
    returned_dict = {'page_count': 1, 'page_number': 1, 'page_size': 30,
                     'total_records': 2, 'next_page_token': None,
                     'users': [{'id': '1234', 'first_name': 'as', 'last_name': 'bla',
                                'email': 'example@example.com', 'type': 1,
                                'pmi': 1234, 'timezone': 'Asia/Jerusalem', 'verified': 1, 'dept': ''}]}
    zoom_list_users_mocker = mocker.patch.object(Client, "zoom_list_users", return_value=returned_dict)
    client = Client(base_url='https://test.com', account_id="mockaccount",
                    client_id="mockclient", client_secret="mocksecret")
    limit = 5
    from Zoom import manual_list_user_pagination
    manual_list_user_pagination(client=client, next_page_token=None, limit=limit,
                                status="None", role_id="None")
    assert zoom_list_users_mocker.called


def test_manual_meeting_list_pagination__next_page_token_None(mocker):
    """
        Given -
           client
        When -
            limit > 0 and next_page_token == None
        Then -
            # Validate that the pagination process will start
    """
    mocker.patch.object(Client, "generate_oauth_token")
    returned_dict = {'page_count': 1, 'page_number': 1, 'page_size': 30,
                     'total_records': 2, 'next_page_token': None,
                     'users': [{'id': '1234', 'first_name': 'as', 'last_name': 'bla',
                                'email': 'example@example.com', 'type': 1,
                                'pmi': 1234, 'timezone': 'Asia/Jerusalem', 'verified': 1, 'dept': ''}]}
    zoom_meeting_list_mocker = mocker.patch.object(Client, "zoom_meeting_list", return_value=returned_dict)
    client = Client(base_url='https://test.com', account_id="mockaccount",
                    client_id="mockclient", client_secret="mocksecret")
    limit = 5
    from Zoom import manual_meeting_list_pagination
    manual_meeting_list_pagination(client=client, user_id="bla", next_page_token=None,
                                   limit=limit, type="all")
    assert zoom_meeting_list_mocker.called


class MockResponse:
    def __init__(self, text='', content='', raw='', decode_content: bool = False):
        self.text = text
        self.content = content
        self.raw = raw
        self.decode_content = decode_content


def test_zoom_fetch_recording__download_success(mocker):
    """
       Given -
          client
       When -
           asking for a specific recording
       Then:
           Validate that the successfull messege is added to the commandResults
           and the writing function was called.
    """
    from Zoom import zoom_fetch_recording_command
    import shutil
    mocker.patch.object(demisto, "debug")
    mocker.patch.object(shutil, "copyfileobj")
    mocker.patch.object(Client, "zoom_fetch_recording",
                        side_effect=[{'recording_files': [{'id': '29c7tc',
                                                           'meeting_id': 'Y',
                                                           'play_url': 'hsy',
                                                           'download_url': 'htsy', 'status': 'completed',
                                                           'recording_type': 't'}
                                                          ]},
                                     MockResponse(raw=MockResponse(decode_content=False))])
    mocker.patch.object(Client, "generate_oauth_token")

    client = Client(base_url='https://test.com', account_id="mockaccount",
                    client_id="mockclient", client_secret="mocksecret")

    res = zoom_fetch_recording_command(
        client=client, meeting_id="000000", delete_after="false")

    assert res[1].readable_output == 'The None file recording_000000_29c7tc.None was downloaded successfully'


def test_zoom_fetch_recording_command__delete_success(mocker):
    """
       Given -
          client
       When -
           asking for a specific recording and deleting that recording from the cloud
       Then -
           Validate that the successfull deleting messege is added to the commandResults
    """
    from Zoom import zoom_fetch_recording_command
    import shutil
    mocker.patch.object(demisto, "debug")
    mocker.patch.object(shutil, "copyfileobj")
    mocker.patch.object(Client, "zoom_fetch_recording",
                        side_effect=[{'recording_files': [{'id': '29c7tc',
                                                           'meeting_id': 'Y',
                                                           'play_url': 'hsy',
                                                           'download_url': 'htsy', 'status': 'completed',
                                                           'recording_type': 't'}
                                                          ]},
                                     MockResponse(raw=MockResponse(decode_content=False)),
                                     MockResponse(text="sff")])
    mocker.patch.object(Client, "generate_oauth_token")
    client = Client(base_url='https://test.com', account_id="mockaccount",
                    client_id="mockclient", client_secret="mocksecret")

    res = zoom_fetch_recording_command(
        client=client, meeting_id="000000", delete_after="true")

    assert res[2].readable_output == 'The None file recording_000000_29c7tc.None was successfully removed from the cloud.'


def test_zoom_fetch_recording_command__recording_dose_not_exist(mocker):
    """
       Given -
          client
       When -
           asking for a specific recording that dose not exist
       Then -
           Validate that right error will return
    """
    from Zoom import zoom_fetch_recording_command
    import shutil
    mocker.patch.object(demisto, "debug")
    mocker.patch.object(shutil, "copyfileobj")
    mocker.patch.object(Client, "zoom_fetch_recording",
                        side_effect=[DemistoException("mockerror")])
    mocker.patch.object(Client, "generate_oauth_token")
    client = Client(base_url='https://test.com', account_id="mockaccount",
                    client_id="mockclient", client_secret="mocksecret")

    with pytest.raises(DemistoException) as e:
        zoom_fetch_recording_command(
            client=client, meeting_id="000000", delete_after="true")
    assert e.value.message == 'mockerror'


def test_zoom_fetch_recording_command__not_able_to_download(mocker):
    """
       Given -
          client
       When -
           asking for a specific recording that exist, but unable to download
       Then -
           Validate that right error will return
    """
    from Zoom import zoom_fetch_recording_command
    import shutil
    mocker.patch.object(demisto, "debug")
    mocker.patch.object(shutil, "copyfileobj")
    mocker.patch.object(Client, "zoom_fetch_recording",
                        side_effect=[{'recording_files': [{'id': '29c7tc',
                                                           'meeting_id': 'Y',
                                                           'play_url': 'hsy',
                                                           'download_url': 'htsy', 'status': 'completed',
                                                           'recording_type': 't'}
                                                          ]},
                                     DemistoException("mockerror")])
    mocker.patch.object(Client, "generate_oauth_token")
    client = Client(base_url='https://test.com', account_id="mockaccount",
                    client_id="mockclient", client_secret="mocksecret")

    with pytest.raises(DemistoException) as e:
        zoom_fetch_recording_command(
            client=client, meeting_id="000000", delete_after="true")
    assert e.value.message == 'Unable to download recording for meeting 000000: mockerror'


def test_zoom_fetch_recording_command__not_able_to_delete(mocker):
    """
       Given -
          client
       When -
           asking for a specific recording that exist,
           successfull downloading, but but unable to download
       Then -
           Validate that right error will return
    """
    from Zoom import zoom_fetch_recording_command
    import shutil
    mocker.patch.object(demisto, "debug")
    mocker.patch.object(shutil, "copyfileobj")
    mocker.patch.object(Client, "zoom_fetch_recording",
                        side_effect=[{'recording_files': [{'id': '29c7tc',
                                                           'meeting_id': 'Y',
                                                           'play_url': 'hsy',
                                                           'download_url': 'htsy', 'status': 'completed',
                                                           'recording_type': 't'}
                                                          ]},
                                     MockResponse(raw=MockResponse(decode_content=False)),
                                     DemistoException("mockerror")])
    mocker.patch.object(Client, "generate_oauth_token")
    client = Client(base_url='https://test.com', account_id="mockaccount",
                    client_id="mockclient", client_secret="mocksecret")

    res = zoom_fetch_recording_command(
        client=client, meeting_id="000000", delete_after="true")
    assert res[2].readable_output == 'Failed to delete file recording_000000_29c7tc.None. mockerror'


def test_zoom_list_user_channels_command(mocker):
    """
        Given -
           client
        When -
            asking for a list public channels
        Then -
            Validate that a func has been called
    """
    client = Client(base_url='https://test.com', account_id="mockaccount", client_id="mockclient", client_secret="mocksecret")
    channel_id = "channel_id"
    user_id = "user_id"

    expected_url_suffix = f'users/{user_id}/channels/{channel_id}' if channel_id else f'users/{user_id}/channels'

    expected_raw_data = {
        "channels": [
            {"jid": "channel_jid_1_t", "id": "channel_id_1", "name": "Channel 1", "type": "public",
             "channel_url": "https://test1.com", "next_page_token": "token1"},
            {"jid": "channel_jid_2", "id": "channel_id_2", "name": "Channel 2", "type": "public",
             "channel_url": "https://test1.com", "next_page_token": "token2"}
        ]
    }

    expected_results = {
        'UserChannelsNextToken': None,
        "channels": [
            {"jid": "channel_jid_1_t", "id": "channel_id_1", "name": "Channel 1", "type": "public",
             "channel_url": "https://test1.com", "next_page_token": "token1"},
            {"jid": "channel_jid_2", "id": "channel_id_2", "name": "Channel 2", "type": "public",
             "channel_url": "https://test1.com", "next_page_token": "token2"}
        ]
    }

    zoom_list_user_channels_mock = mocker.patch.object(client, "zoom_list_user_channels")
    zoom_list_user_channels_mock.return_value = expected_raw_data

    from Zoom import zoom_list_user_channels_command

    result = zoom_list_user_channels_command(
        client,
        channel_id=channel_id,
        user_id=user_id
    )

    zoom_list_user_channels_mock.assert_called_with(
        user_id=user_id,
        page_size=50,
        next_page_token=None,
        url_suffix=expected_url_suffix,
        page_number=1
    )

    assert result.outputs == expected_results
    assert result.outputs['channels'][0]['id'] == expected_results['channels'][0]['id']
    assert result.outputs['channels'][0]['jid'] == expected_results['channels'][0]['jid']


def test_zoom_list_user_channels_command__limit(mocker):
    """
        Given -
           client
        When -
            asking for a limit of results
        Then -
            Validate that a func that runs a pagination has been called
    """
    manual_list_user_channel_pagination_mock = mocker.patch.object(Zoom, "manual_list_user_channel_pagination")
    mocker.patch.object(Client, "generate_oauth_token")
    client = Client(base_url='https://test.com', account_id="mockaccount",
                    client_id="mockclient", client_secret="mocksecret")
    from Zoom import zoom_list_user_channels_command
    zoom_list_user_channels_command(client=client, user_id="user_id", limit=5)
    assert manual_list_user_channel_pagination_mock.called


def test_zoom_create_channel_command(mocker):
    """
    Given -
        client
    When -
        creating a Zoom channel
    Then -
        Validate that the zoom_create_channel function is called with the correct arguments
        Validate the command results including outputs and readable output
    """
    # Mock the response from zoom_create_channel
    response = {
        "id": "channel_id",
        "name": "TestChannel3",
        "type": "1",
        "channel_url": "https://zoom.us/channel/channel_id"
    }
    zoom_create_channel_mock = mocker.patch.object(Client, "zoom_create_channel", return_value=response)

    mocker.patch.object(Client, "generate_oauth_token")
    client = Client(base_url='https://test.com', account_id="mockaccount",
                    client_id="mockclient", client_secret="mocksecret")
    from Zoom import zoom_create_channel_command

    # Set up the inputs
    user_id = "u12345"
    member_emails = ["user2@example.com", "user1@example.com"]
    add_member_permissions = "All channel members can add"
    posting_permissions = "All members can post"
    new_members_can_see_prev_msgs = True
    channel_name = "TestChannel"
    channel_type = "Private channel"

    zoom_create_channel_command(client=client,
                                user_id=user_id,
                                member_emails=member_emails,
                                add_member_permissions=add_member_permissions,
                                posting_permissions=posting_permissions,
                                new_members_can_see_prev_msgs=new_members_can_see_prev_msgs,
                                channel_name=channel_name,
                                channel_type=channel_type)

    # Verify the API call
    expected_url_suffix = f"/chat/users/{user_id}/channels"
    expected_json_data = {
        "channel_settings": {
            "add_member_permissions": 1,
            "new_members_can_see_previous_messages_files": True,
            "posting_permissions": 1,
        },
        "members": [
            {"email": "user2@example.com"},
            {"email": "user1@example.com"}
        ],
        "name": "TestChannel",
        "type": 1
    }
    zoom_create_channel_mock.assert_called_with(expected_url_suffix, expected_json_data)


def test_zoom_delete_channel_command(mocker):
    """
    Given -
        client
    When -
        deleting a Zoom channel
    Then -
        Validate that the zoom_delete_channel function is called with the correct arguments
    """
    client = Client(base_url='https://test.com', account_id="mockaccount",
                    client_id="mockclient", client_secret="mocksecret")

    channel_id = "channel_id"
    user_id = "user_id"
    expected_url_suffix = f"/chat/users/{user_id}/channels/{channel_id}"

    zoom_delete_channel_mock = mocker.patch.object(client, "zoom_delete_channel")
    from Zoom import zoom_delete_channel_command

    zoom_delete_channel_command(client, channel_id=channel_id, user_id=user_id)

    zoom_delete_channel_mock.assert_called_with(expected_url_suffix)


def test_zoom_update_channel_command(mocker):
    """
    Given -
        client
    When -
        updating a Zoom channel
    Then -
        Validate that the zoom_update_channel function is called with the correct arguments
    """
    client = Client(base_url='https://test.com', account_id="mockaccount",
                    client_id="mockclient", client_secret="mocksecret")

    add_member_permissions = "All channel members can add"
    posting_permissions = "All members can post"
    new_members_can_see_prev_msgs = True
    channel_name = "TestChannel"
    channel_id = "channel_id"
    user_id = "user_id"

    expected_url_suffix = f"/chat/users/{user_id}/channels/{channel_id}"
    expected_json_data = {
        "name": channel_name,
        "channel_settings": {
            "add_member_permissions": 1,
            "new_members_can_see_previous_messages_files": new_members_can_see_prev_msgs,
            "posting_permissions": 1,
        }
    }

    zoom_update_channel_mock = mocker.patch.object(client, "zoom_update_channel")
    from Zoom import zoom_update_channel_command

    zoom_update_channel_command(
        client,
        add_member_permissions=add_member_permissions,
        posting_permissions=posting_permissions,
        new_members_can_see_prev_msgs=new_members_can_see_prev_msgs,
        channel_name=channel_name,
        channel_id=channel_id,
        user_id=user_id
    )

    zoom_update_channel_mock.assert_called_with(expected_url_suffix, expected_json_data)


def test_zoom_invite_to_channel_command(mocker):
    """
    Given -
        client
    When -
        Invite user to a Zoom channel
    Then -
        Validate that the zoom_invite_to_channel function is called with the correct arguments
    """
    client = Client(base_url='https://test.com', account_id="mockaccount",
                    client_id="mockclient", client_secret="mocksecret")

    channel_id = "channel_id"
    user_id = "user_id"
    members = ["user1@example.com", "user2@example.com"]
    expected_url_suffix = f"/chat/users/{user_id}/channels/{channel_id}/members"
    expected_json_data = {
        "members": [
            {"email": "user1@example.com"},
            {"email": "user2@example.com"}
        ]
    }
    from Zoom import zoom_invite_to_channel_command

    zoom_invite_to_channel_mock = mocker.patch.object(client, "zoom_invite_to_channel")

    # Convert MagicMock to dictionary
    zoom_invite_to_channel_mock.return_value = expected_json_data

    zoom_invite_to_channel_command(
        client,
        channel_id=channel_id,
        user_id=user_id,
        members=members
    )

    zoom_invite_to_channel_mock.assert_called_with(expected_json_data, expected_url_suffix)


def test_zoom_remove_from_channel_command(mocker):
    """
    Given -
        client
    When -
        Remove user from a Zoom channel
    Then -
        Validate that the zoom_remove_from_channel function is called with the correct arguments
    """
    client = Client(base_url='https://test.com', account_id="mockaccount",
                    client_id="mockclient", client_secret="mocksecret")

    channel_id = "channel_id"
    member_id = "member_id"
    user_id = "user_id"
    expected_url_suffix = f"/chat/users/{user_id}/channels/{channel_id}/members/{member_id}"

    zoom_remove_from_channel_mock = mocker.patch.object(client, "zoom_remove_from_channel")
    from Zoom import zoom_remove_from_channel_command

    zoom_remove_from_channel_command(
        client,
        channel_id=channel_id,
        member_id=member_id,
        user_id=user_id
    )

    zoom_remove_from_channel_mock.assert_called_with(expected_url_suffix)


def test_zoom_send_file_command(mocker):
    """
    Given -
        client
    When -
        Zoom send file to channel
    Then -
        Validate that the zoom_send_file function is called with the correct arguments
        Validate the command results including outputs and readable output

    """
    client = Client(base_url='https://test.com', account_id="mockaccount",
                    client_id="mockclient", client_secret="mocksecret")

    user_id = "user_id"
    to_channel = "channel_id"
    entry_id = "entry_id"

    expected_upload_url = f'https://file.zoom.us/v2/chat/users/{user_id}/messages/files'
    expected_file_info = {
        'name': 'test_file.txt',
        'path': '/path/to/test_file.txt'
    }
    expected_json_data = {
        'to_channel': to_channel
    }
    expected_upload_response = {
        'id': 'file_id'
    }

    mocker.patch('Zoom.demisto.getFilePath', return_value=expected_file_info)

    zoom_send_file_mock = mocker.patch.object(client, "zoom_send_file", return_value=expected_upload_response)

    from Zoom import zoom_send_file_command

    results = zoom_send_file_command(
        client,
        user_id=user_id,
        to_channel=to_channel,
        entry_id=entry_id
    )

    # Assert function calls
    Zoom.demisto.getFilePath.assert_called_with(entry_id)
    zoom_send_file_mock.assert_called_with(expected_upload_url, expected_file_info, expected_json_data)

    # Assert results
    assert results.readable_output == 'Message with id file_id was successfully sent'


def test_zoom_list_account_public_channels_command(mocker):
    """
        Given -
           client
        When -
            asking for a list public channels
        Then -
            Validate that a func has been called
    """
    client = Client(base_url='https://test.com', account_id="mockaccount", client_id="mockclient", client_secret="mocksecret")
    page_size = 50
    channel_id = "channel_id"
    next_page_token = "next_page_token"
    page_number = 2

    expected_url_suffix = f'channels/{channel_id}' if channel_id else 'channels'
    expected_raw_data = {
        "channels": [
            {"jid": "channel_jid_1", "id": "channel_id_1", "name": "Channel 1", "type": "public",
             "channel_url": "https://test1.com", "next_page_token": "token1"},
            {"jid": "channel_jid_2", "id": "channel_id_2", "name": "Channel 2", "type": "public",
             "channel_url": "https://test1.com", "next_page_token": "token2"}
        ]
    }

    zoom_list_channels_mock = mocker.patch.object(client, "zoom_list_channels")
    zoom_list_channels_mock.return_value = expected_raw_data

    from Zoom import zoom_list_account_public_channels_command

    result = zoom_list_account_public_channels_command(
        client,
        page_size=page_size,
        channel_id=channel_id,
        next_page_token=next_page_token,
        page_number=page_number
    )

    zoom_list_channels_mock.assert_called_with(
        page_size=page_size,
        next_page_token=next_page_token,
        url_suffix=expected_url_suffix,
        page_number=page_number
    )

    expected_results = {
        "channels": [
            {"jid": "channel_jid_1", "id": "channel_id_1", "name": "Channel 1", "type": "public",
             "channel_url": "https://test1.com", "next_page_token": "token1"},
            {"jid": "channel_jid_2", "id": "channel_id_2", "name": "Channel 2", "type": "public",
             "channel_url": "https://test1.com", "next_page_token": "token2"}
        ],
        "ChannelsNextToken": None
    }

    assert result.outputs == expected_results
    assert result.outputs['channels'][0]['id'] == expected_results['channels'][0]['id']
    assert result.outputs['channels'][0]['jid'] == expected_results['channels'][0]['jid']


def test_zoom_list_account_public_channels_command__limit(mocker):
    """
        Given -
           client
        When -
            zoom list public account with limit of results
        Then -
            Validate that a func that runs a pagination has been called
    """
    manual_manual_list_channel_paginatio_mock = mocker.patch.object(Zoom, "manual_list_channel_pagination")
    mocker.patch.object(Client, "generate_oauth_token")
    client = Client(base_url='https://test.com', account_id="mockaccount",
                    client_id="mockclient", client_secret="mocksecret")
    from Zoom import zoom_list_account_public_channels_command
    zoom_list_account_public_channels_command(client=client, user_id="example@example.com", limit=5)
    assert manual_manual_list_channel_paginatio_mock.called


def test_zoom_send_message_command_with_file(mocker):
    client = Client(base_url='https://test.com', account_id="mockaccount",
                    client_id="mockclient", client_secret="mocksecret")

    entry_id = "entry_id"
    user_id = "user1"

    expected_file_info = {
        'name': 'test_file.txt',
        'path': '/path/to/test_file.txt'
    }
    expected_upload_response = {
        'id': 'file_id'
    }
    expected_uplaod_file_url = f'https://file.zoom.us/v2/chat/users/{user_id}/files'

    expected_response = {
        'id': 'message_id',
        'contact': "user2@example.com",
        'channel_name': 'channel_name'
    }

    mocker.patch('Zoom.demisto.getFilePath', return_value=expected_file_info)
    zoom_send_file_mock = mocker.patch.object(client, "zoom_upload_file", return_value=expected_upload_response)
    mock_send_chat_message = mocker.patch.object(client, 'zoom_send_message')
    mock_send_chat_message.return_value = expected_response
    from Zoom import zoom_send_message_command

    zoom_send_message_command(client,
                              user_id=user_id,
                              message='Hello from @dima!',
                              to_channel='channel1',
                              entry_ids='entry_id'
                              )
    # Assert function calls
    Zoom.demisto.getFilePath.assert_called_with(entry_id)
    zoom_send_file_mock.assert_called_with(expected_uplaod_file_url, expected_file_info)


def test_zoom_send_message_command(mocker):
    """
    Given -
        client
    When -
        send message to channel
    Then -
        Validate that the zoom_send_message function is called with the correct arguments
        Validate the command results including outputs and readable output
    """
    client = Client(base_url='https://test.com', account_id="mockaccount",
                    client_id="mockclient", client_secret="mocksecret")

    expected_request_payload = {
        'message': 'Hello from @dima!',
        'to_channel': 'channel1',
        'file_ids': []
    }

    expected_response = {
        'id': 'message_id',
        'contact': "user2@example.com",
        'channel_name': 'channel_name'
    }

    mock_send_chat_message = mocker.patch.object(client, 'zoom_send_message')
    mock_send_chat_message.return_value = expected_response
    from Zoom import zoom_send_message_command

    result = zoom_send_message_command(client,
                                       user_id='user1',
                                       message='Hello from @dima!',
                                       to_channel='channel1',

                                       )

    assert result.outputs == expected_response
    assert mock_send_chat_message.call_args[0][1] == expected_request_payload


def test_zoom_send_message_markdown_command(mocker):
    """
    Given -
        client
    When -
        send message to channel with markdown
    Then -
        Validate that the zoom_send_message function is called with the correct arguments
        Validate the command results including outputs and readable output
    """
    client = Client(base_url='https://test.com', account_id="mockaccount",
                    client_id="mockclient", client_secret="mocksecret")

    expected_request_payload = {
        'message': 'HI \n@John, please review the following report',
        'to_channel': 'channel1',
        'at_items': [
            {'text': '@John', 'at_contact': 'user2@example.com', 'at_type': 1, 'start_position': 4, 'end_position': 8}
        ],
        'rich_text': [
            {'text': 'report', 'format_type': 'AddLink', 'format_attr': 'https://example.com',
             'start_position': 39, 'end_position': 44},
            {'text': 'HI ', 'format_type': 'paragraph', 'format_attr': 'h1', 'start_position': 0, 'end_position': 2},
            {'text': '@John, please review the following report', 'format_type': 'LeftIndent',
             'format_attr': 40, 'start_position': 4, 'end_position': 44}
        ],
        'file_ids': []
    }

    expected_response = {
        'id': 'message_id',
        'contact': "user2@example.com",
        'channel_name': 'channel_name'
    }

    mock_send_chat_message = mocker.patch.object(client, 'zoom_send_message')
    mock_send_chat_message.return_value = expected_response
    from Zoom import zoom_send_message_command

    result = zoom_send_message_command(client,
                                       user_id='user1',
                                       at_contact='user2@example.com',
                                       is_markdown=True,
                                       message="# HI \n>> @John, please review the following [report](https://example.com)",
                                       to_channel='channel1'
                                       )

    assert result.outputs == expected_response
    assert mock_send_chat_message.call_args[0][1] == expected_request_payload


def test_zoom_send_message_markdown_command_error_mentions(mocker):
    """
    Given -
        client
    When -
        send message to channel with invalid markdown
    Then -
        Validate that an exception is raised
    """
    client = Client(base_url='https://test.com', account_id="mockaccount",
                    client_id="mockclient", client_secret="mocksecret")

    from Zoom import zoom_send_message_command

    with pytest.raises(Exception) as e:
        zoom_send_message_command(client,
                                  user_id='user1',
                                  at_contact='user2@example.com',
                                  is_markdown=True,
                                  message="@user This is an @invalid markdown",
                                  to_channel='channel1'
                                  )

    assert str(e.value) == "Too many mentions in text. you can provide only one mention in each message"


def test_zoom_list_messages_command(mocker):
    """
    Given -
        client
    When -
        get all messages in date
    Then -
        Validate that the zoom_list_messages_command function is called with the correct arguments
        Validate the command results including outputs and readable output
    """
    client = Client(base_url='https://test.com', account_id="mockaccount", client_id="mockclient", client_secret="mocksecret")
    channel_id = "channel_id"
    user_id = "user_id"
    limit = 100
    to_contact = "contact@example.com"
    to_channel = "channel_id"
    date_arg = "2023-03-07T00:49:01Z"
    include_deleted_and_edited_message = True
    search_type = "message"
    search_key = "keyword"
    exclude_child_message = False

    expected_raw_data = {
        "messages": [
            {"id": "message_id_1", "message": "Message 1", "sender": "sender_1",
             "sender_display_name": "Sender 1", "date_time": "2023-03-07T10:30:00Z"},
            {"id": "message_id_2", "message": "Message 2", "sender": "sender_2",
             "sender_display_name": "Sender 2", "date_time": "2023-03-08T09:15:00Z"}
        ]
    }
    expacted_result = {
        'ChatMessage': {"messages": [
            {"id": "message_id_1", "message": "Message 1", "sender": "sender_1",
             "sender_display_name": "Sender 1", "date_time": "2023-03-07T10:30:00Z"},
            {"id": "message_id_2", "message": "Message 2", "sender": "sender_2",
             "sender_display_name": "Sender 2", "date_time": "2023-03-08T09:15:00Z"}
        ]},
        "ChatMessageNextToken": None
    }
    client.zoom_list_user_messages = mocker.MagicMock(return_value=expected_raw_data)
    from Zoom import zoom_list_messages_command

    result = zoom_list_messages_command(
        client,
        channel_id=channel_id,
        user_id=user_id,
        next_page_token='next_page_token',
        limit=limit,
        to_contact=to_contact,
        to_channel=to_channel,
        date=date_arg,
        include_deleted_and_edited_message=include_deleted_and_edited_message,
        search_type=search_type,
        search_key=search_key,
        exclude_child_message=exclude_child_message
    )

    assert result.outputs == expacted_result
    assert result.outputs['ChatMessage']['messages'][0]['id'] == expacted_result['ChatMessage']['messages'][0]['id']
    assert result.outputs['ChatMessage']['messages'][0]['message'] == expacted_result['ChatMessage']['messages'][0]['message']
    assert result.outputs['ChatMessage']['messages'][0]['sender'] == expacted_result['ChatMessage']['messages'][0]['sender']
    assert result.outputs['ChatMessage']['messages'][0]['sender_display_name'] == expacted_result['ChatMessage']['messages'][0][
        'sender_display_name']  # noqa: E501
    assert result.outputs['ChatMessage']['messages'][0]['date_time'] == expacted_result['ChatMessage']['messages'][0]['date_time']


def test_zoom_list_messages_command_pageination(mocker):
    """
    Given -
        client
    When -
        get all messages in date
    Then -
        Validate that the zoom_list_messages_command function is called with the correct arguments
        Validate the command results including outputs and readable output
    """
    client = Client(base_url='https://test.com', account_id="mockaccount", client_id="mockclient", client_secret="mocksecret")
    channel_id = "channel_id"
    user_id = "user_id"
    limit = 1
    to_contact = "contact@example.com"
    to_channel = "channel_id"
    date_arg = "2023-03-07T00:49:01Z"
    include_deleted_and_edited_message = True
    search_type = "message"
    search_key = "keyword"
    exclude_child_message = False

    expected_raw_data = {
        "messages": [
            {"id": "message_id_1", "message": "Message 1", "sender": "sender_1",
             "sender_display_name": "Sender 1", "date_time": "2023-03-07T10:30:00Z"}
        ],
        "next_page_token": "xxxxxxxxxxx"
    }
    expacted_result = {
        "ChatMessage": {"messages": [
            {"id": "message_id_1", "message": "Message 1", "sender": "sender_1",
             "sender_display_name": "Sender 1", "date_time": "2023-03-07T10:30:00Z"}
        ]},
        "ChatMessageNextToken":
            {"user_id": "user_id",
             "to_contact": "contact@example.com",
             "to_channel": "channel_id",
             "date": "2023-03-07T00:49:01Z",
             "include_deleted_and_edited_message": True,
             "search_type": "message",
             "search_key": "keyword",
             "exclude_child_message": False,
             "page_size": 1,
             "next_page_token": "xxxxxxxxxxx"}
    }
    client.zoom_list_user_messages = mocker.MagicMock(return_value=expected_raw_data)
    from Zoom import zoom_list_messages_command

    result = zoom_list_messages_command(
        client,
        channel_id=channel_id,
        user_id=user_id,
        next_page_token='next_page_token',
        limit=limit,
        to_contact=to_contact,
        to_channel=to_channel,
        date=date_arg,
        include_deleted_and_edited_message=include_deleted_and_edited_message,
        search_type=search_type,
        search_key=search_key,
        exclude_child_message=exclude_child_message
    )

    assert result.outputs == expacted_result
    assert result.outputs['ChatMessageNextToken']['user_id'] == expacted_result['ChatMessageNextToken']['user_id']
    assert result.outputs['ChatMessageNextToken']['date'] == expacted_result['ChatMessageNextToken']['date']


def test_zoom_update_message_command(mocker):
    """
    Given -
        client
    When -
        update a message that was send
    Then -
        Validate that the zoom_update_message function is called with the correct arguments
        Validate the command results including outputs and readable output
    """
    client = Client(base_url='https://test.com', account_id="mockaccount",
                    client_id="mockclient", client_secret="mocksecret")
    mocker.patch.object(Client, "generate_oauth_token")

    user_id = "user1"
    message_id = "2d12042d-1823-4b0c-b26d-3f5ef7a89d68"
    message = "Hello! this is message for all"
    to_channel = "channel1"
    to_contact = "user2@example.com"
    # entry_ids = ["file_entry_id1", "file_entry_id2"]

    expected_payload = {
        "message": message,
        "file_ids": [],
        "to_channel": to_channel,
        "to_contact": to_contact
    }

    zoom_update_message_mock = mocker.patch.object(client, "zoom_update_message")

    from Zoom import zoom_update_message_command

    result = zoom_update_message_command(
        client,
        user_id=user_id,
        message_id=message_id,
        message=message,
        to_channel=to_channel,
        to_contact=to_contact
        # entry_ids=entry_ids
    )

    # Test case: Update message with to_channel
    zoom_update_message_mock.assert_called_with(f"/chat/users/{user_id}/messages/{message_id}", expected_payload)

    assert result.readable_output == 'Message 2d12042d-1823-4b0c-b26d-3f5ef7a89d68 was successfully updated'


def test_zoom_delete_message_command(mocker):
    """
    Given -
        client
    When -
       delete zoom message
    Then -
        Validate that the zoom_delete_message function is called with the correct arguments
        Validate the command results including outputs and readable output
    """
    client = Client(base_url='https://test.com', account_id="mockaccount",
                    client_id="mockclient", client_secret="mocksecret")
    mocker.patch.object(Client, "generate_oauth_token")

    user_id = "user1"
    message_id = "2d12042d-1823-4b0c-b26d-3f5ef7a89d68"
    to_channel = "channel1"
    # entry_ids = ["file_entry_id1", "file_entry_id2"]

    zoom_delete_message_mock = mocker.patch.object(client, "zoom_delete_message")

    from Zoom import zoom_delete_message_command

    result_to_channel = zoom_delete_message_command(
        client,
        user_id=user_id,
        message_id=message_id,
        to_channel=to_channel,
        # entry_ids=entry_ids
    )
    # Test case: Update message with to_channel
    zoom_delete_message_mock.assert_called_with(f"/chat/users/{user_id}/messages/{message_id}?to_channel={to_channel}")

    assert result_to_channel.readable_output == 'Message 2d12042d-1823-4b0c-b26d-3f5ef7a89d68 was deleted successfully'


def test_zoom_get_user_id_by_email(mocker):
    """
    Given -
        client
    When -
        get userID by his email
    Then -
        Validate that the zoom_get_user_id_by_email function is called with the correct arguments
        Validate the command results
    """
    client = Client(base_url='https://test.com', account_id="mockaccount",
                    client_id="mockclient", client_secret="mocksecret")
    email = "user@example.com"

    expected_user_id = "user_id"
    expected_response = {"id": expected_user_id}

    mock_zoom_list_users = mocker.patch.object(client, 'zoom_list_users', return_value=expected_response)
    from Zoom import zoom_get_user_id_by_email
    result = zoom_get_user_id_by_email(client, email)
    mock_zoom_list_users.assert_called_with(page_size=50, url_suffix=f'users/{email}')
    assert result == expected_user_id


def test_zoom_get_user_email_by_id(mocker):
    """
    Given -
        client
    When -
        get user email address by their user ID
    Then -
        Validate that the get_user_email_by_id function is called with the correct arguments
        Validate the command results
    """
    client = Client(base_url='https://test.com', account_id="mockaccount",
                    client_id="mockclient", client_secret="mocksecret")
    user_id = "user_id"
    expected_user_email = "user@example.com"
    expected_response = {"email": expected_user_email}

    mock_zoom_list_users = mocker.patch.object(client, 'zoom_list_users', return_value=expected_response)
    from Zoom import zoom_get_user_email_by_id
    result = zoom_get_user_email_by_id(client, user_id)
    mock_zoom_list_users.assert_called_with(page_size=1, url_suffix=f'users/{user_id}')
    assert result == expected_user_email


def test_zoom_send_notification_command(mocker):
    """
    Given -
        client
    When -
        send message to channel
    Then -
        Validate that the zoom_send_message function is called with the correct arguments
        Validate the command results including outputs and readable output
    """
    client = Client(base_url='https://test.com', account_id="mockaccount",
                    client_id="mockclient", client_secret="mocksecret", bot_client_id="mockclient",
                    bot_client_secret="mocksecret")
    client.bot_jid = 'mock_bot'

    expected_request_payload = {
        'robot_jid': 'mock_bot',
        'to_jid': 'channel1@xmpp.zoom.us',
        'account_id': 'mockaccount',
        'content': {'head': {'type': 'message', 'text': 'Hello'}}
    }

    expected_response = {
        'message_id': 'message_id',
    }

    mock_send_chat_message = mocker.patch.object(client, 'zoom_send_notification')
    mock_send_chat_message.return_value = expected_response
    from Zoom import send_notification

    result = send_notification(client,
                               user_id='user1',
                               message='Hello',
                               to='channel1',
                               )

    assert result.readable_output == 'Message sent to Zoom successfully. Message ID is: message_id'
    assert mock_send_chat_message.call_args[0][1] == expected_request_payload


def test_zoom_delete_user_token_command(mocker):
    """
    Given -
        Zoom client
    When -
       zoom-delete-user-token has called
    Then -
        Validate that the zoom_delete_user_token function is called with the correct arguments
        Validate the command results return the correct readable output
    """

    client = Client(base_url='https://test.com', account_id="mockaccount",
                    client_id="mockclient", client_secret="mocksecret")
    mocker.patch.object(Client, "generate_oauth_token")

    user_id = 'mock_user_id'
    zoom_delete_user_token_mock = mocker.patch.object(client, "zoom_delete_user_token")

    from Zoom import zoom_delete_user_token_command

    result = zoom_delete_user_token_command(client, user_id=user_id)
    zoom_delete_user_token_mock.assert_called_with(f"/users/{user_id}/token")
    assert result.readable_output == 'User SSO token for user mock_user_id is deleted'


@pytest.mark.parametrize("channel_name, investigation_id, expected_result", [
    ('Channel1', None, 'JID1'),  # Scenario 1: Find by channel_name
    (None, 'Incident123', 'JID1'),  # Scenario 2: Find by investigation_id
    ('NonExistentChannel', None, None),  # Scenario 3: Channel not found
])
def test_get_channel_jid_by_channel_name(channel_name, investigation_id, expected_result, mocker):
    """
    Given different scenarios with channel_name and investigation_id parameters,
    When calling the get_channel_jid_from_context function,
    Then validate that the function returns the expected result.
    """
    # Mock integration context
    Zoom.CACHE_EXPIRY = False
    mock_integration_context = {
        'mirrors': json.dumps([
            {'channel_name': 'Channel1', 'channel_jid': 'JID1', 'investigation_id': 'Incident123'},
            {'channel_name': 'Channel2', 'channel_jid': 'JID2', 'investigation_id': 'Incident123'},
        ])
    }
    mocker.patch.object(demisto, 'getIntegrationContext', return_value=mock_integration_context)

    # Call the function
    from Zoom import get_channel_jid_from_context
    result = get_channel_jid_from_context(channel_name, investigation_id)

    # Assert the result
    assert result == expected_result


# Test cases for check_authentication_bot_parameters
@pytest.mark.parametrize("bot_Jid, client_id, client_secret, expected_exception", [
    ('bot_Jid', 'client_id', 'client_secret', None),  # Scenario 1: All parameters provided
    (None, None, None, None),  # Scenario 2: All parameters None
    ('bot_Jid', None, None, DemistoException),  # Scenario 3: bot_Jid provided, others None
    (None, 'client_id', None, DemistoException),  # Scenario 4: client_id provided, others None
    (None, None, 'client_secret', DemistoException),  # Scenario 5: client_secret provided, others None
])
def test_check_authentication_bot_parameters(bot_Jid, client_id, client_secret, expected_exception):
    """
    Given different scenarios with bot_Jid, client_id, and client_secret parameters,
    When calling the check_authentication_bot_parameters function,
    Then validate that the function raises the expected exception or returns without raising an exception.
    """
    from Zoom import check_authentication_bot_parameters
    if expected_exception:
        with pytest.raises(expected_exception):
            check_authentication_bot_parameters(bot_Jid, client_id, client_secret)
    else:
        check_authentication_bot_parameters(bot_Jid, client_id, client_secret)


def test_get_admin_user_id_from_token(mocker):
    """
    Given a mock client with a zoom_get_admin_user_id_from_token method,
    When calling the get_admin_user_id_from_token function,
    Then validate that the function returns the expected user ID.
    """
    # Create a mock client
    client = Client(base_url='https://test.com', account_id="mockaccount",
                    client_id="mockclient", client_secret="mocksecret")
    mocker.patch.object(client, 'zoom_get_admin_user_id_from_token', return_value={'id': 'mock_user_id'})
    # Call the function
    from Zoom import get_admin_user_id_from_token
    result = get_admin_user_id_from_token(client)

    # Assert the result
    assert result == 'mock_user_id'


def test_mirror_investigation_create_new_channel(mocker):
    """
    Given a mock client and relevant arguments,
    When calling the mirror_investigation function to create a new channel,
    Then validate that the function returns the expected CommandResults.
    """
    Zoom.MIRRORING_ENABLED = True
    Zoom.LONG_RUNNING = True
    client = Client(base_url='https://test.com', account_id="mockaccount",
                    client_id="mockclient", client_secret="mocksecret")
    client.bot_jid = 'mock_jid'
    mocker.patch.object(client, 'zoom_send_notification')
    mocker.patch.object(Zoom, 'get_admin_user_id_from_token', return_value='mock_user_id')
    mocker.patch.object(Zoom, 'zoom_create_channel_command',
                        return_value=CommandResults(outputs={"jid": "mock_jid", "id": "mock_id"}))
    mocker.patch.object(demisto, 'demistoUrls', return_value={'server': 'mock_server_url'})
    # mocker.patch.object(client, 'botJid', return_value='bot_jid_mock')

    # Test data
    args = {
        'type': 'all',
        'direction': 'Both',
        'channelName': 'mirror-channel',
        'autoclose': True,
    }

    # Call the function
    from Zoom import mirror_investigation
    result = mirror_investigation(client, **args)

    # Assert the result
    assert 'Investigation mirrored successfully' in result.readable_output


@pytest.mark.asyncio
async def test_check_and_handle_entitlement(mocker):
    """
    Test the asynchronous function check_and_handle_entitlement.
    Given:
    - Input parameters for the function: text, message_id, user_name.
    When:
    - Calling the asynchronous function check_and_handle_entitlement with the given input parameters.
    Then:
    - Validate that the function behaves as expected and returns the expected result.
    """
    # Mock integration context
    mock_integration_context = {
        'messages': json.dumps([
            {'message_id': 'MessageID123',
             'entitlement': '3dcaae6d-d4d2-45b3-81a7-834bce779009@2b03d219-bbac-4333-84a2-d329d7296baa',
             'reply': 'thanks', 'expiry': '2023-08-29 12:32:40', 'sent': '2023-08-29 12:27:42', 'default_response': 'NoResponse'}
        ])
    }
    mocker.patch.object(demisto, 'getIntegrationContext', return_value=mock_integration_context)
    Zoom.CACHE_EXPIRY = False
    # Define the input parameters for the function
    text = "Entitlement Text"
    message_id = "MessageID123"
    user_name = "User123"
    user_id = "user123@example.com"

    # Call the async function and await its result
    from Zoom import check_and_handle_entitlement
    result = await check_and_handle_entitlement(text, message_id, user_name, user_id)

    assert result == 'thanks'  # Adjust the expected reply as needed


@pytest.mark.parametrize("entitlement, expected_result", [
    ("guid123@incident456|task789", ("guid123", "incident456", "task789")),  # Scenario 1: Full entitlement
    ("guid123@incident456", ("guid123", "incident456", "")),  # Scenario 2: No task ID
    ("guid123@", ("guid123", "", "")),  # Scenario 3: No incident ID or task ID
])
def test_extract_entitlement(entitlement, expected_result):
    """
    Test the extract_entitlement function.
    Given:
    - Input entitlement string.
    When:
    - Calling the extract_entitlement function with the given input entitlement.
    Then:
    - Validate that the function correctly extracts the entitlement components: guid, incident_id, and task_id.
    """
    from Zoom import extract_entitlement
    result = extract_entitlement(entitlement)

    # Assert the result against the expected outcome
    assert result == expected_result


# @pytest.mark.asyncio
# async def test_check_for_unanswered_questions(mocker):
#     mock_integration_context = {
#         'messages': json.dumps([
#             {
#                 'message_id': 'MessageID1',
#                 'expiry': '2023-08-29 12:00:00',
#                 'default_response': 'DefaultResponse1'
#             },
#             {
#                 'message_id': 'MessageID2',
#                 'expiry': '2023-08-29 14:00:00',
#                 'default_response': 'DefaultResponse2'
#             },
#         ])
#     }
#     mocker.patch.object(demisto, 'getIntegrationContext', return_value=mock_integration_context)


@pytest.mark.asyncio
async def test_answer_question(mocker):
    """
    Test the answer_question function.
    Given:
    - A mocked question dictionary.
    When:
    - Calling the answer_question function with the mocked question.
    Then:
    - Validate that the function correctly handles the entitlement and returns the incident_id.
    """

    mock_question = {
        'entitlement': 'guid123@incident456|task789',
        'to_jid': 'ToJID123'
    }
    Zoom.CLIENT = Client(base_url='https://test.com', account_id="mockaccount",
                         client_id="mockclient", client_secret="mocksecret")
    Zoom.CLIENT.bot_jid = 'mock_bot_id'
    mocker.patch.object(Zoom, 'process_entitlement_reply')

    from Zoom import answer_question
    result = await answer_question("Answer123", mock_question, "user@example.com")
    assert result == 'incident456'


@pytest.mark.asyncio
async def test_process_entitlement_reply(mocker):
    """
    Test the process_entitlement_reply function.

    Given:
    - Mocked input parameters.

    When:
    - Calling the process_entitlement_reply function with the mocked parameters.

    Then:
    - Validate that the function correctly prepares and sends a Zoom notification.
    """
    # Mocked input parameters
    mock_entitlement_reply = "Entitlement Reply"
    mock_account_id = "mock_account_id"
    mock_robot_jid = "mock_robot_jid"
    mock_to_jid = "mock_to_jid"
    client = Client(base_url='https://test.com', account_id="mockaccount",
                    client_id="mockclient", client_secret="mocksecret")
    # Mock the CLIENT.zoom_send_notification function
    Zoom.CLIENT = client
    mock_zoom_send_notification = mocker.AsyncMock()
    mock_zoom_send_notification = mocker.patch.object(Zoom, 'zoom_send_notification_async')

    # Call the function with the mocked parameters
    from Zoom import process_entitlement_reply
    await process_entitlement_reply(mock_entitlement_reply, mock_account_id, mock_robot_jid, mock_to_jid)

    # Assert that the CLIENT.zoom_send_notification function was called with the correct arguments
    mock_zoom_send_notification.assert_called_with(client,
                                                   '/im/chat/messages',
                                                   {
                                                       "content": {
                                                           "body": [
                                                               {
                                                                   "type": "message",
                                                                   "text": mock_entitlement_reply
                                                               }
                                                           ]
                                                       },
                                                       "to_jid": mock_to_jid,
                                                       "robot_jid": mock_robot_jid,
                                                       "account_id": mock_account_id
                                                   }
                                                   )


# Test cases
@pytest.mark.asyncio
async def test_close_channel(mocker):
    """
    Test the close_channel function
    Given:
    - Mocked input parameters.
    When:
    - Calling the close_channel function.
    Then:
    - Ensure that the function successfully closes the channel.
    """
    mock_integration_context = {
        'mirrors': json.dumps([
            {'channel_name': 'Channel1', 'channel_jid': 'JID1', 'channel_id': 'ID1',
             'investigation_id': 'Incident123', 'mirror_direction': 'both', 'auto_close': True},
            {'channel_name': 'Channel2', 'channel_jid': 'JID2', 'channel_id': 'ID2',
             'investigation_id': 'Incident123', 'mirror_direction': 'both', 'auto_close': True},
        ])
    }
    client = Client(base_url='https://test.com', account_id="mockaccount",
                    client_id="mockclient", client_secret="mocksecret")

    mocker.patch.object(Zoom, 'zoom_delete_channel_command')
    mocker.patch.object(demisto, 'mirrorInvestigation')
    mocker.patch.object(Zoom, 'get_integration_context', return_value=mock_integration_context)
    mocker.patch.object(Zoom, 'set_to_integration_context_with_retries')
    mocker.patch.object(Zoom, 'get_admin_user_id_from_token', return_value='mock_user_id')
    mocker.patch.object(Zoom, 'find_mirror_by_investigation', return_value={'channel_id': 'ID1'})

    from Zoom import close_channel
    result = close_channel(client)

    assert result == 'Channel successfully deleted.'


@pytest.mark.parametrize("event_type, expected_status", [
    ('endpoint.url_validation', status.HTTP_200_OK),
    ('interactive_message_actions', status.HTTP_200_OK),
    ('invalid_event_type', status.HTTP_400_BAD_REQUEST)
])
@pytest.mark.asyncio
async def test_handle_zoom_response(event_type, expected_status,
                                    mocker):
    """
    Test the handle_zoom_response function with different event types and payload conditions.

    Given:
    - Mocked request object.
    - Mocked event_url_validation, check_and_handle_entitlement, process_entitlement_reply, and handle_mirroring functions.
    - Parameters for event types and payload conditions.

    When:
    - Calling the handle_zoom_response function with different event types and payload conditions.

    Then:
    - Ensure that the function returns the expected response status code.
    """
    mock_request = mocker.Mock(spec=Request)
    json_res = {
        "plainToken": 123,
        "encryptedToken": 123
    }
    mocker.patch('Zoom.event_url_validation', return_value=json_res)
    mocker.patch('Zoom.check_and_handle_entitlement')
    mocker.patch('Zoom.process_entitlement_reply')
    mocker.patch('Zoom.handle_mirroring')
    mocker.patch('Zoom.zoom_get_user_email_by_id', return_value="mock_user_email")
    mocker.patch.object(demisto, 'params', return_value={'credentials': {'identifier': 'test', 'password': 'testpass'}})

    # Create a mock HTTPBasicCredentials object
    mock_credentials = HTTPBasicCredentials(
        username="test",
        password="testpass"
    )

    Zoom.SECRET_TOKEN = 'token'

    from Zoom import handle_zoom_response

    mock_request.json.return_value = {
        "event": event_type,
        "payload": {
            "accountId": "mock_accountid",
            "actionItem": {
                "text": "no",
                "value": "no",
                "action": "command"
            },
            "messageId": "message_id",
            "robotJid": "robot_jid",
            "toJid": "mock_jid",
            "userName": "admin zoom",
            "userId": "mock_userId"
        }
    }

    response = await handle_zoom_response(mock_request, mock_credentials)

    assert response.status_code == expected_status


@pytest.mark.asyncio
async def test_event_url_validation():
    Zoom.SECRET_TOKEN = "secret_token"

    # Define the payload for testing
    payload = {
        "plainToken": "plain_token"
    }

    # Calculate the expected signature
    import hashlib
    import hmac
    hash_object = hmac.new(Zoom.SECRET_TOKEN.encode('utf-8'), msg=payload['plainToken'].encode('utf-8'), digestmod=hashlib.sha256)
    expected_signature = hash_object.hexdigest()

    from Zoom import event_url_validation
    response = await event_url_validation(payload)

    # Verify that the response matches the expected signature
    assert response == {
        "plainToken": payload["plainToken"],
        "encryptedToken": expected_signature
    }


@pytest.mark.asyncio
async def test_handle_text(mocker):
    # Create mock arguments
    investigation_id = "123"
    text = "Hello, this is a test message"
    operator_email = "test@example.com"
    operator_name = "Test User"
    MESSAGE_FOOTER = '\n**From Zoom**'
    from Zoom import handle_text_received_from_zoom

    with patch('Zoom.demisto') as mock_demisto:
        # Call the function
        await handle_text_received_from_zoom(investigation_id, text, operator_email, operator_name)
        # Assert that the `demisto.addEntry` method was called with the expected arguments
        mock_demisto.addEntry.assert_called_once_with(
            id=investigation_id,
            entry=text,
            username=operator_name,
            email=operator_email,
            footer=MESSAGE_FOOTER  # Assuming MESSAGE_FOOTER is defined in your module
        )


def test_save_entitlement():
    # Define test inputs
    entitlement = "Test Entitlement"
    message_id = "123"
    reply = "Test Reply"
    expiry = "2023-09-09"
    default_response = "Default Response"
    to_jid = "user@example.com"
    SYNC_CONTEXT = True
    OBJECTS_TO_KEYS = {
        'messages': 'entitlement',
    }
    # Mock the required functions (get_integration_context, set_to_integration_context_with_retries) and any other dependencies
    with patch('Zoom.get_integration_context') as mock_get_integration_context, \
            patch('Zoom.set_to_integration_context_with_retries') as mock_set_integration_context:
        # Mock the return values of the mocked functions
        mock_get_integration_context.return_value = {'messages': []}
        fixed_timestamp = '2023-09-09 20:08:50'

        with freeze_time(fixed_timestamp):
            from Zoom import save_entitlement
            # Call the function to be tested
            save_entitlement(entitlement, message_id, reply, expiry, default_response, to_jid)

        # Define the expected data to be added to integration context
        expected_data = {
            'messages': [
                {
                    'message_id': message_id,
                    'entitlement': entitlement,
                    'reply': reply,
                    'expiry': expiry,
                    'sent': fixed_timestamp,
                    'default_response': default_response,
                    'to_jid': to_jid
                }
            ]
        }

        # Assert that the mocked functions were called with the expected arguments
        mock_get_integration_context.assert_called_once_with(SYNC_CONTEXT)
        mock_set_integration_context.assert_called_once_with(expected_data, OBJECTS_TO_KEYS, SYNC_CONTEXT)
