from FortiManager import Client
import demistomock as demisto


def setup_testing_client(mocker):
    mocker.patch.object(demisto, 'getIntegrationContext', return_value={
        'session': 'some_token'
    })
    return Client(url="my_url",
                  credentials={"identifier": "username", "password": "password"},
                  verify=False,
                  proxy=False,
                  adom="MyADOM")


def set_adom_to_global(client):
    client.adom = 'global'


def set_adom_to_non_global(client):
    client.adom = 'MyADOM'


def test_get_global_or_adom__use_client_non_global(mocker):
    from FortiManager import get_global_or_adom
    client = setup_testing_client(mocker)
    set_adom_to_non_global(client)
    args = {}
    result = get_global_or_adom(client, args)
    assert result == 'adom/MyADOM'


def test_get_global_or_adom__use_client_global(mocker):
    from FortiManager import get_global_or_adom
    client = setup_testing_client(mocker)
    set_adom_to_global(client)
    args = {}
    result = get_global_or_adom(client, args)
    assert result == 'global'


def test_get_global_or_adom__use_arg_non_global(mocker):
    from FortiManager import get_global_or_adom
    client = setup_testing_client(mocker)
    set_adom_to_global(client)
    args = {'adom': "MyArgADOM"}
    result = get_global_or_adom(client, args)
    assert result == 'adom/MyArgADOM'


def test_get_global_or_adom__use_arg_global(mocker):
    from FortiManager import get_global_or_adom
    client = setup_testing_client(mocker)
    set_adom_to_non_global(client)
    args = {'adom': "global"}
    result = get_global_or_adom(client, args)
    assert result == 'global'


def test_setup_request_data():
    from FortiManager import setup_request_data
    args = {'adom': 'MyADOM', 'name': "some_name", "variable": "value", 'ignore': 'this'}
    expected_res = {'name': "some_name", "variable": "value"}
    assert expected_res == setup_request_data(args, ['adom', 'ignore'])


def test_get_range_for_list_command__only_from():
    from FortiManager import get_range_for_list_command
    args = {'offset': 1}
    assert [1, 49] == get_range_for_list_command(args)


def test_get_range_for_list_command__only_to():
    from FortiManager import get_range_for_list_command
    args = {'limit': 1}
    assert [0, 1] == get_range_for_list_command(args)


def test_get_range_for_list_command__from_and_to():
    from FortiManager import get_range_for_list_command
    args = {'limit': 1, 'offset': 0}
    assert [0, 1] == get_range_for_list_command(args)


def test_get_range_for_list_command__no_from_and_to():
    from FortiManager import get_range_for_list_command
    args = {}
    assert get_range_for_list_command(args) == [0, 50]
