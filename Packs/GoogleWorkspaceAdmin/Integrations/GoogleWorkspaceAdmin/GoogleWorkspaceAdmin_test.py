import json
import io
import pytest
from GoogleWorkspaceAdmin import Client, PaginationResult

OUTPUT_PREFIX = 'GoogleWorkspaceAdmin'


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


class MockResponse:
    """ This class will be used to mock a request response (only the json function in the requests.Response class) """
    def __init__(self, json_data):
        self.json_data = json_data

    def json(self):
        return self.json_data


def create_test_client(mocker) -> Client:
    """ This will create a mock client in order to use in the tests

    Returns:
        Client: A mock client instance
    """
    mocker.patch('GoogleWorkspaceAdmin.Client._init_credentials', return_value=None)
    return Client(base_url='https://example.com/', verify=False, proxy=False, service_account_json={})


MOBILE_ACTION_ERROR_CASES = [
    ('error', MockResponse({'error': {'message': 'Internal error encountered'}}), 'Please check the resource_id argument'),
    ('error', MockResponse({'error': {'message': 'Bad Request'}}), 'Please check the resource_id argument'),
    ('error', MockResponse({'error': {'message': 'Some other error'}}), 'Some other error'),
    ('error', MockResponse({'error': 'Some other weird error'}), "{'error': 'Some other weird error'}"),
    ('error_message', None, 'error_message'),
]


@pytest.mark.parametrize('error_message, response_mock, parsed_error_message', MOBILE_ACTION_ERROR_CASES)
def test_invalid_mobile_action_command(mocker, error_message, response_mock, parsed_error_message):
    """
    Given:
        - A client, a resource id, and an action to execute on the mobile device.
    When:
        - Running the google_mobile_device_action_command command, and receiving an error from the API.
    Then:
        - Validate that the ambiguous error message is mapped to a more human readable error message.
    """
    from GoogleWorkspaceAdmin import google_mobile_device_action_command
    from CommonServerPython import DemistoException
    client = create_test_client(mocker=mocker)
    mocker.patch.object(client, 'google_mobile_device_action_request',
                        side_effect=DemistoException(message=error_message, res=response_mock))
    with pytest.raises(DemistoException) as e:
        google_mobile_device_action_command(client=client, customer_id='customer_id', resource_id='wrong_resource_id',
                                            action='some_action')
    assert parsed_error_message in str(e)


CHROMEOS_ACTION_ERROR_CASES = [
    ('error', MockResponse({'error': {'message': 'Delinquent account'}}), 'Please check the resource_id argument'),
    ('error', MockResponse({'error': {'message': 'Some other error'}}), 'Some other error'),
    ('error', MockResponse({'error': 'Some other weird error'}), "{'error': 'Some other weird error'}"),
    ('error_message', None, 'error_message'),
]


@pytest.mark.parametrize('error_message, response_mock, parsed_error_message', CHROMEOS_ACTION_ERROR_CASES)
def test_invalid_chromeos_action_command(mocker, error_message, response_mock, parsed_error_message):
    """
    Given:
        - A client, a resource id, and an action to execute on the chromeOS device.
    When:
        - Running the google_chromeos_device_action_command command, and receiving an error from the API.
    Then:
        - Validate that the ambiguous error message is mapped to a more human readable error message.
    """
    from GoogleWorkspaceAdmin import google_chromeos_device_action_command
    from CommonServerPython import DemistoException
    client = create_test_client(mocker=mocker)
    mocker.patch.object(client, 'google_chromeos_device_action_request',
                        side_effect=DemistoException(message=error_message, res=response_mock))
    with pytest.raises(DemistoException) as e:
        google_chromeos_device_action_command(client=client, customer_id='customer_id', resource_id='wrong_resource_id',
                                              action='some_action')
    assert parsed_error_message in str(e)


TEST_MODULE_ERROR_CASES = [
    ('error', MockResponse(json_data={'error': {'message': 'Bad Request'}}), 'Please check the customer ID parameter'),
    ('error', MockResponse(json_data={'error': {'message': 'Not Authorized to access this resource/api'}}),
     'Please check the authorizations of the configured service account'),
    ('error', MockResponse({'error': {'message': 'Some other error'}}), 'Some other error'),
    ('error', MockResponse({'error': 'Some other weird error'}), "{'error': 'Some other weird error'}"),
    ('error_message', None, 'error_message'),
]


@pytest.mark.parametrize('error_message, response_mock, parsed_error_message', TEST_MODULE_ERROR_CASES)
def test_invalid_client_connection(mocker, error_message, response_mock, parsed_error_message):
    """
    Given:
        - A client to use when running the test module.
    When:
        - Running test module and receiving an error message from the API.
    Then:
        - Validate that the ambiguous error message is mapped to a more human readable error message.
    """
    from GoogleWorkspaceAdmin import test_module
    from CommonServerPython import DemistoException
    mocker.patch('GoogleWorkspaceAdmin.Client._get_oauth_token', return_value='token')
    mocker.patch('GoogleWorkspaceAdmin.Client._http_request',
                 side_effect=DemistoException(message=error_message, res=response_mock))
    client = create_test_client(mocker=mocker)
    with pytest.raises(DemistoException) as e:
        test_module(client=client)
    assert parsed_error_message in str(e)


def test_invalid_service_account_json():
    """
    Given:
        - An invalid service_account_json (that holds the information about the service account).
    When:
        - Creating a client instance.
    Then:
        - Validate that an exception is thrown in response to an invalid service_account_json.
    """
    from CommonServerPython import DemistoException
    with pytest.raises(DemistoException) as e:
        Client(base_url='https://example.com/', verify=False, proxy=False,
               service_account_json={'wrong': 'service_account'})
    assert 'Please check the service account\'s json content' in str(e)


TEST_DATA_INVALID_PAGINATION_ARGUMENTS = [
    ({'page': '3', 'page_token': 'some_token', 'limit': '25'}, ('please supply either the argument limit,'
                                                                ' or the argument page_token, or the arguments'
                                                                ' page_token and page_size together')),
    ({'limit': '0'}, 'The limit argument can\'t be negative or equal to zero'),
    ({'limit': '-78'}, 'The limit argument can\'t be negative or equal to zero'),
    ({'page_token': 'some_token', 'page_size': '101'}, 'The maximum page size is')
]


@pytest.mark.parametrize('args, error_message', TEST_DATA_INVALID_PAGINATION_ARGUMENTS)
def test_invalid_pagination_arguments(args, error_message):
    """
    Given:
        - The pagination arguments supplied by the user.
    When:
        - Running the function prepare_pagination_arguments to check the content of the pagination arguments.
    Then:
        - Validate that an exception is thrown in response to invalid pagination arguments.
    """
    from GoogleWorkspaceAdmin import prepare_pagination_arguments
    from CommonServerPython import DemistoException
    with pytest.raises(DemistoException) as e:
        prepare_pagination_arguments(args=args)
    assert error_message in str(e)


def test_mobile_device_action(mocker):
    """
    Given:
        - A client, a resource id (that identifies a mobile device), and an action that affects the mobile device
    When:
        - The command google-mobiledevice-action is run with a correct action argument
    Then:
        - A CommandResults is returned that marks the command as successful
    """
    from GoogleWorkspaceAdmin import google_mobile_device_action_command
    from CommonServerPython import CommandResults
    expected_command_result = CommandResults(
        outputs_prefix=f'{OUTPUT_PREFIX}.MobileAction',
        outputs_key_field='ResourceId',
        readable_output='Success',
        outputs={'Action': 'correct_action', 'ResourceId': 'resource_id'},
    )
    client = create_test_client(mocker=mocker)
    mocker.patch.object(client, 'google_mobile_device_action_request', return_value='nothing')
    command_result = google_mobile_device_action_command(client=client, customer_id='customer_id', resource_id='resource_id',
                                                         action='correct_action')
    assert command_result.to_context() == expected_command_result.to_context()


def test_chromeos_device_action(mocker):
    """
    Given:
        - A client, a resource id (that identifies a mobile device), and an action that affects the chromeos device
    When:
        - The command google-chromeosdevice-action is run with a correct action argument
    Then:
        - A CommandResults is returned that marks the command as successful
    """
    from GoogleWorkspaceAdmin import google_chromeos_device_action_command
    from CommonServerPython import CommandResults
    expected_command_result = CommandResults(
        outputs_prefix=f'{OUTPUT_PREFIX}.ChromeOSAction',
        outputs_key_field='ResourceId',
        readable_output='Success',
        outputs={'Action': 'correct_action', 'ResourceId': 'resource_id'},
    )
    client = create_test_client(mocker=mocker)
    mocker.patch.object(client, 'google_chromeos_device_action_request', return_value='nothing')
    command_result = google_chromeos_device_action_command(client=client, customer_id='customer_id', resource_id='resource_id',
                                                           deprovision_reason='nothing', action='correct_action')
    assert command_result.to_context() == expected_command_result.to_context()


TEST_DATA_AUTO_PAGINATION_FILES_CASES = [
    ('test_data/mobile_devices_list/automatic_pagination/raw_results_3_pages.json',
     'test_data/mobile_devices_list/automatic_pagination/parsed_results_3_pages.json', {'limit': 7}),
    ('test_data/mobile_devices_list/automatic_pagination/raw_results_2_pages.json',
     'test_data/mobile_devices_list/automatic_pagination/parsed_results_2_pages.json', {'limit': 6})
]


@pytest.mark.parametrize('raw_results_file, parsed_results_file, pagination_args', TEST_DATA_AUTO_PAGINATION_FILES_CASES)
def test_mobile_device_list_automatic_pagination_result_instance(mocker, raw_results_file, parsed_results_file, pagination_args):
    # Since there is not enough mobile devices to actually do pagination, all the requests being mocked
    # are under the impression that the maximum page is of size 3, this will give us the ability to mock the pagination process
    """
    Given:
        - Raw responses representing mobile devices and a limit argument.
    When:
        - Running the command device_list_automatic_pagination to parse the raw results and return an instance of
         PaginationResult that hold the relevant data using automatic pagination.
    Then:
        - Validate the content of the PaginationResult instance.
    """
    from GoogleWorkspaceAdmin import MobileDevicesConfig, device_list_automatic_pagination
    query_params = {'projection': 'full', 'order_by': 'name', 'sort_order': 'descending', **pagination_args}
    client = create_test_client(mocker=mocker)
    raw_responses = util_load_json(raw_results_file)
    expected_pagination_result_instance = create_pagination_result_automatic_instance(
        raw_responses=raw_responses,
        response_devices_list_key=MobileDevicesConfig.response_devices_list_key)
    mocker.patch.object(client, 'google_mobile_device_list_request', side_effect=raw_responses)
    pagination_result = device_list_automatic_pagination(api_request=client.google_mobile_device_list_request,
                                                         customer_id='customer_id',
                                                         query_params=query_params,
                                                         response_devices_list_key=MobileDevicesConfig.response_devices_list_key,
                                                         **pagination_args)
    assert pagination_result == expected_pagination_result_instance


@pytest.mark.parametrize('raw_results_file, parsed_results_file, pagination_args', TEST_DATA_AUTO_PAGINATION_FILES_CASES)
def test_mobile_device_list_automatic_pagination(mocker, raw_results_file, parsed_results_file, pagination_args):
    # Since there is not enough mobile devices to actually do pagination, all the requests being mocked
    # are under the impression that the maximum page is of size 3, this will give us the ability to mock the pagination process
    """
    Given:
        - A client and query parameters for the API.
    When:
        - Running the command google_mobile_device_list_command to retrieve the mobile devices' list using automatic pagination.
    Then:
        - Validate the content of the context data and human readable.
    """
    from GoogleWorkspaceAdmin import google_mobile_device_list_command
    args = {'projection': 'full', 'order_by': 'name', 'sort_order': 'descending', **pagination_args}
    client = create_test_client(mocker=mocker)
    raw_responses = util_load_json(raw_results_file)
    expected_command_results = util_load_json(parsed_results_file)
    mocker.patch.object(client, 'google_mobile_device_list_request', side_effect=raw_responses)
    command_results = google_mobile_device_list_command(client=client, customer_id='customer_id', **args)
    for results, expected_results in zip(command_results, expected_command_results):
        to_context = results.to_context()
        assert expected_results.get('HumanReadable') == to_context.get('HumanReadable')
        assert expected_results.get('EntryContext') == to_context.get('EntryContext')


TEST_DATA_MANUAL_PAGINATION_FILES_CASES = [
    ('test_data/mobile_devices_list/manual_pagination/raw_results_with_next_page_token.json',
     'test_data/mobile_devices_list/manual_pagination/parsed_results_with_next_page_token.json',
     {'page_token': 'dummy_next_page_token', 'page_size': 2}),
    # ('test_data/mobile_devices_list/manual_pagination/raw_results_page_not_found.json',
    #  'test_data/mobile_devices_list/manual_pagination//parsed_results_page_not_found.json', {'page': '4', 'page_size': '3'})
]


@pytest.mark.parametrize('raw_results_file, parsed_results_file, pagination_args', TEST_DATA_MANUAL_PAGINATION_FILES_CASES)
def test_mobile_device_list_manual_pagination_result_instance(mocker, raw_results_file, parsed_results_file, pagination_args):
    # Since there is not enough mobile devices to actually do pagination, all the requests being mocked
    # are under the impression that the maximum page is of size 3, this will give us the ability to mock the pagination process
    """
    Given:
        - Raw responses representing mobile devices, and page_token and page_size arguments.
    When:
        - Running the command device_list_automatic_pagination to parse the raw results and return an instance of
         PaginationResult that hold the relevant data using manual pagination.
    Then:
        - Validate the content of the PaginationResult instance.
    """
    from GoogleWorkspaceAdmin import MobileDevicesConfig, device_list_manual_pagination
    query_params = {'projection': 'full', 'order_by': 'name', 'sort_order': 'descending', **pagination_args}
    client = create_test_client(mocker=mocker)
    raw_responses = util_load_json(raw_results_file)
    expected_pagination_result_instance = create_pagination_result_manual_instance(
        raw_responses=raw_responses,
        response_devices_list_key=MobileDevicesConfig.response_devices_list_key)
    mocker.patch.object(client, 'google_mobile_device_list_request', side_effect=raw_responses)
    pagination_result = device_list_manual_pagination(api_request=client.google_mobile_device_list_request,
                                                      customer_id='customer_id',
                                                      query_params=query_params,
                                                      response_devices_list_key=MobileDevicesConfig.response_devices_list_key,
                                                      **pagination_args)
    assert pagination_result == expected_pagination_result_instance


@pytest.mark.parametrize('raw_results_file, parsed_results_file, pagination_args', TEST_DATA_MANUAL_PAGINATION_FILES_CASES)
def test_mobile_device_list_manual_pagination(mocker, raw_results_file, parsed_results_file, pagination_args):
    # Since there is not enough mobile devices to actually do pagination, all the requests being mocked
    # are under the impression that the maximum page is of size 3, this will give us the ability to mock the pagination process
    """
    Given:
        - A client and query parameters for the API.
    When:
        - Running the command google_mobile_device_list_command to retrieve the mobile devices' list using manual pagination.
    Then:
        - Validate the content of the context data and human readable.
    """
    from GoogleWorkspaceAdmin import google_mobile_device_list_command
    args = {'projection': 'full', 'order_by': 'name', 'sort_order': 'descending', **pagination_args}
    client = create_test_client(mocker=mocker)
    raw_responses = util_load_json(raw_results_file)
    expected_command_results = util_load_json(parsed_results_file)
    mocker.patch.object(client, 'google_mobile_device_list_request', side_effect=raw_responses)
    command_results = google_mobile_device_list_command(client=client, customer_id='customer_id', **args)
    for results, expected_results in zip(command_results, expected_command_results):
        to_context = results.to_context()
        assert expected_results.get('HumanReadable') == to_context.get('HumanReadable')
        assert expected_results.get('EntryContext') == to_context.get('EntryContext')


TEST_PAGINATION_ARGS_CASES = [
    ({'limit': '2'}),
    ({'page_size': '3'})
]


@pytest.mark.parametrize('pagination_args', TEST_PAGINATION_ARGS_CASES)
def test_mobile_device_list_empty_response(mocker, pagination_args):
    """
    Given:
        - A client and query parameters for the API.
    When:
        - Running the command google_mobile_device_list_command to retrieve the mobile devices' and receiving no results.
    Then:
        - Validate the content of the context data and human readable.
    """
    from GoogleWorkspaceAdmin import google_mobile_device_list_command
    args = {'projection': 'full', 'order_by': 'name', 'sort_order': 'descending', **pagination_args}
    client = create_test_client(mocker=mocker)
    raw_responses = util_load_json('test_data/mobile_devices_list/no_results_found.json')
    expected_command_results = util_load_json('test_data/mobile_devices_list/parsed_no_results_found.json')
    mocker.patch.object(client, 'google_mobile_device_list_request', side_effect=raw_responses)
    command_results = google_mobile_device_list_command(client=client, customer_id='customer_id', **args)
    for results, expected_results in zip(command_results, expected_command_results):
        to_context = results.to_context()
        assert expected_results.get('HumanReadable') == to_context.get('HumanReadable')
        assert expected_results.get('EntryContext') == to_context.get('EntryContext')


MOBILE_DEVICES_ERROR_CASES = [
    ('error', MockResponse({'error': {'message': 'Some error'}}), 'Some error'),
    ('error', MockResponse({'error': 'Some other weird error'}), "{'error': 'Some other weird error'}"),
    ('error_message', None, 'error_message'),
]


@pytest.mark.parametrize('error_message, response_mock, parsed_error_message', MOBILE_DEVICES_ERROR_CASES)
def test_invalid_mobile_device_list_command(mocker, error_message, response_mock, parsed_error_message):
    """
    Given:
        - A client and query parameters for the API.
    When:
        - Running the google_mobile_device_list_command command, and receiving an error from the API.
    Then:
        - Validate that the error is caught and is processed.
    """
    from GoogleWorkspaceAdmin import google_mobile_device_list_command
    from CommonServerPython import DemistoException
    args = {'projection': 'full', 'order_by': 'name', 'sort_order': 'descending', 'limit': '531'}
    client = create_test_client(mocker=mocker)
    mocker.patch.object(client, 'google_mobile_device_list_request',
                        side_effect=DemistoException(message=error_message, res=response_mock))
    with pytest.raises(DemistoException) as e:
        google_mobile_device_list_command(client=client, customer_id='customer_id', **args)
    assert parsed_error_message in str(e)


def create_pagination_result_automatic_instance(raw_responses: list[dict], response_devices_list_key: str) -> PaginationResult:
    mocked_data = []
    for raw_response in raw_responses:
        mocked_data.extend(raw_response.get(response_devices_list_key, []))
    return PaginationResult(data=mocked_data, raw_response=raw_responses)


def create_pagination_result_manual_instance(raw_responses: list[dict], response_devices_list_key: str) -> PaginationResult:
    assert len(raw_responses) <= 1, 'The length of the mocked raw responses of a manual pagination should be at most 1.'
    mocked_data = []
    mocked_next_page_token = ''
    for raw_response in raw_responses:
        mocked_data.extend(raw_response.get(response_devices_list_key, []))
        mocked_next_page_token = raw_response.get('nextPageToken', '')
    return PaginationResult(data=mocked_data, raw_response=raw_responses, next_page_token=mocked_next_page_token)
