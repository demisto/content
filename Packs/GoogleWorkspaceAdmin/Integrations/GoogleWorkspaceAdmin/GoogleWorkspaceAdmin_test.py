import json
import io
import pytest
from GoogleWorkspaceAdmin import Client

OUTPUT_PREFIX = 'Google'  # TODO Ask if we should keep this


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
    return Client(base_url='https://example.com/', verify=False, proxy=False, customer_id='id', service_account_json={})


def test_invalid_resource_id_mobile_action_command(mocker):
    """
    Given:
        - A client and an invalid resource id.
    When:
        - Running the google_mobile_device_action_command command, and receiving the error message `Internal error encountered`.
    Then:
        - Validate that the ambiguous error message is mapped to a more human readable error message.
    """
    from GoogleWorkspaceAdmin import google_mobile_device_action_command
    from CommonServerPython import DemistoException
    client = create_test_client(mocker=mocker)
    expected_context_data = {'mobileAction': {'Status': 'Failure'}}
    response_mock = MockResponse(json_data={'error': {'message': 'Internal error encountered.'}})
    mocker.patch.object(client, 'google_mobile_device_action_request',
                        side_effect=DemistoException(message='error', res=response_mock))

    command_result = google_mobile_device_action_command(client=client, resource_id='wrong_resource_id',
                                                         action='some_action')
    assert 'Please check the resource_id argument.' in command_result.to_context().get('HumanReadable')
    assert expected_context_data == command_result.to_context().get('Contents')


def test_invalid_resource_id_chromeos_action_command(mocker):
    """
    Given:
        - A client and an invalid resource id.
    When:
        - Running the google_chromeos_device_action_command command, and receiving the error message `Delinquent account`.
    Then:
        - Validate that the ambiguous error message is mapped to a more human readable error message.
    """
    from GoogleWorkspaceAdmin import google_chromeos_device_action_command
    from CommonServerPython import DemistoException
    client = create_test_client(mocker=mocker)
    expected_context_data = {'chromeOSAction': {'Status': 'Failure'}}
    response_mock = MockResponse(json_data={'error': {'message': 'Delinquent account.'}})
    mocker.patch.object(client, 'google_chromeos_device_action_request',
                        side_effect=DemistoException(message='error', res=response_mock))

    command_result = google_chromeos_device_action_command(client=client, resource_id='wrong_resource_id',
                                                           action='some_action')
    assert 'Please check the resource_id argument.' in command_result.to_context().get('HumanReadable')
    assert expected_context_data == command_result.to_context().get('Contents')


def test_invalid_customer_id_client_connection(mocker):
    """
    Given:
        - A client and an invalid customer id.
    When:
        - Running test module with an invalid customer id, and receiving the error message `Bad Request`.
    Then:
        - Validate that the ambiguous error message is mapped to a more human readable error message.
    """
    from GoogleWorkspaceAdmin import test_module, INVALID_CUSTOMER_ID_ERROR
    from CommonServerPython import DemistoException
    response_mock = MockResponse(json_data={'error': {'message': 'Bad Request'}})
    mocker.patch('GoogleWorkspaceAdmin.Client._get_oauth_token', return_value='token')
    mocker.patch('GoogleWorkspaceAdmin.Client._http_request', side_effect=DemistoException(message='error', res=response_mock))
    client = create_test_client(mocker=mocker)
    with pytest.raises(DemistoException) as e:
        test_module(client=client)
    assert INVALID_CUSTOMER_ID_ERROR in str(e)


def test_unauthorized_service_account_client_connection(mocker):
    """
    Given:
        - A client and an unauthorized service account
    When:
        - Running test module with an unauthorized service account, and receiving the error message
        `Not Authorized to access this resource/api`.
    Then:
        - Validate that the ambiguous error message is mapped to a more human readable error message.
    """
    from GoogleWorkspaceAdmin import test_module, UNAUTHORIZED_SERVICE_ACCOUNT_ERROR
    from CommonServerPython import DemistoException
    response_mock = MockResponse(json_data={'error': {'message': 'Not Authorized to access this resource/api'}})
    mocker.patch('GoogleWorkspaceAdmin.Client._get_oauth_token', return_value='token')
    mocker.patch('GoogleWorkspaceAdmin.Client._http_request', side_effect=DemistoException(message='error', res=response_mock))
    client = create_test_client(mocker=mocker)
    with pytest.raises(DemistoException) as e:
        test_module(client=client)
    assert UNAUTHORIZED_SERVICE_ACCOUNT_ERROR in str(e)


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
        Client(base_url=BASE_URL, verify=False, proxy=False, customer_id='id', service_account_json={'wrong': 'service_account'})
    assert 'Please check the service account\'s json content' in str(e)


TEST_DATA_INVALID_PAGINATION_ARGUMENTS = [
    ({'page': '3', 'page_size': '4', 'limit': '25'}, ('please supply either the argument limit,'
                                                      ' or the argument page, or the arguments page and page_size together.')),
    ({'page_size': '4'}, 'Please insert a page number'),
    ({'page': '2', 'page_size': '101'}, 'The maximum page size is')
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
        outputs_prefix=f'{OUTPUT_PREFIX}',
        outputs_key_field='mobileAction.Status',
        readable_output='Success',
        outputs={'mobileAction': {'Status': 'Success'}},
    )
    client = create_test_client(mocker=mocker)
    mocker.patch.object(client, 'google_mobile_device_action_request', return_value='nothing')
    command_result = google_mobile_device_action_command(client=client, resource_id='nothing', action='correct_action')
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
        outputs_prefix=f'{OUTPUT_PREFIX}',
        outputs_key_field='chromeOSAction.Status',
        readable_output='Success',
        outputs={'chromeOSAction': {'Status': 'Success'}},
    )
    client = create_test_client(mocker=mocker)
    mocker.patch.object(client, 'google_chromeos_device_action_request', return_value='nothing')
    command_result = google_chromeos_device_action_command(client=client, resource_id='nothing', deprovision_reason='nothing',
                                                           action='nothing')
    assert command_result.to_context() == expected_command_result.to_context()


TEST_DATA_AUTO_PAGINATION_FILES_CASES = [
    ('test_data/mobile_devices_list/automatic_pagination/raw_results_3_pages.json',
     'test_data/mobile_devices_list/automatic_pagination//parsed_results_3_pages.json', '7'),
    ('test_data/mobile_devices_list/automatic_pagination/raw_results_2_pages.json',
     'test_data/mobile_devices_list/automatic_pagination//parsed_results_2_pages.json', '6')
]


@pytest.mark.parametrize('raw_results_file, parsed_results_file, limit', TEST_DATA_AUTO_PAGINATION_FILES_CASES)
def test_mobile_device_list_automatic_pagination(mocker, raw_results_file, parsed_results_file, limit):
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
    args = {'projection': 'full', 'order_by': 'name', 'sort_order': 'descending', 'limit': limit}
    client = create_test_client(mocker=mocker)
    raw_responses = util_load_json(raw_results_file)
    expected_command_results = util_load_json(parsed_results_file)
    mocker.patch.object(client, 'google_mobile_device_list_request', side_effect=raw_responses)
    command_results = google_mobile_device_list_command(client=client, **args)
    to_context = command_results.to_context()
    assert expected_command_results.get('HumanReadable') == to_context.get('HumanReadable')
    assert expected_command_results.get('EntryContext') == to_context.get('EntryContext')


TEST_DATA_MANUAL_PAGINATION_FILES_CASES = [
    ('test_data/mobile_devices_list/manual_pagination/raw_results.json',
     'test_data/mobile_devices_list/manual_pagination//parsed_results.json', {'page': '3', 'page_size': '2'}),
    ('test_data/mobile_devices_list/manual_pagination/raw_results_page_not_found.json',
     'test_data/mobile_devices_list/manual_pagination//parsed_results_page_not_found.json', {'page': '4', 'page_size': '3'})
]


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
    command_results = google_mobile_device_list_command(client=client, **args)
    to_context = command_results.to_context()
    assert expected_command_results.get('HumanReadable') == to_context.get('HumanReadable')
    assert expected_command_results.get('EntryContext') == to_context.get('EntryContext')
