import json
import io
import pytest
from GoogleWorkspaceAdmin import Client

BASE_URL = 'https://example.com/'
OUTPUT_PREFIX = 'Google'  # TODO Ask if we should keep this


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def create_test_client(mocker) -> Client:
    """ This will create a mock client in order to use in the tests

    Returns:
        Client: A mock client instance
    """
    mocker.patch('GoogleWorkspaceAdmin.Client._init_credentials', return_value=None)
    return Client(base_url=BASE_URL, verify=False, proxy=False, customer_id='id', service_account_json={})


TEST_DATA_INVALID_PAGINATION_ARGUMENTS = [
    ({'page': '3', 'page_size': '4', 'limit': '25'}, ('please supply either the argument limit,'
                                                      ' or the argument page, or the arguments page and page_size together.')),
    ({'page_size': '4'}, 'Please insert a page number'),
    ({'page': '2', 'page_size': '101'}, 'The maximum page size is')
]

@pytest.mark.parametrize('args, error_message', TEST_DATA_INVALID_PAGINATION_ARGUMENTS)
def test_invalid_pagination_arguments(args, error_message):
    from GoogleWorkspaceAdmin import prepare_pagination_arguments
    from CommonServerPython import DemistoException
    with pytest.raises(DemistoException) as e:
        prepare_pagination_arguments(args=args)
    assert error_message in str(e)


TEST_DATA_MOBILE_DEVICE_LIST_WRONG_ARGUMENTS = [
    ({'projection': 'Basics'}, 'Unsupported argument value'),
    ({'projection': 'Basic', 'sort_order': 'ASCENDINGs'}, 'Unsupported argument value'),
    ({'sort_order': 'ASCENDINGs'}, 'Unsupported argument value'),
    ({'projection': 'Basic', 'sort_order': 'ASCENDING', 'order_by': 'lastsynC'}, 'Unsupported argument value'),
    ({'order_by': 'lastsynC'}, 'Unsupported argument value'),
    ({'sort_order': 'Ascending'}, 'sort_order argument must be used with the order_by parameter.')
]

@pytest.mark.parametrize('args, error_message', TEST_DATA_MOBILE_DEVICE_LIST_WRONG_ARGUMENTS)
def test_mobile_device_list_wrong_arguments(mocker, args, error_message):
    from GoogleWorkspaceAdmin import google_mobile_device_list_command
    from CommonServerPython import DemistoException
    client = create_test_client(mocker=mocker)
    with pytest.raises(DemistoException) as e:
        google_mobile_device_list_command(client=client, **args)
    assert error_message in str(e)


def test_mobile_device_action_exception_wrong_action(mocker):
    """
    Given:
        - A client, a resource id (that identifies a mobile device), and an action that affects the mobile device
    When:
        - The command google-mobiledevice-action is run with a wrong action argument
    Then:
        - A CommandResults is returned that marks the command as failure and an error message is sent to demisto.log
    """
    from GoogleWorkspaceAdmin import google_mobile_device_action_command
    from CommonServerPython import CommandResults
    expected_command_result = CommandResults(
        outputs_prefix=f'{OUTPUT_PREFIX}.mobileAction',
        readable_output='Failure',
        outputs={'Reason': 'Unsupported argument value wrong_action for action.', 'Response': 'Failure'},
    )
    client = create_test_client(mocker=mocker)
    command_result = google_mobile_device_action_command(client=client, resource_id='nothing', action='wrong_action')
    assert command_result.to_context() == expected_command_result.to_context()


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
        outputs_prefix=f'{OUTPUT_PREFIX}.mobileAction',
        readable_output='Success',
        outputs={'Response': 'Success'},
    )
    client = create_test_client(mocker=mocker)
    mocker.patch.object(client, 'google_mobile_device_action_request', return_value='nothing')
    command_result = google_mobile_device_action_command(client=client, resource_id='nothing', action='correct_action')
    assert command_result.to_context() == expected_command_result.to_context()


def test_chromeos_device_action_exception_wrong_action(mocker):
    """
    Given:
        -  A client, a resource id (that identifies a mobile device), and an action that affects the chromeos device
    When:
        - The command google-chromeosdevice-action is run with a wrong action argument
    Then:
        - A CommandResults is returned that marks the command as failure and an error message is sent to demisto.log
    """
    from GoogleWorkspaceAdmin import google_chromeos_device_action_command
    from CommonServerPython import CommandResults
    expected_command_result = CommandResults(
        outputs_prefix=f'{OUTPUT_PREFIX}.chromeOSAction',
        readable_output='Failure',
        outputs={'Reason': 'Unsupported argument value wrong_action for action.', 'Response': 'Failure'},
    )
    client = create_test_client(mocker=mocker)
    command_result = google_chromeos_device_action_command(client=client, resource_id='nothing', action='wrong_action')
    assert command_result.to_context() == expected_command_result.to_context()


def test_chromeos_device_action_exception_wrong_deprovision_reason(mocker):
    """
    Given:
        - A client, a resource id (that identifies a mobile device), and an action that affects the chromeos device
    When:
        - The command google-chromeosdevice-action is run with the action argument being set to `deprovision` and a wrong
          deprovision_reason argument
    Then:
        - A CommandResults is returned that marks the command as failure and an error message is sent to demisto.log
    """
    from GoogleWorkspaceAdmin import google_chromeos_device_action_command
    from CommonServerPython import CommandResults
    expected_command_result = CommandResults(
        outputs_prefix=f'{OUTPUT_PREFIX}.chromeOSAction',
        readable_output='Failure',
        outputs={'Reason': 'Unsupported argument value wrong_reason for deprovision_reason.', 'Response': 'Failure'},
    )
    client = create_test_client(mocker=mocker)
    command_result = google_chromeos_device_action_command(client=client, resource_id='nothing',
                                                           deprovision_reason='wrong_reason', action='deprovision')
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
        outputs_prefix=f'{OUTPUT_PREFIX}.chromeOSAction',
        readable_output='Success',
        outputs={'Response': 'Success'},
    )
    client = create_test_client(mocker=mocker)
    mocker.patch.object(client, 'google_chromeos_device_action_request', return_value='nothing')
    command_result = google_chromeos_device_action_command(client=client, resource_id='nothing', deprovision_reason='nothing',
                                                           action='nothing')
    assert command_result.to_context() == expected_command_result.to_context()


TEST_DATA_CHROMEOS_DEVICE_LIST_WRONG_ARGUMENTS = [
    ({'projection': 'Basics'}, 'Unsupported argument value'),
    ({'projection': 'Basic', 'sort_order': 'ASCENDINGs'}, 'Unsupported argument value'),
    ({'sort_order': 'ASCENDINGs'}, 'Unsupported argument value'),
    ({'projection': 'Basic', 'sort_order': 'ASCENDING', 'order_by': 'lastsynC'}, 'Unsupported argument value'),
    ({'order_by': 'lastsynC'}, 'Unsupported argument value'),
    ({'include_child_org_units': True, 'projection': 'Basic', 'sort_order': 'ASCENDING', 'order_by': 'last_sync'},
     'If include_child_org_units is set to true, org_unit_path must be provided'),
    ({'sort_order': 'Ascending'}, 'sort_order argument must be used with the order_by parameter.')
]

@pytest.mark.parametrize('args, error_message', TEST_DATA_CHROMEOS_DEVICE_LIST_WRONG_ARGUMENTS)
def test_chromeos_device_list_wrong_arguments(mocker, args, error_message):
    from GoogleWorkspaceAdmin import google_chromeos_device_list_command
    from CommonServerPython import DemistoException
    client = create_test_client(mocker=mocker)
    with pytest.raises(DemistoException) as e:
        google_chromeos_device_list_command(client=client, **args)
    assert error_message in str(e)


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
        -
    When:
        -
    Then:
        -
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
        -
    When:
        -
    Then:
        -
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
