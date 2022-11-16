import json
import io
import pytest
from GoogleWorkspaceAdmin import Client
import demistomock as demisto

BASE_URL = 'https://example.com/'
OUTPUT_PREFIX = 'Google'  # TODO Ask if we should keep this


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def create_test_client(mocker):
    mocker.patch('GoogleWorkspaceAdmin.Client._init_credentials', return_value=None)
    return Client(base_url=BASE_URL, verify=False, proxy=False, customer_id='id', service_account_json={})


def test_mobile_device_action_exception(mocker):
    """
    Given:
        - 
    When:
        - 
    Then:
        - 
    """
    from GoogleWorkspaceAdmin import google_mobile_device_action_command
    from CommonServerPython import CommandResults
    expected_command_result = CommandResults(
        outputs_prefix=f'{OUTPUT_PREFIX}.mobileAction',
        readable_output='Failure',
        outputs={'Response': 'Failure'},
    )
    demisto_mocker = mocker.patch.object(demisto, 'debug')
    client = create_test_client(mocker=mocker)
    command_result = google_mobile_device_action_command(client=client, resource_id='nothing', action='wrong_action')
    assert 'Unsupported argument value' and 'action' in demisto_mocker.call_args[0][0]
    assert command_result.to_context() == expected_command_result.to_context()


def test_mobile_device_action(mocker):
    """
    Given:
        - 
    When:
        - 
    Then:
        - 
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
    command_result = google_mobile_device_action_command(client=client, resource_id='nothing', action='nothing')
    assert command_result.to_context() == expected_command_result.to_context()


def test_chromeos_device_action_exception(mocker):
    """
    Given:
        - 
    When:
        - 
    Then:
        - 
    """
    from GoogleWorkspaceAdmin import google_chromeos_device_action_command
    from CommonServerPython import CommandResults
    expected_command_result = CommandResults(
        outputs_prefix=f'{OUTPUT_PREFIX}.chromeOSAction',
        readable_output='Failure',
        outputs={'Response': 'Failure'},
    )
    demisto_mocker = mocker.patch.object(demisto, 'debug')
    client = create_test_client(mocker=mocker)
    command_result = google_chromeos_device_action_command(client=client, resource_id='nothing',
                                                           deprovision_reason='wrong_reason', action='deprovision')
    assert 'Unsupported argument value' and 'deprovision_reason' in demisto_mocker.call_args[0][0]
    assert command_result.to_context() == expected_command_result.to_context()

    command_result = google_chromeos_device_action_command(client=client, resource_id='nothing', action='wrong_action')
    assert 'Unsupported argument value' and 'action' in demisto_mocker.call_args[0][0]
    assert command_result.to_context() == expected_command_result.to_context()


def test_chromeos_device_action(mocker):
    """
    Given:
        - 
    When:
        - 
    Then:
        - 
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
