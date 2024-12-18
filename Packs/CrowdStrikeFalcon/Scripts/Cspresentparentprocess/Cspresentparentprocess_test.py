import pytest
from Cspresentparentprocess import main
from CommonServerPython import *


@pytest.fixture
def raw_response():
    return {
        'resources': [
            {
                'device_id': 'device1',
                'parent_process_id': 'parent1',
                'parent_process_name': 'process1.exe',
                'parent_process_command_line': 'process1.exe --arg1 --arg2'
            },
            {
                'device_id': 'device2',
                'parent_process_id': 'parent2',
                'parent_process_name': 'process2.exe',
                'parent_process_command_line': 'process2.exe --arg3 --arg4'
            }
        ]
    }


def test_main(mocker):
    # Mock demisto.args()
    mocker.patch.object(demisto, 'args', return_value={})

    # Mock demisto.results()
    results = mocker.patch.object(demisto, 'results')

    # Mock demisto.executeCommand()
    mocker.patch.object(demisto, 'executeCommand', return_value=[{'Contents': raw_response()}])

    # Call the main function
    main()

    # Assert the results
    assert results.call_count == 1
    output = results.call_args[0][0]
    assert isinstance(output, dict)
    assert 'CrowdStrike' in output
    assert len(output['CrowdStrike']) == 2
    assert output['CrowdStrike'][0]['DeviceId'] == 'device1'
    assert output['CrowdStrike'][1]['DeviceId'] == 'device2'


def test_main_no_results(mocker):
    # Mock demisto.args()
    mocker.patch.object(demisto, 'args', return_value={})

    # Mock demisto.results()
    results = mocker.patch.object(demisto, 'results')

    # Mock demisto.executeCommand() with empty result
    mocker.patch.object(demisto, 'executeCommand', return_value=[{'Contents': {'resources': []}}])

    # Call the main function
    main()

    # Assert the results
    assert results.call_count == 1
    assert results.call_args[0][0] == 'No parent process information were found on CrowdStrike.Detection key'


if __name__ == "__main__":
    pytest.main([__file__])
