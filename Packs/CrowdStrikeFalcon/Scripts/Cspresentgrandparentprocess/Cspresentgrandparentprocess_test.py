import pytest
from Cspresentgrandparentprocess import main
from CommonServerPython import *


@pytest.fixture
def raw_response():
    return {
        'resources': [
            {
                'device_id': 'device1',
                'grandparent_process_id': 'grandparent1',
                'grandparent_process_name': 'grandprocess1.exe',
                'grandparent_process_command_line': 'grandprocess1.exe --arg1 --arg2'
            },
            {
                'device_id': 'device2',
                'grandparent_process_id': 'grandparent2',
                'grandparent_process_name': 'grandprocess2.exe',
                'grandparent_process_command_line': 'grandprocess2.exe --arg3 --arg4'
            }
        ]
    }


def test_main(mocker, raw_response):
    # Mock demisto.args()
    mocker.patch.object(demisto, 'args', return_value={})

    # Mock demisto.context()
    mock_context = {
        'CrowdStrike': {
            'Detection': [
                {
                    'grandparentprocess': raw_response['resources'][0]
                }
            ]
        }
    }
    mocker.patch.object(demisto, 'context', return_value=mock_context)

    # Mock demisto.results()
    results = mocker.patch.object(demisto, 'results')

    # Call the main function
    main()

    # Assert the results
    assert results.call_count == 1
    output = results.call_args[0][0]
    assert isinstance(output, dict)
    assert 'Contents' in output
    assert '| ***Grand Parent Process Information*** | ***Value*** |' in output['Contents']
    assert 'device_id' in output['Contents']
    assert 'grandparent_process_id' in output['Contents']


def test_main_no_results(mocker):
    # Mock demisto.args()
    mocker.patch.object(demisto, 'args', return_value={})

    # Mock demisto.context() with empty result
    mocker.patch.object(demisto, 'context', return_value={'CrowdStrike': {'Detection': []}})

    # Mock demisto.results()
    results = mocker.patch.object(demisto, 'results')

    # Call the main function
    main()

    # Assert the results
    assert results.call_count == 2
    assert results.call_args[0][0] == 'No grand parent process information were found on CrowdStrike.Detection key'


if __name__ == "__main__":
    pytest.main([__file__])
