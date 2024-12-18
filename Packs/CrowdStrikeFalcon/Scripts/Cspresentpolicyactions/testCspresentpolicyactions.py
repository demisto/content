import pytest
from Cspresentpolicyactions import main
from CommonServerPython import *


@pytest.fixture
def raw_response():
    return {
        'resources': [
            {
                'action': 'ALLOW',
                'name': 'Policy 1',
                'description': 'Description 1'
            },
            {
                'action': 'BLOCK',
                'name': 'Policy 2',
                'description': 'Description 2'
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
    assert output['CrowdStrike'][0]['Action'] == 'ALLOW'
    assert output['CrowdStrike'][1]['Action'] == 'BLOCK'


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
    assert results.call_args[0][0] == 'No results found'
