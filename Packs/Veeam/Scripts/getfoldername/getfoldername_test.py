import pytest
import demistomock as demisto
from getfoldername import find_folder, main


@pytest.mark.parametrize("data, expected", [
    (
        [{'urn': 'folder:123;folder:group-v456'},
         {'urn': 'folder:789'},
         {'urn': 'folder:group-v987;folder:group-v654'}],
        'group-v456'
    ),
    (
        [{'urn': 'host:123'},
         {'urn': 'host:789'}],
        ''
    ),
    (
        [{'urn': 'folder:group-v456'}],
        'group-v456'
    ),
])
def test_find_folder(data, expected):
    assert find_folder(data) == expected


@pytest.mark.parametrize(
    "data, returned_value, expected_command_results",
    [
        (
            {
                'data': [
                    {'urn': 'folder:123;folder:group-v456'},
                    {'urn': 'folder:789'},
                    {'urn': 'folder:group-v987;folder:group-v654'}
                ]
            },
            'group-v456',
            {
                'outputs_prefix': 'Veeam.FOLDER',
                'outputs': {'parsed_value': 'group-v456'}
            }
        )
    ]
)
def test_main(mocker, data, returned_value, expected_command_results):
    mocker.patch.object(demisto, 'args', return_value=data)
    mocker.patch('getfoldername.find_folder', return_value=returned_value)
    mock_return_results = mocker.patch('getfoldername.return_results')
    main()
    mock_return_results.assert_called_once()
    command_results = mock_return_results.call_args[0][0]
    assert command_results.outputs_prefix == expected_command_results['outputs_prefix']
    assert command_results.outputs == expected_command_results['outputs']
