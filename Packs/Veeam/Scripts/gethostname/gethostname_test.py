import pytest
import demistomock as demisto
from gethostname import find_host, main


@pytest.mark.parametrize("data, expected", [
    ([{'urn': 'hostsystem:foo'},
      {'urn': 'hostsystem:bar'}],
     'foo'),
    ([{'urn': 'hostsystem:baz'},
      {'urn': 'folder:123'}],
     'baz'),
    ([{'urn': 'folder:321'},
      {'urn': 'folder:789'}],
     ''),
])
def test_find_host(data, expected):
    assert find_host(data) == expected


@pytest.mark.parametrize(
    "data, returned_value, expected_command_results",
    [
        (
            {
                'data': [
                    {'urn': 'hostsystem:foo'},
                    {'urn': 'hostsystem:bar'}
                ]
            },
            'foo',
            {
                'outputs_prefix': 'Veeam.HOST',
                'outputs': {'parsed_value': 'foo'}
            }
        )
    ]
)
def test_main(mocker, data, returned_value, expected_command_results):
    mocker.patch.object(demisto, 'args', return_value=data)
    mocker.patch('gethostname.find_host', return_value=returned_value)
    mock_return_results = mocker.patch('gethostname.return_results')
    main()
    mock_return_results.assert_called_once()
    command_results = mock_return_results.call_args[0][0]
    assert command_results.outputs_prefix == expected_command_results['outputs_prefix']
    assert command_results.outputs == expected_command_results['outputs']
