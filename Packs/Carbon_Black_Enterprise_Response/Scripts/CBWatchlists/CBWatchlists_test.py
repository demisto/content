import pytest
import demistomock as demisto  # noqa: F401
from CommonServerPython import *

QUERY_COMMAND_RESPONSE = [([{
    'Type': entryTypes['note'],
    'Contents': [
        {'name': 'test_value',
         'last_hit_count': '3'}
    ]
}], [{'name': 'test_value', 'last_hit_count': '3'}]),
    ([{
        'Type': entryTypes['note'],
        'Contents': []
    }], 'No matches.')
]


@pytest.mark.parametrize('res, contents', QUERY_COMMAND_RESPONSE)
def test_mimecast_find_email(res, contents, mocker):
    mocker.patch.object(demisto, 'executeCommand', return_value=res)
    mocker.patch.object(demisto, 'results')
    mocker.patch.object(demisto, 'args', return_value={})

    from CBWatchlists import main

    main()
    results = demisto.results.call_args[0][0]

    assert results[0].get('Contents') == contents
